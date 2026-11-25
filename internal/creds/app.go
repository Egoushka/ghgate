package creds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Egoushka/ghgate/internal/cache"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	renewBefore = 10 * time.Minute
	loadBackoff = 60 * time.Second
)

type installation struct {
	id    int64
	login string
}

type cachedTok struct {
	tok     string
	expires time.Time
}

// App mints installation tokens for a GitHub App, one per owner.
type App struct {
	id      int64
	keyFile string
	apiBase string
	hc      *http.Client
	now     func() time.Time
	flights cache.Group

	mu       sync.Mutex // guards the fields below; never held across an HTTP call
	key      *rsa.PrivateKey
	installs []installation
	loadedAt time.Time
	failedAt time.Time // last failed installation load; retried only after loadBackoff
	loadErr  error
	toks     map[string]cachedTok
}

func NewApp(id int64, keyFile, apiBase string, hc *http.Client) *App {
	return &App{id: id, keyFile: keyFile, apiBase: strings.TrimRight(apiBase, "/"), hc: hc, now: time.Now, toks: map[string]cachedTok{}}
}

type tokResult struct {
	tok, label string
	err        error
}

func (a *App) label(login string) string {
	return fmt.Sprintf("app:%d:%s", a.id, strings.ToLower(login))
}

func (a *App) cached(owner string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.toks[owner]
	if ok && a.now().Before(t.expires.Add(-renewBefore)) {
		return t.tok, true
	}
	return "", false
}

// Token returns a token for owner. Concurrent calls for one owner share one mint.
func (a *App) Token(ctx context.Context, owner string) (string, string, error) {
	owner = strings.ToLower(owner)
	if tok, ok := a.cached(owner); ok {
		return tok, a.label(owner), nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	v, _ := a.flights.Do("tok|"+owner, func() any {
		tok, label, err := a.mint(ctx, owner)
		return tokResult{tok, label, err}
	})
	r := v.(tokResult)
	return r.tok, r.label, r.err
}

func (a *App) mint(ctx context.Context, owner string) (string, string, error) {
	inst, err := a.findInstallation(ctx, owner)
	if err != nil {
		return "", "", err
	}
	login := strings.ToLower(inst.login)
	if tok, ok := a.cached(login); ok {
		return tok, a.label(login), nil
	}
	jwt, err := a.jwt()
	if err != nil {
		return "", "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.call(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", inst.id), jwt, &out); err != nil {
		return "", "", err
	}
	if out.Token == "" {
		return "", "", errors.New("creds: empty installation token")
	}
	a.mu.Lock()
	a.toks[login] = cachedTok{out.Token, out.ExpiresAt}
	a.toks[owner] = cachedTok{out.Token, out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, a.label(login), nil
}

// findInstallation looks the owner up, reloading the installation list at most
// once a minute, and not at all for 60 s after a failed load.
func (a *App) findInstallation(ctx context.Context, owner string) (installation, error) {
	if owner == "" {
		return installation{}, ErrNoInstallation // no owner, no installation: callers use default_owner or another credential
	}
	a.mu.Lock()
	loaded, age := a.installs != nil, a.now().Sub(a.loadedAt)
	i := a.find(owner)
	if (!loaded || i == nil) && a.loadErr != nil && a.now().Sub(a.failedAt) < loadBackoff {
		err := a.loadErr
		a.mu.Unlock()
		return installation{}, err
	}
	a.mu.Unlock()
	if !loaded || (i == nil && age > time.Minute) {
		v, _ := a.flights.Do("installs", func() any { return a.loadInstallations(ctx) })
		if err, _ := v.(error); err != nil {
			return installation{}, err
		}
		a.mu.Lock()
		i = a.find(owner)
		a.mu.Unlock()
	}
	if i != nil {
		return *i, nil
	}
	return installation{}, ErrNoInstallation
}

func (a *App) loadInstallations(ctx context.Context) any {
	fail := func(err error) any {
		a.mu.Lock()
		a.loadErr, a.failedAt = err, a.now()
		a.mu.Unlock()
		return err
	}
	jwt, err := a.jwt()
	if err != nil {
		return fail(err)
	}
	all := []installation{}
	for page := 1; page <= 20; page++ {
		var out []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		}
		if err := a.call(ctx, http.MethodGet, fmt.Sprintf("/app/installations?per_page=100&page=%d", page), jwt, &out); err != nil {
			return fail(err)
		}
		for _, o := range out {
			all = append(all, installation{o.ID, o.Account.Login})
		}
		if len(out) < 100 {
			break
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })
	a.mu.Lock()
	a.installs, a.loadedAt, a.loadErr = all, a.now(), nil
	a.mu.Unlock()
	return nil
}

// find must be called with a.mu held.
func (a *App) find(owner string) *installation {
	for i := range a.installs {
		if owner != "" && strings.EqualFold(a.installs[i].login, owner) {
			return &a.installs[i]
		}
	}
	return nil
}

func (a *App) call(ctx context.Context, method, path, jwt string, out any) error {
	return a.callBody(ctx, method, path, jwt, nil, out)
}

func (a *App) callBody(ctx context.Context, method, path, jwt string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.apiBase+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ghgate")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return errors.New("creds: app request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("creds: app request %s returned %d", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a *App) loadKey() (*rsa.PrivateKey, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.key != nil {
		return a.key, nil
	}
	b, err := os.ReadFile(a.keyFile)
	if err != nil {
		return nil, errors.New("creds: cannot read app key file")
	}
	k, err := ParseKey(b)
	if err != nil {
		return nil, err
	}
	a.key = k
	return k, nil
}

// ParseKey parses an RSA private key in PEM form (PKCS#1 or PKCS#8).
func ParseKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("creds: app key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("creds: cannot parse app key")
	}
	k, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("creds: app key is not RSA")
	}
	return k, nil
}

// KeyFromEnv reads an App key from the environment variable name. The value is
// PEM text or the base64 of the PEM. Errors name the variable, never its value.
func KeyFromEnv(name string) (*rsa.PrivateKey, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return nil, fmt.Errorf("creds: environment variable %s is empty or unset", name)
	}
	if !strings.Contains(v, "-----BEGIN") {
		dec, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("creds: %s is neither PEM nor base64", name)
		}
		v = string(dec)
	}
	k, err := ParseKey([]byte(v))
	if err != nil {
		return nil, fmt.Errorf("%s (from %s)", err.Error(), name)
	}
	return k, nil
}

// NewAppWithKey is NewApp for a key already in memory.
func NewAppWithKey(id int64, key *rsa.PrivateKey, apiBase string, hc *http.Client) *App {
	a := NewApp(id, "", apiBase, hc)
	a.key = key
	return a
}

// jwt signs an RS256 app JWT, valid for 9 minutes.
func (a *App) jwt() (string, error) {
	k, err := a.loadKey()
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	a.mu.Lock()
	now := a.now()
	a.mu.Unlock()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	pl, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": a.id})
	msg := enc.EncodeToString(hdr) + "." + enc.EncodeToString(pl)
	h := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return msg + "." + enc.EncodeToString(sig), nil
}

// scopeKey names one narrowed token: owner, sorted repository names and sorted permissions.
func scopeKey(owner string, repos []string, perms map[string]string) string {
	r := append([]string(nil), repos...)
	sort.Strings(r)
	ks := make([]string, 0, len(perms))
	for k, v := range perms {
		ks = append(ks, k+"="+v)
	}
	sort.Strings(ks)
	return "scoped|" + strings.ToLower(owner) + "|" + strings.Join(r, ",") + "|" + strings.Join(ks, ",")
}

// TokenScoped returns an installation token for owner limited to repos (names, without the owner; empty means
// every repository of the installation) and to perms (empty means the App's own permissions). A token is reused
// until 10 minutes before it expires, so the caller always gets at least 10 minutes of life.
func (a *App) TokenScoped(ctx context.Context, owner string, repos []string, perms map[string]string) (string, string, time.Time, error) {
	owner = strings.ToLower(owner)
	if len(repos) == 0 && len(perms) == 0 {
		tok, label, err := a.Token(ctx, owner)
		a.mu.Lock()
		exp := a.toks[owner].expires
		a.mu.Unlock()
		return tok, label, exp, err
	}
	key := scopeKey(owner, repos, perms)
	if tok, exp, ok := a.cachedKey(key); ok {
		return tok, a.label(owner), exp, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	type res struct {
		tok string
		exp time.Time
		err error
	}
	v, _ := a.flights.Do(key, func() any {
		inst, err := a.findInstallation(ctx, owner)
		if err != nil {
			return res{err: err}
		}
		jwt, err := a.jwt()
		if err != nil {
			return res{err: err}
		}
		req := map[string]any{}
		if len(repos) > 0 {
			req["repositories"] = repos
		}
		if len(perms) > 0 {
			req["permissions"] = perms
		}
		body, _ := json.Marshal(req)
		var out struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := a.callBody(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", inst.id), jwt, body, &out); err != nil {
			return res{err: err}
		}
		if out.Token == "" {
			return res{err: errors.New("creds: empty installation token")}
		}
		a.mu.Lock()
		a.toks[key] = cachedTok{out.Token, out.ExpiresAt}
		a.mu.Unlock()
		return res{tok: out.Token, exp: out.ExpiresAt}
	})
	r := v.(res)
	return r.tok, a.label(owner), r.exp, r.err
}

func (a *App) cachedKey(key string) (string, time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.toks[key]
	if ok && a.now().Before(t.expires.Add(-renewBefore)) {
		return t.tok, t.expires, true
	}
	return "", time.Time{}, false
}

// Inspection is what GitHub says about one owner's installation of this App: nothing secret.
type Inspection struct {
	Owner       string            `json:"owner"`
	Selection   string            `json:"repository_selection"`
	Permissions map[string]string `json:"permissions"`
	Repos       []string          `json:"repositories"`
}

// Inspect mints a fresh installation token for owner (never cached) and reports the installation's permissions and
// the repositories the token can see. The token itself is not returned.
func (a *App) Inspect(ctx context.Context, owner string) (Inspection, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	inst, err := a.findInstallation(ctx, owner)
	if err != nil {
		return Inspection{}, err
	}
	jwt, err := a.jwt()
	if err != nil {
		return Inspection{}, err
	}
	var tok struct {
		Token     string            `json:"token"`
		Selection string            `json:"repository_selection"`
		Perms     map[string]string `json:"permissions"`
	}
	if err := a.call(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", inst.id), jwt, &tok); err != nil {
		return Inspection{}, err
	}
	out := Inspection{Owner: inst.login, Selection: tok.Selection, Permissions: tok.Perms, Repos: []string{}}
	for page := 1; page <= 10; page++ {
		var rs struct {
			Repositories []struct {
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		if err := a.call(ctx, http.MethodGet, fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page), tok.Token, &rs); err != nil {
			return Inspection{}, err
		}
		for _, r := range rs.Repositories {
			out.Repos = append(out.Repos, r.FullName)
		}
		if len(rs.Repositories) < 100 {
			break
		}
	}
	return out, nil
}
