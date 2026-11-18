package creds

import (
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
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const renewBefore = 10 * time.Minute

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
// once a minute. An empty owner picks the lowest installation id.
func (a *App) findInstallation(ctx context.Context, owner string) (installation, error) {
	a.mu.Lock()
	loaded, age := a.installs != nil, a.now().Sub(a.loadedAt)
	i := a.find(owner)
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
	jwt, err := a.jwt()
	if err != nil {
		return err
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
			return err
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
	a.installs, a.loadedAt = all, a.now()
	a.mu.Unlock()
	return nil
}

// find must be called with a.mu held.
func (a *App) find(owner string) *installation {
	for i := range a.installs {
		if owner == "" || strings.EqualFold(a.installs[i].login, owner) {
			return &a.installs[i]
		}
	}
	return nil
}

func (a *App) call(ctx context.Context, method, path, jwt string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, a.apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ghgate")
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
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("creds: app key file is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		a.key = k
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
	a.key = k
	return k, nil
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
