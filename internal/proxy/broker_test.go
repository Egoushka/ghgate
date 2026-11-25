package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Egoushka/ghgate/internal/config"
)

const clientScoped = "client-scoped-token-0003"

type mintLog struct {
	mu   sync.Mutex
	body []string
}

func (m *mintLog) add(b string) { m.mu.Lock(); m.body = append(m.body, b); m.mu.Unlock() }
func (m *mintLog) all() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.body...)
}

// brokerHarness has an App write credential and a client limited to acme/site (contents:write) and globex/*.
func brokerHarness(t *testing.T) (*harness, *mintLog) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	ml := &mintLog{}
	h := newHarness(t, func(c *config.Config) {
		c.Write = &config.Cred{App: &config.App{ID: 77, KeyFile: keyFile}}
		c.Clients = append(c.Clients, config.Client{Name: "scoped", TokenSHA256: hashOf(t, clientScoped), CanWrite: true,
			Repos: []string{"acme/site", "globex/*"}, Perms: map[string]string{"contents": "write", "pull_requests": "read"}})
	})
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations":
			io.WriteString(w, `[{"id":11,"account":{"login":"acme"}},{"id":22,"account":{"login":"globex"}}]`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			b, _ := io.ReadAll(r.Body)
			ml.add(r.URL.Path + " " + string(b))
			fmt.Fprintf(w, `{"token":"inst-%d-%s","expires_at":%q}`, len(ml.all()), strings.Split(r.URL.Path, "/")[3], time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			io.WriteString(w, `{}`)
		}
	}
	return h, ml
}

func TestAC13_ScopedClientWritesWithNarrowedAppToken(t *testing.T) {
	h, ml := brokerHarness(t)
	resp, _ := h.do(h.client(), clientScoped, "POST", "https://api.github.com/repos/acme/site/issues", `{"title":"x"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	m := ml.all()
	if len(m) != 1 || !strings.Contains(m[0], `"repositories":["site"]`) || !strings.Contains(m[0], `"contents":"write"`) || !strings.Contains(m[0], `"pull_requests":"read"`) {
		t.Fatalf("mint request: %v", m)
	}
	reqs := h.api.all()
	if got := reqs[len(reqs)-1]; got.Method != "POST" || !strings.HasPrefix(got.Auth, "Bearer inst-1-11") {
		t.Fatalf("upstream saw %s %s", got.Method, got.Auth)
	}
	// an unscoped client still gets the plain installation token, with no narrowing body
	h.do(h.client(), clientWrite, "POST", "https://api.github.com/repos/acme/other/issues", `{}`)
	if m = ml.all(); len(m) != 2 || strings.Contains(m[1], "repositories") {
		t.Fatalf("unscoped mint: %v", m)
	}
}

func TestAC14_ScopedClientIsLimitedToItsRepos(t *testing.T) {
	h, _ := brokerHarness(t)
	for _, c := range []struct{ method, url string }{
		{"GET", "https://api.github.com/repos/acme/other"},
		{"POST", "https://api.github.com/repos/acme/other/issues"},
		{"GET", "https://api.github.com/user"},
		{"POST", "https://api.github.com/graphql"},
		{"GET", "https://api.github.com/repos/acme/site/../other"},
		{"GET", "https://github.com/acme/other.git/info/refs?service=git-upload-pack"},
	} {
		before := h.api.count() + h.web.count()
		resp, _ := h.do(h.client(), clientScoped, c.method, c.url, "")
		if resp.StatusCode != 403 {
			t.Errorf("%s %s: status %d, want 403", c.method, c.url, resp.StatusCode)
		}
		if h.api.count()+h.web.count() != before {
			t.Errorf("%s %s reached upstream", c.method, c.url)
		}
	}
	if resp, _ := h.do(h.client(), clientScoped, "GET", "https://api.github.com/repos/globex/anything", ""); resp.StatusCode != 200 {
		t.Errorf("owner wildcard: %d", resp.StatusCode)
	}
	if resp, _ := h.do(h.client(), clientScoped, "GET", "https://api.github.com/rate_limit", ""); resp.StatusCode != 200 {
		t.Errorf("rate_limit: %d", resp.StatusCode)
	}
}

func vend(h *harness, tok, body string) (int, map[string]any) {
	req, _ := http.NewRequest("POST", h.proxy.URL+"/v1/token", strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAC15_VendEndpointMintsNarrowedTokensAndNeverMore(t *testing.T) {
	h, ml := brokerHarness(t)
	if code, _ := vend(h, "", ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := vend(h, clientRead, ""); code != 403 {
		t.Fatalf("read-only client: %d", code)
	}
	if code, _ := vend(h, clientWrite, ""); code != 403 {
		t.Fatalf("unscoped client must not vend: %d", code)
	}
	code, out := vend(h, clientScoped, `{"repos":["acme/site"],"permissions":{"contents":"read"}}`)
	if code != 200 || out["token"] == "" || out["expires_at"] == nil {
		t.Fatalf("vend: %d %v", code, out)
	}
	if m := ml.all(); len(m) != 1 || !strings.Contains(m[0], `"repositories":["site"]`) || !strings.Contains(m[0], `"contents":"read"`) || strings.Contains(m[0], "pull_requests") {
		t.Fatalf("mint: %v", m)
	}
	for _, body := range []string{
		`{"repos":["acme/other"]}`,
		`{"repos":["acme/site","globex/x"]}`,
		`{"repos":["acme/*"]}`,
		`{"repos":["acme/site"],"permissions":{"contents":"admin"}}`,
		`{"repos":["acme/site"],"permissions":{"issues":"read"}}`,
	} {
		if code, _ := vend(h, clientScoped, body); code != 403 && code != 400 {
			t.Errorf("%s: %d, want refused", body, code)
		}
	}
	if len(ml.all()) != 1 {
		t.Errorf("refused vends minted tokens: %v", ml.all())
	}
	// no body: the client's whole scope (here two owners) is refused as ambiguous rather than guessed
	if code, _ := vend(h, clientScoped, ""); code != 400 {
		t.Errorf("mixed-owner default scope: %d", code)
	}
}

func TestAC16_ConfigRejectsBadScope(t *testing.T) {
	base := func() config.Config {
		return config.Config{Read: &config.Cred{PatEnv: "X"}, Write: &config.Cred{App: &config.App{ID: 1, KeyEnv: "K"}},
			Clients: []config.Client{{Name: "a", TokenSHA256: strings.Repeat("ab", 32)}}}
	}
	for name, mod := range map[string]func(*config.Client){
		"bad repo":  func(c *config.Client) { c.Repos = []string{"nope"} },
		"bad level": func(c *config.Client) { c.Perms = map[string]string{"contents": "owner"} },
		"bad name":  func(c *config.Client) { c.Perms = map[string]string{"Contents": "read"} },
	} {
		c := base()
		mod(&c.Clients[0])
		if c.Normalize() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := base()
	c.Write = &config.Cred{PatEnv: "P"}
	c.Clients[0].Perms = map[string]string{"contents": "read"}
	if c.Normalize() == nil {
		t.Error("perms with a PAT write credential accepted")
	}
	c = base()
	c.Clients[0].Repos = []string{"Acme/Site", "globex/*"}
	if err := c.Normalize(); err != nil || c.Clients[0].Repos[0] != "acme/site" {
		t.Errorf("good scope: %v %v", err, c.Clients[0].Repos)
	}
}

func TestAC17_ScopedWriteAppServesLimitedClientsAndPATTheRest(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	h := newHarness(t, func(c *config.Config) {
		c.ScopedWrite = &config.Cred{App: &config.App{ID: 77, KeyFile: keyFile}}
		c.Clients = append(c.Clients, config.Client{Name: "scoped", TokenSHA256: hashOf(t, clientScoped), CanWrite: true,
			Repos: []string{"acme/site"}, Perms: map[string]string{"contents": "write"}})
	})
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations":
			io.WriteString(w, `[{"id":11,"account":{"login":"acme"}}]`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			fmt.Fprintf(w, `{"token":"inst-app","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			io.WriteString(w, `{}`)
		}
	}
	h.do(h.client(), clientScoped, "POST", "https://api.github.com/repos/acme/site/issues", `{}`)
	h.do(h.client(), clientWrite, "POST", "https://api.github.com/repos/acme/site/issues", `{}`)
	var auths []string
	for _, r := range h.api.all() {
		if r.Method == "POST" && strings.HasSuffix(r.Path, "/issues") {
			auths = append(auths, r.Auth)
		}
	}
	if len(auths) != 2 || auths[0] != "Bearer inst-app" || auths[1] != "Bearer "+patWrite {
		t.Fatalf("auths %v", auths)
	}
}
