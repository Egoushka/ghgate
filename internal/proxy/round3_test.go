package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Egoushka/ghgate/internal/config"
)

func appHarness(t *testing.T, defaultOwner string) *harness {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	h := newHarness(t, func(c *config.Config) {
		c.Read = &config.Cred{App: &config.App{ID: 4242, KeyFile: keyFile}}
		c.DefaultOwner = defaultOwner
	})
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations":
			io.WriteString(w, `[{"id":1,"account":{"login":"zzz"}},{"id":11,"account":{"login":"acme"}}]`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			fmt.Fprintf(w, `{"token":"inst-%s","expires_at":%q}`, strings.Split(r.URL.Path, "/")[3], time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		}
	}
	return h
}

func lastAuth(h *harness) string {
	r := h.api.all()
	return r[len(r)-1].Auth
}

func TestDefaultOwnerServesRequestsWithoutAnOwner(t *testing.T) {
	h := appHarness(t, "Acme")
	h.get(clientRead, "/user")
	if lastAuth(h) != "Bearer inst-11" {
		t.Fatalf("/user must use default_owner's installation, not the lowest id: %q", lastAuth(h))
	}
	h.do(h.client(), clientRead, "POST", apiURL+"/graphql", `{"query":"{ viewer { login } }"}`)
	if lastAuth(h) != "Bearer inst-11" {
		t.Fatalf("graphql: %q", lastAuth(h))
	}
	h.get(clientRead, "/repositories/123")
	if lastAuth(h) != "Bearer inst-11" {
		t.Fatalf("/repositories/N: %q", lastAuth(h))
	}
}

func TestNoDefaultOwnerFallsBackToTheWriteCredentialOnlyForWriters(t *testing.T) {
	h := appHarness(t, "")
	c := h.client()
	// a read-only client never gets an answer fetched with the write credential (gate r3)
	n := h.api.count()
	for _, p := range []string{"/user", "/repositories/42/contents/secret", "/search/code?q=repo:acme/private+secret"} {
		if resp, _ := h.get(clientRead, p); resp.StatusCode != 403 || h.api.count() != n {
			t.Fatalf("ownerless GET %s by a read-only client must be refused before upstream: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := h.get(clientWrite, "/user"); resp.StatusCode != 200 || lastAuth(h) != "Bearer "+patWrite {
		t.Fatalf("ownerless GET by a writer: %d %q", resp.StatusCode, lastAuth(h))
	}
	n = h.api.count()
	q := `{"query":"{ viewer { login } }"}`
	if resp, _ := h.do(c, clientRead, "POST", apiURL+"/graphql", q); resp.StatusCode != 403 || h.api.count() != n {
		t.Fatalf("graphql by a read-only client must be refused: %d", resp.StatusCode)
	}
	if resp, _ := h.do(c, clientWrite, "POST", apiURL+"/graphql", q); resp.StatusCode != 200 || lastAuth(h) != "Bearer "+patWrite {
		t.Fatalf("graphql by a writer: %d %q", resp.StatusCode, lastAuth(h))
	}
	// an owner in the path still uses the App
	h.get(clientRead, "/repos/acme/x")
	if lastAuth(h) != "Bearer inst-11" {
		t.Fatalf("owner in path: %q", lastAuth(h))
	}
	for _, r := range h.api.all() {
		if strings.Contains(r.Auth, "inst-1") && r.Auth == "Bearer inst-1" {
			t.Fatal("the lowest-id installation must never be picked")
		}
	}
}

func TestSameCredentialIsDecidedByIdentity(t *testing.T) {
	var link string
	h := newHarness(t, func(c *config.Config) {
		d := t.TempDir()
		link = filepath.Join(d, "alias.pat")
		os.Symlink(c.Write.PatFile, link)
		c.Read = &config.Cred{PatFile: link} // a different path and pointer, the same file
	})
	if !h.srv.sameCred {
		t.Fatal("a symlink to the write PAT is the same credential")
	}
	q := `{"query":"{ viewer { login } }"}`
	if resp, _ := h.do(h.client(), clientRead, "POST", apiURL+"/graphql", q); resp.StatusCode != 403 {
		t.Fatalf("graphql by a read-only client: %d", resp.StatusCode)
	}
	other := filepath.Join(t.TempDir(), "other")
	os.WriteFile(other, []byte("x"), 0o600)
	if credID(&config.Cred{PatFile: other}) == credID(&config.Cred{PatFile: h.writeFile}) {
		t.Fatal("different files are different credentials")
	}
	if credID(&config.Cred{App: &config.App{ID: 7, KeyFile: "a"}}) != credID(&config.Cred{App: &config.App{ID: 7, KeyFile: "b"}}) ||
		credID(&config.Cred{App: &config.App{ID: 7}}) == credID(&config.Cred{App: &config.App{ID: 8}}) {
		t.Fatal("Apps are the same credential exactly when the id matches")
	}
}

func TestBlockedIPsEmbeddingIPv4(t *testing.T) {
	for _, ip := range []string{"64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2002:a00:1::1", "2002:6440:4::1", "::10.0.0.1", "::127.0.0.1", "::169.254.169.254"} {
		if !blockedIP(net.ParseIP(ip)) {
			t.Errorf("%s embeds an internal IPv4 address and must be blocked", ip)
		}
	}
	for _, ip := range []string{"64:ff9b::808:808", "2002:808:808::1", "::8.8.8.8"} {
		if blockedIP(net.ParseIP(ip)) {
			t.Errorf("%s embeds a public IPv4 address and must be allowed", ip)
		}
	}
}
