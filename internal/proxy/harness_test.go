package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Egoushka/ghgate/internal/config"
)

const (
	clientRead  = "client-reader-token-0001"
	clientWrite = "client-writer-token-0002"
	patRead     = "ghp_READ_upstream_secret_aaaa"
	patWrite    = "ghp_WRITE_upstream_secret_bbbb"
)

type seen struct {
	Method, Path, RawQuery, Auth, INM string
	Header                            http.Header
	Body                              string
}

type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []seen
	fn   func(w http.ResponseWriter, r *http.Request)
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		u.mu.Lock()
		u.reqs = append(u.reqs, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("If-None-Match"), r.Header.Clone(), string(b)})
		fn := u.fn
		u.mu.Unlock()
		if fn != nil {
			fn(w, r)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) all() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.reqs...)
}

func (u *upstream) count() int { return len(u.all()) }

type harness struct {
	t         *testing.T
	api, web  *upstream
	srv       *Server
	proxy     *httptest.Server
	logs      *syncBuf
	dir       string
	readFile  string
	writeFile string
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func hashOf(t *testing.T, tok string) string {
	return sha(tok)
}

func newHarness(t *testing.T, mod func(*config.Config)) *harness {
	t.Helper()
	h := &harness{t: t, api: newUpstream(t), web: newUpstream(t), logs: &syncBuf{}, dir: t.TempDir()}
	h.readFile = filepath.Join(h.dir, "read.pat")
	h.writeFile = filepath.Join(h.dir, "write.pat")
	os.WriteFile(h.readFile, []byte(patRead+"\n"), 0o600)
	os.WriteFile(h.writeFile, []byte(patWrite+"\n"), 0o600)
	cfg := &config.Config{
		StateDir:    filepath.Join(h.dir, "state"),
		UpstreamAPI: h.api.URL,
		UpstreamWeb: h.web.URL,
		Clients: []config.Client{
			{Name: "reader", TokenSHA256: hashOf(t, clientRead)},
			{Name: "writer", TokenSHA256: hashOf(t, clientWrite), CanWrite: true},
		},
		Read:  &config.Cred{PatFile: h.readFile},
		Write: &config.Cred{PatFile: h.writeFile},
	}
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, Options{Logger: slog.New(slog.NewJSONHandler(h.logs, nil)), Transport: h.api.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = s
	h.proxy = httptest.NewServer(s)
	t.Cleanup(h.proxy.Close)
	return h
}

// client is what an agent looks like: an HTTP client behind the proxy trusting only ghgate's CA.
func (h *harness) client() *http.Client {
	pu, _ := url.Parse(h.proxy.URL)
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: h.srv.CA().Pool()},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (h *harness) do(c *http.Client, tok, method, target, body string) (*http.Response, string) {
	h.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "token "+tok)
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (h *harness) get(tok, path string) (*http.Response, string) {
	return h.do(h.client(), tok, "GET", "https://api.github.com"+path, "")
}

func certPool(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}
