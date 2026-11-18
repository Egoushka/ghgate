package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Egoushka/ghgate/internal/config"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func etagHandler(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, body)
	}
}

func TestAC1_SecondGetRevalidatesAndServes200(t *testing.T) {
	h := newHarness(t, nil)
	h.api.fn = etagHandler("first-body")
	c := h.client()
	r1, b1 := h.do(c, clientRead, "GET", "https://api.github.com/repos/o/r/issues", "")
	r2, b2 := h.do(c, clientRead, "GET", "https://api.github.com/repos/o/r/issues", "")
	if r1.StatusCode != 200 || b1 != "first-body" || r1.Header.Get("X-Ghgate-Cache") != "miss" {
		t.Fatalf("first: %d %q %q", r1.StatusCode, b1, r1.Header.Get("X-Ghgate-Cache"))
	}
	if r2.StatusCode != 200 || b2 != "first-body" || r2.Header.Get("X-Ghgate-Cache") != "revalidated" {
		t.Fatalf("second: %d %q %q", r2.StatusCode, b2, r2.Header.Get("X-Ghgate-Cache"))
	}
	reqs := h.api.all()
	if len(reqs) != 2 || reqs[0].INM != "" || reqs[1].INM != `"v1"` {
		t.Fatalf("upstream requests: %+v", reqs)
	}
	if r2.Header.Get("ETag") != `"v1"` {
		t.Fatalf("etag %q", r2.Header.Get("ETag"))
	}
}

func TestAC2_ConcurrentIdenticalGetsShareOneUpstreamCall(t *testing.T) {
	h := newHarness(t, nil)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			return
		}
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, "body")
	}
	const n = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	outcomes := map[string]int{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := h.client() // own connection, warmed before the race starts
			h.do(c, clientRead, "GET", "https://api.github.com/warm", "")
			<-start
			resp, b := h.do(c, clientRead, "GET", "https://api.github.com/repos/o/r/pulls", "")
			if resp.StatusCode != 200 || b != "body" {
				t.Errorf("got %d %q", resp.StatusCode, b)
			}
			mu.Lock()
			outcomes[resp.Header.Get("X-Ghgate-Cache")]++
			mu.Unlock()
		}()
	}
	time.Sleep(time.Second) // let every goroutine warm up
	close(start)
	wg.Wait()
	calls := 0
	for _, r := range h.api.all() {
		if r.Path == "/repos/o/r/pulls" {
			calls++
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls for the shared URL: %d (outcomes %v)", calls, outcomes)
	}
	if outcomes["miss"] != 1 || outcomes["coalesced"] != n-1 {
		t.Fatalf("outcomes %v", outcomes)
	}
}

func omitRead(c *config.Config) { c.Read = nil }

func TestAC3_CredentialSplitAndClientTokenNeverUpstream(t *testing.T) {
	t.Run("separate", func(t *testing.T) { ac3(t, nil, patRead) })
	t.Run("read omitted", func(t *testing.T) { ac3(t, omitRead, patWrite) })
}

func ac3(t *testing.T, mod func(*config.Config), readTok string) {
	h := newHarness(t, mod)
	c := h.client()
	api := "https://api.github.com"
	h.do(c, clientWrite, "GET", api+"/repos/o/r", "")
	h.do(c, clientWrite, "POST", api+"/graphql", `{"query":"query { viewer { login } }"}`)
	h.do(c, clientWrite, "POST", api+"/repos/o/r/issues", `{"title":"x"}`)
	h.do(c, clientWrite, "PATCH", api+"/repos/o/r/issues/1", `{"state":"closed"}`)
	h.do(c, clientWrite, "DELETE", api+"/repos/o/r/issues/1/labels/bug", "")
	h.do(c, clientWrite, "POST", api+"/graphql", "# c\n"+`{"query":"# hi\nmutation M { addStar(input:{starrableId:\"1\"}) { clientMutationId } }"}`)
	want := []struct{ method, path, tok string }{
		{"GET", "/repos/o/r", readTok},
		{"POST", "/graphql", readTok},
		{"POST", "/repos/o/r/issues", patWrite},
		{"PATCH", "/repos/o/r/issues/1", patWrite},
		{"DELETE", "/repos/o/r/issues/1/labels/bug", patWrite},
		{"POST", "/graphql", patWrite},
	}
	got := h.api.all()
	if len(got) != len(want) {
		t.Fatalf("got %d upstream requests, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Method != w.method || g.Path != w.path || g.Auth != "Bearer "+w.tok {
			t.Errorf("#%d: got %s %s auth-ok=%v", i, g.Method, g.Path, g.Auth == "Bearer "+w.tok)
		}
		all := g.Body + g.Auth
		for k, v := range g.Header {
			all += k + strings.Join(v, ",")
		}
		if strings.Contains(all, clientRead) || strings.Contains(all, clientWrite) {
			t.Errorf("#%d: client token reached upstream", i)
		}
	}
}

func TestAC4_ClientIdentityAndCanWrite(t *testing.T) {
	t.Run("separate", func(t *testing.T) { ac4(t, nil) })
	t.Run("read omitted", func(t *testing.T) { ac4(t, omitRead) })
}

func ac4(t *testing.T, mod func(*config.Config)) {
	h := newHarness(t, mod)
	c := h.client()
	api := "https://api.github.com"
	for _, tok := range []string{"", "not-a-configured-token"} {
		resp, body := h.do(c, tok, "GET", api+"/repos/o/r", "")
		if resp.StatusCode != 401 || !json.Valid([]byte(body)) {
			t.Fatalf("token %q: %d %q", tok, resp.StatusCode, body)
		}
	}
	// the git style: Basic with the token as the password
	req, _ := http.NewRequest("GET", api+"/repos/o/r", nil)
	req.SetBasicAuth("x", "wrong")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("basic wrong: %v %v", err, resp)
	}
	resp.Body.Close()
	if h.api.count() != 0 {
		t.Fatalf("unauthenticated requests reached upstream: %d", h.api.count())
	}
	for _, rq := range [][3]string{
		{"POST", "/repos/o/r/issues", `{}`},
		{"DELETE", "/repos/o/r", ""},
		{"POST", "/graphql", `{"query":"mutation { x }"}`},
		{"POST", "/graphql", `garbage`},
	} {
		resp, _ := h.do(c, clientRead, rq[0], api+rq[1], rq[2])
		if resp.StatusCode != 403 {
			t.Errorf("%v: status %d, want 403", rq[:2], resp.StatusCode)
		}
	}
	if h.api.count() != 0 {
		t.Fatalf("refused writes reached upstream: %d", h.api.count())
	}
	// A GraphQL query is a read for a read-only client only when a separate read credential exists.
	resp, _ = h.do(c, clientRead, "POST", api+"/graphql", `{"query":"{ viewer { login } }"}`)
	if mod == nil && resp.StatusCode != 200 || mod != nil && resp.StatusCode != 403 {
		t.Fatalf("graphql query by a read-only client: %d (read omitted: %v)", resp.StatusCode, mod != nil)
	}
	// Basic auth with the right token works
	req, _ = http.NewRequest("GET", api+"/repos/o/r", nil)
	req.SetBasicAuth("whatever", clientRead)
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("basic ok: %v %v", err, resp)
	}
	resp.Body.Close()
}

func TestAC5_WriteInvalidatesItsRepoOnly(t *testing.T) {
	h := newHarness(t, nil)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			etagHandler("data")(w, r)
		}
	}
	c := h.client()
	api := "https://api.github.com"
	outcome := func(path string) string {
		resp, _ := h.do(c, clientWrite, "GET", api+path, "")
		return resp.Header.Get("X-Ghgate-Cache")
	}
	if outcome("/repos/o/r/issues") != "miss" || outcome("/repos/o/other/issues") != "miss" {
		t.Fatal("setup")
	}
	if outcome("/repos/o/r/issues") != "revalidated" {
		t.Fatal("expected a cached entry before the write")
	}
	h.do(c, clientWrite, "POST", api+"/repos/o/r/issues", `{"title":"t"}`)
	if got := outcome("/repos/o/r/issues"); got != "miss" {
		t.Fatalf("after the write the repo's entry must be gone, got %s", got)
	}
	if got := outcome("/repos/o/other/issues"); got != "revalidated" {
		t.Fatalf("the other repo's entry must stay, got %s", got)
	}
}

func TestAC6_BelowFloorReadsGet429WritesPass(t *testing.T) {
	h := newHarness(t, nil)
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		rem := "4000"
		if r.Header.Get("Authorization") == "Bearer "+patRead {
			rem = "10"
		}
		w.Header().Set("X-RateLimit-Remaining", rem)
		w.Header().Set("X-RateLimit-Reset", reset)
		w.Header().Set("X-RateLimit-Resource", "core")
	}
	c := h.client()
	api := "https://api.github.com"
	if resp, _ := h.do(c, clientRead, "GET", api+"/repos/o/r/a", ""); resp.StatusCode != 200 {
		t.Fatalf("first read: %d", resp.StatusCode)
	}
	before := h.api.count()
	resp, body := h.do(c, clientRead, "GET", api+"/repos/o/r/b", "")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "reset") {
		t.Fatalf("read below floor: %d retry-after=%q body=%q", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || n < 3000 || n > 3600 {
		t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
	if h.api.count() != before {
		t.Fatal("a refused read reached upstream")
	}
	resp, _ = h.do(c, clientWrite, "POST", api+"/repos/o/r/issues", `{}`)
	if resp.StatusCode != 200 || h.api.count() != before+1 {
		t.Fatalf("write must pass: %d", resp.StatusCode)
	}
	st := h.srv.stats.snapshot()["reader"]
	if st.Refusals != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestAC7_ReadNotFoundRetriesOnceWithWrite(t *testing.T) {
	h := newHarness(t, nil)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+patRead {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, "private-data")
	}
	resp, body := h.get(clientRead, "/repos/o/private")
	if resp.StatusCode != 404 || h.api.count() != 1 {
		t.Fatalf("a client without can_write must not get the write-credential retry: %d, %d requests", resp.StatusCode, h.api.count())
	}
	h.api.mu.Lock()
	h.api.reqs = nil
	h.api.mu.Unlock()
	resp, body = h.get(clientWrite, "/repos/o/private")
	if resp.StatusCode != 200 || body != "private-data" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	got := h.api.all()
	if len(got) != 2 || got[0].Auth != "Bearer "+patRead || got[1].Auth != "Bearer "+patWrite {
		t.Fatalf("expected exactly read then write, got %d requests", len(got))
	}
	// a 404 from both stays a 404, still one retry
	h.api.fn = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }
	resp, _ = h.get(clientWrite, "/repos/o/nothing")
	if resp.StatusCode != 404 || h.api.count() != 4 {
		t.Fatalf("both 404: %d, %d requests", resp.StatusCode, h.api.count())
	}
}

func TestAC8_ConnectToOtherHostIsTunnelled(t *testing.T) {
	on := true
	h := newHarnessOpt(t, func(c *config.Config) { c.TunnelOthers = &on }, func(o *Options) { o.AllowPrivateTunnel = true })
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin-says-hi") }))
	defer origin.Close()
	pu, _ := url.Parse(h.proxy.URL)
	pu.User = url.UserPassword("x", clientRead)
	c := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: certPool(origin.Certificate())}, // trusts the origin only, not ghgate's CA
	}}
	resp, err := c.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "origin-says-hi" || !resp.TLS.PeerCertificates[0].Equal(origin.Certificate()) {
		t.Fatalf("not the origin's own certificate: %q", b)
	}
	// and refused when tunnelling is off
	h2 := newHarness(t, nil) // tunnel_others defaults to false
	pu2, _ := url.Parse(h2.proxy.URL)
	pu2.User = url.UserPassword("x", clientRead)
	c2 := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu2), TLSClientConfig: &tls.Config{RootCAs: certPool(origin.Certificate())}}}
	if resp, err := c2.Get(origin.URL); err == nil {
		resp.Body.Close()
		t.Fatal("tunnelling disabled but the request went through")
	}
}

func TestAC10_LogsNeverContainSecrets(t *testing.T) {
	h := newHarness(t, nil)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			w.WriteHeader(500)
			io.WriteString(w, "token "+patRead)
		}
	}
	c := h.client()
	api := "https://api.github.com"
	secretBody := "BODY_SECRET_MARKER"
	h.do(c, clientRead, "GET", api+"/repos/o/r?access_token="+clientRead, "")
	h.do(c, clientWrite, "POST", api+"/repos/o/r/issues", `{"body":"`+secretBody+`"}`)
	h.do(c, clientWrite, "POST", api+"/graphql", `{"query":"query { a }","variables":{"x":"`+secretBody+`"}}`)
	h.do(c, "bogus-client-token-zzz", "GET", api+"/repos/o/r", "")
	h.do(c, clientRead, "GET", api+"/boom", "")
	h.do(c, clientWrite, "GET", "https://github.com/o/r.git/info/refs?service=git-upload-pack", "")
	// a failing upstream, so error paths are exercised too
	h.api.Close()
	h.do(c, clientRead, "GET", api+"/repos/o/gone", "")
	logs := h.logs.String()
	if !strings.Contains(logs, `"client":"reader"`) || !strings.Contains(logs, `"path":"/repos/o/r"`) {
		t.Fatalf("expected request lines, got: %s", logs)
	}
	for _, secret := range []string{clientRead, clientWrite, patRead, patWrite, "bogus-client-token-zzz", secretBody, "access_token"} {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains %q", secret)
		}
	}
}

func TestAC11_ProxyUsesPerOwnerAppTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	var mu sync.Mutex
	mints := map[string]int{}
	h := newHarness(t, func(c *config.Config) { c.Read = &config.Cred{App: &config.App{ID: 4242, KeyFile: keyFile}} })
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations":
			io.WriteString(w, `[{"id":11,"account":{"login":"acme"}},{"id":22,"account":{"login":"globex"}}]`)
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			id := strings.Split(r.URL.Path, "/")[3]
			mu.Lock()
			mints[id]++
			mu.Unlock()
			fmt.Fprintf(w, `{"token":"inst-%s","expires_at":%q}`, id, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		}
	}
	h.get(clientRead, "/repos/acme/x")
	h.get(clientRead, "/repos/globex/y")
	h.get(clientRead, "/repos/acme/z")
	auth := map[string]string{}
	for _, r := range h.api.all() {
		if strings.HasPrefix(r.Path, "/repos/") {
			auth[r.Path] = r.Auth
		}
	}
	if auth["/repos/acme/x"] != "Bearer inst-11" || auth["/repos/acme/z"] != "Bearer inst-11" || auth["/repos/globex/y"] != "Bearer inst-22" {
		t.Fatalf("tokens by path: %v", auth)
	}
	if mints["11"] != 1 || mints["22"] != 1 {
		t.Fatalf("mint counts %v", mints)
	}
	// an owner without the app falls back to the write credential
	if resp, _ := h.get(clientRead, "/repos/nobody/x"); resp.StatusCode != 404 {
		t.Fatalf("read-only client must not fall back to the write credential: %d", resp.StatusCode)
	}
	resp, _ := h.get(clientWrite, "/repos/nobody/x")
	if resp.StatusCode != 200 {
		t.Fatalf("fallback status %d", resp.StatusCode)
	}
	last := h.api.all()
	if last[len(last)-1].Auth != "Bearer "+patWrite {
		t.Fatal("owner without the app must be read with the write credential")
	}
}

func TestAC12_PATFileRotationNeedsNoRestart(t *testing.T) {
	h := newHarness(t, nil)
	h.get(clientRead, "/repos/o/r/one")
	os.WriteFile(h.readFile, []byte("ghp_ROTATED_new_secret\n"), 0o600)
	future := time.Now().Add(5 * time.Second)
	os.Chtimes(h.readFile, future, future)
	h.get(clientRead, "/repos/o/r/two")
	got := h.api.all()
	if got[0].Auth != "Bearer "+patRead || got[1].Auth != "Bearer ghp_ROTATED_new_secret" {
		t.Fatalf("auth sequence not rotated: %q %q", got[0].Auth, got[1].Auth)
	}
}

func TestGitSmartHTTPIsStreamedWithWriteCredential(t *testing.T) {
	h := newHarness(t, nil)
	h.web.fn = func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		io.WriteString(w, "pack:")
		w.(http.Flusher).Flush()
		w.Write(b)
	}
	c := h.client()
	req, _ := http.NewRequest("POST", "https://github.com/o/r.git/git-upload-pack", strings.NewReader("want-abc"))
	req.SetBasicAuth("git", clientRead)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "pack:want-abc" {
		t.Fatalf("body %q", b)
	}
	u, p, _ := (&http.Request{Header: h.web.all()[0].Header}).BasicAuth()
	if u != "x-access-token" || p != patWrite {
		t.Fatal("web upstream must get the write credential as x-access-token basic auth")
	}
	req, _ = http.NewRequest("POST", "https://github.com/o/r.git/git-receive-pack", strings.NewReader("x"))
	req.SetBasicAuth("git", clientRead)
	resp, err = c.Do(req)
	if err != nil || resp.StatusCode != 403 {
		t.Fatalf("receive-pack by a read-only client: %v %v", err, resp)
	}
	resp.Body.Close()
}
