package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Egoushka/ghgate/internal/config"
)

const apiURL = "https://api.github.com"

func TestGraphQLEvasionsAreWrites(t *testing.T) {
	m := `mutation{addStar(input:{starrableId:\"1\"}){clientMutationId}}`
	q := `{viewer{login}}`
	bodies := map[string]string{
		"mixed-case key": `{"query":"` + m + `","QUERY":"` + q + `"}`,
		"duplicate key":  `{"query":"` + m + `","query":"` + q + `"}`,
		"batch":          `[{"query":"` + q + `"},{"query":"` + m + `"}]`,
	}
	h := newHarness(t, nil)
	c := h.client()
	for name, b := range bodies {
		if resp, _ := h.do(c, clientRead, "POST", apiURL+"/graphql", b); resp.StatusCode != 403 {
			t.Errorf("%s: read-only client got %d, want 403", name, resp.StatusCode)
		}
	}
	if h.api.count() != 0 {
		t.Fatal("evasion attempts reached upstream")
	}
	h.do(c, clientWrite, "POST", apiURL+"/graphql", bodies["mixed-case key"])
	if got := h.api.all(); len(got) != 1 || got[0].Auth != "Bearer "+patWrite {
		t.Fatalf("a writer's evasion attempt must use the write credential: %+v", got)
	}
}

func TestSameCredentialGraphQLNeedsCanWrite(t *testing.T) {
	h := newHarness(t, omitRead)
	c := h.client()
	if resp, _ := h.do(c, clientRead, "POST", apiURL+"/graphql", `{"query":"{ viewer { login } }"}`); resp.StatusCode != 403 {
		t.Fatalf("graphql by a read-only client with one shared credential: %d", resp.StatusCode)
	}
	if resp, _ := h.do(c, clientRead, "GET", apiURL+"/repos/o/r", ""); resp.StatusCode != 200 {
		t.Fatalf("plain reads still work: %d", resp.StatusCode)
	}
}

func TestRetryKeepsTheReadFloor(t *testing.T) {
	h := newHarness(t, nil)
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Reset", reset)
		if r.Header.Get("Authorization") == "Bearer "+patWrite {
			w.Header().Set("X-RateLimit-Remaining", "100") // above write_floor 50, below floor 300
			return
		}
		w.Header().Set("X-RateLimit-Remaining", "4000")
		if r.Method == "GET" {
			w.WriteHeader(404)
		}
	}
	c := h.client()
	h.do(c, clientWrite, "POST", apiURL+"/repos/o/r/issues", `{}`) // teaches ghgate the write bucket is at 100
	n := h.api.count()
	resp, _ := h.do(c, clientWrite, "GET", apiURL+"/repos/o/hidden", "")
	if resp.StatusCode != 404 {
		t.Fatalf("want the original 404, got %d", resp.StatusCode)
	}
	if got := h.api.all(); len(got) != n+1 {
		t.Fatalf("the retry must not reach upstream below the read floor: %d new requests", len(got)-n)
	}
}

func TestRateLimited403IsNotRetried(t *testing.T) {
	for name, hdr := range map[string][2]string{"remaining 0": {"X-RateLimit-Remaining", "0"}, "retry-after": {"Retry-After", "30"}} {
		h := newHarness(t, nil)
		h.api.fn = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(hdr[0], hdr[1])
			w.WriteHeader(403)
		}
		resp, _ := h.do(h.client(), clientWrite, "GET", apiURL+"/repos/o/r", "")
		if resp.StatusCode != 403 || h.api.count() != 1 {
			t.Errorf("%s: status %d, %d upstream requests; a rate-limit 403 must not be retried", name, resp.StatusCode, h.api.count())
		}
	}
}

func TestMethodOverrideHeadersNeverGoUpstream(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	for _, rq := range []struct{ method, url string }{
		{"GET", apiURL + "/repos/o/r"},
		{"POST", apiURL + "/repos/o/r/issues"},
		{"GET", "https://github.com/o/r.git/info/refs?service=git-upload-pack"},
	} {
		req, _ := http.NewRequest(rq.method, rq.url, strings.NewReader(""))
		req.Header.Set("Authorization", "token "+clientWrite)
		for _, k := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
			req.Header.Set(k, "DELETE")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	for _, u := range []*upstream{h.api, h.web} {
		for _, r := range u.all() {
			for _, k := range []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"} {
				if r.Header.Get(k) != "" {
					t.Errorf("%s reached upstream on %s %s", k, r.Method, r.Path)
				}
			}
		}
	}
	if h.api.count()+h.web.count() != 3 {
		t.Fatal("setup: expected three upstream requests")
	}
}

func TestGitReadAllowList(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	do := func(tok, method, target string) int {
		req, _ := http.NewRequest(method, target, strings.NewReader(""))
		req.SetBasicAuth("git", tok)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	denied := []struct{ method, path string }{
		{"POST", "/o/r.git/git-receive-pack"},
		{"GET", "/o/r.git/info/refs?service=git-receive-pack"},
		{"GET", "/o/r.git/info/refs?service=git-upload-pack&service=git-receive-pack"},
		{"GET", "/o/r.git/info/refs?service=git-upload-pack;service=git-receive-pack"},
		{"POST", "/o/r.git/git-upload-pack%3B/../git-receive-pack"},
		{"GET", "/o/r.git/info/refs%3Bgit-receive-pack?service=git-upload-pack"},
		{"POST", "/o/r.git/git-upload-pack?service=git-receive-pack"},
		{"GET", "/o/r.git/git-upload-pack"},
		{"POST", "/o/r.git/info/refs?service=git-upload-pack"},
		{"POST", "/o/r/x/git-upload-pack"},
		{"GET", "/login"},
		{"POST", "/o/r/settings"},
	}
	for _, d := range denied {
		if code := do(clientRead, d.method, "https://github.com"+d.path); code != 403 {
			t.Errorf("%s %s by a read-only client: %d, want 403", d.method, d.path, code)
		}
	}
	if h.web.count() != 0 {
		t.Fatalf("denied requests reached upstream: %d", h.web.count())
	}
	for _, a := range []struct{ method, path string }{
		{"GET", "/o/r.git/info/refs?service=git-upload-pack"},
		{"GET", "/o/r/info/refs?service=git-upload-pack"},
		{"POST", "/o/r.git/git-upload-pack"},
	} {
		if code := do(clientRead, a.method, "https://github.com"+a.path); code != 200 {
			t.Errorf("%s %s should be allowed: %d", a.method, a.path, code)
		}
	}
	if code := do(clientWrite, "POST", "https://github.com/o/r.git/git-receive-pack"); code != 200 {
		t.Errorf("writer push: %d", code)
	}
}

func TestSuccessfulPushInvalidatesTheRepo(t *testing.T) {
	h := newHarness(t, nil)
	h.api.fn = etagHandler("data")
	c := h.client()
	outcome := func() string {
		resp, _ := h.do(c, clientWrite, "GET", apiURL+"/repos/o/r/branches", "")
		return resp.Header.Get("X-Ghgate-Cache")
	}
	outcome()
	if outcome() != "revalidated" {
		t.Fatal("setup")
	}
	req, _ := http.NewRequest("POST", "https://github.com/o/r.git/git-receive-pack", strings.NewReader("x"))
	req.SetBasicAuth("git", clientWrite)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := outcome(); got != "miss" {
		t.Fatalf("after a push the repo's cache must be dropped, got %s", got)
	}
}

func TestBufferedBodiesAreBounded(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.MaxBuffers = 2 })
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v"`)
		w.Write([]byte("start"))
		w.(http.Flusher).Flush()
		time.Sleep(150 * time.Millisecond)
		w.Write([]byte("end"))
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, b := h.get(clientRead, "/repos/o/r/p"+strconv.Itoa(i))
			if resp.StatusCode != 200 || b != "startend" {
				t.Errorf("%d %q", resp.StatusCode, b)
			}
		}()
	}
	wg.Wait()
	if peak := h.srv.bufPeak.Load(); peak < 1 || peak > 2 {
		t.Fatalf("peak concurrent buffered bodies %d, want 1..2", peak)
	}
}

func TestResourceIsLearnedFromUpstreamHeader(t *testing.T) {
	h := newHarness(t, nil)
	reset := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	h.api.fn = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Reset", reset)
		if strings.HasPrefix(r.URL.Path, "/search") {
			w.Header().Set("X-RateLimit-Resource", "search")
			w.Header().Set("X-RateLimit-Remaining", "5")
		} else {
			w.Header().Set("X-RateLimit-Resource", "core")
			w.Header().Set("X-RateLimit-Remaining", "4000")
		}
	}
	h.get(clientRead, "/search/issues?q=a")
	if resp, _ := h.get(clientRead, "/search/code?q=b"); resp.StatusCode != 429 {
		t.Fatalf("search bucket is low, got %d", resp.StatusCode)
	}
	if resp, _ := h.get(clientRead, "/repos/o/r/x"); resp.StatusCode != 200 {
		t.Fatalf("core is untouched, got %d", resp.StatusCode)
	}
}

// --- CONNECT: authentication, destinations, idle -------------------------------------------

func rawConnect(t *testing.T, proxyURL, target, proxyAuth string) (*http.Response, net.Conn) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if proxyAuth != "" {
		req += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	io.WriteString(conn, req+"\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return resp, conn
}

func basic(tok string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+tok)) }

func TestConnectRequiresClientTokenAsProxyAuthorization(t *testing.T) {
	on := true
	h := newHarnessOpt(t, func(c *config.Config) { c.TunnelOthers = &on }, func(o *Options) { o.AllowPrivateTunnel = true })
	for name, auth := range map[string]string{"none": "", "wrong": basic("nope"), "garbage": "Digest x"} {
		for _, target := range []string{"api.github.com:443", "127.0.0.1:1"} {
			resp, conn := rawConnect(t, h.proxy.URL, target, auth)
			conn.Close()
			if resp.StatusCode != 407 || resp.Header.Get("Proxy-Authenticate") == "" {
				t.Errorf("%s to %s: %d, want 407 with Proxy-Authenticate", name, target, resp.StatusCode)
			}
		}
	}
	resp, conn := rawConnect(t, h.proxy.URL, "api.github.com:443", "Bearer "+clientRead)
	conn.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("Bearer proxy auth: %d", resp.StatusCode)
	}
}

// The finding behind the README's HTTPS_PROXY=http://x:TOKEN@host:port advice: Go's net/http sends the userinfo
// as Proxy-Authorization: Basic on the CONNECT itself, which is what gh uses.
func TestGoClientSendsProxyAuthorizationFromProxyURL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err == nil {
			got <- req.Method + " " + req.Header.Get("Proxy-Authorization")
		}
	}()
	pu, _ := url.Parse("http://x:" + clientRead + "@" + ln.Addr().String())
	tr := &http.Transport{Proxy: http.ProxyURL(pu)} // ProxyFromEnvironment parses the same URL once per process
	req, _ := http.NewRequest("GET", "https://api.github.com/", nil)
	go (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req)
	select {
	case v := <-got:
		if v != "CONNECT "+basic(clientRead) {
			t.Fatalf("got %q", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no CONNECT seen")
	}
}

func TestTunnelRefusesInternalDestinations(t *testing.T) {
	on := true
	origin, _ := net.Listen("tcp", "127.0.0.1:0")
	defer origin.Close()
	// default: loopback is not a destination
	h := newHarness(t, func(c *config.Config) { c.TunnelOthers = &on })
	resp, conn := rawConnect(t, h.proxy.URL, origin.Addr().String(), basic(clientRead))
	conn.Close()
	if resp.StatusCode == 200 {
		t.Fatal("tunnel to loopback must be refused")
	}
	// even with private destinations allowed (tests), the admin listener is never one
	h2 := newHarnessOpt(t, func(c *config.Config) { c.TunnelOthers = &on; c.Admin = origin.Addr().String() }, func(o *Options) { o.AllowPrivateTunnel = true })
	resp, conn = rawConnect(t, h2.proxy.URL, origin.Addr().String(), basic(clientRead))
	conn.Close()
	if resp.StatusCode == 200 {
		t.Fatal("tunnel to the admin listener must be refused")
	}
}

func TestBlockedIPs(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "fe80::1", "fd00::1",
		"100.64.0.4", "100.127.255.255", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1"} {
		if !blockedIP(net.ParseIP(ip)) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "140.82.112.3", "100.63.255.255", "100.128.0.1", "2606:4700::1"} {
		if blockedIP(net.ParseIP(ip)) {
			t.Errorf("%s must be allowed", ip)
		}
	}
}

func TestTunnelClosesWhenIdle(t *testing.T) {
	origin, _ := net.Listen("tcp", "127.0.0.1:0")
	defer origin.Close()
	go func() {
		c, err := origin.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	on := true
	h := newHarnessOpt(t, func(c *config.Config) { c.TunnelOthers = &on }, func(o *Options) { o.AllowPrivateTunnel = true })
	h.srv.tunnelIdle = 200 * time.Millisecond
	resp, conn := rawConnect(t, h.proxy.URL, origin.Addr().String(), basic(clientRead))
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("an idle tunnel must be closed by the proxy, read returned %v", err)
	}
}
