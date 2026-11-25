// Package proxy is ghgate's forward proxy: CONNECT handling, TLS interception
// of the configured hosts and byte-for-byte tunnelling of the rest.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Egoushka/ghgate/internal/ca"
	"github.com/Egoushka/ghgate/internal/cache"
	"github.com/Egoushka/ghgate/internal/config"
	"github.com/Egoushka/ghgate/internal/creds"
	"github.com/Egoushka/ghgate/internal/floor"
)

type Options struct {
	Logger *slog.Logger
	// Transport overrides the upstream round tripper (tests trust httptest certificates this way).
	Transport http.RoundTripper
	// AllowPrivateTunnel lets CONNECT tunnels reach loopback and private
	// addresses. Tests only: it is not a config option. The admin listener stays refused.
	AllowPrivateTunnel bool
}

type target struct {
	base string // upstream base URL without trailing slash
	api  bool   // api.* hosts are cached and routed by read/write; the rest are streamed
}

type client struct {
	name     string
	hash     [32]byte
	canWrite bool
	scope    *scope
}

type Server struct {
	cfg        *config.Config
	ca         *ca.Set
	cache      *cache.Cache
	flights    cache.Group
	floor      *floor.Tracker
	read       creds.Source
	write      creds.Source
	scopedW    creds.Source // for limited clients; the write source when scoped_write is unset
	sameCred   bool
	hc         *http.Client
	log        *slog.Logger
	stats      *Stats
	clients    []client
	intercept  map[string]target
	maxEntry   int64
	fresh      time.Duration
	dialer     *net.Dialer
	tunnelIdle time.Duration
	bufSem     chan struct{}
	bufNow     atomic.Int64
	bufPeak    atomic.Int64
	resByPath  sync.Map // first path segment -> rate-limit resource the upstream reported
}

func New(cfg *config.Config, opt Options) (*Server, error) {
	authority, err := ca.LoadOrCreateSet(cfg.StateDir, cfg.InterceptHosts)
	if err != nil {
		return nil, err
	}
	tr := opt.Transport
	if tr == nil {
		tr = &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    true,
		}
	}
	if t, ok := tr.(*http.Transport); ok {
		t = t.Clone()
		t.DisableCompression = true
		t.Proxy = nil
		tr = t
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	log := opt.Logger
	if log == nil {
		log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	apiBase := strings.TrimRight(cfg.UpstreamAPI, "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	webBase := strings.TrimRight(cfg.UpstreamWeb, "/")
	if webBase == "" {
		webBase = "https://github.com"
	}
	s := &Server{
		cfg: cfg, ca: authority, cache: cache.New(int64(cfg.CacheMB) << 20), floor: floor.New(),
		hc: hc, log: log, stats: newStats(), intercept: map[string]target{},
		maxEntry: int64(cfg.MaxEntryMB) << 20, fresh: time.Duration(cfg.FreshForMS) * time.Millisecond,
	}
	s.tunnelIdle = defaultTunnelIdle
	s.bufSem = make(chan struct{}, cfg.MaxBuffers)
	s.dialer = &net.Dialer{Timeout: 15 * time.Second, Control: tunnelControl(cfg.Admin, opt.AllowPrivateTunnel)}
	for _, h := range cfg.InterceptHosts {
		switch {
		case h == "api.github.com":
			s.intercept[h] = target{apiBase, true}
		case h == "github.com":
			s.intercept[h] = target{webBase, false}
		default:
			s.intercept[h] = target{"https://" + h, strings.HasPrefix(h, "api.")}
		}
	}
	mk := func(c *config.Cred) (creds.Source, error) {
		switch {
		case c.PatFile != "":
			return creds.NewPAT(c.PatFile), nil
		case c.PatEnv != "":
			return creds.NewPATFromEnv(c.PatEnv)
		case c.App.KeyEnv != "":
			k, err := creds.KeyFromEnv(c.App.KeyEnv)
			if err != nil {
				return nil, err
			}
			return creds.NewAppWithKey(c.App.ID, k, apiBase, hc), nil
		}
		return creds.NewApp(c.App.ID, c.App.KeyFile, apiBase, hc), nil
	}
	if s.write, err = mk(cfg.Write); err != nil {
		return nil, err
	}
	s.scopedW = s.write
	if cfg.ScopedWrite != nil {
		if s.scopedW, err = mk(cfg.ScopedWrite); err != nil {
			return nil, err
		}
	}
	s.sameCred = credID(cfg.Read) == credID(cfg.Write)
	if s.sameCred {
		s.read = s.write
	} else if s.read, err = mk(cfg.Read); err != nil {
		return nil, err
	}
	for _, c := range cfg.Clients {
		b, _ := hex.DecodeString(c.TokenSHA256)
		cl := client{name: c.Name, canWrite: c.CanWrite, scope: newScope(c)}
		copy(cl.hash[:], b)
		s.clients = append(s.clients, cl)
	}
	return s, nil
}

// credID names the credential, so two config entries for the same file or App are one credential.
func credID(c *config.Cred) string {
	if c.App != nil {
		return "app:" + strconv.FormatInt(c.App.ID, 10)
	}
	if c.PatEnv != "" {
		return "patenv:" + c.PatEnv
	}
	p, err := filepath.Abs(c.PatFile)
	if err != nil {
		p = c.PatFile
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return "pat:" + p
}

func (s *Server) CA() *ca.Set { return s.ca }

// ServeHTTP accepts CONNECT; plain proxy requests are refused.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect && r.URL.Path == "/v1/token" && r.URL.Host == "" {
		s.handleVend(w, r)
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "ghgate is a CONNECT-only proxy", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.authenticateValue(r.Header.Get("Proxy-Authorization")); !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="ghgate"`)
		http.Error(w, "ghgate: proxy authentication required (send the client token in Proxy-Authorization)", http.StatusProxyAuthRequired)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT authority", http.StatusBadRequest)
		return
	}
	host = strings.ToLower(host)
	t, intercepted := s.intercept[host]
	intercepted = intercepted && port == "443"
	if !intercepted && !s.cfg.TunnelOthersOn() {
		http.Error(w, "tunnelling is disabled", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	var upstream net.Conn
	if !intercepted {
		upstream, err = s.dialer.DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, "cannot reach host", http.StatusBadGateway)
			return
		}
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	cc := &bufConn{Conn: conn, r: rw.Reader}
	if !intercepted {
		tunnel(cc, upstream, s.tunnelIdle)
		return
	}
	s.mitm(cc, host, t)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// defaultTunnelIdle closes a tunnel that carries no bytes for this long.
const defaultTunnelIdle = 5 * time.Minute

// idleConn pushes its deadline forward on every successful read or write.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

func (c idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func tunnel(a, b net.Conn, idle time.Duration) {
	a, b = idleConn{a, idle}, idleConn{b, idle}
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func (s *Server) mitm(conn net.Conn, host string, t target) {
	leaf, err := s.ca.Leaf(host)
	if err != nil {
		conn.Close()
		return
	}
	tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	tc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return
	}
	tc.SetDeadline(time.Time{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			r.Host = h
		}
		if !strings.EqualFold(r.Host, host) {
			http.Error(w, "Host header does not match the CONNECT target", http.StatusMisdirectedRequest)
			return
		}
		s.handle(w, r, host, t)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: nil}
	srv.Serve(newOneConnListener(tc))
}

// oneConnListener hands out one connection, then blocks until it closes.
type oneConnListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

type notifyConn struct {
	net.Conn
	l *oneConnListener
}

func (c *notifyConn) Close() error {
	c.l.once.Do(func() { close(c.l.done) })
	return c.Conn.Close()
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{ch: make(chan net.Conn, 1), done: make(chan struct{})}
	l.ch <- &notifyConn{c, l}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, errors.New("closed")
	}
}
func (l *oneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }

// authenticate maps the request's token to a configured client.
func (s *Server) authenticate(r *http.Request) (*client, bool) {
	return s.authenticateValue(r.Header.Get("Authorization"))
}

// authenticateValue accepts an Authorization or Proxy-Authorization value.
func (s *Server) authenticateValue(v string) (*client, bool) {
	scheme, val, ok := strings.Cut(strings.TrimSpace(v), " ")
	if !ok {
		return nil, false
	}
	val = strings.TrimSpace(val)
	var tok string
	switch strings.ToLower(scheme) {
	case "token", "bearer":
		tok = val
	case "basic":
		u, p, ok := (&http.Request{Header: http.Header{"Authorization": {"Basic " + val}}}).BasicAuth()
		if !ok {
			return nil, false
		}
		tok = p
		if tok == "" {
			tok = u
		}
	default:
		return nil, false
	}
	if tok == "" {
		return nil, false
	}
	h := sha256.Sum256([]byte(tok))
	var found *client
	for i := range s.clients {
		if subtle.ConstantTimeCompare(h[:], s.clients[i].hash[:]) == 1 {
			found = &s.clients[i]
		}
	}
	return found, found != nil
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.ca.CertPEM())
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entries, bytes := s.cache.Stats()
		writeJSON(w, http.StatusOK, map[string]any{
			"clients":     s.stats.snapshot(),
			"credentials": s.floor.Snapshot(),
			"cache":       map[string]any{"entries": entries, "bytes": bytes},
		})
	})
	return mux
}

var blockedNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// embeddedIPv4 extracts the IPv4 address carried by NAT64 (64:ff9b::/96), 6to4 (2002::/16)
// and IPv4-compatible (::a.b.c.d) addresses, which a dual-stack path may route to that IPv4 host.
func embeddedIPv4(ip net.IP) (net.IP, bool) {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil, false
	}
	switch {
	case bytes.HasPrefix(ip16, []byte{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}):
		return net.IP(ip16[12:16]), true
	case ip16[0] == 0x20 && ip16[1] == 0x02:
		return net.IP(ip16[2:6]), true
	case bytes.Equal(ip16[:12], make([]byte, 12)):
		return net.IP(ip16[12:16]), true
	}
	return nil, false
}

func blockedIP(ip net.IP) bool {
	if a, ok := netip.AddrFromSlice(ip); ok {
		ip = net.IP(a.Unmap().AsSlice())
	}
	if emb, ok := embeddedIPv4(ip); ok && blockedIP(emb) {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// tunnelControl runs after name resolution, on the address about to be dialled,
// so a hostname that resolves (or rebinds) to an internal address is refused.
func tunnelControl(admin string, allowPrivate bool) func(network, address string, _ syscall.RawConn) error {
	ah, ap, _ := net.SplitHostPort(admin)
	aip := net.ParseIP(ah)
	return func(network, address string, _ syscall.RawConn) error {
		h, p, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(h)
		if ip == nil {
			return errors.New("destination is not an IP")
		}
		if p == ap && (aip == nil || aip.IsUnspecified() || aip.Equal(ip)) {
			return errors.New("the admin listener is not a valid destination")
		}
		if !allowPrivate && blockedIP(ip) {
			return errors.New("destination address is not allowed")
		}
		return nil
	}
}
