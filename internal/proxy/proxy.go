// Package proxy is ghgate's forward proxy: CONNECT handling, TLS interception
// of the configured hosts and byte-for-byte tunnelling of the rest.
package proxy

import (
	"bufio"
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
	"strings"
	"sync"
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
}

type target struct {
	base string // upstream base URL without trailing slash
	api  bool   // api.* hosts are cached and routed by read/write; the rest are streamed
}

type client struct {
	name     string
	hash     [32]byte
	canWrite bool
}

type Server struct {
	cfg       *config.Config
	ca        *ca.CA
	cache     *cache.Cache
	flights   cache.Group
	floor     *floor.Tracker
	read      creds.Source
	write     creds.Source
	sameCred  bool
	hc        *http.Client
	log       *slog.Logger
	stats     *Stats
	clients   []client
	intercept map[string]target
	maxEntry  int64
	fresh     time.Duration
}

func New(cfg *config.Config, opt Options) (*Server, error) {
	authority, err := ca.LoadOrCreate(cfg.StateDir, cfg.InterceptHosts)
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
	mk := func(c *config.Cred) creds.Source {
		if c.PatFile != "" {
			return creds.NewPAT(c.PatFile)
		}
		return creds.NewApp(c.App.ID, c.App.KeyFile, apiBase, hc)
	}
	s.write = mk(cfg.Write)
	s.sameCred = cfg.Read == cfg.Write
	if s.sameCred {
		s.read = s.write
	} else {
		s.read = mk(cfg.Read)
	}
	for _, c := range cfg.Clients {
		b, _ := hex.DecodeString(c.TokenSHA256)
		cl := client{name: c.Name, canWrite: c.CanWrite}
		copy(cl.hash[:], b)
		s.clients = append(s.clients, cl)
	}
	return s, nil
}

func (s *Server) CA() *ca.CA { return s.ca }

// ServeHTTP accepts CONNECT; plain proxy requests are refused.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "ghgate is a CONNECT-only proxy", http.StatusMethodNotAllowed)
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
		upstream, err = net.DialTimeout("tcp", r.Host, 15*time.Second)
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
		tunnel(cc, upstream)
		return
	}
	s.mitm(cc, host, t)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func tunnel(a, b net.Conn) {
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
	scheme, val, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok {
		return nil, false
	}
	val = strings.TrimSpace(val)
	var tok string
	switch strings.ToLower(scheme) {
	case "token", "bearer":
		tok = val
	case "basic":
		u, p, ok := r.BasicAuth()
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
