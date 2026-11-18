package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Egoushka/ghgate/internal/cache"
	"github.com/Egoushka/ghgate/internal/creds"
	"github.com/Egoushka/ghgate/internal/route"
)

const (
	hRead  = "read"
	hWrite = "write"
)

type rec struct {
	client  string
	outcome string
	calls   int
	upMS    int64
	refused bool
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() { http.NewResponseController(w.ResponseWriter).Flush() }

func (s *Server) handle(w http.ResponseWriter, r *http.Request, host string, t target) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	rc := &rec{client: "-"}
	defer func() {
		s.stats.record(rc.client, rc.outcome, rc.calls, rc.refused)
		// Never logged: tokens, Authorization values, query strings, bodies.
		s.log.Info("request", "client", rc.client, "method", r.Method, "host", host, "path", r.URL.Path,
			"status", sw.status, "cache", rc.outcome, "upstream_ms", rc.upMS, "total_ms", time.Since(start).Milliseconds())
	}()
	cl, ok := s.authenticate(r)
	if !ok {
		rc.refused = true
		sw.Header().Set("WWW-Authenticate", `Basic realm="ghgate"`)
		writeJSON(sw, http.StatusUnauthorized, map[string]string{"message": "ghgate: missing or unknown client token"})
		return
	}
	rc.client = cl.name
	r.Header.Del("Authorization")
	if t.api {
		s.handleAPI(sw, r, cl, t, rc)
	} else {
		s.handleWeb(sw, r, cl, t, rc)
	}
}

func (s *Server) refuse(w http.ResponseWriter, rc *rec, status int, msg string) {
	rc.refused = true
	writeJSON(w, status, map[string]string{"message": msg})
}

type apiReq struct {
	method, base, uri string
	hdr               http.Header
	body              []byte
	owner, resource   string
	cacheable         bool
	bodyHash          string
}

func (in *apiReq) key(kind string) string {
	k := kind + "|" + in.method + "|" + in.base + in.uri + "|" + in.hdr.Get("Accept") + "|" + in.hdr.Get("X-GitHub-Api-Version")
	if in.bodyHash != "" {
		k += "|" + in.bodyHash
	}
	return k
}

type result struct {
	status   int
	header   http.Header
	body     []byte
	rest     io.ReadCloser // leader only: unread remainder when overflow
	overflow bool
	outcome  string
	calls    int
	ms       int64
	refusal  bool
	err      error
}

func (s *Server) handleAPI(w *statusWriter, r *http.Request, cl *client, t target, rc *rec) {
	gql := r.Method == http.MethodPost && route.IsGraphQLPath(r.URL.Path)
	var body []byte
	if gql {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if err != nil {
			s.refuse(w, rc, http.StatusRequestEntityTooLarge, "ghgate: graphql body too large")
			return
		}
	}
	resource := s.resourceFor(r.URL.Path, gql)
	kind := route.Classify(r.Method, r.URL.Path, body)
	if gql && s.sameCred && !cl.canWrite {
		// One credential does both jobs, so a GraphQL document the parser
		// calls a query still runs with the write credential.
		s.refuse(w, rc, http.StatusForbidden, "ghgate: this client token cannot write, and GraphQL needs a write-capable credential when no separate read credential is configured")
		rc.outcome = "bypass"
		return
	}
	if kind == route.Write {
		s.handleWrite(w, r, cl, t, rc, body, gql, resource)
		return
	}
	in := &apiReq{method: r.Method, base: t.base, uri: r.URL.RequestURI(), hdr: apiHeaders(r.Header), body: body,
		owner: ownerOf(r.URL.Path), resource: resource, cacheable: r.Method == http.MethodGet}
	if gql {
		sum := sha256.Sum256(body)
		in.bodyHash = hex.EncodeToString(sum[:])
	}
	if in.cacheable && s.fresh > 0 {
		if e := s.cache.Get(in.key(hRead)); e != nil && time.Since(e.Validated) < s.fresh {
			s.serve(w, &result{status: e.Status, header: e.Header, body: e.Body}, "fresh", rc)
			return
		}
	}
	ctx := context.WithoutCancel(r.Context())
	// Only clients that may write get the write-credential retry, so they must not share a flight with those that may not.
	retry := cl.canWrite && !s.sameCred
	fk := in.key(hRead) + "|retry=" + strconv.FormatBool(retry)
	v, shared := s.flights.Do(fk, func() any { return s.fetchRead(ctx, in, retry) })
	res := v.(*result)
	if shared && res.overflow && res.err == nil {
		// Too big to share: fetch privately.
		res = s.fetchRead(ctx, in, retry)
		shared = false
	}
	if res.err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "ghgate: upstream request failed"})
		rc.outcome = "bypass"
		return
	}
	outcome := res.outcome
	if shared {
		outcome = "coalesced"
	} else {
		rc.calls += res.calls
		rc.upMS = res.ms
	}
	rc.refused = res.refusal
	s.serve(w, res, outcome, rc)
}

// fetchRead serves a read with the read credential, retrying once with the write credential on 404/403.
func (s *Server) fetchRead(ctx context.Context, in *apiReq, retry bool) *result {
	res := s.upstream(ctx, in, hRead, s.cfg.Floor)
	if retry && res.err == nil && !res.refusal && (res.status == http.StatusNotFound || res.status == http.StatusForbidden) && !rateLimited(res) {
		// The retry still draws on the shared bucket, so it keeps the read floor.
		res2 := s.upstream(ctx, in, hWrite, s.cfg.Floor)
		if res2.err == nil && !res2.refusal {
			if res.rest != nil {
				res.rest.Close()
			}
			res2.calls += res.calls
			res2.ms += res.ms
			return res2
		}
		// The retry was refused or failed: the client gets the original answer.
		res.calls += res2.calls
		if res2.rest != nil {
			res2.rest.Close()
		}
	}
	return res
}

// upstream performs one credential's attempt: conditional request, floor check, caching.
func (s *Server) upstream(ctx context.Context, in *apiReq, kind string, floorN int) *result {
	src := s.read
	if kind == hWrite {
		src = s.write
	}
	tok, label, err := src.Token(ctx, in.owner)
	if errors.Is(err, creds.ErrNoInstallation) && kind == hRead {
		return &result{status: http.StatusNotFound, header: http.Header{"Content-Type": {"application/json"}},
			body: []byte(`{"message":"Not Found"}`), outcome: "bypass"}
	}
	if err != nil {
		return &result{err: err}
	}
	if st, ok := s.floor.Check(label, in.resource, floorN, time.Now()); !ok {
		wait := max(st.Reset-time.Now().Unix(), 1)
		msg := fmt.Sprintf("ghgate: the %s rate limit has %d calls left (floor %d) and resets at %s (in %ds). Wait for the reset, poll less often, or batch reads into one GraphQL query.",
			in.resource, st.Remaining, floorN, time.Unix(st.Reset, 0).UTC().Format(time.RFC3339), wait)
		b, _ := jsonBytes(map[string]any{"message": msg, "resource": in.resource, "remaining": st.Remaining, "reset": st.Reset, "retry_after": wait})
		return &result{status: http.StatusTooManyRequests, refusal: true, outcome: "bypass", body: b,
			header: http.Header{"Content-Type": {"application/json"}, "Retry-After": {strconv.FormatInt(wait, 10)}}}
	}
	key := in.key(kind)
	var ent *cache.Entry
	gen := s.cache.Gen()
	hdr := in.hdr.Clone()
	if in.cacheable {
		if ent = s.cache.Get(key); ent != nil {
			if ent.ETag != "" {
				hdr.Set("If-None-Match", ent.ETag)
			}
			if ent.LastMod != "" {
				hdr.Set("If-Modified-Since", ent.LastMod)
			}
		}
	}
	var br io.Reader
	if len(in.body) > 0 {
		br = bytes.NewReader(in.body)
	}
	req, err := http.NewRequestWithContext(ctx, in.method, in.base+in.uri, br)
	if err != nil {
		return &result{err: err}
	}
	req.Header = hdr
	req.Header.Set("Authorization", "Bearer "+tok)
	setUA(req.Header)
	t0 := time.Now()
	resp, err := s.hc.Do(req)
	if err != nil {
		return &result{err: errors.New("upstream request failed"), calls: 1}
	}
	s.floor.Observe(label, resp.Header)
	s.learnResource(in.uri, resp.Header)
	res := &result{status: resp.StatusCode, header: stripHop(resp.Header), calls: 1, outcome: "bypass"}
	if in.cacheable {
		res.outcome = "miss"
	}
	defer func() { res.ms = time.Since(t0).Milliseconds() }()

	if resp.StatusCode == http.StatusNotModified && ent != nil {
		resp.Body.Close()
		h := ent.Header.Clone()
		for k, v := range res.header {
			if strings.HasPrefix(k, "X-Ratelimit-") {
				h[k] = v
			}
		}
		if et := resp.Header.Get("ETag"); et != "" {
			h.Set("ETag", et)
		}
		ne := *ent
		ne.Header, ne.Validated, ne.ETag = h, time.Now(), h.Get("ETag")
		s.cache.Put(key, &ne, gen)
		res.status, res.header, res.body, res.outcome = http.StatusOK, h, ent.Body, "revalidated"
		return res
	}
	if resp.StatusCode >= 400 && in.cacheable && ent != nil {
		// The resource is gone or hidden: drop the entry.
		s.cache.Delete(key)
	}
	limit := s.maxEntry
	s.bufSem <- struct{}{}
	if n := s.bufNow.Add(1); n > s.bufPeak.Load() {
		s.bufPeak.Store(n)
	}
	prefix, rerr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	s.bufNow.Add(-1)
	<-s.bufSem
	if rerr != nil {
		resp.Body.Close()
		return &result{err: errors.New("upstream read failed"), calls: 1}
	}
	if int64(len(prefix)) > limit {
		res.body, res.rest, res.overflow = prefix, resp.Body, true
		return res
	}
	resp.Body.Close()
	res.body = prefix
	if in.cacheable && resp.StatusCode == http.StatusOK && !strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "no-store") &&
		(resp.Header.Get("ETag") != "" || resp.Header.Get("Last-Modified") != "") {
		h := res.header.Clone()
		h.Set("Content-Length", strconv.Itoa(len(prefix)))
		res.header = h
		s.cache.Put(key, &cache.Entry{Status: 200, Header: h, Body: prefix, ETag: h.Get("ETag"), LastMod: h.Get("Last-Modified"),
			Validated: time.Now(), Repo: repoPrefix(in.uri)}, gen)
	}
	return res
}

// rateLimited reports a 403 that is GitHub's rate limiting, which a second credential must not be spent on.
func rateLimited(res *result) bool {
	return res.header.Get("Retry-After") != "" || res.header.Get("X-RateLimit-Remaining") == "0"
}

func routeKey(path string, gql bool) string {
	if gql {
		return "graphql"
	}
	return strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0]
}

// resourceFor is the rate-limit resource a path drew on last time, as the upstream reported it.
func (s *Server) resourceFor(path string, gql bool) string {
	if v, ok := s.resByPath.Load(routeKey(path, gql)); ok {
		return v.(string)
	}
	if gql {
		return "graphql"
	}
	return "core"
}

func (s *Server) learnResource(uri string, h http.Header) {
	if res := h.Get("X-RateLimit-Resource"); res != "" {
		path := uri
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		s.resByPath.Store(routeKey(path, route.IsGraphQLPath(path)), res)
	}
}

func (s *Server) serve(w http.ResponseWriter, res *result, outcome string, rc *rec) {
	h := w.Header()
	for k, v := range res.header {
		h[k] = v
	}
	h.Set("X-Ghgate-Cache", outcome)
	if !res.overflow {
		h.Set("Content-Length", strconv.Itoa(len(res.body)))
	}
	rc.outcome = outcome
	w.WriteHeader(res.status)
	w.Write(res.body)
	if res.overflow && res.rest != nil {
		io.Copy(w, res.rest)
		res.rest.Close()
		res.rest = nil
	}
}

func (s *Server) handleWrite(w *statusWriter, r *http.Request, cl *client, t target, rc *rec, body []byte, gql bool, resource string) {
	if !cl.canWrite {
		s.refuse(w, rc, http.StatusForbidden, "ghgate: this client token cannot write")
		rc.outcome = "bypass"
		return
	}
	ctx := r.Context()
	tok, label, err := s.write.Token(ctx, ownerOf(r.URL.Path))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "ghgate: write credential unavailable"})
		return
	}
	if st, ok := s.floor.Check(label, resource, s.cfg.WriteFloor, time.Now()); !ok {
		wait := max(st.Reset-time.Now().Unix(), 1)
		w.Header().Set("Retry-After", strconv.FormatInt(wait, 10))
		s.refuse(w, rc, http.StatusTooManyRequests, fmt.Sprintf("ghgate: the %s rate limit has %d calls left (write floor %d); it resets in %ds.", resource, st.Remaining, s.cfg.WriteFloor, wait))
		rc.outcome = "bypass"
		return
	}
	var br io.Reader = r.Body
	if gql {
		br = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, t.base+r.URL.RequestURI(), br)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "ghgate: bad request"})
		return
	}
	req.Header = apiHeaders(r.Header)
	req.Header.Set("Authorization", "Bearer "+tok)
	setUA(req.Header)
	if gql {
		req.ContentLength = int64(len(body))
	} else if r.ContentLength == 0 {
		req.Body = http.NoBody
	} else {
		req.ContentLength = r.ContentLength
	}
	t0 := time.Now()
	resp, err := s.hc.Do(req)
	rc.calls++
	rc.upMS = time.Since(t0).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "ghgate: upstream request failed"})
		return
	}
	defer resp.Body.Close()
	s.floor.Observe(label, resp.Header)
	s.learnResource(r.URL.RequestURI(), resp.Header)
	if p := repoPrefix(r.URL.RequestURI()); p != "" && !gql {
		s.cache.InvalidateRepo(p)
	} else {
		s.cache.InvalidateAll()
	}
	s.pipe(w, resp, rc, false)
}

var gitReadPath = regexp.MustCompile(`^/[^/]+/[^/]+(\.git)?/(info/refs|git-upload-pack)$`)

// gitReadOnly allow-lists the requests that can only read. The raw path is
// matched, and anything percent-encoded or carrying ';' is not read-only.
func gitReadOnly(r *http.Request) bool {
	raw := r.URL.EscapedPath()
	if strings.ContainsAny(raw, "%;") || strings.ContainsRune(r.URL.RawQuery, ';') || !gitReadPath.MatchString(raw) {
		return false
	}
	if strings.HasSuffix(raw, "/info/refs") {
		return r.Method == http.MethodGet && r.URL.RawQuery == "service=git-upload-pack"
	}
	return r.Method == http.MethodPost && r.URL.RawQuery == ""
}

func (s *Server) handleWeb(w *statusWriter, r *http.Request, cl *client, t target, rc *rec) {
	p := r.URL.Path
	if !cl.canWrite && !gitReadOnly(r) {
		s.refuse(w, rc, http.StatusForbidden, "ghgate: this client token cannot write")
		rc.outcome = "bypass"
		return
	}
	seg := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]
	tok, _, err := s.write.Token(r.Context(), seg)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "ghgate: write credential unavailable"})
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, t.base+r.URL.RequestURI(), r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "ghgate: bad request"})
		return
	}
	req.Header = stripHop(r.Header)
	req.Header.Del("Authorization")
	stripOverrides(req.Header)
	req.SetBasicAuth("x-access-token", tok)
	setUA(req.Header)
	if r.ContentLength == 0 {
		req.Body = http.NoBody
	} else {
		req.ContentLength = r.ContentLength
	}
	t0 := time.Now()
	resp, err := s.hc.Do(req)
	rc.calls++
	rc.upMS = time.Since(t0).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"message": "ghgate: upstream request failed"})
		return
	}
	defer resp.Body.Close()
	if r.Method == http.MethodPost && strings.HasSuffix(p, "/git-receive-pack") && resp.StatusCode < 400 {
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		if len(parts) >= 3 {
			s.cache.InvalidateRepo("/repos/" + parts[0] + "/" + strings.TrimSuffix(parts[1], ".git"))
		}
	}
	s.pipe(w, resp, rc, true)
}

// pipe streams an upstream response to the client.
func (s *Server) pipe(w *statusWriter, resp *http.Response, rc *rec, flush bool) {
	h := w.Header()
	for k, v := range stripHop(resp.Header) {
		h[k] = v
	}
	h.Set("X-Ghgate-Cache", "bypass")
	rc.outcome = "bypass"
	w.WriteHeader(resp.StatusCode)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flush {
				w.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

var hop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHop(in http.Header) http.Header {
	h := in.Clone()
	for _, c := range in.Values("Connection") {
		for _, f := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
	for _, k := range hop {
		h.Del(k)
	}
	return h
}

// apiHeaders are the client headers worth forwarding to the API.
func apiHeaders(in http.Header) http.Header {
	h := stripHop(in)
	for _, k := range []string{"Authorization", "Accept-Encoding", "If-None-Match", "If-Modified-Since", "Content-Length", "Cookie"} {
		h.Del(k)
	}
	stripOverrides(h)
	return h
}

// stripOverrides removes headers that make some servers run a different method than the one we classified.
func stripOverrides(h http.Header) {
	for _, k := range []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		h.Del(k)
	}
}

func setUA(h http.Header) {
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", "ghgate")
	}
}

func ownerOf(path string) string {
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(seg) >= 2 && (seg[0] == "repos" || seg[0] == "orgs" || seg[0] == "users") {
		return seg[1]
	}
	return ""
}

// repoPrefix returns "/repos/owner/repo" (lowercase) for a request URI, or "".
func repoPrefix(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	if u, err := url.PathUnescape(uri); err == nil {
		uri = u
	}
	seg := strings.Split(strings.TrimPrefix(uri, "/"), "/")
	if len(seg) >= 3 && seg[0] == "repos" && seg[1] != "" && seg[2] != "" {
		return strings.ToLower("/repos/" + seg[1] + "/" + seg[2])
	}
	return ""
}
