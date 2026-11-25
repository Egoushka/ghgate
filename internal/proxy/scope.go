package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Egoushka/ghgate/internal/config"
	"github.com/Egoushka/ghgate/internal/creds"
)

// scope is a client's repository allowlist and permission ceiling (config Client.Repos and Client.Perms).
type scope struct {
	repos  map[string]bool // "owner/name"
	owners map[string]bool // "owner/*"
	perms  map[string]string
}

func newScope(c config.Client) *scope {
	if len(c.Repos) == 0 && len(c.Perms) == 0 {
		return nil
	}
	sc := &scope{repos: map[string]bool{}, owners: map[string]bool{}, perms: c.Perms}
	for _, r := range c.Repos {
		if o, n, _ := strings.Cut(r, "/"); n == "*" {
			sc.owners[o] = true
		} else {
			sc.repos[r] = true
		}
	}
	return sc
}

// limited reports whether the client has a repository allowlist.
func (sc *scope) limited() bool { return sc != nil && len(sc.repos)+len(sc.owners) > 0 }

func (sc *scope) allows(owner, repo string) bool {
	owner, repo = strings.ToLower(owner), strings.ToLower(repo)
	return sc.owners[owner] || sc.repos[owner+"/"+repo]
}

// names returns the repository names to narrow an owner's token to: none when the owner is allowed whole.
func (sc *scope) names(owner string) []string {
	owner = strings.ToLower(owner)
	if sc == nil || sc.owners[owner] {
		return nil
	}
	var out []string
	for r := range sc.repos {
		if o, n, _ := strings.Cut(r, "/"); o == owner {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// repoOfAPI names the repository an API path is about. ok is false for paths that name none
// (GraphQL, /user, /orgs/...), which a limited client may not use; /rate_limit is the one exception.
func repoOfAPI(path string) (owner, repo string, ok bool) {
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, s := range seg {
		if s == ".." || s == "." {
			return "", "", false
		}
	}
	if len(seg) >= 3 && seg[0] == "repos" && seg[1] != "" && seg[2] != "" {
		return seg[1], seg[2], true
	}
	return "", "", false
}

// repoOfWeb names the repository of a github.com path: /owner/name[.git]/...
func repoOfWeb(path string) (owner, repo string, ok bool) {
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, s := range seg {
		if s == ".." || s == "." {
			return "", "", false
		}
	}
	if len(seg) >= 2 && seg[0] != "" && seg[1] != "" {
		return seg[0], strings.TrimSuffix(seg[1], ".git"), true
	}
	return "", "", false
}

// inScope reports whether a limited client may send r. An unlimited client always may.
func (s *Server) inScope(cl *client, api bool, r *http.Request) bool {
	if !cl.scope.limited() {
		return true
	}
	if api && r.URL.Path == "/rate_limit" {
		return true
	}
	f := repoOfWeb
	if api {
		f = repoOfAPI
	}
	o, n, ok := f(r.URL.Path)
	return ok && cl.scope.allows(o, n)
}

// writeToken is the write credential's token for cl: narrowed to the client's repositories and permissions when
// the credential is an App, the plain token otherwise.
func (s *Server) writeToken(ctx context.Context, cl *client, owner string) (tok, label string, err error) {
	if cl != nil && cl.scope != nil {
		if ss, ok := s.scopedW.(creds.ScopedSource); ok {
			tok, label, _, err = ss.TokenScoped(ctx, owner, cl.scope.names(owner), cl.scope.perms)
			return
		}
		return s.scopedW.Token(ctx, owner)
	}
	return s.write.Token(ctx, owner)
}

type vendReq struct {
	Repos       []string          `json:"repos"`
	Permissions map[string]string `json:"permissions"`
}

var permRank = map[string]int{"read": 1, "write": 2, "admin": 3}

// handleVend answers POST /v1/token: a short-lived installation token for a consumer that cannot use the proxy
// (a git pull job, a CI step). The request may ask for less than the client's scope, never more.
func (s *Server) handleVend(w http.ResponseWriter, r *http.Request) {
	rc := &rec{client: "-", outcome: "bypass"}
	sw := &statusWriter{ResponseWriter: w}
	defer func() {
		s.stats.record(rc.client, rc.outcome, rc.calls, rc.refused)
		s.log.Info("request", "client", rc.client, "method", r.Method, "host", "ghgate", "path", r.URL.Path, "status", sw.status, "cache", rc.outcome)
	}()
	cl, ok := s.authenticate(r)
	if !ok {
		rc.refused = true
		writeJSON(sw, http.StatusUnauthorized, map[string]string{"message": "ghgate: missing or unknown client token"})
		return
	}
	rc.client = cl.name
	if r.Method != http.MethodPost {
		s.refuse(sw, rc, http.StatusMethodNotAllowed, "ghgate: POST /v1/token")
		return
	}
	ss, isApp := s.scopedW.(creds.ScopedSource)
	if !cl.canWrite || !cl.scope.limited() || !isApp {
		s.refuse(sw, rc, http.StatusForbidden, "ghgate: token vending needs a client with can_write and a repos allowlist, and an App write credential")
		return
	}
	var req vendReq
	if err := json.NewDecoder(http.MaxBytesReader(sw, r.Body, 1<<16)).Decode(&req); err != nil && r.ContentLength != 0 {
		s.refuse(sw, rc, http.StatusBadRequest, "ghgate: body must be JSON {\"repos\":[\"owner/name\"],\"permissions\":{\"contents\":\"read\"}}")
		return
	}
	if len(req.Repos) == 0 {
		for x := range cl.scope.repos {
			req.Repos = append(req.Repos, x)
		}
		for o := range cl.scope.owners {
			req.Repos = append(req.Repos, o+"/*")
		}
		sort.Strings(req.Repos)
	}
	owner, names := "", []string{}
	for _, full := range req.Repos {
		o, n, _ := strings.Cut(strings.ToLower(strings.TrimSpace(full)), "/")
		if o == "" || n == "" || (owner != "" && o != owner) {
			s.refuse(sw, rc, http.StatusBadRequest, "ghgate: repos must be owner/name, all of one owner")
			return
		}
		if n == "*" && !cl.scope.owners[o] || n != "*" && !cl.scope.allows(o, n) {
			s.refuse(sw, rc, http.StatusForbidden, "ghgate: "+full+" is outside this client's repos")
			return
		}
		owner = o
		if n == "*" {
			names = nil
			continue
		}
		if names != nil {
			names = append(names, n)
		}
	}
	perms := cl.scope.perms
	if len(req.Permissions) > 0 {
		if len(cl.scope.perms) == 0 {
			s.refuse(sw, rc, http.StatusForbidden, "ghgate: this client has no perms ceiling to narrow")
			return
		}
		perms = map[string]string{}
		for k, v := range req.Permissions {
			if permRank[v] == 0 || permRank[v] > permRank[cl.scope.perms[k]] {
				s.refuse(sw, rc, http.StatusForbidden, "ghgate: permission "+k+":"+v+" is above this client's perms")
				return
			}
			perms[k] = v
		}
	}
	tok, _, exp, err := ss.TokenScoped(r.Context(), owner, names, perms)
	if err != nil {
		writeJSON(sw, http.StatusBadGateway, map[string]string{"message": "ghgate: write credential unavailable"})
		return
	}
	rc.calls = 1
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(sw, http.StatusOK, map[string]any{"token": tok, "expires_at": exp.UTC().Format(time.RFC3339), "owner": owner, "repositories": names, "permissions": perms})
}
