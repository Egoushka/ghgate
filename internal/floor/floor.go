// Package floor tracks GitHub rate-limit headroom per credential and resource.
package floor

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

type State struct {
	Remaining int   `json:"remaining"`
	Reset     int64 `json:"reset"`
}

type Tracker struct {
	mu sync.Mutex
	m  map[string]map[string]State
}

func New() *Tracker { return &Tracker{m: map[string]map[string]State{}} }

// Observe records the x-ratelimit-* headers of an upstream response.
func (t *Tracker) Observe(cred string, h http.Header) {
	rem, err1 := strconv.Atoi(h.Get("X-RateLimit-Remaining"))
	reset, err2 := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64)
	if err1 != nil || err2 != nil {
		return
	}
	res := h.Get("X-RateLimit-Resource")
	if res == "" {
		res = "core"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rm := t.m[cred]
	if rm == nil {
		rm = map[string]State{}
		t.m[cred] = rm
	}
	old, ok := rm[res]
	// Responses race: within one window keep the lowest count, a newer window replaces.
	if ok && old.Reset == reset && old.Remaining < rem {
		return
	}
	if ok && old.Reset > reset {
		return
	}
	rm[res] = State{rem, reset}
}

// Check reports whether a call may go upstream. A passed reset time clears the state.
func (t *Tracker) Check(cred, resource string, floor int, now time.Time) (State, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.m[cred][resource]
	if !ok || now.Unix() >= st.Reset {
		return st, true
	}
	return st, st.Remaining >= floor
}

func (t *Tracker) Snapshot() map[string]map[string]State {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]map[string]State{}
	for k, v := range t.m {
		c := map[string]State{}
		for r, s := range v {
			c[r] = s
		}
		out[k] = c
	}
	return out
}
