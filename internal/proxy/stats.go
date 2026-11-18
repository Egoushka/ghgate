package proxy

import (
	"encoding/json"
	"net/http"
	"sync"
)

type ClientStats struct {
	Requests      int64            `json:"requests"`
	Cache         map[string]int64 `json:"cache"`
	UpstreamCalls int64            `json:"upstream_calls"`
	Refusals      int64            `json:"refusals"`
}

type Stats struct {
	mu sync.Mutex
	m  map[string]*ClientStats
}

func newStats() *Stats { return &Stats{m: map[string]*ClientStats{}} }

func (s *Stats) record(name, outcome string, upstream int, refused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.m[name]
	if c == nil {
		c = &ClientStats{Cache: map[string]int64{}}
		s.m[name] = c
	}
	c.Requests++
	c.UpstreamCalls += int64(upstream)
	if refused {
		c.Refusals++
	}
	if outcome != "" {
		c.Cache[outcome]++
	}
}

func (s *Stats) snapshot() map[string]ClientStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]ClientStats{}
	for k, v := range s.m {
		c := *v
		c.Cache = map[string]int64{}
		for o, n := range v.Cache {
			c.Cache[o] = n
		}
		out[k] = c
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }
