package cache

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ent(repo string, n int) *Entry {
	return &Entry{Status: 200, Header: http.Header{}, Body: []byte(strings.Repeat("x", n)), Repo: repo, Validated: time.Now()}
}

func TestLRUEvictsByBytes(t *testing.T) {
	c := New(3000)
	g := c.Gen()
	c.Put("a", ent("", 1000), g)
	c.Put("b", ent("", 1000), g)
	c.Get("a")
	c.Put("c", ent("", 1000), g)
	if c.Get("b") != nil || c.Get("a") == nil || c.Get("c") == nil {
		t.Fatal("least recently used entry should have been evicted")
	}
	if c.Put("huge", ent("", 10000), g) {
		t.Fatal("an entry larger than the cache must be refused")
	}
}

func TestInvalidateRepoAndRacedPut(t *testing.T) {
	c := New(1 << 20)
	g := c.Gen()
	c.Put("r1", ent("/repos/o/r", 10), g)
	c.Put("r2", ent("/repos/o/other", 10), g)
	c.InvalidateRepo("/repos/o/r")
	if c.Get("r1") != nil || c.Get("r2") == nil {
		t.Fatal("only the named repo may be dropped")
	}
	if c.Put("late", ent("/repos/o/r", 10), g) {
		t.Fatal("a response fetched before an invalidation must not be stored")
	}
}

func TestGroupCoalesces(t *testing.T) {
	var g Group
	var calls atomic.Int32
	var wg sync.WaitGroup
	release := make(chan struct{})
	var shared atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, s := g.Do("k", func() any { calls.Add(1); <-release; return 1 })
			if s {
				shared.Add(1)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 || shared.Load() != 9 {
		t.Fatalf("calls %d shared %d", calls.Load(), shared.Load())
	}
}
