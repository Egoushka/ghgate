// Package cache holds the byte-capped LRU of API responses and a singleflight group.
package cache

import (
	"container/list"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Status    int
	Header    http.Header
	Body      []byte
	ETag      string
	LastMod   string
	Validated time.Time
	Repo      string // "/repos/o/r" (lowercase) the entry belongs to, or ""
}

func (e *Entry) size() int64 {
	n := int64(len(e.Body)) + 256
	for k, v := range e.Header {
		n += int64(len(k))
		for _, s := range v {
			n += int64(len(s))
		}
	}
	return n
}

type item struct {
	key string
	e   *Entry
}

type Cache struct {
	mu     sync.Mutex
	max    int64
	used   int64
	ll     *list.List
	items  map[string]*list.Element
	byRepo map[string]map[string]struct{}
	gen    uint64
}

func New(maxBytes int64) *Cache {
	return &Cache{max: maxBytes, ll: list.New(), items: map[string]*list.Element{}, byRepo: map[string]map[string]struct{}{}}
}

// Gen changes whenever something is invalidated. Pass the value read before an
// upstream call to Put so that a response raced by a write is not stored.
func (c *Cache) Gen() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// Get returns the stored entry; callers must not modify it.
func (c *Cache) Get(key string) *Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.items[key]
	if el == nil {
		return nil
	}
	c.ll.MoveToFront(el)
	return el.Value.(*item).e
}

// Put stores e unless an invalidation happened since gen was read.
func (c *Cache) Put(key string, e *Entry, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.gen || e.size() > c.max {
		return false
	}
	c.removeLocked(key)
	c.items[key] = c.ll.PushFront(&item{key, e})
	c.used += e.size()
	if c.byRepo[e.Repo] == nil {
		c.byRepo[e.Repo] = map[string]struct{}{}
	}
	c.byRepo[e.Repo][key] = struct{}{}
	for c.used > c.max {
		back := c.ll.Back()
		c.removeLocked(back.Value.(*item).key)
	}
	return true
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

func (c *Cache) removeLocked(key string) {
	el := c.items[key]
	if el == nil {
		return
	}
	it := el.Value.(*item)
	c.ll.Remove(el)
	delete(c.items, key)
	c.used -= it.e.size()
	if m := c.byRepo[it.e.Repo]; m != nil {
		delete(m, key)
		if len(m) == 0 {
			delete(c.byRepo, it.e.Repo)
		}
	}
}

// InvalidateRepo drops every entry whose path is under prefix ("/repos/o/r").
func (c *Cache) InvalidateRepo(prefix string) {
	prefix = strings.ToLower(prefix)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	for key := range c.byRepo[prefix] {
		c.removeLocked(key)
	}
}

func (c *Cache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.ll.Init()
	c.items = map[string]*list.Element{}
	c.byRepo = map[string]map[string]struct{}{}
	c.used = 0
}

func (c *Cache) Stats() (entries int, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items), c.used
}

// Group coalesces concurrent calls with the same key.
type Group struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	wg  sync.WaitGroup
	val any
}

// Do runs fn once per key at a time; shared is true for callers that waited on another's result.
func (g *Group) Do(key string, fn func() any) (val any, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*call{}
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, true
	}
	c := &call{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()
	c.val = fn()
	return c.val, false
}
