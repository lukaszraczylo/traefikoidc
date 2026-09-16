package traefikoidc

// Shared CacheInterface / cache-backend test doubles for round-regression
// tests.
//
// Moved here for FIX-41: NewMemoryBackendForTest, mapCache/newMapCache and
// serializingCache were each declared inside a single round file (review_r124,
// review_r146, review_r159) but consumed by other round files, so deleting or
// renaming the declaring file silently broke the consumer. Every
// review_rNN*_test.go file must depend only on shared helpers like this one,
// never on another round file.

import (
	"encoding/json"
	"github.com/alicebob/miniredis/v2"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// NewMemoryBackendForTest returns a cache backend backed by an in-process
// miniredis instance, for white-box tests that need a real CacheBackend
// without depending on a live Redis server. internal/cache's in-memory
// backend was removed as unreachable dead code (FIX-43); RedisBackend
// against miniredis is the project's standard lightweight substitute.
//
// The miniredis server is registered against t.Cleanup so it (and its
// listener goroutine) is closed when t ends. Callers still defer
// backend.Close() to close the RedisBackend connection pool.
func NewMemoryBackendForTest(t *testing.T) (backends.CacheBackend, error) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		return nil, err
	}
	t.Cleanup(mr.Close)
	return backends.NewRedisBackend(backends.DefaultRedisConfig(mr.Addr()))
}

// mapCache is a minimal thread-safe CacheInterface for seeding caches in
// bearer-invalidation tests.
type mapCache struct {
	mu sync.Mutex
	m  map[string]any
}

func newMapCache() *mapCache { return &mapCache{m: map[string]any{}} }
func (c *mapCache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	c.m[key] = value
	c.mu.Unlock()
}
func (c *mapCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}
func (c *mapCache) Delete(key string)        { c.mu.Lock(); delete(c.m, key); c.mu.Unlock() }
func (c *mapCache) SetMaxSize(size int)      {}
func (c *mapCache) Size() int                { return 0 }
func (c *mapCache) Clear()                   {}
func (c *mapCache) Cleanup()                 {}
func (c *mapCache) Close()                   {}
func (c *mapCache) GetStats() map[string]any { return nil }

// serializingCache simulates a UniversalCache backed by a serializing
// store (e.g. Redis): Set JSON-round-trips the value, so Get returns a
// generic map, never the original concrete type. This is exactly what
// production sees on the distributed path.
type serializingCache struct {
	m map[string]interface{}
}

func (c *serializingCache) Set(key string, value any, ttl time.Duration) {
	b, _ := json.Marshal(value)
	var v interface{}
	_ = json.Unmarshal(b, &v)
	c.m[key] = v
}
func (c *serializingCache) Get(key string) (any, bool) {
	v, ok := c.m[key]
	return v, ok
}
func (c *serializingCache) Delete(key string)        { delete(c.m, key) }
func (c *serializingCache) SetMaxSize(int)           {}
func (c *serializingCache) Size() int                { return len(c.m) }
func (c *serializingCache) Clear()                   { c.m = map[string]interface{}{} }
func (c *serializingCache) Cleanup()                 {}
func (c *serializingCache) Close()                   {}
func (c *serializingCache) GetStats() map[string]any { return nil }
