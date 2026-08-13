package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// stubBackend implements backends.CacheBackend with a controllable TTL so the
// UniversalCache.Get re-population path can be tested deterministically.
type stubBackend struct {
	val     []byte
	ttl     time.Duration
	exists  bool
}

func (s *stubBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}
func (s *stubBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	return s.val, s.ttl, s.exists, nil
}
func (s *stubBackend) Delete(ctx context.Context, key string) (bool, error) { return true, nil }
func (s *stubBackend) Exists(ctx context.Context, key string) (bool, error) { return s.exists, nil }
func (s *stubBackend) Clear(ctx context.Context) error                     { return nil }
func (s *stubBackend) GetStats() map[string]interface{}                    { return nil }
func (s *stubBackend) Close() error                                       { return nil }
func (s *stubBackend) Ping(ctx context.Context) error                     { return nil }

// TestUniversalCacheBackendRepopulateKeepsRealTTL guards against Get() re-caching a
// backend value under the federated DefaultTTL instead of the entry's real
// remaining TTL. The old code re-populated the local LRU with DefaultTTL
// (often 1h), so once the distributed backend became unreachable the local
// fast-path served data whose authoritative TTL had already lapsed (e.g. a
// 5-minute token served for up to an hour).
func TestUniversalCacheBackendRepopulateKeepsRealTTL(t *testing.T) {
	backend := &stubBackend{
		val:    []byte("42"),
		ttl:    5 * time.Second,
		exists: true,
	}

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:       CacheTypeMetadata,
		DefaultTTL: time.Hour,
		MaxSize:    100,
		Logger:     NewLogger(DefaultLogLevel),
	}, backend)
	defer cache.Close()

	if _, ok := cache.Get("key"); !ok {
		t.Fatalf("backend hit should return a value")
	}

	item := cache.items["key"]
	if item == nil {
		t.Fatalf("local cache should have been populated from backend")
	}
	remaining := time.Until(item.ExpiresAt)
	if remaining > 10*time.Second || remaining <= 0 {
		t.Fatalf("local cache TTL should track backend real TTL (~5s), got %v (old code used DefaultTTL 1h)", remaining)
	}
}
