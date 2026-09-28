package traefikoidc

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// fix31Backend is a CacheBackend whose Get reports a fixed, caller-supplied
// TTL for every key, simulating what RedisBackend.Get returns for a key
// with under a second of remaining life (0) versus no expiry at all
// (backends.NoExpiryTTL).
type fix31Backend struct {
	val []byte
	ttl time.Duration
}

func (b *fix31Backend) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return nil
}
func (b *fix31Backend) Get(_ context.Context, _ string) ([]byte, time.Duration, bool, error) {
	return b.val, b.ttl, true, nil
}
func (b *fix31Backend) Delete(_ context.Context, _ string) (bool, error) { return true, nil }
func (b *fix31Backend) Exists(_ context.Context, _ string) (bool, error) { return true, nil }
func (b *fix31Backend) Clear(_ context.Context) error                    { return nil }
func (b *fix31Backend) GetStats() map[string]interface{}                 { return nil }
func (b *fix31Backend) Close() error                                     { return nil }
func (b *fix31Backend) Ping(_ context.Context) error                     { return nil }

// TestFIX31_ZeroTTLDoesNotRepopulateForDefaultTTL guards UniversalCache.Get
// (universal_cache.go): a backend TTL of 0 means "under one unit of time
// left" (R59 follow-up), not "no expiry information". Re-populating the
// local copy for the cache's full DefaultTTL in that case serves a dying
// entry long after the backend expires it — up to 25h for the
// session-invalidation cache.
// Fail-on-old: the local copy's remaining TTL is close to DefaultTTL.
func TestFIX31_ZeroTTLDoesNotRepopulateForDefaultTTL(t *testing.T) {
	backend := &fix31Backend{val: []byte(`"v"`), ttl: 0}

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:       CacheTypeToken,
		DefaultTTL: time.Hour,
		MaxSize:    100,
		Logger:     NewLogger("error"),
	}, backend)
	defer cache.Close()

	value, ok := cache.Get("key")
	if !ok {
		t.Fatal("backend hit should still return the value even when not repopulating locally")
	}
	if value != "v" {
		t.Fatalf("value = %v, want v", value)
	}

	item, exists := cache.items["key"]
	if !exists {
		// Not caching the entry locally at all is an acceptable way to
		// satisfy "do not repopulate for DefaultTTL".
		return
	}
	remaining := time.Until(item.ExpiresAt)
	if remaining > 5*time.Second {
		t.Fatalf("local cache TTL should not be repopulated for DefaultTTL on a zero-TTL backend hit, got %v remaining (DefaultTTL=1h)", remaining)
	}
}

// TestFIX31_NoExpirySentinelStillRepopulatesForDefaultTTL pins the
// companion behavior: a backend reporting the distinct "no expiry" sentinel
// (backends.NoExpiryTTL) still federates the cache's own DefaultTTL for the
// local copy, exactly as a zero-meaning-unknown TTL did before FIX-31.
func TestFIX31_NoExpirySentinelStillRepopulatesForDefaultTTL(t *testing.T) {
	backend := &fix31Backend{val: []byte(`"v"`), ttl: backends.NoExpiryTTL}

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:       CacheTypeToken,
		DefaultTTL: time.Hour,
		MaxSize:    100,
		Logger:     NewLogger("error"),
	}, backend)
	defer cache.Close()

	if _, ok := cache.Get("key"); !ok {
		t.Fatal("backend hit should return a value")
	}

	item := cache.items["key"]
	if item == nil {
		t.Fatal("a no-expiry backend hit should still populate the local cache")
	}
	remaining := time.Until(item.ExpiresAt)
	if remaining < 30*time.Minute || remaining > time.Hour {
		t.Fatalf("local cache TTL should track DefaultTTL (~1h) for a no-expiry backend entry, got %v", remaining)
	}
}
