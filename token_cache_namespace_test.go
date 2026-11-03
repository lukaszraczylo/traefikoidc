package traefikoidc

import (
	"testing"
	"time"
)

func newNSCache(t *testing.T) *UniversalCache {
	t.Helper()
	c := NewUniversalCache(UniversalCacheConfig{Type: CacheTypeToken, MaxSize: 100, DefaultTTL: time.Hour, CleanupInterval: time.Hour})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A verdict stored by one middleware instance must not satisfy another
// instance that verifies against a different client or audience.
func TestTokenCacheIsolatedPerInstanceNamespace(t *testing.T) {
	shared := newNSCache(t)
	a := &TokenCache{cache: shared}
	b := &TokenCache{cache: shared}
	a.SetNamespace("https://idp|app-a|app-a")
	b.SetNamespace("https://idp|app-b|app-b")

	a.Set("tok", map[string]interface{}{"sub": "u"}, time.Minute)
	if _, ok := b.Get("tok"); ok {
		t.Fatal("instance B hit a verdict cached by instance A")
	}
	if _, ok := a.Get("tok"); !ok {
		t.Fatal("instance A lost its own verdict")
	}
	a.Delete("tok")
	if _, ok := a.Get("tok"); ok {
		t.Fatal("Delete did not remove the namespaced entry")
	}
}

func TestTokenCacheNamespaceFollowsDCR(t *testing.T) {
	shared := newNSCache(t)
	tc := &TokenCache{cache: shared}
	tc.SetNamespace("p|old|old")
	tc.Set("tok", map[string]interface{}{"sub": "u"}, time.Minute)
	tc.SetNamespace("p|new|new")
	if _, ok := tc.Get("tok"); ok {
		t.Fatal("verdict cached under the old client survived a namespace change")
	}
}

func TestTokenCacheEmptyNamespaceKeepsLegacyKey(t *testing.T) {
	shared := newNSCache(t)
	a := &TokenCache{cache: shared}
	b := &TokenCache{cache: shared}
	a.Set("tok", map[string]interface{}{"sub": "u"}, time.Minute)
	if _, ok := b.Get("tok"); !ok {
		t.Fatal("namespace-less caches must keep sharing the legacy key")
	}
}

func TestIntrospectionKeyScopedPerInstance(t *testing.T) {
	a := &TraefikOidc{tokenCache: &TokenCache{}}
	b := &TraefikOidc{tokenCache: &TokenCache{}}
	a.tokenCache.SetNamespace("p|app-a|app-a")
	b.tokenCache.SetNamespace("p|app-b|app-b")
	if a.introspectionKey("tok") == b.introspectionKey("tok") {
		t.Fatal("different instances share an introspection cache key")
	}
	if got := (&TraefikOidc{}).introspectionKey("tok"); got != "tok" {
		t.Fatalf("namespace-less key = %q, want raw token", got)
	}
}
