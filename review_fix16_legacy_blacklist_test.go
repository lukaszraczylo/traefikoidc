package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// fix16Backend is a CacheBackend backed by a plain map, keyed by the exact
// (already-prefixed) key the caller passes to Get/Set. It lets tests seed
// entries directly under a specific namespace prefix (e.g. "token:jti") to
// simulate data written by a pre-R128 version of the plugin.
type fix16Backend struct {
	m map[string][]byte
}

func (b *fix16Backend) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	b.m[k] = v
	return nil
}
func (b *fix16Backend) Get(_ context.Context, k string) ([]byte, time.Duration, bool, error) {
	v, ok := b.m[k]
	return v, 0, ok, nil
}
func (b *fix16Backend) Delete(_ context.Context, k string) (bool, error) {
	_, ok := b.m[k]
	delete(b.m, k)
	return ok, nil
}
func (b *fix16Backend) Exists(_ context.Context, k string) (bool, error) {
	_, ok := b.m[k]
	return ok, nil
}
func (b *fix16Backend) Clear(_ context.Context) error {
	b.m = map[string][]byte{}
	return nil
}
func (b *fix16Backend) GetStats() map[string]interface{} { return nil }
func (b *fix16Backend) Close() error                     { return nil }
func (b *fix16Backend) Ping(_ context.Context) error     { return nil }

// TestFIX16_LegacyTokenNamespaceBlacklistMarkerHonored guards the R128
// namespace rename (universal_cache_singleton.go: blacklist cache moved
// from CacheTypeToken's "token:" prefix to CacheTypeBlacklist's
// "blacklist:" prefix). A revocation marker written by a pre-upgrade
// replica under the old "token:" namespace (TTL up to 24h, see
// token_manager.go blacklistDuration) must still deny the token for one
// release after the upgrade.
// Fail-on-old: a jti blacklisted only under "token:" is not blacklisted.
func TestFIX16_LegacyTokenNamespaceBlacklistMarkerHonored(t *testing.T) {
	backend := &fix16Backend{m: map[string][]byte{}}
	logger := NewLogger("error")
	cache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), backend)
	defer cache.Close()

	legacy := NewUniversalCache(UniversalCacheConfig{Type: CacheTypeToken, Logger: logger, DefaultTTL: time.Hour})
	defer legacy.Close()
	data, err := legacy.serialize(true)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	backend.m["token:jti-legacy"] = data

	value, ok := cache.Get("jti-legacy")
	if !ok {
		t.Fatal("a jti blacklisted under the legacy token: namespace must still be reported as blacklisted")
	}
	if value != true {
		t.Fatalf("blacklisted value = %v, want true", value)
	}
}

// TestFIX16_LegacyTokenNamespaceClaimsMapNotBlacklisted guards against
// reintroducing the R128 collision the rename fixed: a CacheTypeToken entry
// under "token:<jti>" holding cached claims (a map) must never be
// misread as a blacklist marker just because a key of the same raw token
// exists there.
// Fail-on-old is moot pre-fix (legacy lookup does not exist yet), but this
// pins the "only boolean true counts" contract once it does.
func TestFIX16_LegacyTokenNamespaceClaimsMapNotBlacklisted(t *testing.T) {
	backend := &fix16Backend{m: map[string][]byte{}}
	logger := NewLogger("error")
	cache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), backend)
	defer cache.Close()

	legacy := NewUniversalCache(UniversalCacheConfig{Type: CacheTypeToken, Logger: logger, DefaultTTL: time.Hour})
	defer legacy.Close()
	data, err := legacy.serialize(map[string]interface{}{"sub": "user-123", "jti": "jti-claims"})
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	backend.m["token:jti-claims"] = data

	if _, ok := cache.Get("jti-claims"); ok {
		t.Fatal("a token-cache claims entry under the legacy namespace must not be treated as a blacklist marker")
	}
}

// TestFIX16_NewNamespaceAuthoritativeOverLegacy pins that a hit on the
// current "blacklist:" namespace is returned directly without consulting
// the legacy namespace at all.
func TestFIX16_NewNamespaceAuthoritativeOverLegacy(t *testing.T) {
	backend := &fix16Backend{m: map[string][]byte{}}
	logger := NewLogger("error")
	cache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), backend)
	defer cache.Close()

	if err := cache.Set("jti-current", true, time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	value, ok := cache.Get("jti-current")
	if !ok || value != true {
		t.Fatalf("Get(jti-current) = (%v, %v), want (true, true)", value, ok)
	}
}

// TestFIX16_NonBlacklistCacheDoesNotConsultLegacyNamespace guards against
// the legacy fallback leaking into other cache types (e.g. the token or
// introspection caches), which have no legacy-namespace migration concern.
func TestFIX16_NonBlacklistCacheDoesNotConsultLegacyNamespace(t *testing.T) {
	backend := &fix16Backend{m: map[string][]byte{}}
	logger := NewLogger("error")

	legacy := NewUniversalCache(UniversalCacheConfig{Type: CacheTypeToken, Logger: logger, DefaultTTL: time.Hour})
	defer legacy.Close()
	data, err := legacy.serialize(true)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	// Seed a marker under the legacy "token:" namespace only. An
	// introspection-cache miss on its own "introspection:" namespace must
	// NOT fall back to this legacy blacklist namespace — that fallback is
	// FIX-16's blacklist-specific compatibility shim, not general behavior.
	backend.m["token:jti-x"] = data

	introspection := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type: CacheTypeIntrospection, Logger: logger, DefaultTTL: time.Hour,
	}, backend)
	defer introspection.Close()

	if _, ok := introspection.Get("jti-x"); ok {
		t.Fatal("legacy-namespace fallback must be scoped to the blacklist cache only")
	}
}
