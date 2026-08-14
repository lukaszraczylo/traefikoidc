package traefikoidc

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// R153 review-round regressions.

// TestRedactCallbackURL covers the callback-log redaction helper: the
// one-time authorization code and the state value must be redacted from
// the URL used in the callback Debug/Error log lines, while unrelated
// query values survive. Fail-on-old: the helper previously returned the
// full req.URL.String() (auth_flow.go Debug ~line 195 / Error ~line 230),
// which published the single-use code into the log pipeline.
func TestRedactCallbackURL(t *testing.T) {
	raw := "https://auth.example/callback?code=SECRETCODE123&state=coolstate&issuer=idp"
	got := redactCallbackURL(raw)

	for _, leaked := range []string{"SECRETCODE123", "coolstate"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redactCallbackURL(%q) leaked %q in %q", raw, leaked, got)
		}
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("redactCallbackURL(%q) = %q: expected redaction markers", raw, got)
	}
	if !strings.Contains(got, "issuer=idp") {
		t.Fatalf("redactCallbackURL(%q) dropped unrelated query param: %q", raw, got)
	}

	// Malformed input returned unchanged, never panics.
	if s := redactCallbackURL("%zz"); s != "%zz" {
		t.Fatalf("malformed URL should pass through unchanged, got %q", s)
	}
}

// TestCacheVerifiedToken_ExpiredNotCached covers the negative-TTL guard in
// cacheVerifiedToken. An already-expired token must not be written to the
// verified-cache under a negative TTL; a still-valid token must be
// cached. Fail-on-old: cacheVerifiedToken set the cache unconditionally
// with exp-now, so an expired token (reachable via ClockSkewToleranceFuture
// leeway) was cached as dead weight (token_manager.go ~line 256).
func TestCacheVerifiedToken_ExpiredNotCached(t *testing.T) {
	ResetUniversalCacheManagerForTesting()

	tObj := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		tokenCache:     NewTokenCache(),
		tokenBlacklist: nil,
	}

	mgr := GetUniversalCacheManager(nil)
	store := mgr.GetTokenCache()

	expired := map[string]interface{}{
		"exp": float64(time.Now().Add(-time.Minute).Unix()),
		"jti": "r153-expired",
	}
	tObj.cacheVerifiedToken("r153-bearer-expired", expired)
	if n := store.Size(); n != 0 {
		t.Fatalf("expired token must not be cached under negative TTL, cache holds %d entries", n)
	}

	valid := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"jti": "r153-valid",
	}
	tObj.cacheVerifiedToken("r153-bearer-valid", valid)
	if n := store.Size(); n == 0 {
		t.Fatal("still-valid token should be cached")
	}

	ResetUniversalCacheManagerForTesting()
}

// TestShardedCache_SetOverwriteNoEvict covers the Set overwrite fix. An
// in-place update of an existing key needs no free slot, so it must not
// evict the shard's oldest (still-valid) entry. Fail-on-old:
// ShardedCache.Set evicted whenever the shard was at capacity, so
// overwriting a key at capacity dropped an unrelated oldest valid entry
// (sharded_cache.go Set; the R57 hazard on the replay path).
func TestShardedCache_SetOverwriteNoEvict(t *testing.T) {
	cache := NewShardedCache(1, 100) // maxPerShard = 100, single shard
	for i := 0; i < 100; i++ {
		cache.Set(fmt.Sprintf("key-%d", i), i, time.Hour)
	}
	if got := cache.Size(); got != 100 {
		t.Fatalf("setup: want 100 entries, got %d", got)
	}

	// Overwrite the NEWEST key (not the eviction target). On the old
	// code this triggered an eviction that dropped the OLDEST valid
	// entry (key-0) from the shard.
	cache.Set("key-99", "overwritten", time.Hour)
	if got := cache.Size(); got != 100 {
		t.Fatalf("overwriting existing key must not shrink shard: want 100, got %d", got)
	}
	if _, ok := cache.Get("key-0"); !ok {
		t.Fatal("overwrite dropped unrelated oldest entry key-0")
	}
	if v, ok := cache.Get("key-99"); !ok || v != "overwritten" {
		t.Fatalf("key-99 should be overwritten, got %v ok=%v", v, ok)
	}
}
