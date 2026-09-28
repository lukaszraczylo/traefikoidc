package traefikoidc

// R4 cache review (medium): checkLegacyBlacklistMarker (universal_cache.go)
// ran an extra Redis round trip (GET, plus PTTL when the key existed) on
// EVERY blacklist Get miss — the overwhelming majority of blacklist checks,
// since most tokens are never revoked — with no bound on how often it
// re-asked Redis for the SAME key. It also fully JSON-decoded whatever it
// found there, even a large CacheTypeToken claims map cached under the same
// raw token, just to learn the value was not the boolean revocation marker.
//
// DECIDED (R4 cache review): cache a legacy-namespace miss locally for a
// short window per key, so each key costs at most one extra legacy lookup
// per window; a genuine legacy marker must still be honored, compared
// against the exact bytes serialize(true) produces rather than fully
// decoded.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/require"
)

func newR4BlacklistTestBackend(t *testing.T, mr *miniredis.Miniredis) *backends.RedisBackend {
	t.Helper()
	cfg := backends.DefaultRedisConfig(mr.Addr())
	// A single pooled connection makes the Redis-command counts below
	// deterministic: with the default pool size, which connection serves
	// each Get is unspecified, and a not-yet-used connection sends an extra
	// health-check PING on its first command — noise unrelated to what this
	// test measures.
	cfg.PoolSize = 1
	backend, err := backends.NewRedisBackend(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

// TestR4_LegacyBlacklistMarker_StillHonoursOldMarker guards the fast
// byte-compare path against ever regressing FIX-16: a genuine pre-upgrade
// legacy marker (a bool `true` written under the "token:" namespace) must
// still be recognized as blacklisted, without a full JSON decode.
func TestR4_LegacyBlacklistMarker_StillHonoursOldMarker(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	backend := newR4BlacklistTestBackend(t, mr)
	logger := NewLogger("error")
	blacklistCache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), backend)
	t.Cleanup(func() { _ = blacklistCache.Close() })

	legacyKey := "legacy-revoked-jti"
	data, err := blacklistCache.serialize(true)
	require.NoError(t, err)
	require.NoError(t, backend.Set(context.Background(), legacyBlacklistPrefix+legacyKey, data, time.Hour))

	value, found := blacklistCache.Get(legacyKey)
	require.True(t, found, "a pre-upgrade legacy marker must still be found")
	require.Equal(t, true, value, "a legacy marker must still report blacklisted=true")
}

// TestR4_LegacyBlacklistMarker_NonBoolLegacyEntryStaysUnblacklisted guards
// the other FIX-16 half: a CacheTypeToken claims map cached under the same
// raw token in the legacy "token:" namespace must never be misread as the
// boolean revocation marker.
func TestR4_LegacyBlacklistMarker_NonBoolLegacyEntryStaysUnblacklisted(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	backend := newR4BlacklistTestBackend(t, mr)
	logger := NewLogger("error")
	blacklistCache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), backend)
	t.Cleanup(func() { _ = blacklistCache.Close() })

	rawToken := "cached-not-revoked-token"
	claims, err := blacklistCache.serialize(map[string]interface{}{"sub": "user123", "exp": 1234567890})
	require.NoError(t, err)
	require.NoError(t, backend.Set(context.Background(), legacyBlacklistPrefix+rawToken, claims, time.Hour))

	_, found := blacklistCache.Get(rawToken)
	require.False(t, found, "a cached claims map under the legacy namespace must never be misread as a revocation marker")
}

// TestR4_LegacyBlacklistMarker_RepeatedMissSkipsRedundantLegacyLookup pins
// the DECIDED cost bound: a blacklist Get miss for a key already known to
// have missed the legacy namespace inside the local window must not repeat
// that Redis round trip.
// Fail-on-old: the second Get costs exactly as much as the first — the
// legacy lookup has no local memory of the prior miss at all.
func TestR4_LegacyBlacklistMarker_RepeatedMissSkipsRedundantLegacyLookup(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	backend := newR4BlacklistTestBackend(t, mr)
	logger := NewLogger("error")
	blacklistCache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), backend)
	t.Cleanup(func() { _ = blacklistCache.Close() })

	key := "never-revoked-raw-token"

	// Warm the connection (and its one-time health-check PING) on an
	// unrelated key first, so the measured deltas below reflect only the
	// legacy-lookup cost this test is pinning, not connection setup.
	_, _ = blacklistCache.Get("warmup-key-unrelated")

	before := mr.CommandCount()
	_, found := blacklistCache.Get(key)
	require.False(t, found)
	afterFirst := mr.CommandCount()
	firstCost := afterFirst - before
	// Each RedisBackend.Get is a health-check PING (the pooled connection is
	// reused, and EnableHealthCheck validates it on every reuse) plus the
	// GET itself: one such round trip against the main "blacklist:"
	// namespace, one more against the legacy "token:" namespace.
	require.Equal(t, 4, firstCost, "a first-ever miss costs a PING+GET against the main \"blacklist:\" namespace plus a PING+GET against the legacy \"token:\" namespace")

	_, found = blacklistCache.Get(key)
	require.False(t, found)
	afterSecond := mr.CommandCount()
	secondCost := afterSecond - afterFirst

	require.Equal(t, 2, secondCost,
		"a repeated blacklist miss for the SAME key within the local miss window must skip the extra legacy-namespace Redis lookup (only the main-namespace PING+GET should run), not repeat it on every call")
}
