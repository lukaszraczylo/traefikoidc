package traefikoidc

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/require"
)

// TestBlacklist_NoIntrospectionKeyCollision_Redis guards the R114 blacklist /
// introspection key collision. Both caches keyed an opaque token by its raw
// value, and both previously used CacheTypeToken, so in Redis (shared
// backend) mode they composed the SAME Redis key (KeyPrefix + "token:" + raw).
// An introspection write could then clobber a same-token blacklist marker, so
// a revoked opaque token could be re-accepted on another replica.
func TestBlacklist_NoIntrospectionKeyCollision_Redis(t *testing.T) {
	t.Parallel()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisConfig := backends.DefaultRedisConfig(mr.Addr())
	redisConfig.RedisPrefix = "test:"
	backend, err := backends.NewRedisBackend(redisConfig)
	require.NoError(t, err)
	defer backend.Close()

	// Both caches share ONE Redis backend — mirrors production where every
	// UniversalCache wraps the same redisBackend (createBackend ignores its arg).
	blacklist := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:       CacheTypeBlacklist, // distinct "blacklist:" namespace (R128)
		MaxSize:    1000,
		DefaultTTL: 24 * time.Hour,
	}, backend)
	defer blacklist.Close()

	introsp := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:       CacheTypeIntrospection, // distinct "introspection:" namespace
		MaxSize:    1000,
		DefaultTTL: 5 * time.Minute,
	}, backend)
	defer introsp.Close()

	raw := "opaque.signed.revoked-token"

	// 1. Revoke the opaque token: blacklist marker lands at blacklist:<raw>.
	require.NoError(t, blacklist.Set(raw, true, time.Hour))

	// 2. Cache an introspection result for the SAME raw token.
	//    Distinct namespaces — introspection:<raw> — marker stays intact.
	require.NoError(t, introsp.Set(raw, &IntrospectionResponse{Active: true}, time.Minute))

	// 3. The blacklist must STILL report the token as revoked.
	v, ok := blacklist.Get(raw)
	require.True(t, ok, "blacklist entry must exist for a revoked token")
	revoked, isBool := v.(bool)
	require.True(t, isBool, "blacklist value must be a bool, got %T (introspection clobbered the key?)", v)
	require.True(t, revoked, "revoked opaque token must remain blacklisted")
}
