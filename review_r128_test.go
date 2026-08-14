package traefikoidc

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/require"
)

// TestBlacklist_TokenCacheNamespaceIsolation_Redis guards the R128 fix:
// the blacklist cache shared CacheTypeToken with the token cache, and both
// compose their Redis key from c.config.Type (prefixKey). In shared
// backend (Redis) mode the two caches therefore used IDENTICAL keys
// (token:<raw>) for the same raw token, so a cached verified token's
// claims made the blacklist report it as blacklisted, and a token-cache
// write clobbered a real blacklist marker — defeating the revoke
// feature. The blacklist must live in its own namespace.
func TestBlacklist_TokenCacheNamespaceIsolation_Redis(t *testing.T) {
	t.Parallel()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisConfig := backends.DefaultRedisConfig(mr.Addr())
	redisConfig.RedisPrefix = "iso:"
	backend, err := backends.NewRedisBackend(redisConfig)
	require.NoError(t, err)
	defer backend.Close()

	blacklist := NewUniversalCacheWithBackend(newBlacklistCacheConfig(nil), backend)
	t.Cleanup(func() { _ = blacklist.Close() })
	tokenCache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:       CacheTypeToken,
		MaxSize:    1000,
		DefaultTTL: time.Hour,
	}, backend)
	t.Cleanup(func() { _ = tokenCache.Close() })

	// Direction A: a valid token with its claims cached must NOT be seen as
	// blacklisted. OLD: blacklist and token share "token:", so Get returns
	// the cached claims (non-nil) and reports the valid token blacklisted.
	tok := "valid.signed.token"
	require.NoError(t, tokenCache.Set(tok, []string{"cid"}, time.Hour))
	if _, found := blacklist.Get(tok); found {
		t.Fatal("valid token whose claims are cached must not be reported blacklisted")
	}

	// Direction B: a real blacklist marker must survive a token-cache write of
	// the same raw token. OLD: the token-cache write clobbers the shared key,
	// turning the marker into claims (not a bool) or dropping it.
	revoked := "revoked.signed.token"
	require.NoError(t, blacklist.Set(revoked, true, time.Hour))
	require.NoError(t, tokenCache.Set(revoked, []string{"cid"}, time.Hour))
	v, found := blacklist.Get(revoked)
	require.True(t, found, "blacklist entry must survive a same-token cache write")
	isBool, ok := v.(bool)
	require.True(t, ok, "blacklist value must remain a bool, got %T", v)
	require.True(t, isBool, "revoked token must remain blacklisted")
}
