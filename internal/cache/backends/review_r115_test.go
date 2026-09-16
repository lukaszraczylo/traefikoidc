package backends

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRedisBackend_SetNegativeTTL_NotPersistent guards the R115 negative-TTL
// fix. The cache stack's convention is that a non-positive TTL means "already
// expired". Previously RedisBackend.Set/SetMany fell through to a bare SET
// when ttl<=0, writing an entry with NO expiry — i.e. an expired-dated value
// became permanent. Now expired TTLs write nothing.
func TestRedisBackend_SetNegativeTTL_NotPersistent(t *testing.T) {
	_, backend := setupTestRedis(t)
	ctx := context.Background()

	// Single Set with an expired TTL must not create an entry.
	require.NoError(t, backend.Set(ctx, "neg", []byte("v"), -time.Second))
	_, _, exists, err := backend.Get(ctx, "neg")
	require.NoError(t, err)
	require.False(t, exists, "negative-TTL Set must not create a persistent entry")

	// SetMany with multiple items and an expired TTL must not create entries.
	require.NoError(t, backend.SetMany(ctx, map[string][]byte{
		"a": []byte("1"),
		"b": []byte("2"),
	}, -time.Second))
	for _, k := range []string{"a", "b"} {
		_, _, exists, err := backend.Get(ctx, k)
		require.NoError(t, err)
		require.False(t, exists, "negative-TTL SetMany must not create a persistent entry for %q", k)
	}
}
