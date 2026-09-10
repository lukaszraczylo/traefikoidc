package backends

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFIX31_GetNoExpiryReturnsDistinctSentinel guards RedisBackend.Get
// against the R59 follow-up: the old code read TTL (second precision),
// which maps both "no expiry" (-1) and "under one second left" to a
// reported ttl of 0. UniversalCache.Get then treated any ttl<=0 as
// DefaultTTL, so a key on the verge of expiring in Redis got re-cached
// locally for the cache's full DefaultTTL (up to 25h for the
// session-invalidation cache).
//
// Get must now use PTTL (millisecond precision) and report NoExpiryTTL,
// not 0, for a key with no associated expiry, so the caller can still
// distinguish "no expiry" from "expiring now".
// Fail-on-old: a key stored with no TTL reports ttl == 0, indistinguishable
// from an about-to-expire key.
func TestFIX31_GetNoExpiryReturnsDistinctSentinel(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	key := "fix31-no-expiry-key"

	// ttl=0 to Set takes the bare-SET path (no expiry attached).
	require.NoError(t, backend.Set(ctx, key, []byte("v"), 0))

	_, ttl, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, NoExpiryTTL, ttl, "a key with no Redis expiry must report the distinct NoExpiryTTL sentinel, not 0")
}

// TestFIX31_GetWithRealTTLReportsPositiveDuration pins that a key with a
// real remaining TTL still reports a normal positive duration (not the
// sentinel, not zero) after switching from TTL to PTTL.
func TestFIX31_GetWithRealTTLReportsPositiveDuration(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	key := "fix31-real-ttl-key"

	require.NoError(t, backend.Set(ctx, key, []byte("v"), 10*time.Second))

	_, ttl, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, exists)
	assert.NotEqual(t, NoExpiryTTL, ttl)
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, 10*time.Second)
}
