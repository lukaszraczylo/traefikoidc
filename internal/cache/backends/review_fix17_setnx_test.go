package backends

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFIX17_RedisBackendSetNX_ClaimsOnlyWhenAbsent pins RedisBackend.SetNX's
// contract: it stores the value and reports true only when the key does not
// already exist, using Redis SET key value NX PX <ttl-ms> as one atomic
// server-side operation, and never overwrites an existing key.
func TestFIX17_RedisBackendSetNX_ClaimsOnlyWhenAbsent(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	key := "fix17-setnx-key"

	set, err := backend.SetNX(ctx, key, []byte("first"), time.Minute)
	require.NoError(t, err)
	assert.True(t, set, "first SetNX on an absent key must claim it")

	set, err = backend.SetNX(ctx, key, []byte("second"), time.Minute)
	require.NoError(t, err)
	assert.False(t, set, "second SetNX on an already-claimed key must not claim it")

	value, ttl, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, "first", string(value), "the losing SetNX must not overwrite the winner's value")
	assert.Greater(t, ttl, 50*time.Second, "the winning SetNX must have attached the requested TTL")
}

// TestFIX17_RedisBackendSetNX_ConcurrentSameKeyExactlyOneWinner drives many
// goroutines through SetNX on the SAME key against a single miniredis
// instance shared by every caller (simulating every Traefik replica sharing
// one Redis-backed session-invalidation cache). Exactly one must win: this
// is the primitive UniversalCache.SetIfAbsent relies on to close the
// cross-replica gap the FIX-17 R36 fix left open (backchannelLogoutJTIMu is
// process-local and cannot coordinate across replicas; Redis SET NX can).
func TestFIX17_RedisBackendSetNX_ConcurrentSameKeyExactlyOneWinner(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	key := "fix17-setnx-concurrent-key"

	const n = 20
	var wg sync.WaitGroup
	results := make([]bool, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = backend.SetNX(ctx, key, []byte("claimant"), time.Minute)
		}(i)
	}
	wg.Wait()

	wins := 0
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		if results[i] {
			wins++
		}
	}
	assert.Equal(t, 1, wins, "exactly one of %d concurrent SetNX calls on the same key must win", n)
}
