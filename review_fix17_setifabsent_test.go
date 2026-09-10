package traefikoidc

// Regression tests for UniversalCache.SetIfAbsent, the atomic check-and-set
// primitive that closes the remaining half of FIX-17: the backchannel-logout
// jti replay check (OIDC Back-Channel Logout 1.0 §2.5) must be one atomic
// operation, including across Traefik replicas that share a Redis-backed
// sessionInvalidationCache, not the process-local-mutex-guarded Get-then-Set
// review_fix17_backchannel_jti_atomic_test.go already pins for a single
// process. See review_fix17_backchannel_atomic_integration_test.go for the
// end-to-end pin that logout.go's jti check actually uses this primitive.

import (
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFIX17_UniversalCacheSetIfAbsent_LocalOnlyBasicSemantics pins
// SetIfAbsent's single-threaded contract for a cache with no distributed
// backend: the first call claims the key and stores the value, and a second
// call for the same key reports false and leaves the stored value untouched.
func TestFIX17_UniversalCacheSetIfAbsent_LocalOnlyBasicSemantics(t *testing.T) {
	cache := NewUniversalCache(UniversalCacheConfig{
		Type:            CacheTypeGeneral,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	})
	defer func() { _ = cache.Close() }()

	set, err := cache.SetIfAbsent("k", "first", time.Minute)
	require.NoError(t, err)
	assert.True(t, set, "first SetIfAbsent on an absent key must claim it")

	set, err = cache.SetIfAbsent("k", "second", time.Minute)
	require.NoError(t, err)
	assert.False(t, set, "second SetIfAbsent on an already-claimed key must not claim it")

	value, found := cache.Get("k")
	require.True(t, found)
	assert.Equal(t, "first", value, "the losing SetIfAbsent must not overwrite the winner's value")
}

// TestFIX17_UniversalCacheSetIfAbsent_LocalOnlyConcurrentExactlyOneWinner
// pins SetIfAbsent's "atomic under c.mu for local storage" requirement: with
// no distributed backend, the presence check and the insert happen inside
// one c.mu critical section, so many concurrent callers racing the same key
// can never both observe "absent" (the TOCTOU gap a separate Get then Set
// has).
func TestFIX17_UniversalCacheSetIfAbsent_LocalOnlyConcurrentExactlyOneWinner(t *testing.T) {
	cache := NewUniversalCache(UniversalCacheConfig{
		Type:            CacheTypeGeneral,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	})
	defer func() { _ = cache.Close() }()

	const n = 20
	var wg sync.WaitGroup
	results := make([]bool, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = cache.SetIfAbsent("concurrent-key", i, time.Minute)
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
	assert.Equal(t, 1, wins, "exactly one of %d concurrent SetIfAbsent calls on the same key must win", n)
}

// TestFIX17_UniversalCacheSetIfAbsent_RedisBackendConcurrentExactlyOneWinner
// drives SetIfAbsent through a real Redis backend (miniredis), simulating
// every Traefik replica racing the same jti against a shared Redis-backed
// sessionInvalidationCache. Exactly one must win: this is the case the
// process-local backchannelLogoutJTIMu could never cover, and is only
// correct because SetIfAbsent reaches RedisBackend.SetNX (Redis SET NX PX)
// through the optional-interface type assertion, not a Get-then-Set.
func TestFIX17_UniversalCacheSetIfAbsent_RedisBackendConcurrentExactlyOneWinner(t *testing.T) {
	backend, err := NewMemoryBackendForTest(t)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, backend)
	defer func() { _ = cache.Close() }()

	const n = 20
	var wg sync.WaitGroup
	results := make([]bool, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = cache.SetIfAbsent("redis-concurrent-key", "claimant", time.Minute)
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
	assert.Equal(t, 1, wins, "exactly one of %d concurrent Redis-backed SetIfAbsent calls on the same key must win", n)
}

// TestFIX17R2_UniversalCacheSetIfAbsent_TwoReplicasShareRawRedisBackend_ExactlyOneWinner
// is the round-2 verifier's mutation-resistant version of
// TestFIX17_UniversalCacheSetIfAbsent_RedisBackendConcurrentExactlyOneWinner
// above: that test drives 20 concurrent calls through a SINGLE
// UniversalCache instance, so c.mu's own single-process atomicity produces
// exactly one winner even if the c.backend.(backendSetNXer) branch were
// dead code — it does not, by itself, prove the winning claim crossed into
// Redis rather than staying in that one instance's local map. This test
// uses two SEPARATE UniversalCache instances (simulated Traefik replicas)
// sharing one miniredis-backed RedisBackend and asserts both properties
// together: the second instance's call is rejected, AND the key is
// actually present in the shared miniredis (mr.Keys()), which only the
// SetNX branch, not two independent local maps, can produce.
func TestFIX17R2_UniversalCacheSetIfAbsent_TwoReplicasShareRawRedisBackend_ExactlyOneWinner(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	backend, err := backends.NewRedisBackend(backends.DefaultRedisConfig(mr.Addr()))
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, backend)
	defer func() { _ = replicaA.Close() }()

	replicaB := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, backend)
	defer func() { _ = replicaB.Close() }()

	claimedA, errA := replicaA.SetIfAbsent("two-replica-raw-redis-key", "replica-a", time.Minute)
	require.NoError(t, errA)
	claimedB, errB := replicaB.SetIfAbsent("two-replica-raw-redis-key", "replica-b", time.Minute)
	require.NoError(t, errB)

	assert.True(t, claimedA, "the first replica must claim the key")
	assert.False(t, claimedB, "a second replica sharing the same raw Redis backend must not also claim the key")
	assert.NotEmpty(t, mr.Keys(), "the winning claim must be written to the shared Redis backend, not kept process-local")
}

// TestFIX17_CacheInterfaceWrapperSetIfAbsent_SatisfiesOptionalInterface
// pins that the production CacheInterface implementation (CacheManager's
// CacheInterfaceWrapper, what logout.go's sessionInvalidationCache actually
// is at runtime) exposes SetIfAbsent and therefore satisfies the optional
// AtomicSetIfAbsentCache interface logout.go type-asserts against, and that
// the delegation to UniversalCache.SetIfAbsent behaves correctly.
func TestFIX17_CacheInterfaceWrapperSetIfAbsent_SatisfiesOptionalInterface(t *testing.T) {
	wrapper := &CacheInterfaceWrapper{cache: NewUniversalCache(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	})}
	defer wrapper.Close()

	atomicCache, ok := CacheInterface(wrapper).(AtomicSetIfAbsentCache)
	require.True(t, ok, "CacheInterfaceWrapper must satisfy AtomicSetIfAbsentCache")

	set, err := atomicCache.SetIfAbsent("k", "v1", time.Minute)
	require.NoError(t, err)
	assert.True(t, set)

	set, err = atomicCache.SetIfAbsent("k", "v2", time.Minute)
	require.NoError(t, err)
	assert.False(t, set)
}
