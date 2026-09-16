package traefikoidc

// Round-2 verifier regression for FIX-17: UniversalCache.SetIfAbsent's
// cross-replica guarantee must hold when the shared Redis backend is
// wrapped by resilience.CircuitBreakerBackend or resilience.HealthCheckBackend
// — the configuration docs/REDIS.md and examples/redis-config.yaml recommend
// running in production. At round-1 HEAD neither wrapper implements SetNX,
// so the c.backend.(backendSetNXer) type assertion in
// UniversalCache.SetIfAbsent silently fails and every call falls back to
// setIfAbsentLocal, which only ever looks at and writes THIS process's
// in-memory map: two replicas sharing the same wrapped Redis backend both
// see "absent" and both claim, and the key is never written to Redis at
// all. See review_fix17_setifabsent_test.go for the primitive's unwrapped
// contract.

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/resilience"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoReplicaSetIfAbsentWinner drives SetIfAbsent for the same key on two
// separate UniversalCache instances that share one wrapped backend
// (simulating two Traefik replicas behind the same Redis). It asserts
// exactly one claims the key AND that the write actually reached the shared
// miniredis instance — the two properties setIfAbsentLocal cannot deliver
// together across replicas.
func twoReplicaSetIfAbsentWinner(t *testing.T, wrap func(backends.CacheBackend) backends.CacheBackend) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	raw, err := backends.NewRedisBackend(backends.DefaultRedisConfig(mr.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	shared := wrap(raw)

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, shared)
	defer func() { _ = replicaA.Close() }()

	replicaB := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, shared)
	defer func() { _ = replicaB.Close() }()

	claimedA, errA := replicaA.SetIfAbsent("wrapped-jti", "replica-a", time.Minute)
	require.NoError(t, errA)
	claimedB, errB := replicaB.SetIfAbsent("wrapped-jti", "replica-b", time.Minute)
	require.NoError(t, errB)

	assert.True(t, claimedA, "the first replica to call SetIfAbsent must claim the key")
	assert.False(t, claimedB, "a second replica sharing the same wrapped Redis backend must NOT also claim the key")

	keys := mr.Keys()
	assert.NotEmpty(t, keys, "SetIfAbsent's claim must be written to the shared Redis backend, not kept process-local")
}

// TestFIX17R2_UniversalCacheSetIfAbsent_CircuitBreakerWrappedRedis_CrossReplica
// pins the case docs/REDIS.md and examples/redis-config.yaml recommend
// (enableCircuitBreaker: true).
func TestFIX17R2_UniversalCacheSetIfAbsent_CircuitBreakerWrappedRedis_CrossReplica(t *testing.T) {
	twoReplicaSetIfAbsentWinner(t, func(b backends.CacheBackend) backends.CacheBackend {
		return resilience.NewCircuitBreakerBackend(b, nil)
	})
}

// TestFIX17R2_UniversalCacheSetIfAbsent_HealthCheckWrappedRedis_CrossReplica
// pins the case docs/REDIS.md and examples/redis-config.yaml recommend
// (enableHealthCheck: true).
func TestFIX17R2_UniversalCacheSetIfAbsent_HealthCheckWrappedRedis_CrossReplica(t *testing.T) {
	twoReplicaSetIfAbsentWinner(t, func(b backends.CacheBackend) backends.CacheBackend {
		hc := resilience.NewHealthCheckBackend(b, nil)
		t.Cleanup(func() { _ = hc.Close() })
		return hc
	})
}

// TestFIX17R2_UniversalCacheSetIfAbsent_HealthCheckThenCircuitBreakerWrappedRedis_CrossReplica
// pins the production wiring order in initializeCachesWithRedis
// (universal_cache_singleton.go): circuit breaker wraps the raw backend
// first, then health check wraps the circuit breaker, when both are
// enabled (both default to true — see internal/cache/backends/config.go
// DefaultRedisConfig).
func TestFIX17R2_UniversalCacheSetIfAbsent_HealthCheckThenCircuitBreakerWrappedRedis_CrossReplica(t *testing.T) {
	twoReplicaSetIfAbsentWinner(t, func(b backends.CacheBackend) backends.CacheBackend {
		cb := resilience.NewCircuitBreakerBackend(b, nil)
		hc := resilience.NewHealthCheckBackend(cb, nil)
		t.Cleanup(func() { _ = hc.Close() })
		return hc
	})
}
