package traefikoidc

// Round-2 verifier regression for FIX-17 (defense in depth): a distributed
// backend that does not implement backendSetNXer at all — not only the
// CircuitBreakerBackend/HealthCheckBackend case fixed in
// review_r2_fix17_setifabsent_wrapped_backend_test.go, but any future or
// custom backends.CacheBackend implementer — must not let
// UniversalCache.SetIfAbsent silently degrade to the local-only path.
// Silently degrading means two UniversalCache instances sharing that
// backend (two Traefik replicas) each observe only their own in-process
// map and both report "claimed", exactly the double-accept FIX-17 exists to
// close. SetIfAbsent must instead report an error so a caller like
// checkAndMarkLogoutJTIProcessed falls through to its own
// backchannelLogoutJTIMu-guarded Get+Set, which does read and write the
// shared backend.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noSetNXBackend is a minimal backends.CacheBackend that deliberately does
// NOT implement SetNX, standing in for a backend implementer that has not
// (or cannot) add the optional check-and-set primitive.
type noSetNXBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newNoSetNXBackend() *noSetNXBackend {
	return &noSetNXBackend{data: make(map[string][]byte)}
}

func (b *noSetNXBackend) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[key] = value
	return nil
}

func (b *noSetNXBackend) Get(_ context.Context, key string) ([]byte, time.Duration, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.data[key]
	if !ok {
		return nil, 0, false, nil
	}
	return v, time.Minute, true, nil
}

func (b *noSetNXBackend) Delete(_ context.Context, key string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[key]
	delete(b.data, key)
	return ok, nil
}

func (b *noSetNXBackend) Exists(_ context.Context, key string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[key]
	return ok, nil
}

func (b *noSetNXBackend) Clear(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = make(map[string][]byte)
	return nil
}

func (b *noSetNXBackend) GetStats() map[string]interface{} { return nil }
func (b *noSetNXBackend) Close() error                     { return nil }
func (b *noSetNXBackend) Ping(_ context.Context) error     { return nil }

var _ backends.CacheBackend = (*noSetNXBackend)(nil)

// TestFIX17R2_UniversalCacheSetIfAbsent_UnsupportedBackend_ReportsErrorNotSilentLocalClaim
// pins that SetIfAbsent never falls back to setIfAbsentLocal for a backend
// it cannot reach atomically. Two UniversalCache instances share one
// noSetNXBackend (simulated replicas); both must fail with the same error,
// and neither may silently claim the key using only its own in-process map.
func TestFIX17R2_UniversalCacheSetIfAbsent_UnsupportedBackend_ReportsErrorNotSilentLocalClaim(t *testing.T) {
	backend := newNoSetNXBackend()

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

	claimedA, errA := replicaA.SetIfAbsent("unsupported-backend-key", "a", time.Minute)
	assert.False(t, claimedA, "SetIfAbsent must not silently claim locally when the backend lacks SetNX")
	require.Error(t, errA, "SetIfAbsent must report an error when the backend lacks SetNX, so callers know to use their own shared fallback")

	claimedB, errB := replicaB.SetIfAbsent("unsupported-backend-key", "b", time.Minute)
	assert.False(t, claimedB, "SetIfAbsent must not silently claim locally when the backend lacks SetNX")
	require.Error(t, errB)

	assert.Equal(t, errA, errB, "the unsupported-backend error must be a stable sentinel, not a one-off wrapped error")
}
