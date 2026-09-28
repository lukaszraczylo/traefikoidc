package traefikoidc

// R4 cache review (medium): FIX-04's backend-stale mark (universal_cache.go
// markBackendStale/backendStaleLocalValue) let Get serve the LOCAL value
// over EVERY later backend value for a marked key, as long as the local
// entry was still live. That assumed the backend value could only ever be
// OLDER than the local one — true for a same-replica write that may have
// landed after a timeout. It is false across replicas: another replica can
// write a genuinely NEWER value (e.g. a later backchannel logout) to the
// same key while this replica's own Set failed and left it marked stale.
// Before the fix, this replica kept serving its own older local value —
// for the session-invalidation cache (MonotonicMarkers, 25h local TTL) that
// meant an up-to-25h window of ignored cross-replica logouts.
//
// r4SharedBackend is a CacheBackend two UniversalCache instances share
// directly (standing in for two Traefik replicas pointed at the same Redis),
// so a "replica B" write is visible to "replica A" exactly the way a shared
// Redis instance would be. failOnce lets a single test-controlled Set call
// fail without applying — modeling replica A's own write timing out or being
// rejected — while a normal Set (used to model replica B) always applies.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

type r4SharedBackend struct {
	mu       sync.Mutex
	m        map[string][]byte
	failOnce error
}

func (b *r4SharedBackend) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failOnce != nil {
		err := b.failOnce
		b.failOnce = nil
		return err
	}
	b.m[k] = v
	return nil
}
func (b *r4SharedBackend) Get(_ context.Context, k string) ([]byte, time.Duration, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[k]
	return v, 0, ok, nil
}
func (b *r4SharedBackend) Delete(_ context.Context, k string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.m[k]
	delete(b.m, k)
	return ok, nil
}
func (b *r4SharedBackend) Exists(_ context.Context, k string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.m[k]
	return ok, nil
}
func (b *r4SharedBackend) Clear(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m = map[string][]byte{}
	return nil
}
func (b *r4SharedBackend) GetStats() map[string]interface{} { return nil }
func (b *r4SharedBackend) Close() error                     { return nil }
func (b *r4SharedBackend) Ping(_ context.Context) error     { return nil }

// TestR4_BackendStale_CrossReplicaNewerValue_PrefersNewerBackend guards
// Get() (universal_cache.go, around the backendStaleLocalValue branch) for a
// plain (non-MonotonicMarkers) cache. R4 cache review round 2 (minor,
// universal_cache.go:546) found this test's ORIGINAL premise wrong: it
// expected the numeric "larger value wins" comparison (backendValueIsNewer)
// to resolve a cross-replica race on a cache that never set
// MonotonicMarkers. That comparison is meaningful ONLY for a MonotonicMarkers
// cache's timestamp markers — for any other numeric cache, a larger number
// is not necessarily a newer write, so trusting it risks exactly the
// clobber FIX-04 exists to prevent (see
// TestR4_BackendStale_NonMonotonicNumeric_OlderLargerBackendDoesNotClobber).
// Get() now gates the numeric comparison on c.config.MonotonicMarkers, so a
// plain cache like this one recovers from a stale mark only once
// backendStaleMarkTTL elapses — the same time-bounded mechanism that
// recovers a non-numeric value (see
// review_r4_backendstale_timebound_test.go), not numeric order.
// Fail-on-old (pre-gate code): immediately after replica B's write, Get
// already returns 3000 via the numeric comparison, so the "still local"
// assertion below fails.
func TestR4_BackendStale_CrossReplicaNewerValue_PrefersNewerBackend(t *testing.T) {
	orig := backendStaleMarkTTL
	backendStaleMarkTTL = 50 * time.Millisecond
	t.Cleanup(func() { backendStaleMarkTTL = orig })

	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          logger,
		Type:            CacheTypeSession,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, shared)
	defer replicaA.Close()

	// Replica A's own write times out — Redis may or may not have applied
	// it — so Set marks the key backend-stale and keeps 2000 locally.
	shared.failOnce = context.DeadlineExceeded
	if err := replicaA.Set("k1", int64(2000), time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	// Replica B's later write reaches the SAME shared backend directly with
	// a numerically larger value.
	data, err := replicaA.serialize(int64(3000))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := shared.Set(context.Background(), replicaA.prefixKey("k1"), data, time.Minute); err != nil {
		t.Fatalf("simulated replica B write failed: %v", err)
	}

	// Immediately after B's write, this non-MonotonicMarkers cache must NOT
	// resolve the race by numeric order: the mark is still fresh, so A keeps
	// serving its own local value.
	value, ok := replicaA.Get("k1")
	if !ok {
		t.Fatal("Get: key not found")
	}
	if got, numeric := sessionInvalidationTime(value); !numeric || got != 2000 {
		t.Fatalf("Get returned %v (%T), want the local 2000 — a non-MonotonicMarkers cache must not let a larger backend number win while the stale mark is still fresh", value, value)
	}

	// Once the mark's bound elapses, the (now current) backend value is
	// trusted again — recovery via the time bound, not numeric order.
	time.Sleep(backendStaleMarkTTL + 150*time.Millisecond)

	value, ok = replicaA.Get("k1")
	if !ok {
		t.Fatal("Get: key not found")
	}
	got, numeric := sessionInvalidationTime(value)
	if !numeric || got != 3000 {
		t.Fatalf("Get returned %v (%T), want 3000 — once the backend-stale mark's bound has elapsed, replica A must serve the backend's current value", value, value)
	}
}

// TestR4_BackendStale_NonMonotonicNumeric_OlderLargerBackendDoesNotClobber
// guards the direction TestR4_BackendStale_CrossReplicaNewerValue_
// PrefersNewerBackend used to get backwards (R4 cache review round 2, minor,
// universal_cache.go:546): backendValueIsNewer's "larger number wins"
// comparison must apply ONLY to a MonotonicMarkers cache. On any other
// numeric cache, a larger backend value is not necessarily newer — here the
// backend holds an OLD but numerically LARGER value from before a fresh,
// smaller write times out. The gate must keep serving the fresh local write
// while the mark is still within backendStaleMarkTTL, exactly as it already
// does for a value type backendValueIsNewer cannot compare at all.
// Fail-on-old (pre-gate code): Get returns the backend's stale 100 instead
// of the fresh local 5, because backendValueIsNewer(100, 5) reports 100 as
// "newer" purely by numeric size.
func TestR4_BackendStale_NonMonotonicNumeric_OlderLargerBackendDoesNotClobber(t *testing.T) {
	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          logger,
		Type:            CacheTypeGeneral,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, shared)
	defer replicaA.Close()

	// Seed the backend with an old value that happens to be numerically
	// larger than the fresh write about to be made. This cache is not
	// MonotonicMarkers, so "larger" carries no meaning at all.
	if err := replicaA.Set("k1", int64(100), time.Minute); err != nil {
		t.Fatalf("seed Set returned error: %v", err)
	}

	// A fresh, smaller write times out. FIX-04 must keep 5 locally rather
	// than let Get resurrect the backend's stale (but larger) 100.
	shared.failOnce = context.DeadlineExceeded
	if err := replicaA.Set("k1", int64(5), time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	value, ok := replicaA.Get("k1")
	if !ok {
		t.Fatal("Get: key not found")
	}
	got, numeric := sessionInvalidationTime(value)
	if !numeric || got != 5 {
		t.Fatalf("Get returned %v (%T), want the fresh local write 5 — backendValueIsNewer's numeric \"larger wins\" comparison must not apply to a non-MonotonicMarkers cache", value, value)
	}
}

// TestR4_BackendStale_CrossReplicaNewerLogout_InvalidatesSession is the
// MonotonicMarkers counterpart against the real session-invalidation
// config and isSessionInvalidated (logout.go): replica A's own backchannel
// logout write fails with a non-timeout error (a MonotonicMarkers cache
// marks stale on ANY Set error, not only a timeout — see universal_cache.go
// Set), then replica B's logout for the same subject lands directly in the
// shared backend with a newer timestamp. A session created between the two
// timestamps must be reported invalidated once replica A reads that newer
// value.
// Fail-on-old: isSessionInvalidated returns false — replica A keeps its own
// older 2500 marker over the backend's newer 3000.
func TestR4_BackendStale_CrossReplicaNewerLogout_InvalidatesSession(t *testing.T) {
	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:           logger,
		Type:             CacheTypeSession,
		DefaultTTL:       25 * time.Hour,
		SkipAutoCleanup:  true,
		MonotonicMarkers: true,
	}, shared)
	defer replicaA.Close()

	oidc := &TraefikOidc{sessionInvalidationCache: &CacheInterfaceWrapper{cache: replicaA}, logger: logger}
	sub := "alice"
	key := oidc.buildSessionInvalidationKey("sub", sub)

	// Replica A's own logout write for alice is rejected outright (e.g. its
	// own circuit breaker is open) — not a timeout, but MonotonicMarkers
	// marks stale on any Set error.
	shared.failOnce = backends.ErrCircuitOpen
	if err := replicaA.Set(key, int64(2500), 25*time.Hour); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	// Replica B's later logout for the same subject lands directly in the
	// shared backend with a newer timestamp.
	data, err := replicaA.serialize(int64(3000))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := shared.Set(context.Background(), replicaA.prefixKey(key), data, 25*time.Hour); err != nil {
		t.Fatalf("simulated replica B write failed: %v", err)
	}

	createdAt := time.Unix(2800, 0) // between A's stale 2500 and B's newer 3000
	if !oidc.isSessionInvalidated("", sub, createdAt) {
		t.Fatal("a session created after replica A's failed logout but before replica B's newer logout must be invalidated once replica A observes B's write")
	}
}
