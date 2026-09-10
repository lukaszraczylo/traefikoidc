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
// Get() (universal_cache.go, around the backendStaleLocalValue branch): once
// a plain (non-MonotonicMarkers) cache's Set fails on a context deadline —
// FIX-04's original case, "the write may have landed" — and a DIFFERENT
// replica then writes a genuinely NEWER value to the shared backend, Get
// must serve that newer backend value, not keep pinning the older local one
// forever.
// Fail-on-old: Get returns the local 2000 instead of the backend's 3000.
func TestR4_BackendStale_CrossReplicaNewerValue_PrefersNewerBackend(t *testing.T) {
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
	// a newer value.
	data, err := replicaA.serialize(int64(3000))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := shared.Set(context.Background(), replicaA.prefixKey("k1"), data, time.Minute); err != nil {
		t.Fatalf("simulated replica B write failed: %v", err)
	}

	value, ok := replicaA.Get("k1")
	if !ok {
		t.Fatal("Get: key not found")
	}
	got, numeric := sessionInvalidationTime(value)
	if !numeric || got != 3000 {
		t.Fatalf("Get returned %v (%T), want 3000 — replica A must not keep serving its own older local value once the backend holds a genuinely newer one written by another replica", value, value)
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
