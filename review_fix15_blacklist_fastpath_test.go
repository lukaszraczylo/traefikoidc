package traefikoidc

import (
	"testing"
	"time"
)

// assertFastRLockPath probes whether UniversalCache.getLocal takes the
// RLock fast path or the exclusive-Lock slow path for cache type ct. The
// test goroutine holds c.mu.RLock() itself; a concurrent Get on the fast
// path (also c.mu.RLock()) completes immediately alongside it, while a Get
// on the slow path (c.mu.Lock()) blocks until the held RLock is released,
// since Go's RWMutex never lets a Lock() proceed while any RLock is held.
func assertFastRLockPath(t *testing.T, ct CacheType, wantFast bool) {
	t.Helper()

	c := NewUniversalCache(UniversalCacheConfig{
		Type:       ct,
		MaxSize:    100,
		DefaultTTL: time.Minute,
		Logger:     NewLogger("error"),
	})
	defer c.Close()

	if err := c.SetLocal("k", "v", time.Minute); err != nil {
		t.Fatalf("SetLocal: %v", err)
	}

	c.mu.RLock()

	getDone := make(chan struct{})
	go func() {
		c.Get("k")
		close(getDone)
	}()

	completedWhileRLocked := false
	select {
	case <-getDone:
		completedWhileRLocked = true
	case <-time.After(150 * time.Millisecond):
		completedWhileRLocked = false
	}

	c.mu.RUnlock()

	// Whether or not it raced ahead of our RLock, let the goroutine finish
	// before returning so nothing leaks into the next subtest.
	if !completedWhileRLocked {
		<-getDone
	}

	if completedWhileRLocked != wantFast {
		if wantFast {
			t.Fatalf("cache type %s: Get blocked behind a held RLock; getLocal is not using the RLock fast path", ct)
		}
		t.Fatalf("cache type %s: Get completed while a concurrent RLock was held; expected it to serialize behind the exclusive Lock path", ct)
	}
}

// TestFIX15_FastPathCacheTypesTable pins getLocal's RLock fast-path case
// list (universal_cache.go). The blacklist cache moved from CacheTypeToken
// to CacheTypeBlacklist (universal_cache_singleton.go), but the fast path
// was extended only with CacheTypeIntrospection, so every blacklist lookup
// fell to the exclusive c.mu.Lock() — the same convoy pattern (a single
// expired entry serializing every concurrent JWT verify under yaegi) the
// fast path was built to avoid for token/JWK/session lookups.
// Fail-on-old: the CacheTypeBlacklist subtest blocks instead of completing.
func TestFIX15_FastPathCacheTypesTable(t *testing.T) {
	fastPathTypes := []CacheType{
		CacheTypeToken,
		CacheTypeJWK,
		CacheTypeSession,
		CacheTypeIntrospection,
		CacheTypeBlacklist,
	}
	slowPathTypes := []CacheType{
		CacheTypeMetadata,
		CacheTypeGeneral,
	}

	for _, ct := range fastPathTypes {
		ct := ct
		t.Run(string(ct)+"_fast_path", func(t *testing.T) {
			assertFastRLockPath(t, ct, true)
		})
	}
	for _, ct := range slowPathTypes {
		ct := ct
		t.Run(string(ct)+"_slow_path", func(t *testing.T) {
			assertFastRLockPath(t, ct, false)
		})
	}
}

// TestFIX15_ConcurrentBlacklistGetsDoNotSerialize is a direct pin: two
// concurrent Get calls on a CacheTypeBlacklist cache must both complete
// promptly instead of queuing behind one exclusive lock.
// Fail-on-old: the second Get does not complete within the deadline.
func TestFIX15_ConcurrentBlacklistGetsDoNotSerialize(t *testing.T) {
	c := NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeBlacklist,
		MaxSize:    100,
		DefaultTTL: time.Minute,
		Logger:     NewLogger("error"),
	})
	defer c.Close()

	if err := c.SetLocal("jti1", true, time.Minute); err != nil {
		t.Fatalf("SetLocal: %v", err)
	}
	if err := c.SetLocal("jti2", true, time.Minute); err != nil {
		t.Fatalf("SetLocal: %v", err)
	}

	const readers = 2
	done := make(chan struct{}, readers)

	c.mu.RLock()
	go func() { c.Get("jti1"); done <- struct{}{} }()
	go func() { c.Get("jti2"); done <- struct{}{} }()

	timeout := time.After(200 * time.Millisecond)
	completed := 0
	for completed < readers {
		select {
		case <-done:
			completed++
		case <-timeout:
			c.mu.RUnlock()
			t.Fatalf("only %d/%d concurrent blacklist Gets completed while a reader held c.mu.RLock(); they are serializing on the exclusive lock", completed, readers)
		}
	}
	c.mu.RUnlock()
}
