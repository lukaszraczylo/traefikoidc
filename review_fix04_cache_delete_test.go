package traefikoidc

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fix04Backend is a CacheBackend whose Set always stores the value (as Redis
// would even when the client gives up waiting for the reply) and can be told
// to report a failure back to the caller anyway. Delete is instrumented so
// tests can assert whether UniversalCache.Set called it.
type fix04Backend struct {
	m            map[string][]byte
	setErr       error
	deleteCalled bool
}

func (b *fix04Backend) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	b.m[k] = v
	return b.setErr
}
func (b *fix04Backend) Get(_ context.Context, k string) ([]byte, time.Duration, bool, error) {
	v, ok := b.m[k]
	return v, 0, ok, nil
}
func (b *fix04Backend) Delete(_ context.Context, k string) (bool, error) {
	b.deleteCalled = true
	delete(b.m, k)
	return true, nil
}
func (b *fix04Backend) Exists(_ context.Context, k string) (bool, error) {
	_, ok := b.m[k]
	return ok, nil
}
func (b *fix04Backend) Clear(_ context.Context) error {
	b.m = map[string][]byte{}
	return nil
}
func (b *fix04Backend) GetStats() map[string]interface{} { return nil }
func (b *fix04Backend) Close() error                     { return nil }
func (b *fix04Backend) Ping(_ context.Context) error     { return nil }

// TestFIX04_DeadlineExceededSetDoesNotDeleteAppliedWrite guards
// UniversalCache.Set (universal_cache.go): a backend Set that reports
// context.DeadlineExceeded after the write actually landed (a slow-but-
// applied Redis SET past the 500ms client deadline, see
// internal/cache/backends/redis.go executeWithRetry) must not trigger a
// Delete. The DEL would erase the value the SET just wrote, and on a
// blacklist/session-invalidation key that write is a revocation marker
// other replicas rely on (R162 follow-up).
// Fail-on-old: the key is gone from the backend after Set.
func TestFIX04_DeadlineExceededSetDoesNotDeleteAppliedWrite(t *testing.T) {
	fb := &fix04Backend{m: map[string][]byte{}, setErr: context.DeadlineExceeded}
	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          NewLogger("error"),
		Type:            CacheTypeToken,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, fb)
	defer uc.Close()

	if err := uc.Set("k1", "v1", time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if fb.deleteCalled {
		t.Fatal("Set must not Delete a backend entry after a context-deadline Set error")
	}
	if _, ok := fb.m["token:k1"]; !ok {
		t.Fatal("the applied write must remain in the backend after a deadline-exceeded Set")
	}
}

// TestFIX04_BlacklistSetFailureNeverDeletes guards the blacklist cache
// specifically: its values are monotonic revocation markers, so even a
// genuine (non-timeout) Set failure must never Delete a pre-existing marker
// for the same key.
// Fail-on-old: Delete is called for a plain backend error too.
func TestFIX04_BlacklistSetFailureNeverDeletes(t *testing.T) {
	fb := &fix04Backend{m: map[string][]byte{}, setErr: fmt.Errorf("backend down")}
	uc := NewUniversalCacheWithBackend(newBlacklistCacheConfig(NewLogger("error")), fb)

	if err := uc.Set("jti1", true, time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if fb.deleteCalled {
		t.Fatal("Set on the blacklist cache must never Delete an existing backend marker, even for a non-timeout Set error")
	}
}

// TestFIX04_NonMonotonicNonTimeoutSetFailureStillDeletes pins the existing
// R162 behavior for the general case: a genuine (non-timeout) Set failure
// on a plain (non-monotonic-marker) cache still evicts the stale backend
// entry so Get falls through to the fresh local value.
func TestFIX04_NonMonotonicNonTimeoutSetFailureStillDeletes(t *testing.T) {
	fb := &fix04Backend{m: map[string][]byte{}, setErr: fmt.Errorf("backend down")}
	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          NewLogger("error"),
		Type:            CacheTypeToken,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, fb)
	defer uc.Close()

	if err := uc.Set("k1", "v1", time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if !fb.deleteCalled {
		t.Fatal("a non-timeout Set failure on a plain cache must still Delete the stale backend entry (R162)")
	}
}

// fix04StaleBackend is a CacheBackend whose Set can be told to fail WITHOUT
// applying the write, modeling a client that gives up (context deadline, a
// pool-wait timeout, a dropped connection) before the backend ever executes
// the command. Whatever was already stored under the key is left in place.
// This is the counterpart to fix04Backend, whose Set always applies the
// write even when it reports an error.
type fix04StaleBackend struct {
	m        map[string][]byte
	failNext bool
	failErr  error
}

func (b *fix04StaleBackend) Set(_ context.Context, k string, v []byte, _ time.Duration) error {
	if b.failNext {
		return b.failErr
	}
	b.m[k] = v
	return nil
}
func (b *fix04StaleBackend) Get(_ context.Context, k string) ([]byte, time.Duration, bool, error) {
	v, ok := b.m[k]
	return v, 0, ok, nil
}
func (b *fix04StaleBackend) Delete(_ context.Context, k string) (bool, error) {
	_, ok := b.m[k]
	delete(b.m, k)
	return ok, nil
}
func (b *fix04StaleBackend) Exists(_ context.Context, k string) (bool, error) {
	_, ok := b.m[k]
	return ok, nil
}
func (b *fix04StaleBackend) Clear(_ context.Context) error {
	b.m = map[string][]byte{}
	return nil
}
func (b *fix04StaleBackend) GetStats() map[string]interface{} { return nil }
func (b *fix04StaleBackend) Close() error                     { return nil }
func (b *fix04StaleBackend) Ping(_ context.Context) error     { return nil }

// TestFIX04_TimeoutSetFailureServesFreshLocalNotStale guards Get()
// (universal_cache.go): when Set skips the post-failure Delete because the
// error is a context deadline/timeout, the backend still holds whatever
// OLDER value was there before (the SET may never have reached it). Get
// must not resurrect that stale backend value over the fresh local write
// Set just made — it must prefer the local value until the key's local
// entry expires or a later Set succeeds against the backend.
// Fail-on-old: Get returns the old backend value instead of the fresh one.
func TestFIX04_TimeoutSetFailureServesFreshLocalNotStale(t *testing.T) {
	backend := &fix04StaleBackend{m: map[string][]byte{}}
	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          NewLogger("error"),
		Type:            CacheTypeToken,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, backend)
	defer uc.Close()

	oldData, err := uc.serialize("old")
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	backend.m[uc.prefixKey("k1")] = oldData

	backend.failNext = true
	backend.failErr = context.DeadlineExceeded
	if err := uc.Set("k1", "fresh", time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	value, ok := uc.Get("k1")
	if !ok || value != "fresh" {
		t.Fatalf("Get returned (%v, %v), want fresh", value, ok)
	}
}

// TestFIX04_SessionInvalidationNewerLogoutDeadlineServesFreshLocal guards
// isSessionInvalidated (logout.go) against the MonotonicMarkers case: the
// session-invalidation cache stores Unix timestamps compared by value, so
// an OLDER timestamp left in the backend by a prior logout is genuinely
// stale once a NEWER logout's Set fails on a context deadline. A session
// created between the two logout timestamps must still be reported
// invalidated, using the fresher local write rather than the stale backend
// value.
// Fail-on-old: isSessionInvalidated returns false for a session created
// between the two logout timestamps.
func TestFIX04_SessionInvalidationNewerLogoutDeadlineServesFreshLocal(t *testing.T) {
	backend := &fix04StaleBackend{m: map[string][]byte{}}
	logger := NewLogger("error")
	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:           logger,
		Type:             CacheTypeSession,
		DefaultTTL:       25 * time.Hour,
		SkipAutoCleanup:  true,
		MonotonicMarkers: true,
	}, backend)
	defer uc.Close()

	oidc := &TraefikOidc{sessionInvalidationCache: &CacheInterfaceWrapper{cache: uc}, logger: logger}
	sid := "sess-1"
	key := oidc.buildSessionInvalidationKey("sid", sid)

	// An older logout already landed in the backend.
	oldData, err := uc.serialize(int64(1000))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	backend.m[uc.prefixKey(key)] = oldData

	// A newer logout whose backend write never applies.
	backend.failNext = true
	backend.failErr = context.DeadlineExceeded
	if err := uc.Set(key, int64(2000), 25*time.Hour); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	createdAt := time.Unix(1500, 0)
	if !oidc.isSessionInvalidated(sid, "", createdAt) {
		t.Fatal("session created at 1500 not invalidated after logout at 2000; cache returned old 1000")
	}
}

// TestFIX04_SessionInvalidationNewerLogoutErrorReplyServesFreshLocal is the
// TestFIX04_SessionInvalidationNewerLogoutDeadlineServesFreshLocal
// counterpart for a plain (non-timeout) backend error, for example a Redis
// error reply. MonotonicMarkers skips the Delete for any error on this
// cache, not only a timeout, so the same staleness must be guarded for a
// non-timeout failure too.
// Fail-on-old: isSessionInvalidated returns false for a session created
// between the two logout timestamps.
func TestFIX04_SessionInvalidationNewerLogoutErrorReplyServesFreshLocal(t *testing.T) {
	backend := &fix04StaleBackend{m: map[string][]byte{}}
	logger := NewLogger("error")
	uc := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:           logger,
		Type:             CacheTypeSession,
		DefaultTTL:       25 * time.Hour,
		SkipAutoCleanup:  true,
		MonotonicMarkers: true,
	}, backend)
	defer uc.Close()

	oidc := &TraefikOidc{sessionInvalidationCache: &CacheInterfaceWrapper{cache: uc}, logger: logger}
	sid := "sess-2"
	key := oidc.buildSessionInvalidationKey("sid", sid)

	oldData, err := uc.serialize(int64(1000))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	backend.m[uc.prefixKey(key)] = oldData

	backend.failNext = true
	backend.failErr = fmt.Errorf("redis command error reply: OOM command not allowed")
	if err := uc.Set(key, int64(2000), 25*time.Hour); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	createdAt := time.Unix(1500, 0)
	if !oidc.isSessionInvalidated(sid, "", createdAt) {
		t.Fatal("session created at 1500 not invalidated after logout at 2000; cache returned old 1000")
	}
}
