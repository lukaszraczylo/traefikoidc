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
		Logger:     NewLogger("error"),
		Type:       CacheTypeToken,
		DefaultTTL: time.Minute,
	}, fb)

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
		Logger:     NewLogger("error"),
		Type:       CacheTypeToken,
		DefaultTTL: time.Minute,
	}, fb)

	if err := uc.Set("k1", "v1", time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if !fb.deleteCalled {
		t.Fatal("a non-timeout Set failure on a plain cache must still Delete the stale backend entry (R162)")
	}
}
