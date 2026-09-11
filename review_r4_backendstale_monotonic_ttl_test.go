package traefikoidc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// r4MonoAsInt64 normalizes a cached numeric marker, which is int64 when it
// comes from the local store and float64 when it is decoded from the backend.
func r4MonoAsInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	}
	return 0, false
}

// TestR4_BackendStale_MonotonicMarker_SurvivesMarkTTL pins the round-4
// re-verification fix. The backendStaleMarkTTL bound must not expire the
// backend-stale mark of a MonotonicMarkers cache (session invalidation).
// Redis holds an older marker (1000) and rejects the newer one (2000) with a
// definitive error reply. After the mark TTL the replica must still enforce
// its own newer marker, not fall back to the older backend value. A newer
// marker that another replica writes must still win.
func TestR4_BackendStale_MonotonicMarker_SurvivesMarkTTL(t *testing.T) {
	orig := backendStaleMarkTTL
	backendStaleMarkTTL = 50 * time.Millisecond
	t.Cleanup(func() { backendStaleMarkTTL = orig })

	shared := &r4SharedBackend{m: map[string][]byte{}}
	replica := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:           NewLogger("error"),
		Type:             CacheTypeSession,
		DefaultTTL:       time.Minute,
		MonotonicMarkers: true,
		SkipAutoCleanup:  true,
	}, shared)
	defer replica.Close()

	seed := func(v int64) {
		t.Helper()
		data, err := replica.serialize(v)
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		if err := shared.Set(context.Background(), replica.prefixKey("sid-1"), data, time.Minute); err != nil {
			t.Fatalf("backend write: %v", err)
		}
	}
	want := func(when string, expected int64) {
		t.Helper()
		v, ok := replica.Get("sid-1")
		got, numeric := r4MonoAsInt64(v)
		if !ok || !numeric || got != expected {
			t.Fatalf("%s: Get = %v (%T, ok=%v), want %d", when, v, v, ok, expected)
		}
	}

	seed(1000)
	shared.failOnce = errors.New("READONLY You can't write against a read only replica")
	if err := replica.Set("sid-1", int64(2000), time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}
	want("right after the rejected write", 2000)

	time.Sleep(backendStaleMarkTTL + 150*time.Millisecond)
	want("after backendStaleMarkTTL elapsed", 2000)

	seed(3000)
	want("after another replica wrote a newer marker", 3000)
}
