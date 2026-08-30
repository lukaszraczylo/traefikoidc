package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestR185_PerSourceLimiterSweepEvictsIdle guards the memory-bounding of the
// per-source limiter (R185): entries for sources that stop returning must
// be evicted by the sweep, otherwise an attacker rotating spoofed
// X-Forwarded-For values would grow the map unboundedly. Forces the sweep
// (lastSweep in the past) and asserts an idle-over-threshold entry is gone.
func TestR185_PerSourceLimiterSweepEvictsIdle(t *testing.T) {
	l := newPerSourceAuthLimiter(100)

	// Register two external sources.
	if !l.allow(httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("first request should be allowed")
	}
	// (override) second source via direct allow with a different XFF.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("X-Forwarded-For", "9.9.9.9")
	if !l.allow(r2) {
		t.Fatal("second source should be allowed")
	}

	l.mu.Lock()
	// Age both entries far past the idle eviction threshold and push the
	// last sweep back so the next allow() triggers a sweep.
	now := time.Now()
	for _, e := range l.entries {
		e.lastSeen = now.Add(-15 * time.Minute)
	}
	l.lastSweep = now.Add(-2 * time.Minute)
	l.mu.Unlock()

	// Trigger the sweep directly (the public allow() path would also
	// re-register the triggering source, which is correct but obscures the
	// eviction-under-test).
	l.mu.Lock()
	l.sweep(now.Add(1 * time.Minute)) // a "now" past the -15m entry ages
	left := len(l.entries)
	l.mu.Unlock()
	if left != 0 {
		t.Fatalf("sweep must evict idle entries; %d remain (potential unbounded memory growth)", left)
	}

	// A source that returns (re-)registers and is throttled fresh, not
	// carried over from before the sweep.
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.Header.Set("X-Forwarded-For", "9.9.9.9")
	_ = l.allow(r3)
	l.mu.Lock()
	hasNew := false
	for ip := range l.entries {
		if ip == "9.9.9.9" {
			hasNew = true
		}
	}
	l.mu.Unlock()
	if !hasNew {
		t.Fatal("a returning source must be re-registered after eviction")
	}
}
