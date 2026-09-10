package traefikoidc

import (
	"fmt"
	"testing"
	"time"
)

// TestBearerFailureTrackerSweepBoundsMemory guards the R117 sweep, as
// refined by FIX-28: under a flood of distinct source IPs, the tracker's
// memory is bounded once entries age past the counting window — not
// instantly at the threshold. FIX-28 found that sweeping ANY untripped
// entry once the map crossed the threshold (ignoring how recently it
// started) let an attacker flood many other source IPs to force a sweep
// that discarded every OTHER source's genuinely in-progress, still-fresh
// counter, resetting them before they could ever trip. So a fresh flood
// within the window is now expected to grow past the threshold — that is
// the fix, not a regression — while entries that age past the window still
// get swept, which this test verifies in a second phase.
func TestBearerFailureTrackerSweepBoundsMemory(t *testing.T) {
	bt := newBearerFailureTracker(20, time.Minute, time.Minute)

	const n = 5000
	for i := 0; i < n; i++ {
		bt.recordFailure(fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256))
	}

	bt.mu.Lock()
	freshSize := len(bt.entries)
	bt.mu.Unlock()
	t.Logf("bearer tracker map size after %d fresh distinct sources: %d", n, freshSize)
	if freshSize != n {
		t.Fatalf("a flood of fresh (within-window) sources must NOT be swept — that would let an attacker evict other sources' in-progress counters (FIX-28); got size=%d, want=%d", freshSize, n)
	}

	// Age every existing entry past the counting window, simulating time
	// passing with no further failures from any of these sources.
	bt.mu.Lock()
	past := time.Now().Add(-2 * time.Minute)
	for _, e := range bt.entries {
		e.firstFailureAt = past
	}
	bt.mu.Unlock()

	// One more failure re-triggers the sweep branch (map size still above
	// the threshold); every now-stale entry above must be dropped.
	bt.recordFailure("trigger-sweep")

	bt.mu.Lock()
	agedSize := len(bt.entries)
	bt.mu.Unlock()
	t.Logf("bearer tracker map size after aging past the window: %d", agedSize)
	if agedSize > defaultBearerEntrySweepThreshold+16 {
		t.Fatalf("bearer failure tracker map size %d exceeds sweep bound %d+slack once entries age past the window", agedSize, defaultBearerEntrySweepThreshold)
	}
}
