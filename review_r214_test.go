package traefikoidc

import (
	"fmt"
	"testing"
	"time"
)

// TestBearerFailureTrackerSweepBoundsMemory guards the R117 sweep: under a
// flood of distinct source IPs (each failing once and never returning), the
// tracker must not grow unboundedly. The sweep runs when the map exceeds
// defaultBearerEntrySweepThreshold and drops stale entries, keeping memory
// bounded. A tracker without the sweep would reach ~N entries.
func TestBearerFailureTrackerSweepBoundsMemory(t *testing.T) {
	bt := newBearerFailureTracker(20, time.Minute, time.Minute)

	const n = 5000
	for i := 0; i < n; i++ {
		bt.recordFailure(fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256))
	}

	bt.mu.Lock()
	size := len(bt.entries)
	bt.mu.Unlock()

	t.Logf("bearer tracker map size after %d distinct sources: %d", n, size)
	// The sweep keeps the map bounded well below the raw source count;
	// without it the map would hold ~n entries.
	if size >= n {
		t.Fatalf("bearer failure tracker grew to %d entries (one per source); sweep must bound it (n=%d)", size, n)
	}
	if size > defaultBearerEntrySweepThreshold+16 {
		t.Fatalf("bearer failure tracker map size %d exceeds sweep bound %d+slack", size, defaultBearerEntrySweepThreshold)
	}
}
