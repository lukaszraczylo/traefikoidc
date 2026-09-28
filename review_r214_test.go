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
	staleKeys := make([]string, 0, len(bt.entries))
	for k, e := range bt.entries {
		e.firstFailureAt = past
		staleKeys = append(staleKeys, k)
	}
	nextSweepAt := bt.nextSweepAt
	sweepsBefore := bt.sweepPasses
	bt.mu.Unlock()

	// The sweep is now amortized (FIX-28): it only runs once len(entries)
	// crosses bt.nextSweepAt, not on every call past the static threshold.
	// Record fresh, distinct failures until that next sweep actually fires
	// (sweepPasses advances), then assert the aged (stale) keys captured
	// above are gone. Do NOT assert a total-size bound here — a fresh flood
	// legitimately grows the map past defaultBearerEntrySweepThreshold+16
	// while it accumulates toward the next amortized sweep point; that
	// growth is expected, not a regression (see the freshSize assertion
	// above).
	for i := 0; ; i++ {
		bt.recordFailure(fmt.Sprintf("phase2-filler-%d", i))
		bt.mu.Lock()
		triggered := bt.sweepPasses > sweepsBefore
		bt.mu.Unlock()
		if triggered {
			break
		}
		if i > 4*nextSweepAt {
			t.Fatalf("sweep did not trigger after %d additional fresh failures (nextSweepAt=%d)", i, nextSweepAt)
		}
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()
	for _, k := range staleKeys {
		if _, present := bt.entries[k]; present {
			t.Fatalf("stale entry %q (aged past the window before the amortized sweep triggered) must be gone once the next sweep fires", k)
		}
	}
}

// TestBearerFailureTrackerSweepAmortized guards the FIX-28 amortization: the
// static `len > defaultBearerEntrySweepThreshold` gate made recordFailure
// re-scan the ENTIRE map on every call once the map crossed 1024 entries,
// turning a flood of distinct attacker-controlled source IPs into O(n^2)
// work (and, combined with the FIX-28 predicate fix, a full scan that
// deletes nothing). nextSweepAt doubles after each sweep
// (max(defaultBearerEntrySweepThreshold, 2*len(entries))), so the number of
// full-map scans grows only logarithmically with the flood size. At HEAD
// (before this amortization), 30,000 fresh distinct sources trigger a sweep
// on very nearly all ~29,000 calls above the threshold.
func TestBearerFailureTrackerSweepAmortized(t *testing.T) {
	bt := newBearerFailureTracker(20, time.Minute, time.Minute)

	const n = 30000
	for i := 0; i < n; i++ {
		bt.recordFailure(fmt.Sprintf("172.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256))
	}

	bt.mu.Lock()
	sweeps := bt.sweepPasses
	size := len(bt.entries)
	bt.mu.Unlock()

	t.Logf("bearer tracker: %d fresh distinct sources triggered %d full-map sweep passes (map size=%d)", n, sweeps, size)
	if size != n {
		t.Fatalf("every fresh distinct source must be retained, got size=%d want=%d", size, n)
	}
	if sweeps > 6 {
		t.Fatalf("recording %d fresh distinct sources triggered %d full-map sweep passes, want <= 6 with amortized doubling (FIX-28); HEAD (static per-call threshold) triggers roughly one sweep per call above the threshold (~%d)", n, sweeps, n-defaultBearerEntrySweepThreshold)
	}
}
