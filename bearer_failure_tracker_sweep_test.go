package traefikoidc

import (
	"fmt"
	"testing"
	"time"
)

// FIX-28 regression tests.
//
// R117's map-growth sweep in recordFailure deleted every entry whose
// penaltyUntil was before the cutoff. An entry that has not tripped the
// penalty box yet has a ZERO penaltyUntil, which is always before any
// cutoff — so once the map passed defaultBearerEntrySweepThreshold, every
// accumulating (not-yet-tripped) counter was discarded regardless of how
// recently it started, no matter how recent firstFailureAt was. A source
// whose failures interleave with sweeps could never reach the threshold.

// TestBearerFailureTracker_SweepDoesNotDiscardFreshCounters guards the
// exact scenario from the finding: threshold 3, 2 failures for a target
// IP, then 1025 other IPs failing once each (crossing the sweep
// threshold), then a 3rd failure for the target IP. The target's count
// must survive the sweep and trip the penalty box.
// Fail-on-old: the sweep discards the target's in-progress counter, so the
// 3rd failure restarts it at count=1 and blocked() reports false.
func TestBearerFailureTracker_SweepDoesNotDiscardFreshCounters(t *testing.T) {
	b := newBearerFailureTracker(3, 60*time.Second, 60*time.Second)

	b.recordFailure("target-ip")
	b.recordFailure("target-ip")

	// Push the map past defaultBearerEntrySweepThreshold with distinct,
	// equally-fresh IPs so recordFailure's sweep branch runs.
	for i := 0; i < defaultBearerEntrySweepThreshold+1; i++ {
		b.recordFailure(fmt.Sprintf("other-ip-%d", i))
	}

	b.recordFailure("target-ip")

	blocked, _ := b.blocked("target-ip")
	if !blocked {
		t.Fatal("a source whose failures are recent (within the window) must not lose its count to the map-growth sweep, and must trip the penalty box on its 3rd failure")
	}
}

// TestBearerFailureTracker_SweepRemovesTrulyStaleEntries is the positive
// control: an entry that is BOTH untripped AND outside the window (a
// source that failed once, long ago, and never returned) must still be
// swept once the map grows past the threshold — otherwise the fix would
// defeat the sweep's original memory-bound purpose entirely.
func TestBearerFailureTracker_SweepRemovesTrulyStaleEntries(t *testing.T) {
	b := newBearerFailureTracker(20, 60*time.Second, 60*time.Second)

	b.mu.Lock()
	b.entries["stale-ip"] = &bearerFailureEntry{
		firstFailureAt: time.Now().Add(-time.Hour), // well outside the 60s window
		count:          1,
		// penaltyUntil left zero: never tripped.
	}
	b.mu.Unlock()

	for i := 0; i < defaultBearerEntrySweepThreshold+1; i++ {
		b.recordFailure(fmt.Sprintf("filler-ip-%d", i))
	}

	b.mu.Lock()
	_, stillPresent := b.entries["stale-ip"]
	b.mu.Unlock()
	if stillPresent {
		t.Fatal("an untripped entry whose firstFailureAt is outside the window must still be swept once the map grows past the threshold")
	}
}
