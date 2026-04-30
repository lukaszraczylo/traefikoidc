//go:build !yaegi

package backends

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHybridBackend_L1BackfillBounded verifies that a burst of L2 hits does
// not detonate the goroutine count. Pre-fix the code spawned one goroutine
// per Get() L2 hit; post-fix all backfills funnel through a single worker.
func TestHybridBackend_L1BackfillBounded(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         primary,
		Secondary:       secondary,
		AsyncBufferSize: 256,
	})
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	const burst = 1000

	// Pre-populate L2 with `burst` distinct keys so each Get triggers a
	// fresh L1 backfill enqueue.
	for i := 0; i < burst; i++ {
		require.NoError(t, secondary.Set(ctx, fmt.Sprintf("k:%d", i), []byte("v"), time.Minute))
	}

	baseline := runtime.NumGoroutine()

	// Issue the burst as fast as possible; the backfill worker MUST be the
	// only goroutine doing L1 writes. Allow brief slack for the test runtime
	// scheduling but anything north of +20 means goroutine leakage.
	peak := baseline
	for i := 0; i < burst; i++ {
		_, _, exists, err := hybrid.Get(ctx, fmt.Sprintf("k:%d", i))
		require.NoError(t, err)
		require.True(t, exists)
		if g := runtime.NumGoroutine(); g > peak {
			peak = g
		}
	}

	delta := peak - baseline
	if delta > 20 {
		t.Fatalf("goroutine count grew by %d during burst (baseline=%d peak=%d); backfill worker not bounding goroutines",
			delta, baseline, peak)
	}

	// L1 must eventually catch up via the worker. Worker drains serially so
	// give it a generous window proportional to the burst size.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var populated int
		for i := 0; i < burst; i++ {
			if _, _, ok, _ := primary.Get(ctx, fmt.Sprintf("k:%d", i)); ok {
				populated++
			}
		}
		// Be lenient: drops are acceptable under buffer pressure, just want
		// most of the keys to make it.
		if populated >= burst-int(hybrid.l1BackfillDrops.Load()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("L1 not backfilled within deadline: l2Hits=%d l1Writes=%d drops=%d",
		hybrid.l2Hits.Load(), hybrid.l1Writes.Load(), hybrid.l1BackfillDrops.Load())
}

// TestHybridBackend_L1BackfillFullDrops verifies the drop semantics when the
// buffer is saturated. Drops must be counted, never block, never spawn a
// goroutine.
func TestHybridBackend_L1BackfillFullDrops(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	// Tiny buffer + slow primary writes via failSet so the worker stays
	// blocked enough to overflow the buffer.
	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         primary,
		Secondary:       secondary,
		AsyncBufferSize: 4,
	})
	require.NoError(t, err)
	defer hybrid.Close()

	// Stop the worker from draining: cancel the underlying context so the
	// worker bails out, leaving us with a cold buffer and the queue method
	// itself responsible for drop accounting.
	hybrid.cancel()
	// Wait for worker to exit so it can't drain.
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 50; i++ {
		hybrid.queueL1Backfill(fmt.Sprintf("k:%d", i), []byte("v"), time.Minute)
	}

	assert.Greater(t, hybrid.l1BackfillDrops.Load(), int64(0),
		"expected some drops when buffer is saturated and worker is stopped")
}
