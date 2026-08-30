package traefikoidc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestGoroutinePoolShutdownDrainsQueuedTasks verifies that a graceful Shutdown
// runs every already-submitted task and lets Wait() return. Previously a
// worker that randomly chose the closed shutdownChan over a ready task exited,
// leaving buffered tasks silently dropped and their pendingTasks count never
// decremented, so Wait() blocked forever.
func TestGoroutinePoolShutdownDrainsQueuedTasks(t *testing.T) {
	const iterations = 15
	for it := 0; it < iterations; it++ {
		pool := NewGoroutinePool(1, NewLogger(DefaultLogLevel))

		var ran int32
		gate := make(chan struct{})

		if err := pool.Submit(func() { <-gate }); err != nil { // occupies the worker
			t.Fatalf("iter %d: submit block failed: %v", it, err)
		}
		if err := pool.Submit(func() { atomic.AddInt32(&ran, 1) }); err != nil {
			t.Fatalf("iter %d: submit counted task failed: %v", it, err)
		}

		done := make(chan struct{})
		go func() {
			_ = pool.Shutdown(context.Background())
			close(done)
		}()
		// Release the blocking task after shutdown is signaled.
		go func() {
			time.Sleep(5 * time.Millisecond)
			close(gate)
		}()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("iter %d: Shutdown did not return", it)
		}

		if atomic.LoadInt32(&ran) != 1 {
			t.Fatalf("iter %d: queued task %d was dropped on shutdown (want 1)", it, atomic.LoadInt32(&ran))
		}

		// Wait() must return now that every counted task completed.
		waitCh := make(chan struct{})
		go func() { pool.Wait(); close(waitCh) }()
		select {
		case <-waitCh:
		case <-time.After(1 * time.Second):
			t.Fatalf("iter %d: Wait() blocked after shutdown (pending task never ran)", it)
		}
	}
}
