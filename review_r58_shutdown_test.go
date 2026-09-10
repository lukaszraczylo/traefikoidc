package traefikoidc

import (
	"testing"
	"time"
)

// TestRefreshCoordinatorShutdownIdempotent guards against a panic when the
// coordinator is shut down more than once. Close() on the same
// Authenticator can be reached via both the plugin-context cancellation hook
// (main.go) and the resource-manager teardown path, so RefreshCoordinator
// Shutdown must tolerate repeated calls — the previous close(rc.stopChan)
// panicked with 'close of closed channel' on the second call.
func TestRefreshCoordinatorShutdownIdempotent(t *testing.T) {
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), NewLogger(DefaultLogLevel))
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Shutdown panicked: %v", r)
		}
	}()
	rc.Shutdown()
	rc.Shutdown()
}

// TestRefreshCoordinatorShutdownStopsCleanup ensures the cleanup goroutine is
// running before shutdown completes so the shutdown path is actually
// exercised (stopChan close) and wg drained.
//
// FIX-23: the original version of this test called Shutdown() with no
// assertion at all, so it passed on base regardless of whether Shutdown
// actually stopped the cleanup goroutine — only the sibling
// TestRefreshCoordinatorShutdownIdempotent's panic recovery caught anything.
// This version asserts Shutdown returns within a bounded deadline, and
// separately observes the cleanup goroutine's exit via rc.wg (the same
// WaitGroup Shutdown's own wg.Wait() depends on). If cleanupRoutine's stop
// signal (case <-rc.stopChan: return) were ever removed, the goroutine would
// loop forever, wg.Done() would never fire, and both waits below would time
// out instead of completing.
func TestRefreshCoordinatorShutdownStopsCleanup(t *testing.T) {
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), NewLogger(DefaultLogLevel))
	// Let the cleanup goroutine actually start running its select loop
	// before Shutdown races it.
	time.Sleep(50 * time.Millisecond)

	shutdownDone := make(chan struct{})
	go func() {
		rc.Shutdown()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return within the deadline — the cleanup goroutine did not exit (stop signal missing?)")
	}

	// Independently observe the cleanup goroutine's exit: rc.wg.Add(1)/Done()
	// bracket exactly cleanupRoutine (see NewRefreshCoordinator), so a wait
	// on it that returns immediately proves the goroutine is gone, not
	// merely inferred from Shutdown's own black-box return above.
	wgDone := make(chan struct{})
	go func() {
		rc.wg.Wait()
		close(wgDone)
	}()
	select {
	case <-wgDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("cleanup goroutine's WaitGroup entry was not released after Shutdown returned")
	}
}
