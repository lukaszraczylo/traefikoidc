package traefikoidc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefreshCoordinatorShutdownReleasesWaiterOnInflight verifies that
// Shutdown does not hang forever while a refresh operation is in flight, and
// that the caller waiting on an operation Shutdown gives up on gets an error
// rather than blocking forever.
//
// This test originally pinned the "Shutdown blocks until the in-flight
// refresh finishes naturally" contract, fixed for a goroutine-tracking bug
// where in-flight refresh goroutines were not tracked at all and Shutdown
// returned immediately with no wait and no error to the waiter. FIX-36 then
// replaced that with "Shutdown cancels immediately, waiter always gets an
// error". DECIDED follow-up: canceling immediately discarded a refresh the
// IdP had already completed, losing its (possibly one-time-use, rotated)
// tokens. Shutdown now waits up to shutdownRefreshDrainTimeout for an
// in-flight refresh to finish naturally before giving up — this test's
// refreshFunc never releases on its own, so it still exercises the
// "Shutdown eventually gives up and the waiter gets an error" path, just
// bounded by the drain cap instead of returning immediately. See
// refresh_coordinator.go's Shutdown and executeRefreshAsync comments.
func TestRefreshCoordinatorShutdownReleasesWaiterOnInflight(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.RefreshTimeout = shutdownRefreshDrainTimeout + 10*time.Second // keep RefreshTimeout out of the way; only the drain cap should bound Shutdown
	rc := NewRefreshCoordinator(cfg, logger)

	started := make(chan struct{})
	release := make(chan struct{})
	waiterErrCh := make(chan error, 1)

	go func() {
		_, err := rc.CoordinateRefresh(context.Background(), "s1", "rt1", func() (*TokenResponse, error) {
			close(started)
			<-release
			return &TokenResponse{}, nil
		})
		waiterErrCh <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh never started")
	}
	defer close(release) // let the leaked refreshFunc goroutine finish

	shutDone := make(chan struct{})
	shutdownStart := time.Now()
	go func() { rc.Shutdown(); close(shutDone) }()

	select {
	case <-shutDone:
	case <-time.After(shutdownRefreshDrainTimeout + 2*time.Second):
		t.Fatal("Shutdown did not return after the shutdown drain cap elapsed")
	}
	if elapsed := time.Since(shutdownStart); elapsed < shutdownRefreshDrainTimeout {
		t.Fatalf("Shutdown returned after %v, want at least the %v drain cap since the refresh never completed on its own", elapsed, shutdownRefreshDrainTimeout)
	}

	// R63/R154 wg tracking: Shutdown's wg.Wait must not return before the
	// tracked executeRefreshAsync goroutine has recorded the aborted outcome.
	if got := atomic.LoadInt32(&rc.circuitBreaker.failures); got != 1 {
		t.Fatalf("Shutdown returned before the tracked refresh goroutine finished: circuit-breaker failures=%d, want 1", got)
	}

	select {
	case err := <-waiterErrCh:
		if err == nil {
			t.Fatal("waiter of an operation aborted by Shutdown must get an error, not a nil result")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("waiter did not get a result within 1s of Shutdown returning — looks like a hang")
	}
	_ = logger
}
