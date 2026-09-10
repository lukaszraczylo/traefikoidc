package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// TestRefreshCoordinatorShutdownReleasesWaiterOnInflight verifies that
// Shutdown does not hang while a refresh operation is in flight, and that the
// caller waiting on that operation gets an error rather than blocking
// forever.
//
// This test originally pinned the opposite contract (Shutdown blocks until
// the in-flight refresh finishes naturally), fixed for a goroutine-tracking
// bug where in-flight refresh goroutines were not tracked at all and
// Shutdown returned immediately with no wait and no error to the waiter.
// FIX-36 replaced that "wait for it" contract: Shutdown now cancels a
// coordinator-owned context so it returns promptly instead, and the waiter
// observes an error instead of a silently dropped goroutine. See
// refresh_coordinator.go's Shutdown and executeRefreshAsync comments.
func TestRefreshCoordinatorShutdownReleasesWaiterOnInflight(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.RefreshTimeout = 10 * time.Second
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
	go func() { rc.Shutdown(); close(shutDone) }()

	select {
	case <-shutDone:
	case <-time.After(1 * time.Second):
		t.Fatal("Shutdown did not return promptly while a refresh was still in flight")
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
