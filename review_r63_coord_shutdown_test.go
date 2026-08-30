package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// TestRefreshCoordinatorShutdownWaitsForInflight verifies that Shutdown waits
// for in-flight refresh operations to finish before returning. Previously
// in-flight refresh goroutines were not tracked, so Shutdown returned
// immediately while a refresh was still running — leaking the goroutine and
// letting it continue using resources after the coordinator was torn down
// (e.g. during Traefik plugin reload).
func TestRefreshCoordinatorShutdownWaitsForInflight(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.RefreshTimeout = 10 * time.Second
	rc := NewRefreshCoordinator(cfg, logger)

	started := make(chan struct{})
	release := make(chan struct{})

	go func() {
		_, _ = rc.CoordinateRefresh(context.Background(), "s1", "rt1", func() (*TokenResponse, error) {
			close(started)
			<-release
			return &TokenResponse{}, nil
		})
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh never started")
	}

	shutDone := make(chan struct{})
	go func() { rc.Shutdown(); close(shutDone) }()

	// Shutdown must NOT return while a refresh is still in flight (old
	// behavior returned immediately, dropping the in-flight goroutine).
	select {
	case <-shutDone:
		t.Fatal("Shutdown returned while a refresh was still in flight")
	case <-time.After(300 * time.Millisecond):
	}

	close(release)

	select {
	case <-shutDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after the in-flight refresh completed")
	}
	_ = logger
}
