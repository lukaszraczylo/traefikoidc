package traefikoidc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRefreshCoordinator_SingleCircuitBreakerRecordPerOperation guards the
// fix that moves circuit-breaker / per-session recording into
// executeRefreshAsync so it runs exactly once per refresh OPERATION.
//
// Regression: CoordinateRefresh previously recorded cb.RecordFailure and
// recordRefreshFailure once per WAITER. When N requests coalesced onto a
// single failing refresh operation, one upstream failure was written as N
// failures — over-triggering the circuit breaker (MaxFailures=3) from a
// single provider error.
func TestRefreshCoordinator_SingleCircuitBreakerRecordPerOperation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxRefreshAttempts = 1000 // keep cooldown out of the way
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	const waiters = 4 // >= MaxFailures(3): enough to over-trigger the old behavior

	// One shared failing refresh operation.
	var upstreamCalls int32
	failingRefresh := func() (*TokenResponse, error) {
		atomic.AddInt32(&upstreamCalls, 1)
		return nil, errors.New("provider_down")
	}

	sameToken := "shared_rotating_token"
	sameSession := "shared_session"

	var wg sync.WaitGroup
	wg.Add(waiters)
	var gotErrs int32
	for range waiters {
		go func() {
			defer wg.Done()
			_, err := coordinator.CoordinateRefresh(context.Background(), sameSession, sameToken, failingRefresh)
			if err != nil {
				atomic.AddInt32(&gotErrs, 1)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&gotErrs) != waiters {
		t.Fatalf("all waiters should observe the failure, got %d/%d errors", gotErrs, waiters)
	}
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Fatalf("one shared operation must make exactly one upstream call, got %d", upstreamCalls)
	}

	// A single upstream failure (one operation) must leave the circuit
	// breaker CLOSED: 1 failure < MaxFailures(3). Before the fix, 4
	// waiters recorded 4 failures and opened it.
	success := func() (*TokenResponse, error) {
		return &TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			IDToken:      "new_id_token",
			ExpiresIn:    3600,
		}, nil
	}

	resp, err := coordinator.CoordinateRefresh(context.Background(), "other_session", "other_token", success)
	if err != nil {
		t.Fatalf("follow-up refresh must be allowed while the circuit breaker is closed (got %v): %v",
			coordinator.circuitBreaker.GetState(), err)
	}
	if resp == nil || resp.AccessToken != "new_access_token" {
		t.Fatalf("expected successful follow-up refresh, got %+v", resp)
	}
}

// TestRefreshCoordinator_SuccessOnlyClosesAfterRealFailures verifies that
// several DISTINCT failing operations still trip the breaker as intended
// (sanity check that the once-per-operation recording did not neuter it).
func TestRefreshCoordinator_SuccessOnlyAfterCombinedOperations(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxRefreshAttempts = 1000
	// Immediate cleanup for deterministic test behavior (FIX-22): removes
	// the in-flight entry synchronously before CoordinateRefresh returns,
	// instead of racing the 100ms default cleanup timer with a fixed sleep.
	config.DeduplicationCleanupDelay = 0
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	failingRefresh := func() (*TokenResponse, error) {
		return nil, errors.New("provider_down")
	}

	// MaxFailures=3 -> three distinct failing operations must open it.
	// DeduplicationCleanupDelay=0 (set above), combined with polling for the
	// in-flight entry's removal below, guarantees each attempt is a
	// deterministically new operation, not a join (FIX-22: no fixed sleep).
	for range 3 {
		_, err := coordinator.CoordinateRefresh(
			context.Background(),
			"target_session",
			"target_token", // same token so all three are distinct sequential ops
			failingRefresh,
		)
		if err == nil {
			t.Fatal("expected refresh to fail")
		}
		waitForRefreshDrain(t, coordinator, "target_token")
	}

	if got := coordinator.circuitBreaker.GetState(); got != "open" {
		t.Fatalf("three real failures should open the circuit breaker, got state %q", got)
	}
}
