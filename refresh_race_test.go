package traefikoidc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefreshCoordinatorRaceCondition specifically tests for race conditions
// in the refresh coordinator's concurrent operation handling
func TestRefreshCoordinatorRaceCondition(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	// Increase rate limit for this race condition test
	config.MaxRefreshAttempts = 100 // Allow many attempts for race testing
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Test concurrent access to the same refresh token
	var executions int32
	refreshFunc := func() (*TokenResponse, error) {
		atomic.AddInt32(&executions, 1)
		time.Sleep(50 * time.Millisecond) // Simulate work
		return &TokenResponse{
			AccessToken:  "test_token",
			RefreshToken: "test_refresh",
		}, nil
	}

	// Launch many goroutines concurrently
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	ctx := context.Background()
	sessionID := "test_session"
	refreshToken := "test_refresh_token"

	// Use a channel to ensure all goroutines start at the same time
	startChan := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			// Wait for signal to start
			<-startChan

			// All goroutines try to refresh at the same time
			result, err := coordinator.CoordinateRefresh(
				ctx,
				sessionID,
				refreshToken,
				refreshFunc,
			)

			// Basic validation
			if err != nil {
				t.Errorf("Goroutine %d: unexpected error: %v", id, err)
			}
			if result == nil || result.AccessToken != "test_token" {
				t.Errorf("Goroutine %d: invalid result", id)
			}
		}(i)
	}

	// Release all goroutines at once
	close(startChan)

	// Wait for completion
	wg.Wait()

	// Check that deduplication worked
	actualExecutions := atomic.LoadInt32(&executions)
	t.Logf("Executions: %d out of %d goroutines", actualExecutions, numGoroutines)

	// With proper deduplication, we should have very few executions
	// Allow for some timing slack - up to 3 executions is acceptable
	if actualExecutions > 3 {
		t.Errorf("Too many refresh executions: %d (expected <= 3)", actualExecutions)
	}

	// Verify metrics
	metrics := coordinator.GetMetrics()
	if total, ok := metrics["total_requests"].(int64); ok {
		if total != int64(numGoroutines) {
			t.Errorf("Expected %d total requests, got %d", numGoroutines, total)
		}
	}
}

// TestRefreshCoordinatorNoRaceWithDifferentTokens verifies no interference
// between different refresh tokens
func TestRefreshCoordinatorNoRaceWithDifferentTokens(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	// Increase concurrent limit to handle 10 different tokens
	config.MaxConcurrentRefreshes = 15
	config.DeduplicationCleanupDelay = 0 // Immediate cleanup for deterministic test behavior
	// Increase rate limit since we have 5 goroutines per token
	config.MaxRefreshAttempts = 10 // Allow multiple attempts per session
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	const numTokens = 10
	const goroutinesPerToken = 5

	var totalExecutions int32
	var wg sync.WaitGroup
	wg.Add(numTokens * goroutinesPerToken)

	refreshFunc := func() (*TokenResponse, error) {
		atomic.AddInt32(&totalExecutions, 1)
		time.Sleep(10 * time.Millisecond)
		return &TokenResponse{
			AccessToken: "token",
		}, nil
	}

	// Launch goroutines for different tokens with unique identifiers
	baseID := time.Now().UnixNano()
	for tokenID := 0; tokenID < numTokens; tokenID++ {
		sessionID := fmt.Sprintf("session_%d_%d", baseID, tokenID)
		refreshToken := fmt.Sprintf("refresh_%d_%d", baseID, tokenID)

		for i := 0; i < goroutinesPerToken; i++ {
			go func(tid, gid int) {
				defer wg.Done()

				ctx := context.Background()
				_, err := coordinator.CoordinateRefresh(
					ctx,
					sessionID,
					refreshToken,
					refreshFunc,
				)

				if err != nil && err.Error() != "maximum concurrent refresh operations reached" {
					// Only log non-concurrent-limit errors as failures
					t.Errorf("Token %d, Goroutine %d: unexpected error: %v", tid, gid, err)
				}
			}(tokenID, i)
		}
	}

	wg.Wait()

	// Each token should have had ~1 execution (maybe 2 due to timing)
	actualExecutions := atomic.LoadInt32(&totalExecutions)
	t.Logf("Total executions: %d for %d different tokens", actualExecutions, numTokens)

	// Should be close to numTokens (one per unique token)
	if actualExecutions > numTokens*2 {
		t.Errorf("Too many executions: %d (expected ~%d)", actualExecutions, numTokens)
	}
}
