package traefikoidc

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitForRefreshDrain polls until refreshToken's entry is gone from rc's
// in-flight map, instead of sleeping a fixed margin (FIX-22). Even with
// DeduplicationCleanupDelay=0, executeRefreshAsync's close(operation.done)
// and its synchronous performCleanup call are two separate statements in the
// same deferred closure: a waiter unblocked by close(operation.done) can run
// concurrently with (and observe the map entry before) that same goroutine's
// next statement. Actively polling for the entry's removal — rather than
// guessing a sleep long enough to outrun that window — makes the next
// CoordinateRefresh call for the same token deterministically start a new
// operation instead of occasionally joining the one that just finished.
func waitForRefreshDrain(t *testing.T, rc *RefreshCoordinator, refreshToken string) {
	t.Helper()
	tokenHash := rc.hashRefreshToken(refreshToken)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := rc.inFlightRefreshes.Load(tokenHash); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("refresh operation for token %q never drained from the in-flight map", refreshToken)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestConcurrentRefreshDeduplication verifies that concurrent refresh attempts
// for the same token are deduplicated and only one refresh operation occurs
func TestConcurrentRefreshDeduplication(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	// Keep default delay for this test - it's testing deduplication behavior
	// Disable rate limiting for this test since we're testing deduplication
	config.MaxRefreshAttempts = 1000 // High enough to not interfere
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Counter to track actual refresh executions
	var refreshExecutions int32

	// Mock refresh function
	refreshFunc := func() (*TokenResponse, error) {
		atomic.AddInt32(&refreshExecutions, 1)
		// Simulate some processing time
		time.Sleep(100 * time.Millisecond)
		return &TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			IDToken:      "new_id_token",
			ExpiresIn:    3600,
		}, nil
	}

	// Number of concurrent requests
	numRequests := 100
	var wg sync.WaitGroup
	wg.Add(numRequests)

	// Channel to collect results
	results := make(chan *TokenResponse, numRequests)
	errors := make(chan error, numRequests)

	// Launch concurrent refresh attempts with unique identifiers
	refreshToken := fmt.Sprintf("test_refresh_token_%d", time.Now().UnixNano())
	sessionID := fmt.Sprintf("test_session_%d", time.Now().UnixNano())

	for i := 0; i < numRequests; i++ {
		go func(reqID int) {
			defer wg.Done()

			ctx := context.Background()
			resp, err := coordinator.CoordinateRefresh(
				ctx,
				sessionID,
				refreshToken,
				refreshFunc,
			)

			if err != nil {
				errors <- err
			} else {
				results <- resp
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)
	close(errors)

	// Verify results
	actualExecutions := atomic.LoadInt32(&refreshExecutions)
	// Allow for slight timing variations - up to 2 executions is acceptable
	// This can happen when a second goroutine starts just as the first completes
	if actualExecutions > 2 {
		t.Errorf("Expected 1-2 refresh executions, got %d", actualExecutions)
	}

	// Verify all requests got the same result
	var firstResponse *TokenResponse
	responseCount := 0

	for resp := range results {
		responseCount++
		if firstResponse == nil {
			firstResponse = resp
		} else {
			// All responses should be identical (same pointer)
			if resp.AccessToken != firstResponse.AccessToken {
				t.Error("Different responses returned for concurrent requests")
			}
		}
	}

	// Check for errors
	errorCount := 0
	for range errors {
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Unexpected errors in concurrent requests: %d", errorCount)
	}

	if responseCount != numRequests {
		t.Errorf("Expected %d successful responses, got %d", numRequests, responseCount)
	}

	// Verify metrics
	metrics := coordinator.GetMetrics()
	if deduped, ok := metrics["deduplicated_requests"].(int64); ok {
		// Allow for slight timing variations - at least 98 out of 100 should be deduplicated
		if deduped < int64(numRequests-2) {
			t.Errorf("Expected at least %d deduplicated requests, got %d", numRequests-2, deduped)
		}
	}
}

// TestRefreshRateLimiting verifies that refresh attempts are rate-limited per session
func TestRefreshRateLimiting(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxRefreshAttempts = 3
	config.RefreshAttemptWindow = 1 * time.Second
	config.RefreshCooldownPeriod = 2 * time.Second
	// Immediate cleanup for deterministic test behavior (FIX-22 pattern,
	// matching TestCircuitBreakerProtection below): removes the in-flight
	// entry synchronously before CoordinateRefresh returns, instead of
	// racing the default 100ms cleanup timer with a fixed sleep margin.
	config.DeduplicationCleanupDelay = 0

	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Set circuit breaker to not interfere with rate limiting test
	// We want to test rate limiting, not circuit breaker
	coordinator.circuitBreaker.config.MaxFailures = 10

	sessionID := "rate_limited_session"
	refreshToken := "test_refresh_token"

	// Mock refresh function that always fails
	refreshFunc := func() (*TokenResponse, error) {
		return nil, fmt.Errorf("refresh failed")
	}

	// Attempt refreshes beyond the limit
	var attempts int
	var cooldownTriggered bool

	for i := 0; i < 5; i++ {
		ctx := context.Background()
		_, err := coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)

		if err != nil {
			if err.Error() == "refresh attempts exceeded for session, in cooldown period" {
				cooldownTriggered = true
				break
			}
		}
		attempts++
		// Wait for the operation to actually drain from the in-flight map
		// (FIX-22 pattern) instead of sleeping a fixed margin against the
		// dedup cleanup timer: with DeduplicationCleanupDelay=0 the timer is
		// gone, but performCleanup still runs after close(operation.done) in
		// the same deferred closure, so a fixed sleep could still race it
		// under load.
		waitForRefreshDrain(t, coordinator, refreshToken)
	}

	// Verify that cooldown was triggered after max attempts.
	// With applyLeaderGates checking cooldown BEFORE recording the attempt
	// (the v1.0.16 reorder fixing the thundering-herd off-by-one), N attempts
	// run to completion and the (N+1)th is denied. Previously the Nth was
	// denied as it tried to record, which under burst load let multiple
	// concurrent leaders increment past the limit before any one of them
	// observed the gate.
	expectedSuccessfulAttempts := config.MaxRefreshAttempts
	if attempts != expectedSuccessfulAttempts {
		t.Errorf("Expected %d successful attempts before cooldown, got %d", expectedSuccessfulAttempts, attempts)
	}

	if !cooldownTriggered {
		t.Error("Cooldown was not triggered after max attempts")
	}

	// Verify that requests are blocked during cooldown
	ctx := context.Background()
	_, err := coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
	if err == nil || err.Error() != "refresh attempts exceeded for session, in cooldown period" {
		t.Error("Request should be blocked during cooldown period")
	}

	// Wait for cooldown to expire
	time.Sleep(config.RefreshCooldownPeriod + 100*time.Millisecond)

	// Verify that requests are allowed after cooldown
	_, err = coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
	if err != nil && err.Error() == "refresh attempts exceeded for session, in cooldown period" {
		t.Error("Request should be allowed after cooldown period")
	}
}

// TestCircuitBreakerProtection verifies that the circuit breaker prevents
// cascading failures during repeated refresh failures
func TestCircuitBreakerProtection(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	// Immediate cleanup for deterministic test behavior (FIX-22): removes
	// the in-flight entry synchronously before CoordinateRefresh returns,
	// instead of racing the 100ms default cleanup timer with a fixed sleep.
	config.DeduplicationCleanupDelay = 0
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Set circuit breaker to trip after 3 failures
	coordinator.circuitBreaker.config.MaxFailures = 3
	coordinator.circuitBreaker.config.OpenDuration = 1 * time.Second

	// Mock refresh function that always fails
	refreshFunc := func() (*TokenResponse, error) {
		return nil, fmt.Errorf("service unavailable")
	}

	// Cause circuit breaker to trip with genuinely distinct failing
	// operations. DeduplicationCleanupDelay=0 (set above), combined with
	// polling for the in-flight entry's removal below, guarantees each
	// same-token call is not absorbed as a join on the previous operation
	// (FIX-22: no fixed sleep).
	var tripCount int
	for i := 0; i < 5; i++ {
		ctx := context.Background()
		_, err := coordinator.CoordinateRefresh(
			ctx,
			fmt.Sprintf("session_%d", i), // Different sessions
			"refresh_token",
			refreshFunc,
		)
		waitForRefreshDrain(t, coordinator, "refresh_token")

		if err != nil && err.Error() == "refresh circuit breaker is open due to repeated failures" {
			tripCount++
		}
	}

	// Verify circuit breaker tripped
	if tripCount == 0 {
		t.Error("Circuit breaker did not trip after repeated failures")
	}

	// Verify circuit breaker state
	if coordinator.circuitBreaker.GetState() != "open" {
		t.Errorf("Expected circuit breaker state 'open', got '%s'", coordinator.circuitBreaker.GetState())
	}

	// Wait for circuit to transition to half-open
	time.Sleep(coordinator.circuitBreaker.config.OpenDuration + 100*time.Millisecond)

	// Mock successful refresh
	successfulRefreshFunc := func() (*TokenResponse, error) {
		return &TokenResponse{
			AccessToken: "new_token",
		}, nil
	}

	// Verify circuit allows request in half-open state
	ctx := context.Background()
	_, err := coordinator.CoordinateRefresh(ctx, "session_recovery", "refresh_token", successfulRefreshFunc)
	if err != nil {
		t.Errorf("Circuit breaker should allow request in half-open state: %v", err)
	}

	// Verify circuit closed after success
	if coordinator.circuitBreaker.GetState() != "closed" {
		t.Errorf("Expected circuit breaker state 'closed' after successful request, got '%s'",
			coordinator.circuitBreaker.GetState())
	}
}

// TestMemoryLeakPrevention verifies that the coordinator doesn't leak memory
// during sustained concurrent refresh operations
func TestMemoryLeakPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.CleanupInterval = 100 * time.Millisecond
	config.DeduplicationCleanupDelay = 0 // Immediate cleanup for deterministic test behavior
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Force garbage collection and record initial memory
	runtime.GC()
	runtime.GC()
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)

	// Run sustained concurrent operations
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	numWorkers := 10
	wg.Add(numWorkers)

	// Each worker continuously attempts refreshes
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()

			refreshCount := 0
			refreshFunc := func() (*TokenResponse, error) {
				// Simulate varying response times
				time.Sleep(time.Duration(workerID*10) * time.Millisecond)
				return &TokenResponse{
					AccessToken:  fmt.Sprintf("token_%d_%d", workerID, refreshCount),
					RefreshToken: fmt.Sprintf("refresh_%d_%d", workerID, refreshCount),
				}, nil
			}

			for {
				select {
				case <-ctx.Done():
					return
				default:
					sessionID := fmt.Sprintf("session_%d", workerID)
					refreshToken := fmt.Sprintf("refresh_%d_%d", workerID, refreshCount)

					_, _ = coordinator.CoordinateRefresh(
						context.Background(),
						sessionID,
						refreshToken,
						refreshFunc,
					)

					refreshCount++
					// Small delay to prevent CPU saturation
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	// Wait for workers to complete
	wg.Wait()

	// Allow cleanup to run
	time.Sleep(2 * config.CleanupInterval)

	// Force garbage collection and check memory
	runtime.GC()
	runtime.GC()
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)

	// Calculate memory growth safely to prevent underflow
	var memGrowthMB float64
	if finalMem.HeapAlloc >= initialMem.HeapAlloc {
		memGrowthMB = float64(finalMem.HeapAlloc-initialMem.HeapAlloc) / (1024 * 1024)
	} else {
		// Memory decreased (GC occurred), treat as 0 growth
		memGrowthMB = 0
	}

	// Log memory statistics for debugging
	t.Logf("Initial memory: %.2f MB", float64(initialMem.HeapAlloc)/(1024*1024))
	t.Logf("Final memory: %.2f MB", float64(finalMem.HeapAlloc)/(1024*1024))
	t.Logf("Memory growth: %.2f MB", memGrowthMB)

	// Check for excessive memory growth (threshold: 50MB)
	if memGrowthMB > 50 {
		t.Errorf("Excessive memory growth detected: %.2f MB", memGrowthMB)
	}

	// Verify no lingering operations
	metrics := coordinator.GetMetrics()
	if inflight, ok := metrics["current_inflight"].(int32); ok {
		if inflight != 0 {
			t.Errorf("Expected 0 in-flight operations after completion, got %d", inflight)
		}
	}

	// Verify cleanup is working. sync.Map has no Len(); count via Range.
	sessionCount := 0
	coordinator.sessionRefreshAttempts.Range(func(_, _ interface{}) bool {
		sessionCount++
		return true
	})

	// Should have cleaned up old sessions (only recent ones remain)
	if sessionCount > numWorkers*2 {
		t.Errorf("Session cleanup not working properly, %d sessions remain", sessionCount)
	}
}

// TestRefreshTimeoutHandling verifies that refresh operations timeout properly
func TestRefreshTimeoutHandling(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.RefreshTimeout = 100 * time.Millisecond
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Mock refresh function that hangs
	refreshFunc := func() (*TokenResponse, error) {
		time.Sleep(1 * time.Second) // Much longer than timeout
		return &TokenResponse{AccessToken: "token"}, nil
	}

	ctx := context.Background()
	start := time.Now()

	_, err := coordinator.CoordinateRefresh(ctx, "session", "refresh_token", refreshFunc)

	elapsed := time.Since(start)

	// Verify timeout occurred
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	// Verify it timed out within reasonable bounds
	if elapsed > 200*time.Millisecond {
		t.Errorf("Timeout took too long: %v", elapsed)
	}

	if err != nil && err.Error() != fmt.Sprintf("refresh operation timed out after %v", config.RefreshTimeout) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestConcurrentDifferentTokens verifies that refreshes for different tokens
// proceed independently without blocking each other
func TestConcurrentDifferentTokens(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	numTokens := 10
	var wg sync.WaitGroup
	wg.Add(numTokens)

	// Track execution order
	executionOrder := make([]int, 0, numTokens)
	var executionMutex sync.Mutex

	for i := 0; i < numTokens; i++ {
		go func(tokenID int) {
			defer wg.Done()

			refreshFunc := func() (*TokenResponse, error) {
				executionMutex.Lock()
				executionOrder = append(executionOrder, tokenID)
				executionMutex.Unlock()

				// Varying processing times
				time.Sleep(time.Duration(tokenID*10) * time.Millisecond)

				return &TokenResponse{
					AccessToken:  fmt.Sprintf("token_%d", tokenID),
					RefreshToken: fmt.Sprintf("refresh_%d", tokenID),
				}, nil
			}

			ctx := context.Background()
			resp, err := coordinator.CoordinateRefresh(
				ctx,
				fmt.Sprintf("session_%d", tokenID),
				fmt.Sprintf("refresh_token_%d", tokenID),
				refreshFunc,
			)

			if err != nil {
				t.Errorf("Token %d refresh failed: %v", tokenID, err)
			}

			if resp == nil || resp.AccessToken != fmt.Sprintf("token_%d", tokenID) {
				t.Errorf("Token %d got wrong response", tokenID)
			}
		}(i)
	}

	wg.Wait()

	// Verify all tokens were processed
	if len(executionOrder) != numTokens {
		t.Errorf("Expected %d executions, got %d", numTokens, len(executionOrder))
	}

	// Verify no deduplication occurred (all different tokens)
	metrics := coordinator.GetMetrics()
	if deduped, ok := metrics["deduplicated_requests"].(int64); ok {
		if deduped != 0 {
			t.Errorf("No deduplication expected for different tokens, got %d", deduped)
		}
	}
}

// TestMaxConcurrentRefreshes verifies that the coordinator respects
// the maximum concurrent refresh limit
func TestMaxConcurrentRefreshes(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxConcurrentRefreshes = 2
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Track concurrent executions
	var currentConcurrent int32
	var maxConcurrent int32

	refreshFunc := func() (*TokenResponse, error) {
		current := atomic.AddInt32(&currentConcurrent, 1)

		// Update max if needed
		for {
			max := atomic.LoadInt32(&maxConcurrent)
			if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
				break
			}
		}

		time.Sleep(100 * time.Millisecond)
		atomic.AddInt32(&currentConcurrent, -1)

		return &TokenResponse{AccessToken: "token"}, nil
	}

	numRequests := 10
	var wg sync.WaitGroup
	wg.Add(numRequests)

	errors := make([]error, 0, numRequests)
	var errorMutex sync.Mutex

	for i := 0; i < numRequests; i++ {
		go func(id int) {
			defer wg.Done()

			ctx := context.Background()
			_, err := coordinator.CoordinateRefresh(
				ctx,
				fmt.Sprintf("session_%d", id),
				fmt.Sprintf("token_%d", id),
				refreshFunc,
			)

			if err != nil {
				errorMutex.Lock()
				errors = append(errors, err)
				errorMutex.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// Some requests should have been rejected due to concurrency limit
	if len(errors) == 0 {
		t.Error("Expected some requests to be rejected due to concurrency limit")
	}

	// Verify max concurrent never exceeded limit
	if maxConcurrent > int32(config.MaxConcurrentRefreshes) {
		t.Errorf("Max concurrent refreshes (%d) exceeded limit (%d)",
			maxConcurrent, config.MaxConcurrentRefreshes)
	}
}

// TestSessionWindowReset verifies that refresh attempt windows reset properly
func TestSessionWindowReset(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxRefreshAttempts = 2
	config.RefreshAttemptWindow = 500 * time.Millisecond
	config.RefreshCooldownPeriod = 2 * time.Second // Explicitly set cooldown > window
	config.DeduplicationCleanupDelay = 0           // Immediate cleanup for deterministic test behavior

	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Set circuit breaker to not interfere with rate limiting test
	coordinator.circuitBreaker.config.MaxFailures = 10

	// Use unique identifiers to prevent test interference
	sessionID := fmt.Sprintf("window_test_session_%d", time.Now().UnixNano())
	refreshToken := fmt.Sprintf("test_refresh_token_%d", time.Now().UnixNano())

	// Mock refresh function that always fails
	refreshFunc := func() (*TokenResponse, error) {
		return nil, fmt.Errorf("refresh failed")
	}

	// Use up the attempts in the first window
	for i := 0; i < config.MaxRefreshAttempts; i++ {
		ctx := context.Background()
		_, _ = coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
		// Add small delay to ensure attempts are registered separately
		time.Sleep(10 * time.Millisecond)
	}

	// Next attempt should trigger cooldown
	ctx := context.Background()
	_, err := coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
	if err == nil || err.Error() != "refresh attempts exceeded for session, in cooldown period" {
		t.Errorf("Expected cooldown after max attempts, got: %v", err)
	}

	// Wait for window to expire (but not cooldown)
	// Use generous buffer for CI environments
	time.Sleep(config.RefreshAttemptWindow + 200*time.Millisecond)

	// Should still be in cooldown (cooldown=2s > window=500ms)
	_, err = coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
	if err == nil || err.Error() != "refresh attempts exceeded for session, in cooldown period" {
		t.Errorf("Should still be in cooldown period after window expiry, got: %v", err)
	}
}

// BenchmarkConcurrentRefreshDeduplication measures performance of deduplication
func BenchmarkConcurrentRefreshDeduplication(b *testing.B) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	refreshFunc := func() (*TokenResponse, error) {
		time.Sleep(10 * time.Millisecond)
		return &TokenResponse{
			AccessToken: "token",
		}, nil
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ctx := context.Background()
			sessionID := fmt.Sprintf("session_%d", i%10)  // Reuse 10 sessions
			refreshToken := fmt.Sprintf("token_%d", i%10) // Reuse 10 tokens
			_, _ = coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
			i++
		}
	})

	b.StopTimer()

	// Report metrics
	metrics := coordinator.GetMetrics()
	b.Logf("Total requests: %v", metrics["total_requests"])
	b.Logf("Deduplicated: %v", metrics["deduplicated_requests"])
}

// TestCleanupRoutine verifies that the cleanup routine removes stale entries
func TestCleanupRoutine(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.CleanupInterval = 100 * time.Millisecond
	config.RefreshAttemptWindow = 200 * time.Millisecond

	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Add some sessions
	for i := 0; i < 5; i++ {
		coordinator.recordRefreshAttempt(fmt.Sprintf("session_%d", i))
	}

	countSessions := func() int {
		n := 0
		coordinator.sessionRefreshAttempts.Range(func(_, _ interface{}) bool {
			n++
			return true
		})
		return n
	}

	if initialCount := countSessions(); initialCount != 5 {
		t.Errorf("Expected 5 sessions, got %d", initialCount)
	}

	// Wait for cleanup to run (2x window + cleanup interval)
	time.Sleep(2*config.RefreshAttemptWindow + 2*config.CleanupInterval)

	if finalCount := countSessions(); finalCount != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", finalCount)
	}
}

// TestNoGoroutineExplosionWithTimers verifies that timer-based cleanup doesn't cause goroutine explosion
// This was the original issue: spawning a goroutine per refresh to sleep and cleanup
func TestNoGoroutineExplosionWithTimers(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.DeduplicationCleanupDelay = 100 * time.Millisecond // Non-zero delay
	config.MaxConcurrentRefreshes = 100                       // Allow many concurrent
	config.MaxRefreshAttempts = 10000                         // Don't rate limit

	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Record initial goroutines (allow settling time)
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	// Submit many refresh operations rapidly
	const numRefreshes = 500
	var wg sync.WaitGroup
	wg.Add(numRefreshes)

	refreshFunc := func() (*TokenResponse, error) {
		return &TokenResponse{AccessToken: "token"}, nil
	}

	for i := 0; i < numRefreshes; i++ {
		go func(id int) {
			defer wg.Done()
			ctx := context.Background()
			_, _ = coordinator.CoordinateRefresh(
				ctx,
				fmt.Sprintf("session_%d", id),
				fmt.Sprintf("token_%d", id),
				refreshFunc,
			)
		}(i)
	}

	wg.Wait()

	// Measure goroutines immediately after all operations complete
	// With the old approach, we'd have ~500 sleeping goroutines
	// With the new timer approach, we should have much fewer
	currentGoroutines := runtime.NumGoroutine()
	t.Logf("Goroutines after %d refresh operations: %d", numRefreshes, currentGoroutines)

	// (Coordinator no longer tracks pending timers; time.AfterFunc closures
	// fire performCleanup directly. This test now only checks the goroutine
	// budget, which was always the real invariant.)

	// With timer-based cleanup, goroutine increase should be minimal
	// Timers don't create goroutines - they use the runtime timer heap
	goroutineIncrease := currentGoroutines - initialGoroutines

	// Allow for some goroutine overhead (test framework, etc)
	// With the old approach, we'd see ~500 goroutines
	// With the new approach, we should see <50 (much smaller)
	maxAcceptableIncrease := 100 // Very generous limit

	if goroutineIncrease > maxAcceptableIncrease {
		t.Errorf("Goroutine explosion detected: started with %d, now have %d (increase of %d)",
			initialGoroutines, currentGoroutines, goroutineIncrease)
	}

	// Wait for timers to fire and cleanup.
	time.Sleep(config.DeduplicationCleanupDelay + 50*time.Millisecond)

	// Verify goroutines returned to near initial
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines: %d", finalGoroutines)

	// Should be close to initial (within tolerance)
	finalIncrease := finalGoroutines - initialGoroutines
	if finalIncrease > 20 {
		t.Errorf("Goroutine leak detected: started with %d, ended with %d (increase of %d)",
			initialGoroutines, finalGoroutines, finalIncrease)
	}
}

// TestFix36_CoordinateRefreshRejectedAfterShutdown guards the FIX-36 fix:
// CoordinateRefresh called wg.Add(1) unconditionally, with no check on
// rc.stopChan, so a call arriving after Shutdown still registered and ran a
// brand-new refresh operation instead of being rejected.
func TestFix36_CoordinateRefreshRejectedAfterShutdown(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	coordinator := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), logger)
	coordinator.Shutdown()

	var ran int32
	_, err := coordinator.CoordinateRefresh(context.Background(), "fix36-session", "fix36-token", func() (*TokenResponse, error) {
		atomic.StoreInt32(&ran, 1)
		return &TokenResponse{AccessToken: "should-not-run"}, nil
	})

	if err == nil {
		t.Fatal("CoordinateRefresh called after Shutdown must return an error instead of running a new refresh")
	}
	if atomic.LoadInt32(&ran) == 1 {
		t.Fatal("refreshFunc must not run for a CoordinateRefresh call rejected after Shutdown")
	}
}

// TestFix36_ShutdownDeliversResultForRefreshCompletingWithinDrainCap pins the
// DECIDED FIX-36 contract: a refresh already sent to the IdP may finish and
// deliver its result to its waiters. Shutdown waits for in-flight refreshes
// up to shutdownRefreshDrainTimeout before giving up, instead of canceling
// them the instant Shutdown is called.
//
// This supersedes the old "Shutdown cancels immediately, waiter always gets
// an error" contract that this test, review_r63's
// TestRefreshCoordinatorShutdownReleasesWaiterOnInflight, and review_r154's
// TestRefreshCoordinator_ShutdownWaitsForInFlight used to pin — all three
// were rewritten to the drain-cap contract. Discarding a refresh the IdP
// already completed loses a rotated (one-time-use) refresh token, forcing a
// re-login; see refresh_coordinator.go's Shutdown comment.
//
// refreshFunc blocks on a channel released well inside the cap (not a fixed
// sleep) instead of using a fixed sleep, so no goroutine is left running
// past this test even on failure — release fires unconditionally via
// t.Cleanup.
//
// Fails on pre-fix code: Shutdown cancels rc.ctx immediately, so the waiter
// gets "refresh coordinator is shutting down" instead of its tokens.
func TestFix36_ShutdownDeliversResultForRefreshCompletingWithinDrainCap(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.RefreshTimeout = 30 * time.Second
	rc := NewRefreshCoordinator(cfg, logger)

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFn)

	type result struct {
		resp *TokenResponse
		err  error
	}
	waiterCh := make(chan result, 1)
	go func() {
		resp, err := rc.CoordinateRefresh(context.Background(), "fix36-cap-session", "fix36-cap-token",
			func() (*TokenResponse, error) {
				close(started)
				<-release
				return &TokenResponse{AccessToken: "delivered-within-cap"}, nil
			})
		waiterCh <- result{resp, err}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh never started")
	}

	shutdownDone := make(chan struct{})
	go func() {
		rc.Shutdown()
		close(shutdownDone)
	}()

	// Let Shutdown begin its bounded wait, then let the refresh finish well
	// inside shutdownRefreshDrainTimeout.
	time.Sleep(50 * time.Millisecond)
	releaseFn()

	select {
	case <-shutdownDone:
	case <-time.After(shutdownRefreshDrainTimeout):
		t.Fatal("Shutdown did not return after the in-flight refresh completed")
	}

	select {
	case res := <-waiterCh:
		if res.err != nil {
			t.Fatalf("waiter of a refresh that completed within the drain cap must get its tokens, got error: %v", res.err)
		}
		if res.resp == nil || res.resp.AccessToken != "delivered-within-cap" {
			t.Fatalf("waiter got unexpected result: %+v", res.resp)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("waiter did not get a result after Shutdown returned")
	}
}

// TestFix36_ShutdownReturnsNearCapWhenRefreshExceedsIt pins the other half
// of the DECIDED FIX-36 contract: a refresh still running once
// shutdownRefreshDrainTimeout elapses is abandoned — Shutdown returns near
// the cap instead of waiting indefinitely, and its waiter gets the shutdown
// error.
//
// refreshFunc blocks on a channel released via t.Cleanup (not a fixed
// sleep) so the untracked inner goroutine (see executeRefreshAsync) does not
// keep running past this test even though it never completes on its own.
func TestFix36_ShutdownReturnsNearCapWhenRefreshExceedsIt(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.RefreshTimeout = shutdownRefreshDrainTimeout + 30*time.Second // keep RefreshTimeout out of the way; only the drain cap should bound Shutdown
	rc := NewRefreshCoordinator(cfg, logger)

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	waiterErrCh := make(chan error, 1)
	go func() {
		_, err := rc.CoordinateRefresh(context.Background(), "fix36-exceeds-cap-session", "fix36-exceeds-cap-token",
			func() (*TokenResponse, error) {
				close(started)
				<-release
				return &TokenResponse{AccessToken: "too-late"}, nil
			})
		waiterErrCh <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh never started")
	}

	shutdownStart := time.Now()
	rc.Shutdown()
	elapsed := time.Since(shutdownStart)

	if elapsed < shutdownRefreshDrainTimeout {
		t.Fatalf("Shutdown returned after %v, want at least the %v drain cap", elapsed, shutdownRefreshDrainTimeout)
	}
	if margin := elapsed - shutdownRefreshDrainTimeout; margin > 2*time.Second {
		t.Fatalf("Shutdown took %v past the %v drain cap, want it to return near the cap", margin, shutdownRefreshDrainTimeout)
	}

	select {
	case err := <-waiterErrCh:
		if err == nil {
			t.Fatal("waiter of a refresh that outlives the shutdown drain cap must get an error")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("waiter did not get a result within 1s of Shutdown returning")
	}
}

// TestFix36_CoordinateRefreshRejectedAfterShutdownStillImmediate pins that
// the drain-cap change above does not weaken the other half of FIX-36: a
// CoordinateRefresh call arriving after Shutdown has started is still
// rejected before wg.Add, without waiting for the drain cap. See
// TestFix36_CoordinateRefreshRejectedAfterShutdown for the simple
// after-Shutdown-completes case; this one calls CoordinateRefresh WHILE
// Shutdown is in its bounded wait for a different in-flight refresh.
func TestFix36_CoordinateRefreshRejectedAfterShutdownStillImmediate(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.RefreshTimeout = shutdownRefreshDrainTimeout + 30*time.Second
	rc := NewRefreshCoordinator(cfg, logger)

	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	go func() {
		_, _ = rc.CoordinateRefresh(context.Background(), "fix36-parallel-session", "fix36-parallel-token",
			func() (*TokenResponse, error) {
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

	go rc.Shutdown()
	time.Sleep(20 * time.Millisecond) // let Shutdown close stopChan and enter its bounded wait

	rejectStart := time.Now()
	var ran int32
	_, err := rc.CoordinateRefresh(context.Background(), "fix36-rejected-session", "fix36-rejected-token",
		func() (*TokenResponse, error) {
			atomic.StoreInt32(&ran, 1)
			return &TokenResponse{AccessToken: "should-not-run"}, nil
		})
	if elapsed := time.Since(rejectStart); elapsed > time.Second {
		t.Fatalf("CoordinateRefresh took %v to reject after Shutdown started, want near-immediate", elapsed)
	}
	if err == nil {
		t.Fatal("CoordinateRefresh called while Shutdown is draining must still be rejected")
	}
	if atomic.LoadInt32(&ran) == 1 {
		t.Fatal("refreshFunc must not run for a CoordinateRefresh call rejected while Shutdown is draining")
	}
}

// TestFix36_ExecuteRefreshAsyncSkipsRefreshFuncWhenAlreadyCanceled pins the
// case where rc.ctx is already canceled (Shutdown ran, or raced ahead of
// CoordinateRefresh's own stopChan check) before executeRefreshAsync's inner
// goroutine starts. That goroutine must not call refreshFunc at all: the
// result would only be discarded (the outer select already took the
// refreshCtx.Done() branch), and for a rotating IdP refresh-token grant,
// discarding a successful response still consumes the one-time-use refresh
// token, leaving the caller and the IdP out of sync.
//
// Calling rc.cancel() directly (rather than rc.Shutdown()) isolates this
// from the stopChan-reject path added by FIX-36: it exercises the case
// where CoordinateRefresh's own stopChan check has already passed and the
// operation is genuinely running under an already-canceled rc.ctx.
func TestFix36_ExecuteRefreshAsyncSkipsRefreshFuncWhenAlreadyCanceled(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	rc := NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), logger)
	rc.cancel()

	var called int32
	_, err := rc.CoordinateRefresh(context.Background(), "fix36-precanceled-session", "fix36-precanceled-token",
		func() (*TokenResponse, error) {
			atomic.StoreInt32(&called, 1)
			return &TokenResponse{AccessToken: "should-be-discarded"}, nil
		})
	if err == nil {
		t.Fatal("waiter of an operation whose context was already canceled must get an error, not a nil result")
	}

	// Give the untracked inner goroutine time to run refreshFunc if the fix
	// is absent, before asserting it never did.
	time.Sleep(200 * time.Millisecond)
	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("refreshFunc must not be called when rc.ctx is already canceled before the refresh starts")
	}
}
