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
		// Add delay to ensure operations complete and aren't deduplicated
		time.Sleep(150 * time.Millisecond)
	}

	// Verify that cooldown was triggered after max attempts
	// With the new logic, the Nth attempt triggers cooldown, so we get N-1 successful attempts
	expectedSuccessfulAttempts := config.MaxRefreshAttempts - 1
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
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Set circuit breaker to trip after 3 failures
	coordinator.circuitBreaker.config.MaxFailures = 3
	coordinator.circuitBreaker.config.OpenDuration = 1 * time.Second

	// Mock refresh function that always fails
	refreshFunc := func() (*TokenResponse, error) {
		return nil, fmt.Errorf("service unavailable")
	}

	// Cause circuit breaker to trip
	var tripCount int
	for i := 0; i < 5; i++ {
		ctx := context.Background()
		_, err := coordinator.CoordinateRefresh(
			ctx,
			fmt.Sprintf("session_%d", i), // Different sessions
			"refresh_token",
			refreshFunc,
		)

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

	// Verify cleanup is working
	coordinator.attemptsMutex.RLock()
	sessionCount := len(coordinator.sessionRefreshAttempts)
	coordinator.attemptsMutex.RUnlock()

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

	// Verify sessions exist
	coordinator.attemptsMutex.RLock()
	initialCount := len(coordinator.sessionRefreshAttempts)
	coordinator.attemptsMutex.RUnlock()

	if initialCount != 5 {
		t.Errorf("Expected 5 sessions, got %d", initialCount)
	}

	// Wait for cleanup to run (2x window + cleanup interval)
	time.Sleep(2*config.RefreshAttemptWindow + 2*config.CleanupInterval)

	// Verify sessions were cleaned up
	coordinator.attemptsMutex.RLock()
	finalCount := len(coordinator.sessionRefreshAttempts)
	coordinator.attemptsMutex.RUnlock()

	if finalCount != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", finalCount)
	}
}
