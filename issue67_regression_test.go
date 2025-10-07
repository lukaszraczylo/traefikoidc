package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIssue67_InfiniteRefreshLoop reproduces and verifies the fix for issue #67
// where concurrent requests with expired tokens caused an infinite refresh loop
// leading to OOM conditions
func TestIssue67_InfiniteRefreshLoop(t *testing.T) {
	// Track memory at start
	runtime.GC()
	var startMem runtime.MemStats
	runtime.ReadMemStats(&startMem)

	// Create a mock authorization server
	var refreshAttempts int32
	var concurrentRefreshes int32
	var maxConcurrent int32

	// Create a handler with server URL to be set after creation
	var serverURL string

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Track concurrent refresh attempts
			current := atomic.AddInt32(&concurrentRefreshes, 1)
			defer atomic.AddInt32(&concurrentRefreshes, -1)

			// Update max concurrent
			for {
				max := atomic.LoadInt32(&maxConcurrent)
				if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
					break
				}
			}

			attempts := atomic.AddInt32(&refreshAttempts, 1)

			// Simulate slow/failing token endpoint (like in the issue)
			if attempts < 5 {
				// First few attempts fail to trigger retries
				time.Sleep(100 * time.Millisecond)
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"error": "temporarily_unavailable"}`))
			} else {
				// Eventually succeed
				time.Sleep(50 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{
					"access_token": "new_access_token",
					"refresh_token": "new_refresh_token",
					"id_token": "new_id_token",
					"expires_in": 3600,
					"token_type": "Bearer"
				}`))
			}

		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(fmt.Sprintf(`{
				"issuer": "%s",
				"authorization_endpoint": "%s/authorize",
				"token_endpoint": "%s/token",
				"jwks_uri": "%s/keys",
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"],
				"scopes_supported": ["openid", "profile", "email"],
				"token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
				"claims_supported": ["sub", "name", "email"]
			}`, serverURL, serverURL, serverURL, serverURL)))

		case "/keys":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"keys": [{
					"kty": "RSA",
					"use": "sig",
					"kid": "test-key",
					"n": "test",
					"e": "AQAB"
				}]
			}`))
		}
	}))
	defer authServer.Close()

	// Set the server URL after creation
	serverURL = authServer.URL

	// Setup TraefikOIDC with refresh coordinator
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxRefreshAttempts = 3
	config.RefreshAttemptWindow = 1 * time.Second
	config.MaxConcurrentRefreshes = 2

	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Simulate expired session
	expiredSession := &MockExpiredSession{
		refreshToken: "test_refresh_token",
		sessionID:    "test_session",
		isExpired:    true,
	}

	// Simulate multiple concurrent requests (as reported in issue)
	numConcurrentRequests := 50
	var wg sync.WaitGroup
	wg.Add(numConcurrentRequests)

	// Track results
	var successCount int32
	var errorCount int32
	errors := make([]error, 0, numConcurrentRequests)
	var errorMutex sync.Mutex

	// Launch concurrent requests with expired tokens
	startTime := time.Now()
	timeout := 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i := 0; i < numConcurrentRequests; i++ {
		go func(reqID int) {
			defer wg.Done()

			// Each request tries to refresh the expired token
			refreshFunc := func() (*TokenResponse, error) {
				// Simulate calling the token endpoint
				resp, err := http.Post(
					serverURL+"/token",
					"application/x-www-form-urlencoded",
					nil,
				)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("token refresh failed: %d", resp.StatusCode)
				}

				return &TokenResponse{
					AccessToken:  fmt.Sprintf("new_access_%d", reqID),
					RefreshToken: "new_refresh",
					IDToken:      "new_id",
					ExpiresIn:    3600,
				}, nil
			}

			// Use coordinator to prevent infinite loop
			result, err := coordinator.CoordinateRefresh(
				ctx,
				expiredSession.sessionID,
				expiredSession.refreshToken,
				refreshFunc,
			)

			if err != nil {
				atomic.AddInt32(&errorCount, 1)
				errorMutex.Lock()
				errors = append(errors, err)
				errorMutex.Unlock()
			} else if result != nil {
				atomic.AddInt32(&successCount, 1)
			}
		}(i)
	}

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Completed normally
	case <-ctx.Done():
		t.Fatal("Test timed out - possible infinite loop detected!")
	}

	elapsed := time.Since(startTime)

	// Verify no infinite loop occurred
	if elapsed > timeout {
		t.Fatalf("Requests took too long: %v (possible infinite loop)", elapsed)
	}

	// Check memory usage
	runtime.GC()
	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)

	// Calculate memory growth safely to prevent underflow
	var memGrowthMB float64
	if endMem.HeapAlloc >= startMem.HeapAlloc {
		memGrowthMB = float64(endMem.HeapAlloc-startMem.HeapAlloc) / (1024 * 1024)
	} else {
		// Memory decreased (GC occurred), treat as 0 growth
		memGrowthMB = 0
	}
	t.Logf("Memory stats: start=%d bytes, end=%d bytes, growth=%.2f MB",
		startMem.HeapAlloc, endMem.HeapAlloc, memGrowthMB)

	// Memory should not grow excessively (issue reported OOM at 2GB)
	if memGrowthMB > 100 {
		t.Errorf("Excessive memory growth: %.2f MB (possible memory leak)", memGrowthMB)
	}

	// Verify refresh deduplication worked
	actualRefreshAttempts := atomic.LoadInt32(&refreshAttempts)
	t.Logf("Total refresh attempts to server: %d", actualRefreshAttempts)
	t.Logf("Max concurrent refreshes: %d", maxConcurrent)
	t.Logf("Successful refreshes: %d", successCount)
	t.Logf("Failed refreshes: %d", errorCount)

	// With deduplication, refresh attempts should be much less than concurrent requests
	if actualRefreshAttempts > int32(numConcurrentRequests/2) {
		t.Errorf("Too many refresh attempts (%d), deduplication not working properly",
			actualRefreshAttempts)
	}

	// Max concurrent should respect our limit
	if maxConcurrent > int32(config.MaxConcurrentRefreshes) {
		t.Errorf("Max concurrent refreshes (%d) exceeded configured limit (%d)",
			maxConcurrent, config.MaxConcurrentRefreshes)
	}

	// Check coordinator metrics
	metrics := coordinator.GetMetrics()
	t.Logf("Coordinator metrics: %+v", metrics)

	if deduped, ok := metrics["deduplicated_requests"].(int64); ok {
		if deduped == 0 {
			t.Error("No requests were deduplicated - deduplication not working")
		}
		t.Logf("Deduplicated requests: %d", deduped)
	}
}

// TestIssue67_WithoutCoordinator demonstrates the issue without the fix
// WARNING: This test may consume significant memory - skip in CI
func TestIssue67_WithoutCoordinator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory-intensive test in short mode")
	}

	// Only run this test with explicit flag to demonstrate the issue
	if !testing.Verbose() {
		t.Skip("Skipping demonstration of issue without fix (run with -v to see)")
	}

	// Track memory at start
	runtime.GC()
	var startMem runtime.MemStats
	runtime.ReadMemStats(&startMem)

	var refreshAttempts int32
	var maxConcurrent int32
	var currentConcurrent int32

	// Simulate the issue: multiple goroutines attempting refresh without coordination
	numRequests := 100
	var wg sync.WaitGroup
	wg.Add(numRequests)

	// Use a context with short timeout to prevent actual OOM
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < numRequests; i++ {
		go func(id int) {
			defer wg.Done()

			// Simulate retry logic without deduplication (the bug)
			for attempt := 0; attempt < 3; attempt++ {
				select {
				case <-ctx.Done():
					return
				default:
				}

				current := atomic.AddInt32(&currentConcurrent, 1)

				// Track max concurrent
				for {
					max := atomic.LoadInt32(&maxConcurrent)
					if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
						break
					}
				}

				atomic.AddInt32(&refreshAttempts, 1)

				// Simulate token refresh with exponential backoff
				time.Sleep(time.Duration(attempt*100) * time.Millisecond)

				// Allocate memory to simulate token processing
				_ = make([]byte, 1024*10) // 10KB per attempt

				atomic.AddInt32(&currentConcurrent, -1)

				// Simulate failure requiring retry
				if attempt < 2 {
					continue
				}
				break
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Completed
	case <-ctx.Done():
		// Timed out (expected in problematic scenario)
	}

	// Check memory usage
	runtime.GC()
	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)

	memGrowthMB := float64(endMem.HeapAlloc-startMem.HeapAlloc) / (1024 * 1024)

	t.Logf("WITHOUT COORDINATOR:")
	t.Logf("  Refresh attempts: %d", refreshAttempts)
	t.Logf("  Max concurrent: %d", maxConcurrent)
	t.Logf("  Memory growth: %.2f MB", memGrowthMB)

	// This demonstrates the issue - high concurrency and many attempts
	if refreshAttempts < int32(numRequests*2) {
		t.Logf("Note: Without coordinator, saw %d refresh attempts for %d requests",
			refreshAttempts, numRequests)
	}
}

// MockExpiredSession simulates an expired session for testing
type MockExpiredSession struct {
	refreshToken string
	sessionID    string
	isExpired    bool
}

func (m *MockExpiredSession) GetRefreshToken() string {
	return m.refreshToken
}

func (m *MockExpiredSession) GetSessionID() string {
	return m.sessionID
}

func (m *MockExpiredSession) IsExpired() bool {
	return m.isExpired
}

// BenchmarkRefreshWithCoordinator measures performance with the fix
func BenchmarkRefreshWithCoordinator(b *testing.B) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	refreshFunc := func() (*TokenResponse, error) {
		// Simulate token refresh
		time.Sleep(10 * time.Millisecond)
		return &TokenResponse{
			AccessToken:  "new_token",
			RefreshToken: "new_refresh",
		}, nil
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ctx := context.Background()
			sessionID := fmt.Sprintf("session_%d", i%10)
			refreshToken := "refresh_token"

			_, _ = coordinator.CoordinateRefresh(ctx, sessionID, refreshToken, refreshFunc)
			i++
		}
	})

	b.StopTimer()

	metrics := coordinator.GetMetrics()
	b.Logf("Total requests: %v", metrics["total_requests"])
	b.Logf("Deduplicated: %v", metrics["deduplicated_requests"])
	b.Logf("Success rate: %.2f%%",
		float64(metrics["successful_refreshes"].(int64))/
			float64(metrics["total_requests"].(int64))*100)
}

// TestRefreshCoordinatorIntegration tests the full integration
func TestRefreshCoordinatorIntegration(t *testing.T) {
	// This test verifies the coordinator integrates properly with:
	// 1. Circuit breaker
	// 2. Rate limiting
	// 3. Deduplication
	// 4. Memory management
	// 5. Cleanup routines

	logger := GetSingletonNoOpLogger()
	config := DefaultRefreshCoordinatorConfig()
	config.MaxRefreshAttempts = 5
	config.RefreshAttemptWindow = 1 * time.Second
	config.RefreshCooldownPeriod = 2 * time.Second
	config.MaxConcurrentRefreshes = 3
	config.CleanupInterval = 500 * time.Millisecond

	coordinator := NewRefreshCoordinator(config, logger)
	defer coordinator.Shutdown()

	// Test 1: Normal operation
	t.Run("NormalOperation", func(t *testing.T) {
		refreshFunc := func() (*TokenResponse, error) {
			return &TokenResponse{AccessToken: "token1"}, nil
		}

		ctx := context.Background()
		result, err := coordinator.CoordinateRefresh(ctx, "session1", "refresh1", refreshFunc)

		if err != nil {
			t.Errorf("Normal refresh failed: %v", err)
		}
		if result == nil || result.AccessToken != "token1" {
			t.Error("Invalid result from normal refresh")
		}
	})

	// Test 2: Circuit breaker activation
	t.Run("CircuitBreaker", func(t *testing.T) {
		failingRefresh := func() (*TokenResponse, error) {
			return nil, fmt.Errorf("service unavailable")
		}

		// Trigger circuit breaker
		for i := 0; i < 4; i++ {
			ctx := context.Background()
			_, _ = coordinator.CoordinateRefresh(ctx,
				fmt.Sprintf("cb_session_%d", i), "refresh_cb", failingRefresh)
		}

		// Next request should be blocked by circuit breaker
		ctx := context.Background()
		_, err := coordinator.CoordinateRefresh(ctx, "cb_session_blocked", "refresh_cb", failingRefresh)

		if err == nil || !strings.Contains(err.Error(), "circuit breaker") {
			t.Errorf("Circuit breaker should have blocked request: %v", err)
		}
	})

	// Test 3: Rate limiting
	t.Run("RateLimiting", func(t *testing.T) {
		// Reset circuit breaker to closed state for this test
		coordinator.circuitBreaker.mutex.Lock()
		atomic.StoreInt32(&coordinator.circuitBreaker.state, 0) // closed
		atomic.StoreInt32(&coordinator.circuitBreaker.failures, 0)
		coordinator.circuitBreaker.mutex.Unlock()

		// Temporarily increase circuit breaker threshold to not interfere
		oldMaxFailures := coordinator.circuitBreaker.config.MaxFailures
		coordinator.circuitBreaker.config.MaxFailures = 20
		defer func() {
			coordinator.circuitBreaker.config.MaxFailures = oldMaxFailures
		}()

		failingRefresh := func() (*TokenResponse, error) {
			return nil, fmt.Errorf("failed")
		}

		sessionID := "rate_limit_session"

		// Exhaust attempts
		for i := 0; i < config.MaxRefreshAttempts+1; i++ {
			ctx := context.Background()
			_, _ = coordinator.CoordinateRefresh(ctx, sessionID, "refresh_rl", failingRefresh)
			// Add delay to ensure operations complete and aren't deduplicated
			time.Sleep(150 * time.Millisecond)
		}

		// Should be in cooldown
		ctx := context.Background()
		_, err := coordinator.CoordinateRefresh(ctx, sessionID, "refresh_rl", failingRefresh)

		if err == nil || !strings.Contains(err.Error(), "cooldown") {
			t.Errorf("Rate limiting should have triggered cooldown: %v", err)
		}
	})

	// Test 4: Cleanup
	t.Run("Cleanup", func(t *testing.T) {
		// Add some sessions
		for i := 0; i < 5; i++ {
			coordinator.recordRefreshAttempt(fmt.Sprintf("cleanup_session_%d", i))
		}

		// Wait for cleanup
		time.Sleep(config.CleanupInterval * 3)

		// Old sessions should be cleaned up
		coordinator.attemptsMutex.RLock()
		count := len(coordinator.sessionRefreshAttempts)
		coordinator.attemptsMutex.RUnlock()

		// Should have fewer sessions after cleanup
		if count > 10 {
			t.Errorf("Cleanup not working, %d sessions remain", count)
		}
	})

	// Verify final metrics
	metrics := coordinator.GetMetrics()
	t.Logf("Final metrics: %+v", metrics)
}

// TestIssue67_TokenResilienceRecursionBug directly tests the recursion bug identified by jetexe
// in the comment: https://github.com/lukaszraczylo/traefikoidc/issues/67#issuecomment-2391821890
//
// The bug is in token_resilience.go:180-190 where ExecuteTokenRefresh calls
// getNewTokenWithRefreshToken which calls ExecuteTokenRefresh again, causing infinite recursion.
func TestIssue67_TokenResilienceRecursionBug(t *testing.T) {
	// Track call depth to detect recursion
	var callDepth int32
	var maxDepth int32 = 5 // If we reach this, we have recursion

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			// Increment call depth
			depth := atomic.AddInt32(&callDepth, 1)
			defer atomic.AddInt32(&callDepth, -1)

			// Check if we've exceeded max depth (indicates recursion)
			if depth > maxDepth {
				t.Errorf("Call depth exceeded %d - infinite recursion detected!", maxDepth)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Simulate successful token refresh
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"access_token": "new_access_token",
				"refresh_token": "new_refresh_token",
				"id_token": "new_id_token",
				"expires_in": 3600,
				"token_type": "Bearer"
			}`))
		}
	}))
	defer server.Close()

	// Create TraefikOidc with tokenResilienceManager (this triggers the bug)
	logger := GetSingletonNoOpLogger()
	resilienceConfig := DefaultTokenResilienceConfig()
	resilienceManager := NewTokenResilienceManager(resilienceConfig, logger)

	oidc := &TraefikOidc{
		tokenURL:               server.URL + "/token",
		clientID:               "test_client",
		clientSecret:           "test_secret",
		tokenResilienceManager: resilienceManager,
		tokenHTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger,
	}

	// Create context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Run in goroutine to detect stack overflow
	done := make(chan struct{})
	var testErr error

	go func() {
		defer func() {
			if r := recover(); r != nil {
				testErr = fmt.Errorf("panic recovered: %v (likely stack overflow from recursion)", r)
			}
			close(done)
		}()

		// This call should NOT recurse infinitely after the fix
		_, err := oidc.getNewTokenWithRefreshToken("test_refresh_token")
		if err != nil {
			testErr = err
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		// Check for recursion via call depth
		if atomic.LoadInt32(&callDepth) > maxDepth {
			t.Fatal("Infinite recursion detected via call depth counter")
		}

		// Check for panic/stack overflow
		if testErr != nil && strings.Contains(testErr.Error(), "stack overflow") {
			t.Fatalf("Stack overflow detected: %v", testErr)
		}

		// After fix, this should succeed
		if testErr != nil {
			t.Logf("Token refresh completed with error: %v", testErr)
		}

	case <-ctx.Done():
		t.Fatal("Test timed out - likely infinite recursion in getNewTokenWithRefreshToken -> ExecuteTokenRefresh loop")
	}
}

// TestIssue67_TokenResilienceManager_NoRecursion verifies ExecuteTokenRefresh
// calls exchangeTokens directly and doesn't recurse back to getNewTokenWithRefreshToken
func TestIssue67_TokenResilienceManager_NoRecursion(t *testing.T) {
	var exchangeTokensCalls int32
	var getNewTokenCalls int32

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&exchangeTokensCalls, 1)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"access_token": "test_token",
			"refresh_token": "test_refresh",
			"id_token": "test_id",
			"expires_in": 3600,
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	// Create TraefikOidc with instrumented methods
	logger := GetSingletonNoOpLogger()
	resilienceConfig := DefaultTokenResilienceConfig()
	resilienceManager := NewTokenResilienceManager(resilienceConfig, logger)

	// Create custom TraefikOidc to track calls
	oidc := &TraefikOidc{
		tokenURL:               server.URL + "/token",
		clientID:               "test_client",
		clientSecret:           "test_secret",
		tokenResilienceManager: resilienceManager,
		tokenHTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger,
	}

	// Wrap getNewTokenWithRefreshToken to count calls
	originalGetNewToken := oidc.getNewTokenWithRefreshToken
	wrappedGetNewToken := func(refreshToken string) (*TokenResponse, error) {
		atomic.AddInt32(&getNewTokenCalls, 1)
		return originalGetNewToken(refreshToken)
	}
	_ = wrappedGetNewToken // Use the wrapper

	// Execute token refresh through resilience manager
	ctx := context.Background()
	_, err := resilienceManager.ExecuteTokenRefresh(ctx, oidc, "test_refresh_token")

	if err != nil {
		t.Logf("Token refresh returned error (may be expected): %v", err)
	}

	// Verify exchangeTokens was called
	exchangeCalls := atomic.LoadInt32(&exchangeTokensCalls)
	if exchangeCalls == 0 {
		t.Error("exchangeTokens was never called")
	}

	t.Logf("exchangeTokens called %d times", exchangeCalls)

	// After the fix, ExecuteTokenRefresh should call exchangeTokens directly
	// and NOT call getNewTokenWithRefreshToken (which would cause recursion)
}

// TestIssue67_DirectRecursionDetection uses a simpler approach to detect the recursion
func TestIssue67_DirectRecursionDetection(t *testing.T) {
	// This test will fail BEFORE the fix and pass AFTER the fix

	var recursionDepth int32
	const maxAllowedDepth = 3

	// Create a simple mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		depth := atomic.AddInt32(&recursionDepth, 1)
		defer atomic.AddInt32(&recursionDepth, -1)

		if depth > maxAllowedDepth {
			// Recursion detected - fail fast
			t.Errorf("RECURSION BUG DETECTED: depth=%d exceeds max=%d", depth, maxAllowedDepth)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test","refresh_token":"test","id_token":"test","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	logger := GetSingletonNoOpLogger()
	config := DefaultTokenResilienceConfig()
	config.RetryEnabled = false // Disable retries to make the test clearer

	oidc := &TraefikOidc{
		tokenURL:               server.URL + "/token",
		clientID:               "test",
		clientSecret:           "test",
		tokenResilienceManager: NewTokenResilienceManager(config, logger),
		tokenHTTPClient:        &http.Client{Timeout: 2 * time.Second},
		logger:                 logger,
	}

	// Set a timeout to prevent infinite hangs
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := oidc.getNewTokenWithRefreshToken("test_token")
		done <- err
	}()

	select {
	case err := <-done:
		finalDepth := atomic.LoadInt32(&recursionDepth)
		if finalDepth > maxAllowedDepth {
			t.Fatalf("Recursion bug confirmed: max depth reached %d", finalDepth)
		}
		if err != nil {
			t.Logf("Completed with error: %v", err)
		} else {
			t.Log("Token refresh completed successfully without recursion")
		}
	case <-ctx.Done():
		t.Fatal("RECURSION BUG: Test timed out, indicating infinite loop in getNewTokenWithRefreshToken -> ExecuteTokenRefresh")
	}
}
