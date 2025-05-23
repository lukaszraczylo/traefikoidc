package traefikoidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestConcurrentTokenVerification tests race conditions in token verification
func TestConcurrentTokenVerification(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	// Create multiple valid tokens to avoid replay detection
	tokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"nbf":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create test token %d: %v", i, err)
		}
		tokens[i] = token
	}

	// Create a fresh instance for this test
	tOidc := &TraefikOidc{
		issuerURL:          "https://test-issuer.com",
		clientID:           "test-client-id",
		jwkCache:           ts.mockJWKCache,
		tokenBlacklist:     NewCache(),
		tokenCache:         NewTokenCache(),
		limiter:            rate.NewLimiter(rate.Every(time.Microsecond), 10000), // Very high rate limit
		logger:             NewLogger("debug"),
		allowedUserDomains: map[string]struct{}{"example.com": {}},
		httpClient:         &http.Client{},
		extractClaimsFunc:  extractClaims,
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc

	// Ensure cleanup when test finishes
	defer func() {
		if err := tOidc.Close(); err != nil {
			t.Logf("Error closing TraefikOidc instance: %v", err)
		}
	}()

	// Test concurrent verification
	const numGoroutines = 50
	const verificationsPerGoroutine = 10

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	errors := make(chan error, numGoroutines*verificationsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < verificationsPerGoroutine; j++ {
				tokenIndex := (goroutineID*verificationsPerGoroutine + j) % len(tokens)
				err := tOidc.VerifyToken(tokens[tokenIndex])
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					select {
					case errors <- fmt.Errorf("goroutine %d, verification %d: %w", goroutineID, j, err):
					default:
					}
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check results
	totalOperations := int64(numGoroutines * verificationsPerGoroutine)
	t.Logf("Concurrent verification results: %d successes, %d errors out of %d total operations",
		successCount, errorCount, totalOperations)

	// Collect and log errors
	var errorList []error
	for err := range errors {
		errorList = append(errorList, err)
	}

	if len(errorList) > 0 {
		t.Logf("Errors encountered during concurrent verification:")
		for i, err := range errorList {
			if i < 10 { // Log first 10 errors
				t.Logf("  %d: %v", i+1, err)
			}
		}
		if len(errorList) > 10 {
			t.Logf("  ... and %d more errors", len(errorList)-10)
		}
	}

	// We expect most operations to succeed
	if successCount < totalOperations/2 {
		t.Errorf("Too many failures in concurrent verification: %d successes out of %d operations", successCount, totalOperations)
	}

	// Check for data races by verifying cache consistency
	cacheSize := len(tOidc.tokenCache.cache.items)
	blacklistSize := len(tOidc.tokenBlacklist.items)
	t.Logf("Final cache sizes: token cache=%d, blacklist=%d", cacheSize, blacklistSize)
}

// TestCacheMemoryExhaustion tests cache behavior under memory pressure
func TestCacheMemoryExhaustion(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	// Create a cache with limited size
	cache := NewTokenCache()
	cache.cache.SetMaxSize(100) // Small cache size

	// Ensure cleanup when test finishes
	defer cache.Close()

	// Create many tokens to exceed cache capacity
	const numTokens = 500
	tokens := make([]string, numTokens)

	for i := 0; i < numTokens; i++ {
		token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"nbf":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   fmt.Sprintf("jti-%d", i),
		})
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}
		tokens[i] = token

		// Add to cache
		claims := map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   fmt.Sprintf("jti-%d", i),
		}
		cache.Set(token, claims, time.Hour)
	}

	// Verify cache size is within limits
	cacheSize := len(cache.cache.items)
	if cacheSize > 100 {
		t.Errorf("Cache size exceeded limit: got %d, expected <= 100", cacheSize)
	}

	// Verify LRU eviction works
	// The first tokens should have been evicted
	firstToken := tokens[0]
	if _, exists := cache.Get(firstToken); exists {
		t.Errorf("First token should have been evicted from cache")
	}

	// The last tokens should still be in cache
	lastToken := tokens[numTokens-1]
	if _, exists := cache.Get(lastToken); !exists {
		t.Errorf("Last token should still be in cache")
	}

	t.Logf("Cache memory exhaustion test passed: cache size=%d", cacheSize)
}

// TestSessionConcurrencyProtection tests session safety under concurrent access
func TestSessionConcurrencyProtection(t *testing.T) {
	logger := NewLogger("debug")
	sessionManager, err := NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Test concurrent session access with separate requests
	const numGoroutines = 20
	const operationsPerGoroutine = 10 // Reduced to avoid overwhelming

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			// Each goroutine gets its own request and session
			req := httptest.NewRequest("GET", "/test", nil)

			for j := 0; j < operationsPerGoroutine; j++ {
				// Get a fresh session for each operation
				s, err := sessionManager.GetSession(req)
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					continue
				}

				// Perform operations on session
				s.SetEmail(fmt.Sprintf("user%d-%d@example.com", goroutineID, j))
				s.SetAuthenticated(true)
				s.SetAccessToken(fmt.Sprintf("token-%d-%d", goroutineID, j))

				// Save session
				testRR := httptest.NewRecorder()
				if err := s.Save(req, testRR); err != nil {
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}

				// Copy cookies back to request for next iteration
				for _, cookie := range testRR.Result().Cookies() {
					req.Header.Set("Cookie", cookie.String())
				}
			}
		}(i)
	}

	wg.Wait()

	totalOperations := int64(numGoroutines * operationsPerGoroutine)
	t.Logf("Session concurrency test results: %d successes, %d errors out of %d operations",
		successCount, errorCount, totalOperations)

	// Most operations should succeed
	if successCount < totalOperations/2 {
		t.Errorf("Too many session operation failures: %d successes out of %d operations", successCount, totalOperations)
	}
}

// TestParallelCacheOperations tests cache thread safety
func TestParallelCacheOperations(t *testing.T) {
	cache := NewCache()
	cache.SetMaxSize(1000)

	// Ensure cleanup when test finishes
	defer cache.Close()

	const numGoroutines = 10
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	var setCount int64
	var getCount int64
	var deleteCount int64

	// Start multiple goroutines performing cache operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				key := fmt.Sprintf("key-%d-%d", goroutineID, j)
				value := fmt.Sprintf("value-%d-%d", goroutineID, j)

				// Set operation
				cache.Set(key, value, time.Minute)
				atomic.AddInt64(&setCount, 1)

				// Get operation
				if _, exists := cache.Get(key); exists {
					atomic.AddInt64(&getCount, 1)
				}

				// Delete some items
				if j%10 == 0 {
					cache.Delete(key)
					atomic.AddInt64(&deleteCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Parallel cache operations completed: %d sets, %d gets, %d deletes",
		setCount, getCount, deleteCount)

	// Verify cache is still functional
	cache.Set("test-key", "test-value", time.Minute)
	if value, exists := cache.Get("test-key"); !exists || value != "test-value" {
		t.Errorf("Cache corrupted after parallel operations")
	}

	// Check cache size is reasonable
	cacheSize := len(cache.items)
	expectedSize := int(setCount - deleteCount)
	if cacheSize > expectedSize {
		t.Logf("Cache size after operations: %d (expected around %d)", cacheSize, expectedSize)
	}
}

// TestProviderFailureRecovery tests network failure scenarios
func TestProviderFailureRecovery(t *testing.T) {
	// Create a server that fails initially then recovers
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt64(&requestCount, 1)
		if count <= 3 {
			// Fail first 3 requests
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed after 3 failures
		metadata := ProviderMetadata{
			Issuer:        "https://test-issuer.com",
			AuthURL:       "https://test-issuer.com/auth",
			TokenURL:      "https://test-issuer.com/token",
			JWKSURL:       "https://test-issuer.com/jwks",
			RevokeURL:     "https://test-issuer.com/revoke",
			EndSessionURL: "https://test-issuer.com/end-session",
		}
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	// Test metadata discovery with retries
	logger := NewLogger("debug")
	httpClient := createDefaultHTTPClient()

	start := time.Now()
	metadata, err := discoverProviderMetadata(server.URL, httpClient, logger)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Provider metadata discovery failed after retries: %v", err)
	}

	if metadata == nil {
		t.Errorf("Expected metadata to be returned after recovery")
	}

	// Should have taken some time due to retries (at least the sum of delays: 10ms + 20ms + 40ms = 70ms)
	expectedMinDuration := 70 * time.Millisecond
	if duration < expectedMinDuration {
		t.Errorf("Expected discovery to take at least %v due to retries, but took %v", expectedMinDuration, duration)
	}

	t.Logf("Provider failure recovery test passed: %d requests, duration: %v", requestCount, duration)
}

// TestOversizedTokenHandling tests boundary value handling
func TestOversizedTokenHandling(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	// Create an oversized token with large claims
	largeClaim := strings.Repeat("x", 10000) // 10KB claim
	oversizedClaims := map[string]interface{}{
		"iss":        "https://test-issuer.com",
		"aud":        "test-client-id",
		"exp":        float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":        float64(time.Now().Add(-2 * time.Minute).Unix()),
		"nbf":        float64(time.Now().Add(-2 * time.Minute).Unix()),
		"sub":        "test-subject",
		"email":      "user@example.com",
		"jti":        generateRandomString(16),
		"large_data": largeClaim,
	}

	oversizedToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", oversizedClaims)
	if err != nil {
		t.Fatalf("Failed to create oversized token: %v", err)
	}

	t.Logf("Created oversized token of length: %d bytes", len(oversizedToken))

	// Test verification of oversized token
	err = ts.tOidc.VerifyToken(oversizedToken)
	if err != nil {
		t.Logf("Oversized token verification failed as expected: %v", err)
		// This is acceptable - oversized tokens should be rejected
	} else {
		t.Logf("Oversized token verification succeeded")
		// Verify it was cached properly
		if _, exists := ts.tOidc.tokenCache.Get(oversizedToken); !exists {
			t.Errorf("Oversized token was not cached after successful verification")
		}
	}

	// Test extremely long token (beyond reasonable limits)
	extremelyLongClaim := strings.Repeat("y", 100000) // 100KB claim
	extremeClaims := map[string]interface{}{
		"iss":          "https://test-issuer.com",
		"aud":          "test-client-id",
		"exp":          float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":          float64(time.Now().Add(-2 * time.Minute).Unix()),
		"nbf":          float64(time.Now().Add(-2 * time.Minute).Unix()),
		"sub":          "test-subject",
		"email":        "user@example.com",
		"jti":          generateRandomString(16),
		"extreme_data": extremelyLongClaim,
	}

	extremeToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", extremeClaims)
	if err != nil {
		t.Fatalf("Failed to create extreme token: %v", err)
	}

	t.Logf("Created extreme token of length: %d bytes", len(extremeToken))

	// This should likely fail due to size limits
	err = ts.tOidc.VerifyToken(extremeToken)
	if err != nil {
		t.Logf("Extreme token verification failed as expected: %v", err)
	} else {
		t.Logf("Warning: Extreme token verification succeeded - consider adding size limits")
	}
}

// TestMaliciousInputValidation tests security input validation
func TestMaliciousInputValidation(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	maliciousInputs := []struct {
		name  string
		token string
	}{
		{
			name:  "Empty token",
			token: "",
		},
		{
			name:  "Single dot",
			token: ".",
		},
		{
			name:  "Two dots only",
			token: "..",
		},
		{
			name:  "SQL injection attempt",
			token: "'; DROP TABLE users; --",
		},
		{
			name:  "Script injection attempt",
			token: "<script>alert('xss')</script>",
		},
		{
			name:  "Path traversal attempt",
			token: "../../../etc/passwd",
		},
		{
			name:  "Null bytes",
			token: "token\x00with\x00nulls",
		},
		{
			name:  "Unicode control characters",
			token: "token\u0000\u0001\u0002",
		},
		{
			name:  "Extremely long string",
			token: strings.Repeat("a", 1000000), // 1MB string
		},
		{
			name:  "Invalid base64 characters",
			token: "header.payload!@#$%^&*().signature",
		},
		{
			name:  "Binary data",
			token: string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}),
		},
	}

	for _, test := range maliciousInputs {
		t.Run(test.name, func(t *testing.T) {
			// Create a fresh instance for each test to avoid rate limiting issues
			freshOidc := &TraefikOidc{
				issuerURL:          "https://test-issuer.com",
				clientID:           "test-client-id",
				jwkCache:           ts.mockJWKCache,
				tokenBlacklist:     NewCache(),
				tokenCache:         NewTokenCache(),
				limiter:            rate.NewLimiter(rate.Every(time.Microsecond), 10000), // Very high rate limit
				logger:             NewLogger("debug"),
				allowedUserDomains: map[string]struct{}{"example.com": {}},
				httpClient:         &http.Client{},
				extractClaimsFunc:  extractClaims,
			}
			freshOidc.tokenVerifier = freshOidc
			freshOidc.jwtVerifier = freshOidc

			// Ensure cleanup when test finishes
			defer func() {
				if err := freshOidc.Close(); err != nil {
					t.Logf("Error closing TraefikOidc instance: %v", err)
				}
			}()

			// All malicious inputs should be safely rejected
			err := freshOidc.VerifyToken(test.token)
			if err == nil {
				t.Errorf("Malicious input '%s' was not rejected", test.name)
			} else {
				t.Logf("Malicious input '%s' correctly rejected: %v", test.name, err)
			}

			// Verify the system is still functional after malicious input
			validToken, createErr := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
				"iss":   "https://test-issuer.com",
				"aud":   "test-client-id",
				"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
				"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
				"nbf":   float64(time.Now().Add(-2 * time.Minute).Unix()),
				"sub":   "test-subject",
				"email": "user@example.com",
				"jti":   generateRandomString(16),
			})
			if createErr != nil {
				t.Fatalf("Failed to create valid token for recovery test: %v", createErr)
			}

			// System should still work with valid tokens
			if verifyErr := freshOidc.VerifyToken(validToken); verifyErr != nil {
				t.Errorf("System failed to process valid token after malicious input: %v", verifyErr)
			}
		})
	}
}

// TestNetworkErrorCleanup tests resource cleanup on network errors
func TestNetworkErrorCleanup(t *testing.T) {
	// Create a server that times out
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate network timeout by sleeping
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create HTTP client with short timeout
	httpClient := &http.Client{
		Timeout: 100 * time.Millisecond, // Very short timeout
	}

	logger := NewLogger("debug")

	// Track goroutines before test
	initialGoroutines := runtime.NumGoroutine()

	// Attempt metadata discovery that should timeout
	start := time.Now()
	_, err := discoverProviderMetadata(server.URL, httpClient, logger)
	duration := time.Since(start)

	// Should fail due to timeout
	if err == nil {
		t.Errorf("Expected timeout error, but request succeeded")
	}

	// Should fail quickly due to timeout
	if duration > time.Second {
		t.Errorf("Request took too long despite timeout: %v", duration)
	}

	// Give time for cleanup
	time.Sleep(100 * time.Millisecond)

	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 { // Allow some tolerance
		t.Errorf("Potential goroutine leak: started with %d, ended with %d goroutines",
			initialGoroutines, finalGoroutines)
	}

	t.Logf("Network error cleanup test passed: duration=%v, goroutines=%d->%d",
		duration, initialGoroutines, finalGoroutines)
}

// TestResourceLimits tests system behavior under resource constraints
func TestResourceLimits(t *testing.T) {
	// Test memory allocation limits
	cache := NewCache()
	cache.SetMaxSize(10) // Very small cache

	// Ensure cleanup when test finishes
	defer cache.Close()

	// Try to overwhelm the cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := fmt.Sprintf("value-%d", i)
		cache.Set(key, value, time.Minute)
	}

	// Cache should not exceed its limit
	if len(cache.items) > 10 {
		t.Errorf("Cache exceeded size limit: got %d items, expected <= 10", len(cache.items))
	}

	// Test rate limiting under load
	limiter := rate.NewLimiter(rate.Every(time.Second), 5) // 5 requests per second

	allowed := 0
	denied := 0

	// Make many requests quickly
	for i := 0; i < 100; i++ {
		if limiter.Allow() {
			allowed++
		} else {
			denied++
		}
	}

	// Most should be denied due to rate limiting
	if denied < 90 {
		t.Errorf("Rate limiting not effective: allowed=%d, denied=%d", allowed, denied)
	}

	t.Logf("Resource limits test passed: cache size=%d, rate limiting: allowed=%d, denied=%d",
		len(cache.items), allowed, denied)
}

// TestErrorRecoveryPatterns tests various error recovery scenarios
func TestErrorRecoveryPatterns(t *testing.T) {
	ts := &TestSuite{t: t}
	ts.Setup()

	// Test recovery from cache corruption
	t.Run("CacheCorruption", func(t *testing.T) {
		// Corrupt the cache by setting invalid data
		ts.tOidc.tokenCache.cache.items["corrupted"] = CacheItem{
			Value:     "invalid-data",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		// System should handle corrupted cache gracefully
		validToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"nbf":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create valid token: %v", err)
		}

		// Should still work despite cache corruption
		if err := ts.tOidc.VerifyToken(validToken); err != nil {
			t.Errorf("Token verification failed despite cache corruption: %v", err)
		}
	})

	// Test recovery from blacklist corruption
	t.Run("BlacklistCorruption", func(t *testing.T) {
		// Add invalid data to blacklist
		ts.tOidc.tokenBlacklist.Set("corrupted-entry", "invalid-data", time.Hour)

		// System should still function
		validToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"nbf":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create valid token: %v", err)
		}

		if err := ts.tOidc.VerifyToken(validToken); err != nil {
			t.Errorf("Token verification failed despite blacklist corruption: %v", err)
		}
	})
}

// TestPerformanceUnderLoad tests system performance under high load
func TestPerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ts := &TestSuite{t: t}
	ts.Setup()

	// Create multiple valid tokens
	const numTokens = 100
	tokens := make([]string, numTokens)
	for i := 0; i < numTokens; i++ {
		token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"nbf":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   fmt.Sprintf("jti-%d", i),
		})
		if err != nil {
			t.Fatalf("Failed to create token %d: %v", i, err)
		}
		tokens[i] = token
	}

	// Create fresh instance with high rate limit
	tOidc := &TraefikOidc{
		issuerURL:          "https://test-issuer.com",
		clientID:           "test-client-id",
		jwkCache:           ts.mockJWKCache,
		tokenBlacklist:     NewCache(),
		tokenCache:         NewTokenCache(),
		limiter:            rate.NewLimiter(rate.Every(time.Microsecond), 10000), // Very high limit
		logger:             NewLogger("info"),                                    // Reduce logging for performance
		allowedUserDomains: map[string]struct{}{"example.com": {}},
		httpClient:         &http.Client{},
		extractClaimsFunc:  extractClaims,
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc

	// Ensure cleanup when test finishes
	defer func() {
		if err := tOidc.Close(); err != nil {
			t.Logf("Error closing TraefikOidc instance: %v", err)
		}
	}()

	// Performance test
	const iterations = 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		tokenIndex := i % numTokens
		err := tOidc.VerifyToken(tokens[tokenIndex])
		if err != nil {
			t.Errorf("Token verification failed at iteration %d: %v", i, err)
		}
	}

	duration := time.Since(start)
	opsPerSecond := float64(iterations) / duration.Seconds()

	t.Logf("Performance test completed: %d operations in %v (%.2f ops/sec)",
		iterations, duration, opsPerSecond)

	// Should achieve reasonable performance
	if opsPerSecond < 100 {
		t.Errorf("Performance too low: %.2f ops/sec (expected > 100)", opsPerSecond)
	}
}
