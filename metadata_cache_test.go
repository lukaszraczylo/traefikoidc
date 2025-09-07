package traefikoidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// MetadataCacheTestSuite provides comprehensive testing for MetadataCache
type MetadataCacheTestSuite struct {
	runner    *TestSuiteRunner
	factory   *TestDataFactory
	edgeGen   *EdgeCaseGenerator
	perfTest  *PerformanceTestHelper
	mockWG    *sync.WaitGroup
	logger    *Logger
	testCache *MetadataCache
}

// NewMetadataCacheTestSuite creates a new test suite for MetadataCache
func NewMetadataCacheTestSuite() *MetadataCacheTestSuite {
	return &MetadataCacheTestSuite{
		runner:   NewTestSuiteRunner(),
		factory:  NewTestDataFactory(),
		edgeGen:  NewEdgeCaseGenerator(),
		perfTest: NewPerformanceTestHelper(),
		mockWG:   &sync.WaitGroup{},
		logger:   NewLogger("error"),
	}
}

// setup creates a new MetadataCache for testing
func (suite *MetadataCacheTestSuite) setup() {
	suite.testCache = NewMetadataCacheWithLogger(suite.mockWG, suite.logger)
}

// cleanup cleans up test resources
func (suite *MetadataCacheTestSuite) cleanup() {
	if suite.testCache != nil {
		suite.testCache.Close()
	}
	suite.perfTest.Reset()
}

// createTestServer creates a mock HTTP server for testing
func (suite *MetadataCacheTestSuite) createTestServer(metadata *ProviderMetadata, statusCode int, delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			time.Sleep(delay)
		}

		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK && metadata != nil {
			json.NewEncoder(w).Encode(metadata)
		}
	}))
}

// createErrorClient creates an HTTP client that returns errors
func (suite *MetadataCacheTestSuite) createErrorClient(err error) *http.Client {
	return &http.Client{
		Transport: &errorRoundTripper{err: err},
	}
}

// createTimeoutClient creates an HTTP client with timeout
func (suite *MetadataCacheTestSuite) createTimeoutClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
}

// errorRoundTripper implements http.RoundTripper for error testing
type errorRoundTripper struct {
	err error
}

func (e *errorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, e.err
}

// TestMetadataCache_BasicOperations tests basic cache operations
func TestMetadataCache_BasicOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping basic operations test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	suite := NewMetadataCacheTestSuite()

	tests := []TableTestCase{
		{
			Name:        "CleanupExpiredMetadata",
			Description: "Test that expired metadata is removed during cleanup",
			Setup: func(t *testing.T) error {
				suite.setup()
				// Set expired metadata
				suite.testCache.metadata = &ProviderMetadata{Issuer: "test"}
				suite.testCache.expiresAt = time.Now().Add(-1 * time.Hour)
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "CleanupValidMetadata",
			Description: "Test that valid metadata is not removed during cleanup",
			Setup: func(t *testing.T) error {
				suite.setup()
				// Set valid metadata
				suite.testCache.metadata = &ProviderMetadata{Issuer: "test"}
				suite.testCache.expiresAt = time.Now().Add(1 * time.Hour)
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "CleanupNilMetadata",
			Description: "Test cleanup when metadata is nil",
			Setup: func(t *testing.T) error {
				suite.setup()
				suite.testCache.metadata = nil
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
	}

	// Run basic cleanup tests
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}
			defer func() {
				if test.Teardown != nil {
					if err := test.Teardown(t); err != nil {
						t.Errorf("Teardown failed: %v", err)
					}
				}
			}()

			originalMetadata := suite.testCache.metadata
			suite.testCache.Cleanup()

			switch test.Name {
			case "CleanupExpiredMetadata":
				if suite.testCache.metadata != nil {
					t.Error("Expected expired metadata to be nil after cleanup")
				}
			case "CleanupValidMetadata":
				if suite.testCache.metadata != originalMetadata {
					t.Error("Expected valid metadata to remain after cleanup")
				}
			case "CleanupNilMetadata":
				if suite.testCache.metadata != nil {
					t.Error("Expected metadata to remain nil after cleanup")
				}
			}
		})
	}
}

// TestMetadataCache_CacheHitMiss tests cache hit and miss scenarios
func TestMetadataCache_CacheHitMiss(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cache hit/miss test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	suite := NewMetadataCacheTestSuite()
	testMetadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
		JWKSURL:  "https://example.com/jwks",
	}

	server := suite.createTestServer(testMetadata, http.StatusOK, 0)
	defer server.Close()

	tests := []TableTestCase{
		{
			Name:        "CacheHit_ValidMetadata",
			Description: "Test cache hit with valid cached metadata",
			Setup: func(t *testing.T) error {
				suite.setup()
				suite.testCache.metadata = testMetadata
				suite.testCache.expiresAt = time.Now().Add(1 * time.Hour)
				suite.testCache.providerURL = server.URL
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "CacheMiss_ExpiredMetadata",
			Description: "Test cache miss with expired metadata triggers refresh",
			Setup: func(t *testing.T) error {
				suite.setup()
				suite.testCache.metadata = testMetadata
				suite.testCache.expiresAt = time.Now().Add(-1 * time.Hour)
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "CacheMiss_NoMetadata",
			Description: "Test cache miss when no metadata exists",
			Setup: func(t *testing.T) error {
				suite.setup()
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}
			defer func() {
				if test.Teardown != nil {
					if err := test.Teardown(t); err != nil {
						t.Errorf("Teardown failed: %v", err)
					}
				}
			}()

			result, err := suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)

			switch test.Name {
			case "CacheHit_ValidMetadata":
				if err != nil {
					t.Errorf("Expected no error for cache hit, got: %v", err)
				}
				if result != testMetadata {
					t.Error("Expected cached metadata to be returned")
				}
			case "CacheMiss_ExpiredMetadata", "CacheMiss_NoMetadata":
				if err != nil {
					t.Errorf("Expected no error after refresh, got: %v", err)
				}
				if result == nil {
					t.Error("Expected metadata to be fetched and returned")
				}
			}
		})
	}
}

// TestMetadataCache_ErrorHandling tests error scenarios
func TestMetadataCache_ErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping error handling test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	suite := NewMetadataCacheTestSuite()

	tests := []TableTestCase{
		{
			Name:        "NetworkError_NoCache",
			Description: "Test network error when no cached data exists",
			Setup: func(t *testing.T) error {
				suite.setup()
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "NetworkError_WithExpiredCache",
			Description: "Test network error with expired cached data falls back to cache",
			Setup: func(t *testing.T) error {
				suite.setup()
				suite.testCache.metadata = &ProviderMetadata{Issuer: "cached"}
				suite.testCache.expiresAt = time.Now().Add(-1 * time.Minute)
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "HTTPError_404",
			Description: "Test HTTP 404 error handling",
			Setup: func(t *testing.T) error {
				suite.setup()
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
		{
			Name:        "HTTPError_500",
			Description: "Test HTTP 500 error handling",
			Setup: func(t *testing.T) error {
				suite.setup()
				return nil
			},
			Teardown: func(t *testing.T) error {
				suite.cleanup()
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				if err := test.Setup(t); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}
			defer func() {
				if test.Teardown != nil {
					if err := test.Teardown(t); err != nil {
						t.Errorf("Teardown failed: %v", err)
					}
				}
			}()

			var client *http.Client
			var url string

			switch test.Name {
			case "NetworkError_NoCache", "NetworkError_WithExpiredCache":
				client = suite.createErrorClient(fmt.Errorf("network error"))
				url = "http://example.com"
			case "HTTPError_404":
				server := suite.createTestServer(nil, http.StatusNotFound, 0)
				defer server.Close()
				client = server.Client()
				url = server.URL
			case "HTTPError_500":
				server := suite.createTestServer(nil, http.StatusInternalServerError, 0)
				defer server.Close()
				client = server.Client()
				url = server.URL
			}

			result, err := suite.testCache.GetMetadata(url, client, suite.logger)

			switch test.Name {
			case "NetworkError_NoCache", "HTTPError_404", "HTTPError_500":
				if err == nil {
					t.Error("Expected error when no cached data and network/HTTP error")
				}
				if result != nil {
					t.Error("Expected nil result on error without cached data")
				}
			case "NetworkError_WithExpiredCache":
				if err != nil {
					t.Errorf("Expected no error with fallback to cache, got: %v", err)
				}
				if result == nil || result.Issuer != "cached" {
					t.Error("Expected fallback to cached data")
				}
			}
		})
	}
}

// TestMetadataCache_Concurrency tests concurrent access patterns
func TestMetadataCache_Concurrency(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeConcurrencyStress) {
		return
	}

	suite := NewMetadataCacheTestSuite()
	suite.setup()
	defer suite.cleanup()

	testMetadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
	}

	server := suite.createTestServer(testMetadata, http.StatusOK, 10*time.Millisecond)
	defer server.Close()

	numGoroutines := config.AdjustConcurrencyParams(50)
	numRequests := config.MaxIterations
	if numRequests > 10 {
		numRequests = 10
	}

	var wg sync.WaitGroup
	results := make(chan *ProviderMetadata, numGoroutines*numRequests)
	errors := make(chan error, numGoroutines*numRequests)

	// Test concurrent GetMetadata calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numRequests; j++ {
				result, err := suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)
				if err != nil {
					errors <- err
				} else {
					results <- result
				}
			}
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Unexpected error in concurrent test: %v", err)
	}

	// Check results consistency
	var firstResult *ProviderMetadata
	resultCount := 0
	for result := range results {
		resultCount++
		if firstResult == nil {
			firstResult = result
		}
		if result.Issuer != firstResult.Issuer {
			t.Error("Inconsistent results from concurrent calls")
		}
	}

	expectedResults := numGoroutines * numRequests
	if resultCount != expectedResults {
		t.Errorf("Expected %d results, got %d", expectedResults, resultCount)
	}
}

// TestMetadataCache_AutoCleanup tests automatic cleanup functionality
func TestMetadataCache_AutoCleanup(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	suite := NewMetadataCacheTestSuite()

	// Create cache with cleanup interval adjusted for test mode
	cleanupInterval := config.GetCleanupInterval()
	cache := &MetadataCache{
		autoCleanupInterval: cleanupInterval,
		logger:              suite.logger,
		wg:                  suite.mockWG,
		stopChan:            make(chan struct{}),
	}
	cache.startAutoCleanup()
	defer cache.Close()

	// Set expired metadata
	cache.mutex.Lock()
	cache.metadata = &ProviderMetadata{Issuer: "test"}
	cache.expiresAt = time.Now().Add(-cleanupInterval)
	cache.mutex.Unlock()

	// Wait for auto cleanup (adjusted for config)
	waitTime := cleanupInterval * 3
	if waitTime > 500*time.Millisecond {
		waitTime = 500 * time.Millisecond
	}
	time.Sleep(waitTime)

	cache.mutex.RLock()
	result := cache.metadata
	cache.mutex.RUnlock()

	if result != nil {
		t.Error("Expected auto cleanup to clear expired metadata")
	}
}

// TestMetadataCache_EdgeCases tests edge cases
func TestMetadataCache_EdgeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping edge cases test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	suite := NewMetadataCacheTestSuite()
	edgeCaseURLs := []string{
		"",                                 // Empty URL
		"invalid-url",                      // Invalid URL format
		"http://",                          // Incomplete URL
		"https://nonexistent.domain.local", // Non-existent domain
		"http://localhost:99999",           // Invalid port
		strings.Repeat("http://very-long-domain", 100), // Very long URL
	}

	for _, url := range edgeCaseURLs {
		t.Run(fmt.Sprintf("EdgeCase_%s", url), func(t *testing.T) {
			suite.setup()
			defer suite.cleanup()

			client := suite.createTimeoutClient(1 * time.Second)
			result, err := suite.testCache.GetMetadata(url, client, suite.logger)

			// Edge cases should generally fail
			if err == nil && url == "" {
				t.Error("Expected error for empty URL")
			}
			if result != nil && strings.HasPrefix(url, "http://nonexistent") {
				t.Error("Expected nil result for non-existent domain")
			}
		})
	}
}

// TestMetadataCache_MemoryLeaks tests for memory leaks
func TestMetadataCache_MemoryLeaks(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMetadataCacheTestSuite()

	leakTests := []MemoryLeakTestCase{
		{
			Name:               "CreateAndDestroy_Cache",
			Description:        "Test creating and destroying cache instances",
			Iterations:         config.MaxIterations * 10, // Scale with config
			MaxGoroutineGrowth: config.GoroutineGrowth,
			MaxMemoryGrowthMB:  config.MemoryThreshold,
			GCBetweenRuns:      true,
			Operation: func() error {
				cache := NewMetadataCacheWithLogger(&sync.WaitGroup{}, suite.logger)
				defer cache.Close()

				// Add some metadata
				cache.metadata = &ProviderMetadata{Issuer: "test"}
				cache.expiresAt = time.Now().Add(1 * time.Hour)

				return nil
			},
		},
		{
			Name:               "ConcurrentOperations",
			Description:        "Test concurrent cache operations",
			Iterations:         config.MaxIterations * 5,
			MaxGoroutineGrowth: config.GoroutineGrowth * 2,
			MaxMemoryGrowthMB:  config.MemoryThreshold * 2,
			GCBetweenRuns:      true,
			Operation: func() error {
				cache := NewMetadataCacheWithLogger(&sync.WaitGroup{}, suite.logger)
				defer cache.Close()

				testMetadata := &ProviderMetadata{Issuer: "test"}
				server := suite.createTestServer(testMetadata, http.StatusOK, 0)
				defer server.Close()

				var wg sync.WaitGroup
				concurrency := config.AdjustConcurrencyParams(10)
				for i := 0; i < concurrency; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						cache.GetMetadata(server.URL, server.Client(), suite.logger)
					}()
				}
				wg.Wait()

				return nil
			},
		},
	}

	// Adjust all test cases based on configuration
	for i := range leakTests {
		config.AdjustMemoryLeakTestCase(&leakTests[i])
	}

	runner := NewTestSuiteRunner()
	runner.RunMemoryLeakTests(t, leakTests)
}

// TestMetadataCache_Performance tests performance characteristics
func TestMetadataCache_Performance(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	suite := NewMetadataCacheTestSuite()
	suite.setup()
	defer suite.cleanup()

	testMetadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
	}

	server := suite.createTestServer(testMetadata, http.StatusOK, 1*time.Millisecond)
	defer server.Close()

	// Warm up the cache
	suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)

	// Test cache hit performance with adjusted iterations
	iterations := config.MaxIterations * 100
	if iterations > 1000 && config.QuickMode {
		iterations = 100
	}
	for i := 0; i < iterations; i++ {
		duration := suite.perfTest.Measure(func() {
			suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)
		})

		// Cache hits should be fast (< 1ms typically)
		if duration > 10*time.Millisecond {
			t.Errorf("Cache hit too slow: %v (iteration %d)", duration, i)
		}
	}

	avgTime := suite.perfTest.GetAverageTime()
	t.Logf("Average cache hit time: %v over %d iterations", avgTime, iterations)

	if avgTime > 5*time.Millisecond {
		t.Errorf("Average cache hit time too slow: %v", avgTime)
	}
}

// TestMetadataCache_ThreadSafety tests thread safety with race conditions
func TestMetadataCache_ThreadSafety(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeConcurrencyStress) {
		return
	}

	suite := NewMetadataCacheTestSuite()
	suite.setup()
	defer suite.cleanup()

	testMetadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
	}

	server := suite.createTestServer(testMetadata, http.StatusOK, 50*time.Millisecond)
	defer server.Close()

	// Test with race detector enabled - adjust based on config
	numGoroutines := config.AdjustConcurrencyParams(20)
	numOperations := config.MaxIterations * 10
	if numOperations > 100 && config.QuickMode {
		numOperations = 10
	}

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines*numOperations)

	// Run many concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				// Mix different operations to test race conditions
				switch j % 4 {
				case 0:
					// Test GetMetadata
					_, err := suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)
					if err != nil {
						errChan <- fmt.Errorf("goroutine %d GetMetadata failed: %v", id, err)
					}
				case 1:
					// Test Cleanup
					suite.testCache.Cleanup()
				case 2:
					// Test direct cache access (simulating expiration check)
					suite.testCache.mutex.RLock()
					_ = suite.testCache.metadata
					suite.testCache.mutex.RUnlock()
				case 3:
					// Test setting expired metadata
					suite.testCache.mutex.Lock()
					if suite.testCache.metadata != nil {
						suite.testCache.expiresAt = time.Now().Add(-1 * time.Minute)
					}
					suite.testCache.mutex.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Check for race condition errors
	for err := range errChan {
		t.Errorf("Thread safety test failed: %v", err)
	}
}

// TestMetadataCache_TimeoutHandling tests various timeout scenarios
func TestMetadataCache_TimeoutHandling(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	suite := NewMetadataCacheTestSuite()

	tests := []struct {
		name          string
		serverDelay   time.Duration
		clientTimeout time.Duration
		expectTimeout bool
	}{
		{
			name:          "FastResponse",
			serverDelay:   10 * time.Millisecond,
			clientTimeout: 1 * time.Second,
			expectTimeout: false,
		},
		{
			name:          "SlowResponse_WithinTimeout",
			serverDelay:   100 * time.Millisecond,
			clientTimeout: 200 * time.Millisecond,
			expectTimeout: false,
		},
		{
			name:          "SlowResponse_ExceedsTimeout",
			serverDelay:   200 * time.Millisecond,
			clientTimeout: 100 * time.Millisecond,
			expectTimeout: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			suite.setup()
			defer suite.cleanup()

			testMetadata := &ProviderMetadata{Issuer: "https://example.com"}
			server := suite.createTestServer(testMetadata, http.StatusOK, test.serverDelay)
			defer server.Close()

			client := suite.createTimeoutClient(test.clientTimeout)

			result, err := suite.testCache.GetMetadata(server.URL, client, suite.logger)

			if test.expectTimeout {
				if err == nil {
					t.Error("Expected timeout error but got none")
				}
				if result != nil {
					t.Error("Expected nil result on timeout")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if result == nil {
					t.Error("Expected metadata result")
				}
			}
		})
	}
}

// TestMetadataCache_ErrorRecovery tests error recovery scenarios
func TestMetadataCache_ErrorRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping error recovery test in short mode")
	}

	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeExtended) {
		return
	}

	suite := NewMetadataCacheTestSuite()
	suite.setup()
	defer suite.cleanup()

	// Skip this test if ErrorRecoveryManager isn't available
	// This tests the GetMetadataWithRecovery method when available
	t.Run("ErrorRecovery_Integration", func(t *testing.T) {
		// This is a placeholder test - in a real scenario, you would test
		// the GetMetadataWithRecovery method if ErrorRecoveryManager is available
		// For now, we'll just verify the basic GetMetadata functionality

		testMetadata := &ProviderMetadata{Issuer: "https://example.com"}
		server := suite.createTestServer(testMetadata, http.StatusOK, 0)
		defer server.Close()

		result, err := suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result == nil {
			t.Error("Expected metadata result")
		}
	})
}

// TestMetadataCache_Close tests proper resource cleanup
func TestMetadataCache_Close(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	suite := NewMetadataCacheTestSuite()

	t.Run("Close_MultipleCallsSafe", func(t *testing.T) {
		cache := NewMetadataCacheWithLogger(&sync.WaitGroup{}, suite.logger)

		// Close multiple times should be safe
		cache.Close()
		cache.Close()
		cache.Close()

		// Verify metadata is cleared
		if cache.metadata != nil {
			t.Error("Expected metadata to be cleared after close")
		}
	})

	t.Run("Close_WithActiveOperations", func(t *testing.T) {
		cache := NewMetadataCacheWithLogger(&sync.WaitGroup{}, suite.logger)
		testMetadata := &ProviderMetadata{Issuer: "test"}

		// Reduce server delay for race testing
		serverDelay := 100 * time.Millisecond
		if testing.Short() {
			serverDelay = 10 * time.Millisecond
		}
		server := suite.createTestServer(testMetadata, http.StatusOK, serverDelay)
		defer server.Close()

		// Start some operations - reduced count for race testing
		numOperations := 5
		if testing.Short() {
			numOperations = 2
		}
		var wg sync.WaitGroup
		for i := 0; i < numOperations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cache.GetMetadata(server.URL, server.Client(), suite.logger)
			}()
		}

		// Close while operations are running - reduced delay for race testing
		go func() {
			closeDelay := 50 * time.Millisecond
			if testing.Short() {
				closeDelay = 5 * time.Millisecond
			}
			time.Sleep(closeDelay)
			cache.Close()
		}()

		wg.Wait()

		// Wait a bit more to ensure Close() completes - reduced for race testing
		finalWait := 10 * time.Millisecond
		if testing.Short() {
			finalWait = 2 * time.Millisecond
		}
		time.Sleep(finalWait)

		// Should not panic or cause issues - main test is that it doesn't deadlock
		// Note: metadata might still be present if operations completed successfully before close
		// The main goal is to test that Close() doesn't cause deadlocks or crashes
	})
}

// Benchmark tests for performance analysis
func BenchmarkMetadataCache_CacheHit(b *testing.B) {
	suite := NewMetadataCacheTestSuite()
	suite.setup()
	defer suite.cleanup()

	// Set up cached data
	suite.testCache.metadata = &ProviderMetadata{Issuer: "test"}
	suite.testCache.expiresAt = time.Now().Add(1 * time.Hour)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			suite.testCache.GetMetadata("http://example.com", http.DefaultClient, suite.logger)
		}
	})
}

func BenchmarkMetadataCache_ConcurrentAccess(b *testing.B) {
	suite := NewMetadataCacheTestSuite()
	suite.setup()
	defer suite.cleanup()

	testMetadata := &ProviderMetadata{Issuer: "test"}
	server := suite.createTestServer(testMetadata, http.StatusOK, 0)
	defer server.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			suite.testCache.GetMetadata(server.URL, server.Client(), suite.logger)
		}
	})
}
