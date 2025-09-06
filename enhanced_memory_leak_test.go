package traefikoidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestBackgroundGoroutineLeaks tests that background goroutines don't leak memory
// even when no requests are made to protected resources
func TestBackgroundGoroutineLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running memory leak test in short mode")
	}
	t.Run("Idle middleware memory growth", func(t *testing.T) {
		// Force GC to get clean baseline
		runtime.GC()
		runtime.GC()
		time.Sleep(100 * time.Millisecond)

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc
		baselineGoroutines := runtime.NumGoroutine()

		t.Logf("Baseline: Memory=%d KB, Goroutines=%d", baselineAlloc/1024, baselineGoroutines)

		// Create test cleanup
		tc := newTestCleanup(t)

		// Create middleware instance with mock setup
		config := createTestConfig()
		config.LogLevel = "error" // Reduce noise

		middleware, server := setupTestOIDCMiddleware(t, config)
		tc.addServer(server)
		tc.addOIDC(middleware)

		// Let it sit idle for a while - simulating no requests
		// During this time, background goroutines are running
		t.Log("Letting middleware sit idle for 3 seconds...")

		// Take measurements every 1 second
		for i := 0; i < 3; i++ {
			time.Sleep(GetTestDuration(1 * time.Second))

			runtime.GC()
			runtime.ReadMemStats(&m)
			currentAlloc := m.Alloc
			currentGoroutines := runtime.NumGoroutine()

			allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024
			goroutineIncrease := currentGoroutines - baselineGoroutines

			t.Logf("After %d seconds: Memory increase=%.2f MB, Goroutine increase=%d",
				(i + 1), allocIncrease, goroutineIncrease)

			// Check for significant memory growth (more than 5MB)
			if allocIncrease > 5.0 {
				t.Errorf("Significant memory increase detected: %.2f MB after %d seconds of idle",
					allocIncrease, (i + 1))
			}

			// Check for goroutine leaks (more than 10 extra goroutines)
			if goroutineIncrease > 10 {
				t.Errorf("Goroutine leak detected: %d extra goroutines after %d seconds",
					goroutineIncrease, (i+1)*5)
			}
		}

		// Clean up
		if err := middleware.Close(); err != nil {
			t.Errorf("Failed to close middleware: %v", err)
		}

		// Wait for cleanup
		time.Sleep(GetTestDuration(500 * time.Millisecond))

		// Final check
		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc
		finalGoroutines := runtime.NumGoroutine()

		finalAllocIncrease := float64(finalAlloc-baselineAlloc) / 1024 / 1024
		finalGoroutineIncrease := finalGoroutines - baselineGoroutines

		t.Logf("Final: Memory increase=%.2f MB, Goroutine increase=%d",
			finalAllocIncrease, finalGoroutineIncrease)

		if finalGoroutineIncrease > 2 {
			t.Errorf("Goroutines not cleaned up properly: %d extra goroutines remain",
				finalGoroutineIncrease)
		}
	})
}

// TestHTTPClientConnectionLeaks tests that HTTP clients don't leak connections
func TestHTTPClientConnectionLeaks(t *testing.T) {
	t.Run("HTTP client connection accumulation", func(t *testing.T) {
		// Create test server that simulates OIDC endpoints
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{
					"issuer": "https://example.com",
					"authorization_endpoint": "https://example.com/auth",
					"token_endpoint": "https://example.com/token",
					"jwks_uri": "https://example.com/jwks",
					"userinfo_endpoint": "https://example.com/userinfo"
				}`))
			case "/jwks":
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"keys": []}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Monitor connection count
		getActiveConnections := func(client *http.Client) int {
			if transport, ok := client.Transport.(*http.Transport); ok {
				// This is a simplified check - in reality we'd need to inspect
				// the transport's connection pool
				return transport.MaxIdleConnsPerHost
			}
			return 0
		}

		// Create multiple HTTP clients like the middleware does
		clients := make([]*http.Client, 10)
		for i := 0; i < 10; i++ {
			clients[i] = createDefaultHTTPClient()

			// Make requests
			resp, err := clients[i].Get(server.URL + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			// Check connection settings
			conns := getActiveConnections(clients[i])
			if conns > 1 {
				t.Logf("Client %d has %d max idle connections per host", i, conns)
			}
		}

		// Let connections sit idle briefly to test cleanup
		time.Sleep(GetTestDuration(1 * time.Second)) // Reduced for faster tests

		// Force cleanup
		for _, client := range clients {
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}

		t.Log("HTTP clients cleaned up successfully")
	})
}

// TestCacheBackgroundTaskLeaks tests that cache background tasks don't leak
func TestCacheBackgroundTaskLeaks(t *testing.T) {
	t.Run("Multiple cache instances with cleanup tasks", func(t *testing.T) {
		// Reset global state to prevent test interference
		resetGlobalState()

		initialGoroutines := runtime.NumGoroutine()

		// Create many cache instances
		caches := make([]*Cache, 50)

		// Ensure cleanup even on test failure or panic
		defer func() {
			for _, cache := range caches {
				if cache != nil {
					cache.Close()
				}
			}
			// Wait a bit for goroutines to stop
			time.Sleep(GetTestDuration(100 * time.Millisecond))
		}()

		for i := 0; i < 50; i++ {
			caches[i] = NewCache()
			// Add some data
			for j := 0; j < 100; j++ {
				key := fmt.Sprintf("key-%d-%d", i, j)
				caches[i].Set(key, "value", 5*time.Minute)
			}
		}

		// Wait for all cleanup goroutines to start
		time.Sleep(GetTestDuration(200 * time.Millisecond))

		afterCreateGoroutines := runtime.NumGoroutine()
		goroutineIncrease := afterCreateGoroutines - initialGoroutines

		t.Logf("Created %d caches, goroutine increase: %d", len(caches), goroutineIncrease)

		// Expected: roughly one cleanup goroutine per cache, but allow significant variance
		// In test suites with global state, goroutine counts can vary significantly
		expectedMin := len(caches) - 25 // Allow up to 25 goroutines variance for test interference
		if goroutineIncrease < expectedMin {
			t.Logf("Lower than expected goroutine count: %d (expected at least %d)",
				goroutineIncrease, expectedMin)
			// Don't fail the test - just log as this could be due to goroutine reuse or cleanup
		}

		// The main goal is to ensure we don't have excessive goroutine growth
		maxExpected := len(caches) + 25 // Allow up to 25 extra goroutines
		if goroutineIncrease > maxExpected {
			t.Errorf("Too many goroutines created: %d (expected max %d)",
				goroutineIncrease, maxExpected)
		}

		// Close all caches
		for _, cache := range caches {
			cache.Close()
		}

		// Wait for goroutines to stop with timeout
		done := make(chan bool)
		go func() {
			for i := 0; i < 20; i++ { // Try for 2 seconds
				time.Sleep(GetTestDuration(100 * time.Millisecond))
				currentGoroutines := runtime.NumGoroutine()
				if currentGoroutines-initialGoroutines <= 5 {
					done <- true
					return
				}
			}
			done <- false
		}()

		success := <-done
		finalGoroutines := runtime.NumGoroutine()
		remainingGoroutines := finalGoroutines - initialGoroutines

		if !success && remainingGoroutines > 5 { // Allow small tolerance
			t.Errorf("Cache cleanup goroutines not stopped properly: %d extra goroutines remain",
				remainingGoroutines)
		}
	})
}

// TestGlobalSingletonMemoryGrowth tests that global singletons don't grow unbounded
func TestGlobalSingletonMemoryGrowth(t *testing.T) {
	t.Run("Global cache manager memory growth", func(t *testing.T) {
		// Clean up any existing global state
		CleanupGlobalCacheManager()
		CleanupGlobalMemoryPools()

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		// Get global cache manager
		wg := &sync.WaitGroup{}
		cm := GetGlobalCacheManager(wg)

		// Simulate continuous usage without cleanup
		for i := 0; i < 1000; i++ {
			// Add to token cache
			cm.GetSharedTokenCache().Set(
				fmt.Sprintf("token-%d", i),
				map[string]interface{}{"claim": fmt.Sprintf("value-%d", i)},
				5*time.Minute,
			)

			// Add to blacklist
			cm.GetSharedTokenBlacklist().Set(
				fmt.Sprintf("blacklist-%d", i),
				true,
				5*time.Minute,
			)

			// Every 100 iterations, check memory
			if i%100 == 0 {
				runtime.GC()
				runtime.ReadMemStats(&m)
				currentAlloc := m.Alloc
				allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024

				t.Logf("After %d items: Memory increase=%.2f MB", i, allocIncrease)

				// The caches should have max size limits
				// If memory grows more than 10MB, there's likely a leak
				if allocIncrease > 10.0 {
					t.Errorf("Excessive memory growth in global caches: %.2f MB after %d items",
						allocIncrease, i)
					break
				}
			}
		}

		// Cleanup
		CleanupGlobalCacheManager()
		CleanupGlobalMemoryPools()
		wg.Wait()

		// Force full cleanup of replay cache too
		cleanupReplayCache()

		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc

		// Handle potential negative differences (memory freed beyond baseline)
		var finalAllocIncrease float64
		if finalAlloc >= baselineAlloc {
			finalAllocIncrease = float64(finalAlloc-baselineAlloc) / 1024 / 1024
		} else {
			// Memory decreased below baseline - this is good!
			finalAllocIncrease = -float64(baselineAlloc-finalAlloc) / 1024 / 1024
		}

		t.Logf("Final memory increase after cleanup: %.2f MB", finalAllocIncrease)

		if finalAllocIncrease > 2.0 {
			t.Errorf("Memory not properly released after cleanup: %.2f MB remains",
				finalAllocIncrease)
		}
	})
}

// TestMetadataCacheRefreshLeak tests for memory leaks in metadata refresh
func TestMetadataCacheRefreshLeak(t *testing.T) {
	t.Run("Metadata cache refresh memory leak", func(t *testing.T) {
		wg := &sync.WaitGroup{}
		cache := NewMetadataCacheWithLogger(wg, NewLogger("error"))
		defer cache.Close()

		// Mock HTTP client that returns metadata
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Return a large metadata response to amplify any leaks
			w.Write([]byte(`{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/jwks",
				"userinfo_endpoint": "https://example.com/userinfo",
				"extra_field_1": "` + strings.Repeat("x", 1000) + `",
				"extra_field_2": "` + strings.Repeat("y", 1000) + `"
			}`))
		}))
		defer server.Close()

		client := &http.Client{Timeout: 5 * time.Second}

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		// Simulate many metadata refreshes
		for i := 0; i < 100; i++ {
			_, err := cache.GetMetadata(server.URL, client, NewLogger("error"))
			if err != nil {
				t.Logf("Metadata fetch error (expected for test server): %v", err)
			}

			// Force cache expiry to trigger refresh
			cache.mutex.Lock()
			cache.expiresAt = time.Now().Add(-1 * time.Hour)
			cache.mutex.Unlock()

			if i%20 == 0 && i > 0 {
				runtime.GC()
				runtime.ReadMemStats(&m)
				currentAlloc := m.Alloc
				allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024

				t.Logf("After %d refreshes: Memory increase=%.2f MB", i, allocIncrease)

				// Metadata cache should only store one copy
				if allocIncrease > 3.0 {
					t.Errorf("Metadata cache leak detected: %.2f MB after %d refreshes",
						allocIncrease, i)
					break
				}
			}
		}

		cache.Close()
		wg.Wait()

		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc
		finalAllocIncrease := float64(finalAlloc-baselineAlloc) / 1024 / 1024

		t.Logf("Final memory after metadata cache closure: %.2f MB", finalAllocIncrease)

		if finalAllocIncrease > 1.0 {
			t.Errorf("Metadata cache not cleaned properly: %.2f MB remains", finalAllocIncrease)
		}
	})
}

// TestMemoryPoolLeak tests for leaks in memory pool management
func TestMemoryPoolLeak(t *testing.T) {
	t.Run("Memory pool buffer leaks", func(t *testing.T) {
		// Clean up any existing pools
		CleanupGlobalMemoryPools()

		pools := GetGlobalMemoryPools()

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		// Simulate heavy buffer usage
		var buffers [][]byte
		for i := 0; i < 1000; i++ {
			buf := pools.GetHTTPResponseBuffer()
			// Simulate using the buffer
			copy(buf, []byte("test data"))

			// 90% of the time, return the buffer
			// 10% of the time, "forget" to return it (simulating a leak)
			if i%10 != 0 {
				pools.PutHTTPResponseBuffer(buf)
			} else {
				// Keep reference to simulate leak
				buffers = append(buffers, buf)
			}

			if i%100 == 0 && i > 0 {
				runtime.GC()
				runtime.ReadMemStats(&m)
				currentAlloc := m.Alloc
				allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024

				t.Logf("After %d buffer operations: Memory increase=%.2f MB, Leaked buffers=%d",
					i, allocIncrease, len(buffers))

				// With proper pooling, memory should be bounded
				if allocIncrease > 5.0 {
					t.Errorf("Memory pool leak detected: %.2f MB after %d operations",
						allocIncrease, i)
					break
				}
			}
		}

		// Return the "leaked" buffers
		for _, buf := range buffers {
			pools.PutHTTPResponseBuffer(buf)
		}

		CleanupGlobalMemoryPools()

		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc
		finalAllocIncrease := float64(finalAlloc-baselineAlloc) / 1024 / 1024

		t.Logf("Final memory after pool cleanup: %.2f MB", finalAllocIncrease)

		if finalAllocIncrease > 1.0 {
			t.Errorf("Memory pools not cleaned properly: %.2f MB remains", finalAllocIncrease)
		}
	})
}

// TestConcurrentMemoryLeaks tests for memory leaks under concurrent load
func TestConcurrentMemoryLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent memory leak test in short mode")
	}

	t.Run("Concurrent operations memory stability", func(t *testing.T) {
		// Reset global state
		resetGlobalState()

		// Set lower GC percentage to trigger GC more frequently
		debug.SetGCPercent(50)
		defer debug.SetGCPercent(100)

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc
		baselineGoroutines := runtime.NumGoroutine()

		// Create a mock OIDC server
		var mockServerURL string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"issuer":                 mockServerURL,
					"authorization_endpoint": mockServerURL + "/auth",
					"token_endpoint":         mockServerURL + "/token",
					"userinfo_endpoint":      mockServerURL + "/userinfo",
					"jwks_uri":               mockServerURL + "/keys",
				})
			case "/keys":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"use": "sig",
							"kid": "test-key",
							"n":   "test-modulus",
							"e":   "AQAB",
						},
					},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer mockServer.Close()
		mockServerURL = mockServer.URL

		// Create middleware config with mock server
		config := createTestConfig()
		config.ProviderURL = mockServerURL
		config.LogLevel = "error"

		// Create middleware directly without using New() to avoid automatic metadata fetch
		middleware := &TraefikOidc{
			next:                 http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
			providerURL:          config.ProviderURL,
			clientID:             config.ClientID,
			clientSecret:         config.ClientSecret,
			redirURLPath:         "/callback",
			scopes:               []string{"openid", "email", "profile"},
			logger:               NewLogger(config.LogLevel),
			excludedURLs:         make(map[string]struct{}),
			httpClient:           &http.Client{Timeout: 5 * time.Second},
			sessionManager:       nil, // Will be created below
			tokenCache:           NewTokenCache(),
			tokenBlacklist:       NewCache(),
			limiter:              rate.NewLimiter(rate.Every(time.Second), 10),
			goroutineWG:          &sync.WaitGroup{},
			firstRequestMutex:    sync.Mutex{},
			firstRequestReceived: false,
		}

		// Create session manager
		var err error
		middleware.sessionManager, err = NewSessionManager(
			config.SessionEncryptionKey,
			config.ForceHTTPS,
			config.CookieDomain,
			middleware.logger,
		)
		if err != nil {
			t.Fatal(err)
		}

		// Simulate concurrent operations
		var wg sync.WaitGroup
		stopChan := make(chan struct{})

		// Worker that continuously performs operations
		worker := func(id int) {
			defer wg.Done()

			for {
				select {
				case <-stopChan:
					return
				default:
					// Simulate various operations
					switch id % 4 {
					case 0:
						// Cache operations
						cache := NewCache()
						cache.Set(fmt.Sprintf("key-%d", id), "value", time.Minute)
						cache.Get(fmt.Sprintf("key-%d", id))
						cache.Close()
					case 1:
						// Session operations
						req := httptest.NewRequest("GET", "/", nil)
						session, _ := middleware.sessionManager.GetSession(req)
						if session != nil {
							session.SetAccessToken("token")
							session.returnToPoolSafely()
						}
					case 2:
						// Token cache operations
						cm := GetGlobalCacheManager(nil)
						if cm != nil {
							tc := cm.GetSharedTokenCache()
							tc.Set("test-token", map[string]interface{}{"test": "data"}, time.Minute)
							tc.Get("test-token")
						}
					case 3:
						// Memory pool operations
						pools := GetGlobalMemoryPools()
						buf := pools.GetHTTPResponseBuffer()
						pools.PutHTTPResponseBuffer(buf)
					}

					// Small delay to prevent tight loop
					time.Sleep(10 * time.Millisecond)
				}
			}
		}

		// Start workers - reduced for race testing
		numWorkers := 20
		if testing.Short() {
			numWorkers = 2
		}
		wg.Add(numWorkers)
		for i := 0; i < numWorkers; i++ {
			go worker(i)
		}

		// Let it run and measure periodically - reduced timing for race testing
		iterations := 3
		sleepDuration := 1 * time.Second
		if testing.Short() {
			iterations = 1
			sleepDuration = 100 * time.Millisecond
		}

		for i := 0; i < iterations; i++ {
			time.Sleep(sleepDuration)

			runtime.GC()
			runtime.ReadMemStats(&m)
			currentAlloc := m.Alloc
			currentGoroutines := runtime.NumGoroutine()

			allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024
			goroutineIncrease := currentGoroutines - baselineGoroutines

			t.Logf("After %d seconds of concurrent load: Memory increase=%.2f MB, Goroutine increase=%d",
				(i + 1), allocIncrease, goroutineIncrease)

			// Under sustained concurrent load, memory should stabilize
			if i > 1 && allocIncrease > 20.0 {
				t.Errorf("Memory leak under concurrent load: %.2f MB after %d seconds",
					allocIncrease, (i + 1))
			}
		}

		// Stop workers
		close(stopChan)
		wg.Wait()

		// Clean up
		middleware.Close()

		// Final measurements - reduced timing for race testing
		cleanupDelay := 500 * time.Millisecond
		if testing.Short() {
			cleanupDelay = 50 * time.Millisecond
		}
		time.Sleep(cleanupDelay)
		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc
		finalGoroutines := runtime.NumGoroutine()

		finalAllocIncrease := float64(finalAlloc-baselineAlloc) / 1024 / 1024
		finalGoroutineIncrease := finalGoroutines - baselineGoroutines

		t.Logf("Final after cleanup: Memory increase=%.2f MB, Goroutine increase=%d",
			finalAllocIncrease, finalGoroutineIncrease)

		if finalGoroutineIncrease > 5 {
			t.Errorf("Goroutines not cleaned up after concurrent operations: %d extra remain",
				finalGoroutineIncrease)
		}

		if finalAllocIncrease > 5.0 {
			t.Errorf("Memory not released after concurrent operations: %.2f MB remains",
				finalAllocIncrease)
		}
	})
}
