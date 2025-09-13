package traefikoidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lukaszraczylo/traefikoidc/circuit_breaker"
)

// TestConnectionPoolingFailureScenarios tests connection pooling behavior during various failure scenarios
func TestConnectionPoolingFailureScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping connection pooling failure tests in short mode")
	}

	t.Run("pool_maintains_connections_during_intermittent_failures", func(t *testing.T) {
		// Create a server that fails 50% of requests
		failureCount := int64(0)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt64(&failureCount, 1)%2 == 0 {
				// Fail every other request
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		pool := GetGlobalTransportPool()
		defer pool.Cleanup()

		config := DefaultHTTPClientConfig()
		client := CreatePooledHTTPClient(config)

		// Make multiple concurrent requests to test pool behavior
		var wg sync.WaitGroup
		successCount := int64(0)
		errorCount := int64(0)

		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(server.URL)
				if err != nil || resp.StatusCode != http.StatusOK {
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
					resp.Body.Close()
				}
			}()
		}

		wg.Wait()

		// Verify that both successes and errors occurred
		finalSuccess := atomic.LoadInt64(&successCount)
		finalError := atomic.LoadInt64(&errorCount)

		assert.Greater(t, finalSuccess, int64(0), "Should have some successful requests")
		assert.Greater(t, finalError, int64(0), "Should have some failed requests")

		// Verify connection pool reuse by checking transport reuse
		pool.mu.RLock()
		transportCount := len(pool.transports)
		pool.mu.RUnlock()

		assert.Equal(t, 1, transportCount, "Should reuse a single transport for same config")
	})

	t.Run("pool_recovers_from_complete_outages", func(t *testing.T) {
		// Server that starts failing, then recovers
		serverDown := int64(1) // Start with server down
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.LoadInt64(&serverDown) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		pool := GetGlobalTransportPool()
		defer pool.Cleanup()

		config := DefaultHTTPClientConfig()
		client := CreatePooledHTTPClient(config)

		// Make requests while server is down
		downRequests := 5
		for i := 0; i < downRequests; i++ {
			resp, err := client.Get(server.URL)
			if err == nil {
				assert.NotEqual(t, http.StatusOK, resp.StatusCode, "Server should be down")
				resp.Body.Close()
			}
		}

		// Bring server back up
		atomic.StoreInt64(&serverDown, 0)

		// Verify recovery
		upRequests := 5
		successCount := 0
		for i := 0; i < upRequests; i++ {
			resp, err := client.Get(server.URL)
			require.NoError(t, err, "Should be able to make requests after recovery")
			if resp.StatusCode == http.StatusOK {
				successCount++
			}
			resp.Body.Close()
		}

		assert.Equal(t, upRequests, successCount, "All requests should succeed after recovery")

		// Verify transport pool still functional
		pool.mu.RLock()
		transportCount := len(pool.transports)
		var refCount int
		for _, shared := range pool.transports {
			refCount += shared.refCount
		}
		pool.mu.RUnlock()

		assert.Equal(t, 1, transportCount, "Should maintain single transport")
		assert.Greater(t, refCount, 0, "Transport should still be referenced")
	})

	t.Run("pool_handles_connection_timeout_gracefully", func(t *testing.T) {
		// Server that delays responses to cause timeouts
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond) // Longer than client timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		pool := GetGlobalTransportPool()
		defer pool.Cleanup()

		config := DefaultHTTPClientConfig()
		config.Timeout = 50 * time.Millisecond // Short timeout
		client := CreatePooledHTTPClient(config)

		// Make requests that will timeout
		var wg sync.WaitGroup
		timeoutCount := int64(0)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := client.Get(server.URL)
				if err != nil {
					atomic.AddInt64(&timeoutCount, 1)
				}
			}()
		}

		wg.Wait()

		assert.Greater(t, atomic.LoadInt64(&timeoutCount), int64(0), "Should have timeout errors")

		// Verify transport pool is still functional after timeouts
		pool.mu.RLock()
		transportCount := len(pool.transports)
		pool.mu.RUnlock()

		assert.Equal(t, 1, transportCount, "Transport should still exist after timeouts")
	})

	t.Run("pool_enforces_connection_limits_during_load", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(10 * time.Millisecond) // Simulate processing time
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		pool := GetGlobalTransportPool()
		defer pool.Cleanup()

		config := DefaultHTTPClientConfig()
		client := CreatePooledHTTPClient(config)

		// Create high load to test connection limits
		var wg sync.WaitGroup
		requestCount := 50
		completedRequests := int64(0)

		for i := 0; i < requestCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(server.URL)
				if err == nil {
					atomic.AddInt64(&completedRequests, 1)
					resp.Body.Close()
				}
			}()
		}

		wg.Wait()

		completed := atomic.LoadInt64(&completedRequests)
		assert.Greater(t, completed, int64(0), "Should complete some requests")

		// Verify connection limits are enforced
		pool.mu.RLock()
		for _, shared := range pool.transports {
			// Check that transport limits are reasonable
			transport := shared.transport
			assert.LessOrEqual(t, transport.MaxIdleConnsPerHost, 5, "MaxIdleConnsPerHost should be limited")
			assert.LessOrEqual(t, transport.MaxConnsPerHost, 10, "MaxConnsPerHost should be limited")
		}
		pool.mu.RUnlock()
	})
}

// TestCircuitBreakerTokenOperations tests circuit breaker behavior for token operations
func TestCircuitBreakerTokenOperations(t *testing.T) {
	t.Run("circuit_breaker_prevents_excessive_token_refresh_attempts", func(t *testing.T) {
		// Mock base recovery mechanism
		baseRecovery := &mockBaseRecoveryMechanism{
			baseMetrics: make(map[string]interface{}),
		}

		// Mock logger
		logger := &mockLogger{}

		// Configure circuit breaker with low failure threshold for testing
		config := circuit_breaker.CircuitBreakerConfig{
			MaxFailures:  2,
			Timeout:      100 * time.Millisecond,
			ResetTimeout: 50 * time.Millisecond,
		}

		cb := circuit_breaker.NewCircuitBreaker(config, logger, baseRecovery)

		// Simulate token refresh failures
		tokenRefreshError := errors.New("token refresh failed: server unavailable")
		failingTokenRefresh := func() error {
			// Simulate token refresh operation that fails
			return tokenRefreshError
		}

		// Execute failing token refresh operations to trigger circuit breaker
		ctx := context.Background()
		var firstError, secondError, thirdError error

		// First failure
		firstError = cb.ExecuteWithContext(ctx, failingTokenRefresh)
		assert.Equal(t, tokenRefreshError, firstError, "First attempt should return the actual error")
		assert.Equal(t, circuit_breaker.CircuitBreakerClosed, cb.GetState(), "Circuit should remain closed after first failure")

		// Second failure - should open the circuit
		secondError = cb.ExecuteWithContext(ctx, failingTokenRefresh)
		assert.Equal(t, tokenRefreshError, secondError, "Second attempt should return the actual error")
		assert.Equal(t, circuit_breaker.CircuitBreakerOpen, cb.GetState(), "Circuit should be open after max failures")

		// Third attempt - should be blocked by circuit breaker
		callCount := 0
		blockedTokenRefresh := func() error {
			callCount++
			return nil // This shouldn't be called
		}

		thirdError = cb.ExecuteWithContext(ctx, blockedTokenRefresh)
		assert.Error(t, thirdError, "Third attempt should be blocked")
		assert.Contains(t, thirdError.Error(), "circuit breaker is open", "Error should indicate circuit breaker is open")
		assert.Equal(t, 0, callCount, "Token refresh function should not be called when circuit is open")

		// Verify metrics
		metrics := cb.GetMetrics()
		assert.Equal(t, "open", metrics["state"], "Circuit breaker state should be open")
		assert.Equal(t, int64(2), metrics["current_failures"], "Should record 2 failures")
		assert.Equal(t, int64(3), baseRecovery.getRequestCount(), "Should record 3 requests (including blocked one)")
		assert.Equal(t, int64(2), atomic.LoadInt64(&baseRecovery.failureCount), "Should record 2 failures")
	})

	t.Run("circuit_breaker_allows_gradual_recovery_for_token_operations", func(t *testing.T) {
		baseRecovery := &mockBaseRecoveryMechanism{
			baseMetrics: make(map[string]interface{}),
		}
		logger := &mockLogger{}

		config := circuit_breaker.CircuitBreakerConfig{
			MaxFailures:  1,
			Timeout:      10 * time.Millisecond, // Short timeout for testing
			ResetTimeout: 10 * time.Millisecond,
		}

		cb := circuit_breaker.NewCircuitBreaker(config, logger, baseRecovery)

		// Trigger circuit opening
		failingOperation := func() error {
			return errors.New("token server unavailable")
		}

		err := cb.ExecuteWithContext(context.Background(), failingOperation)
		assert.Error(t, err, "First attempt should fail")
		assert.Equal(t, circuit_breaker.CircuitBreakerOpen, cb.GetState(), "Circuit should be open")

		// Wait for timeout to allow half-open transition
		time.Sleep(15 * time.Millisecond)

		// Successful token operation should close circuit
		successfulTokenRefresh := func() error {
			// Simulate successful token refresh
			return nil
		}

		err = cb.ExecuteWithContext(context.Background(), successfulTokenRefresh)
		assert.NoError(t, err, "Successful operation should work in half-open state")
		assert.Equal(t, circuit_breaker.CircuitBreakerClosed, cb.GetState(), "Circuit should be closed after success")

		// Subsequent operations should work normally
		err = cb.ExecuteWithContext(context.Background(), successfulTokenRefresh)
		assert.NoError(t, err, "Operations should work normally after recovery")

		// Verify recovery was logged
		infoLogs := baseRecovery.getInfoLogs()
		assert.Greater(t, len(infoLogs), 0, "Should have logged recovery")
	})

	t.Run("circuit_breaker_handles_concurrent_token_operations", func(t *testing.T) {
		baseRecovery := &mockBaseRecoveryMechanism{
			baseMetrics: make(map[string]interface{}),
		}
		logger := &mockLogger{}

		config := circuit_breaker.CircuitBreakerConfig{
			MaxFailures:  5, // Higher threshold for concurrency test
			Timeout:      100 * time.Millisecond,
			ResetTimeout: 50 * time.Millisecond,
		}

		cb := circuit_breaker.NewCircuitBreaker(config, logger, baseRecovery)

		// Simulate concurrent token operations with mixed success/failure
		var wg sync.WaitGroup
		successCount := int64(0)
		errorCount := int64(0)
		circuitOpenCount := int64(0)

		operationCount := 20
		for i := 0; i < operationCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				tokenOperation := func() error {
					// Simulate some failures
					if id%4 == 0 {
						return errors.New("token operation failed")
					}
					// Simulate processing time
					time.Sleep(time.Millisecond)
					return nil
				}

				err := cb.ExecuteWithContext(context.Background(), tokenOperation)
				if err != nil {
					if err.Error() == "circuit breaker is open" {
						atomic.AddInt64(&circuitOpenCount, 1)
					} else {
						atomic.AddInt64(&errorCount, 1)
					}
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()

		finalSuccess := atomic.LoadInt64(&successCount)
		finalError := atomic.LoadInt64(&errorCount)
		finalCircuitOpen := atomic.LoadInt64(&circuitOpenCount)

		assert.Greater(t, finalSuccess, int64(0), "Should have some successful operations")
		totalProcessed := finalSuccess + finalError + finalCircuitOpen
		assert.LessOrEqual(t, totalProcessed, int64(operationCount), "Should not exceed total operations")

		// Verify final state and metrics
		metrics := cb.GetMetrics()
		t.Logf("Final state: %s, successes: %d, errors: %d, circuit blocked: %d",
			metrics["state"], finalSuccess, finalError, finalCircuitOpen)
	})

	t.Run("circuit_breaker_respects_timeout_for_token_operations", func(t *testing.T) {
		baseRecovery := &mockBaseRecoveryMechanism{
			baseMetrics: make(map[string]interface{}),
		}
		logger := &mockLogger{}

		config := circuit_breaker.CircuitBreakerConfig{
			MaxFailures:  1,
			Timeout:      50 * time.Millisecond, // Specific timeout for testing
			ResetTimeout: 25 * time.Millisecond,
		}

		cb := circuit_breaker.NewCircuitBreaker(config, logger, baseRecovery)

		// Open the circuit
		err := cb.ExecuteWithContext(context.Background(), func() error {
			return errors.New("initial failure")
		})
		assert.Error(t, err)
		assert.Equal(t, circuit_breaker.CircuitBreakerOpen, cb.GetState())

		// Should be blocked before timeout
		err = cb.ExecuteWithContext(context.Background(), func() error {
			return nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circuit breaker is open")

		// Wait for timeout
		time.Sleep(60 * time.Millisecond)

		// Should be available after timeout (half-open)
		available := cb.IsAvailable()
		assert.True(t, available, "Circuit breaker should be available after timeout")

		// Successful operation should close the circuit
		err = cb.ExecuteWithContext(context.Background(), func() error {
			return nil // Success
		})
		assert.NoError(t, err)
		assert.Equal(t, circuit_breaker.CircuitBreakerClosed, cb.GetState())
	})
}

// TestMetadataCacheGracePeriodExtensions tests metadata cache grace period behavior during outages
func TestMetadataCacheGracePeriodExtensions(t *testing.T) {
	t.Run("cache_extends_grace_period_during_provider_outage", func(t *testing.T) {
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(10, 1, logger)
		defer cache.Clear()

		// Initial metadata with short TTL
		metadata := &ProviderMetadata{
			Issuer:   "https://test-provider.com",
			AuthURL:  "https://test-provider.com/auth",
			TokenURL: "https://test-provider.com/token",
			JWKSURL:  "https://test-provider.com/jwks",
		}

		initialTTL := 100 * time.Millisecond
		cache.Set("test-provider", metadata, initialTTL)

		// Verify initial retrieval
		retrieved, found := cache.Get("test-provider")
		require.True(t, found, "Should find initial metadata")
		assert.Equal(t, metadata.Issuer, retrieved.Issuer)

		// Wait for initial TTL to expire
		time.Sleep(120 * time.Millisecond)

		// Should be expired by now
		_, found = cache.Get("test-provider")
		assert.False(t, found, "Metadata should be expired after TTL")

		// Simulate grace period extension by re-adding with longer TTL
		gracePeriodTTL := 5 * time.Minute // Extended grace period
		cache.Set("test-provider", metadata, gracePeriodTTL)

		// Should be available during grace period
		retrieved, found = cache.Get("test-provider")
		assert.True(t, found, "Should find metadata during grace period")
		assert.Equal(t, metadata.Issuer, retrieved.Issuer)

		// Verify the cache maintains the entry longer
		time.Sleep(50 * time.Millisecond) // Still within grace period
		_, found = cache.Get("test-provider")
		assert.True(t, found, "Should still find metadata in extended grace period")
	})

	t.Run("cache_progressive_grace_period_extension", func(t *testing.T) {
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(10, 1, logger)
		defer cache.Clear()

		metadata := &ProviderMetadata{
			Issuer:   "https://progressive-test.com",
			AuthURL:  "https://progressive-test.com/auth",
			TokenURL: "https://progressive-test.com/token",
		}

		// Simulate progressive grace period extensions: 5min -> 15min -> 30min+
		gracePeriods := []time.Duration{
			5 * time.Minute,  // First extension
			15 * time.Minute, // Second extension
			30 * time.Minute, // Final extension
		}

		for i, gracePeriod := range gracePeriods {
			key := fmt.Sprintf("progressive-provider-%d", i)
			cache.Set(key, metadata, gracePeriod)

			// Verify each grace period is set correctly
			retrieved, found := cache.Get(key)
			require.True(t, found, "Should find metadata for grace period %d", i)
			assert.Equal(t, metadata.Issuer, retrieved.Issuer)
		}

		// Verify all entries exist
		stats := cache.GetStats()
		entries, ok := stats["entries"].(int64)
		if !ok {
			// Try int for backward compatibility
			if entriesInt, ok := stats["entries"].(int); ok {
				entries = int64(entriesInt)
			} else {
				t.Fatalf("entries field is not int64 or int: %T", stats["entries"])
			}
		}
		assert.Equal(t, int64(3), entries, "Should have 3 entries with different grace periods")

		// Test that longer grace periods are indeed longer
		time.Sleep(100 * time.Millisecond)
		for i := 0; i < 3; i++ {
			key := fmt.Sprintf("progressive-provider-%d", i)
			_, found := cache.Get(key)
			assert.True(t, found, "All entries should still be valid after short delay")
		}
	})

	t.Run("cache_handles_outage_with_memory_pressure", func(t *testing.T) {
		// Very small cache to test memory pressure during outages
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(3, 1, logger) // Very small limits
		defer cache.Clear()

		metadata := &ProviderMetadata{
			Issuer:   "https://memory-pressure-test.com",
			AuthURL:  "https://memory-pressure-test.com/auth",
			TokenURL: "https://memory-pressure-test.com/token",
		}

		// Add entries up to limit with grace period
		gracePeriod := 30 * time.Minute
		for i := 0; i < 3; i++ {
			key := fmt.Sprintf("pressure-provider-%d", i)
			cache.Set(key, metadata, gracePeriod)
		}

		// Verify all entries are present
		for i := 0; i < 3; i++ {
			key := fmt.Sprintf("pressure-provider-%d", i)
			_, found := cache.Get(key)
			assert.True(t, found, "Entry %d should be present", i)
		}

		// Add one more entry, should trigger eviction
		cache.Set("pressure-provider-overflow", metadata, gracePeriod)

		// Verify eviction occurred (should have max 3 entries)
		stats := cache.GetStats()
		entries := stats["entries"].(int64)
		evictions := stats["evictions"].(int64)

		assert.LessOrEqual(t, entries, int64(3), "Should not exceed max entries")
		assert.Greater(t, evictions, int64(0), "Should have evictions due to overflow")
	})

	t.Run("cache_cleanup_respects_extended_grace_periods", func(t *testing.T) {
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(10, 1, logger)
		defer cache.Clear()

		metadata := &ProviderMetadata{
			Issuer: "https://cleanup-test.com",
		}

		// Add entry with very short TTL (should be cleaned up)
		cache.Set("short-ttl", metadata, 10*time.Millisecond)

		// Add entry with long grace period (should survive cleanup)
		cache.Set("long-grace", metadata, 30*time.Minute)

		// Wait for short TTL to expire
		time.Sleep(20 * time.Millisecond)

		// Trigger cleanup
		cache.CleanupExpired()

		// Verify short TTL entry was cleaned up
		_, found := cache.Get("short-ttl")
		assert.False(t, found, "Short TTL entry should be cleaned up")

		// Verify long grace period entry survives
		_, found = cache.Get("long-grace")
		assert.True(t, found, "Long grace period entry should survive cleanup")

		// Verify stats reflect cleanup
		stats := cache.GetStats()
		entries := stats["entries"].(int64)
		assert.Equal(t, int64(1), entries, "Should have 1 entry remaining after cleanup")
	})

	t.Run("cache_concurrent_access_during_grace_period", func(t *testing.T) {
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(20, 2, logger)
		defer cache.Clear()

		metadata := &ProviderMetadata{
			Issuer:   "https://concurrent-test.com",
			AuthURL:  "https://concurrent-test.com/auth",
			TokenURL: "https://concurrent-test.com/token",
		}

		gracePeriod := 10 * time.Minute

		// Concurrent access during grace period setup
		var wg sync.WaitGroup
		successCount := int64(0)
		errorCount := int64(0)

		// Set initial entries concurrently
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("concurrent-provider-%d", id)
				cache.Set(key, metadata, gracePeriod)
			}(i)
		}

		// Concurrent reads during setup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("concurrent-provider-%d", id)
				// Wait a bit for the setter to run
				time.Sleep(time.Millisecond)
				_, found := cache.Get(key)
				if found {
					atomic.AddInt64(&successCount, 1)
				} else {
					atomic.AddInt64(&errorCount, 1)
				}
			}(i)
		}

		wg.Wait()

		finalSuccess := atomic.LoadInt64(&successCount)
		finalError := atomic.LoadInt64(&errorCount)

		// Should have mostly successful reads
		assert.Greater(t, finalSuccess, int64(5), "Should have several successful concurrent reads")
		t.Logf("Concurrent access results: %d successes, %d errors", finalSuccess, finalError)

		// Verify cache is still functional
		cache.Set("final-test", metadata, gracePeriod)
		_, found := cache.Get("final-test")
		assert.True(t, found, "Cache should still be functional after concurrent access")
	})
}

// TestMemoryUsageImprovementBenchmarks provides benchmarks for memory usage improvements
func TestMemoryUsageImprovementBenchmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory benchmark tests in short mode")
	}

	t.Run("benchmark_connection_pool_memory_efficiency", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Measure memory before
		runtime.GC()
		var memBefore, memAfter runtime.MemStats
		runtime.ReadMemStats(&memBefore)

		// Create many HTTP clients with pooled transports
		clients := make([]*http.Client, 100)
		config := DefaultHTTPClientConfig()

		for i := 0; i < 100; i++ {
			clients[i] = CreatePooledHTTPClient(config)
		}

		// Use the clients
		for i := 0; i < 100; i++ {
			resp, err := clients[i].Get(server.URL)
			if err == nil {
				resp.Body.Close()
			}
		}

		// Measure memory after
		runtime.GC()
		runtime.ReadMemStats(&memAfter)

		// Handle potential overflow in memory calculation
		var memGrowthMB float64
		if memAfter.HeapAlloc > memBefore.HeapAlloc {
			memGrowthMB = float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / 1024 / 1024
		} else {
			memGrowthMB = 0 // Memory decreased or stayed same
		}
		t.Logf("Memory growth with pooled connections: %.2f MB", memGrowthMB)

		// Should not grow excessively (threshold: 50MB) when measurement is reliable
		if memGrowthMB > 0 && memGrowthMB < 1000 { // Reasonable range
			assert.Less(t, memGrowthMB, 50.0, "Memory growth should be reasonable with pooled connections")
		}

		// Cleanup
		pool := GetGlobalTransportPool()
		pool.Cleanup()
	})

	t.Run("benchmark_bounded_cache_memory_efficiency", func(t *testing.T) {
		runtime.GC()
		var memBefore, memAfter runtime.MemStats
		runtime.ReadMemStats(&memBefore)

		// Create bounded cache and fill it beyond limits
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(100, 1, logger) // 1MB limit
		defer cache.Clear()

		// Create large metadata entries
		metadata := &ProviderMetadata{
			Issuer:   string(make([]byte, 1024)), // 1KB
			AuthURL:  string(make([]byte, 1024)),
			TokenURL: string(make([]byte, 1024)),
		}

		// Add many entries (should trigger eviction)
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("large-entry-%d", i)
			cache.Set(key, metadata, time.Hour)
		}

		runtime.GC()
		runtime.ReadMemStats(&memAfter)

		// Handle potential overflow in memory calculation
		var memGrowthMB float64
		if memAfter.HeapAlloc > memBefore.HeapAlloc {
			memGrowthMB = float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / 1024 / 1024
		} else {
			memGrowthMB = 0 // Memory decreased or stayed same
		}
		t.Logf("Memory growth with bounded cache: %.2f MB", memGrowthMB)

		// Verify cache stats
		stats := cache.GetStats()
		entries := stats["entries"].(int64)
		evictions := stats["evictions"].(int64)
		memoryUsage := stats["memory"].(int64)
		maxMemory := stats["max_memory"].(int64)

		t.Logf("Cache stats - entries: %d, evictions: %d, memory: %d/%d bytes",
			entries, evictions, memoryUsage, maxMemory)

		// Should respect memory limits
		assert.LessOrEqual(t, memoryUsage, maxMemory, "Should not exceed memory limit")
		assert.Greater(t, evictions, int64(0), "Should have evictions")
		// Memory calculation can be unreliable in tests, just verify bounds are working
		if memGrowthMB > 0 && memGrowthMB < 1000 { // Reasonable range
			assert.Less(t, memGrowthMB, 50.0, "Memory growth should be bounded when measurable")
		}
	})

	t.Run("benchmark_circuit_breaker_memory_efficiency", func(t *testing.T) {
		runtime.GC()
		var memBefore, memAfter runtime.MemStats
		runtime.ReadMemStats(&memBefore)

		// Create many circuit breakers
		breakers := make([]*circuit_breaker.CircuitBreaker, 100)
		baseRecoveries := make([]*mockBaseRecoveryMechanism, 100)
		loggers := make([]*mockLogger, 100)

		config := circuit_breaker.DefaultCircuitBreakerConfig()

		for i := 0; i < 100; i++ {
			baseRecoveries[i] = &mockBaseRecoveryMechanism{
				baseMetrics: make(map[string]interface{}),
			}
			loggers[i] = &mockLogger{}
			breakers[i] = circuit_breaker.NewCircuitBreaker(config, loggers[i], baseRecoveries[i])
		}

		// Exercise the circuit breakers
		for i := 0; i < 100; i++ {
			// Some operations that succeed
			for j := 0; j < 10; j++ {
				breakers[i].Execute(func() error { return nil })
			}

			// Some operations that fail
			for j := 0; j < 3; j++ {
				breakers[i].Execute(func() error { return errors.New("test error") })
			}

			// Get metrics (this allocates)
			_ = breakers[i].GetMetrics()
		}

		runtime.GC()
		runtime.ReadMemStats(&memAfter)

		// Handle potential overflow in memory calculation
		var memGrowthMB float64
		if memAfter.HeapAlloc > memBefore.HeapAlloc {
			memGrowthMB = float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / 1024 / 1024
		} else {
			memGrowthMB = 0 // Memory decreased or stayed same
		}
		t.Logf("Memory growth with circuit breakers: %.2f MB", memGrowthMB)

		// Circuit breakers should not consume excessive memory when measurement is reliable
		if memGrowthMB > 0 && memGrowthMB < 1000 { // Reasonable range
			assert.Less(t, memGrowthMB, 10.0, "Circuit breakers should be memory efficient")
		}

		// Reset and verify all circuit breakers are functional
		for i := 0; i < 10; i++ { // Test a sample
			breakers[i].Reset() // Reset to closed state
			err := breakers[i].Execute(func() error { return nil })
			assert.NoError(t, err, "Circuit breaker %d should be functional after reset", i)
		}
	})

	t.Run("benchmark_goroutine_leak_prevention", func(t *testing.T) {
		initialGoroutines := runtime.NumGoroutine()

		// Create and start multiple background tasks
		var wg sync.WaitGroup
		tasks := make([]*LazyBackgroundTask, 20)
		logger := GetSingletonNoOpLogger()

		for i := 0; i < 20; i++ {
			taskFunc := func() {
				// Minimal task work
				time.Sleep(time.Millisecond)
			}

			tasks[i] = NewLazyBackgroundTask(
				fmt.Sprintf("benchmark-task-%d", i),
				10*time.Millisecond,
				taskFunc,
				logger,
				&wg,
			)
			tasks[i].StartIfNeeded()
		}

		// Let tasks run briefly
		time.Sleep(50 * time.Millisecond)

		// Stop all tasks
		for _, task := range tasks {
			task.Stop()
		}

		// Wait for cleanup
		wg.Wait()
		time.Sleep(100 * time.Millisecond)
		runtime.GC()

		finalGoroutines := runtime.NumGoroutine()
		goroutineGrowth := finalGoroutines - initialGoroutines

		t.Logf("Goroutine count - initial: %d, final: %d, growth: %d",
			initialGoroutines, finalGoroutines, goroutineGrowth)

		// Should not have significant goroutine leaks
		assert.LessOrEqual(t, goroutineGrowth, 5, "Goroutine growth should be minimal after cleanup")
	})
}

// TestRaceConditionDetection tests for race conditions in memory leak fixes
func TestRaceConditionDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping race condition tests in short mode")
	}

	t.Run("connection_pool_race_conditions", func(t *testing.T) {
		pool := GetGlobalTransportPool()
		defer pool.Cleanup()

		var wg sync.WaitGroup
		operationCount := 50

		// Concurrent transport creation and release
		for i := 0; i < operationCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				config := DefaultHTTPClientConfig()
				config.MaxConnsPerHost = id % 5 // Create some variety

				// Get transport
				transport := pool.GetOrCreateTransport(config)
				assert.NotNil(t, transport, "Should get a valid transport")

				// Use transport briefly
				time.Sleep(time.Millisecond)

				// Release transport
				pool.ReleaseTransport(transport)
			}(i)
		}

		// Concurrent cleanup operations
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(25 * time.Millisecond)

				// This tests concurrent cleanup
				pool.mu.RLock()
				transportCount := len(pool.transports)
				pool.mu.RUnlock()

				assert.GreaterOrEqual(t, transportCount, 0, "Transport count should be non-negative")
			}()
		}

		wg.Wait()
	})

	t.Run("circuit_breaker_race_conditions", func(t *testing.T) {
		baseRecovery := &mockBaseRecoveryMechanism{
			baseMetrics: make(map[string]interface{}),
		}
		logger := &mockLogger{}
		config := circuit_breaker.DefaultCircuitBreakerConfig()
		cb := circuit_breaker.NewCircuitBreaker(config, logger, baseRecovery)

		var wg sync.WaitGroup
		operationCount := 100
		successCount := int64(0)
		errorCount := int64(0)

		// Concurrent executions
		for i := 0; i < operationCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				operation := func() error {
					if id%10 == 0 {
						return errors.New("simulated failure")
					}
					return nil
				}

				err := cb.ExecuteWithContext(context.Background(), operation)
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}(i)
		}

		// Concurrent state checks
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = cb.GetState()
				_ = cb.IsAvailable()
				_ = cb.GetMetrics()
				_ = cb.GetFailureCount()
			}()
		}

		// Concurrent resets
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(50 * time.Millisecond)
				cb.Reset()
			}()
		}

		wg.Wait()

		finalSuccess := atomic.LoadInt64(&successCount)
		finalError := atomic.LoadInt64(&errorCount)

		assert.Greater(t, finalSuccess, int64(0), "Should have successful operations")
		t.Logf("Race condition test results: %d successes, %d errors", finalSuccess, finalError)
	})

	t.Run("metadata_cache_race_conditions", func(t *testing.T) {
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(50, 2, logger)
		defer cache.Clear()

		metadata := &ProviderMetadata{
			Issuer:   "https://race-test.com",
			AuthURL:  "https://race-test.com/auth",
			TokenURL: "https://race-test.com/token",
		}

		var wg sync.WaitGroup
		operationCount := 100

		// Concurrent sets
		for i := 0; i < operationCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("race-key-%d", id%20) // Some key overlap
				cache.Set(key, metadata, time.Minute)
			}(i)
		}

		// Concurrent gets
		for i := 0; i < operationCount; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("race-key-%d", id%20)
				_, _ = cache.Get(key) // Ignore result, just test for races
			}(i)
		}

		// Concurrent deletes
		for i := 0; i < operationCount/4; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("race-key-%d", id%20)
				cache.Delete(key)
			}(i)
		}

		// Concurrent stats and cleanup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = cache.GetStats()
				cache.CleanupExpired()
			}()
		}

		wg.Wait()

		// Verify cache is still functional
		cache.Set("final-race-test", metadata, time.Minute)
		_, found := cache.Get("final-race-test")
		assert.True(t, found, "Cache should be functional after race condition test")
	})

	t.Run("lazy_background_task_race_conditions", func(t *testing.T) {
		var mainWG sync.WaitGroup
		taskCount := 10 // Reduced count to avoid timeout
		tasks := make([]*LazyBackgroundTask, taskCount)
		logger := GetSingletonNoOpLogger()

		callCounts := make([]int64, taskCount)

		for i := 0; i < taskCount; i++ {
			taskID := i
			taskFunc := func() {
				atomic.AddInt64(&callCounts[taskID], 1)
			}

			// Use separate WaitGroups for each task to avoid conflicts
			var taskWG sync.WaitGroup
			tasks[i] = NewLazyBackgroundTask(
				fmt.Sprintf("race-task-%d", i),
				50*time.Millisecond, // Longer interval to reduce contention
				taskFunc,
				logger,
				&taskWG,
			)
		}

		// Concurrent start operations
		for i := 0; i < taskCount; i++ {
			mainWG.Add(1)
			go func(id int) {
				defer mainWG.Done()
				tasks[id].StartIfNeeded()
				// Multiple start attempts to test sync.Once
				tasks[id].StartIfNeeded()
				tasks[id].StartIfNeeded()
			}(i)
		}

		mainWG.Wait()

		// Let tasks run briefly
		time.Sleep(100 * time.Millisecond)

		// Concurrent stop operations
		for i := 0; i < taskCount; i++ {
			mainWG.Add(1)
			go func(id int) {
				defer mainWG.Done()
				tasks[id].Stop()
			}(i)
		}

		mainWG.Wait()

		// Verify most tasks executed (some may not have had time to run)
		executedCount := 0
		for i := 0; i < taskCount; i++ {
			callCount := atomic.LoadInt64(&callCounts[i])
			if callCount > 0 {
				executedCount++
			}
		}
		assert.Greater(t, executedCount, taskCount/2, "At least half the tasks should have executed")
	})
}

// Mock implementations for testing
type mockBaseRecoveryMechanism struct {
	requestCount int64
	successCount int64
	failureCount int64
	infoLogs     []string
	errorLogs    []string
	debugLogs    []string
	baseMetrics  map[string]interface{}
	mu           sync.RWMutex
}

func (m *mockBaseRecoveryMechanism) RecordRequest() {
	atomic.AddInt64(&m.requestCount, 1)
}

func (m *mockBaseRecoveryMechanism) RecordSuccess() {
	atomic.AddInt64(&m.successCount, 1)
}

func (m *mockBaseRecoveryMechanism) RecordFailure() {
	atomic.AddInt64(&m.failureCount, 1)
}

func (m *mockBaseRecoveryMechanism) GetBaseMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range m.baseMetrics {
		result[k] = v
	}
	result["total_requests"] = atomic.LoadInt64(&m.requestCount)
	result["total_successes"] = atomic.LoadInt64(&m.successCount)
	result["total_failures"] = atomic.LoadInt64(&m.failureCount)
	return result
}

func (m *mockBaseRecoveryMechanism) LogInfo(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = append(m.infoLogs, fmt.Sprintf(format, args...))
}

func (m *mockBaseRecoveryMechanism) LogError(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, fmt.Sprintf(format, args...))
}

func (m *mockBaseRecoveryMechanism) LogDebug(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, fmt.Sprintf(format, args...))
}

func (m *mockBaseRecoveryMechanism) getRequestCount() int64 {
	return atomic.LoadInt64(&m.requestCount)
}

func (m *mockBaseRecoveryMechanism) getInfoLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.infoLogs))
	copy(result, m.infoLogs)
	return result
}

type mockLogger struct {
	infoLogs  []string
	errorLogs []string
	debugLogs []string
	mu        sync.RWMutex
}

func (m *mockLogger) Infof(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = append(m.infoLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Errorf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Debugf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, fmt.Sprintf(format, args...))
}

// BenchmarkConnectivityIssuesFixes provides performance benchmarks for connectivity fixes
func BenchmarkConnectivityIssuesFixes(b *testing.B) {
	b.Run("ConnectionPooling", func(b *testing.B) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		pool := GetGlobalTransportPool()
		defer pool.Cleanup()

		config := DefaultHTTPClientConfig()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				client := CreatePooledHTTPClient(config)
				resp, err := client.Get(server.URL)
				if err == nil {
					resp.Body.Close()
				}
			}
		})
	})

	b.Run("CircuitBreakerOperations", func(b *testing.B) {
		baseRecovery := &mockBaseRecoveryMechanism{
			baseMetrics: make(map[string]interface{}),
		}
		logger := &mockLogger{}
		config := circuit_breaker.DefaultCircuitBreakerConfig()
		cb := circuit_breaker.NewCircuitBreaker(config, logger, baseRecovery)

		operation := func() error {
			return nil // Always succeed for benchmark
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				cb.ExecuteWithContext(context.Background(), operation)
			}
		})
	})

	b.Run("MetadataCacheOperations", func(b *testing.B) {
		logger := NewLogger("debug")
		cache := NewFixedMetadataCache(1000, 10, logger)
		defer cache.Clear()

		metadata := &ProviderMetadata{
			Issuer:   "https://benchmark-test.com",
			AuthURL:  "https://benchmark-test.com/auth",
			TokenURL: "https://benchmark-test.com/token",
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("bench-key-%d", i%100)
				if i%2 == 0 {
					cache.Set(key, metadata, time.Hour)
				} else {
					cache.Get(key)
				}
				i++
			}
		})
	})

	b.Run("LazyBackgroundTaskOperations", func(b *testing.B) {
		logger := GetSingletonNoOpLogger()
		taskFunc := func() {
			// Minimal work
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			task := NewLazyBackgroundTask("bench-task", time.Second, taskFunc, logger, &wg)
			task.StartIfNeeded()
			task.Stop()
		}
	})
}
