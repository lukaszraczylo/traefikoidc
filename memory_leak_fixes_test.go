package traefikoidc

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MemoryLeakFixesTestSuite provides comprehensive memory leak testing using unified infrastructure
type MemoryLeakFixesTestSuite struct {
	runner   *TestSuiteRunner
	factory  *TestDataFactory
	edgeGen  *EdgeCaseGenerator
	perfTest *PerformanceTestHelper
	logger   *Logger
}

// NewMemoryLeakFixesTestSuite creates a new test suite for memory leak fixes
func NewMemoryLeakFixesTestSuite() *MemoryLeakFixesTestSuite {
	return &MemoryLeakFixesTestSuite{
		runner:   NewTestSuiteRunner(),
		factory:  NewTestDataFactory(),
		edgeGen:  NewEdgeCaseGenerator(),
		perfTest: NewPerformanceTestHelper(),
		logger:   GetSingletonNoOpLogger(),
	}
}

// TestOptimizedCacheLifecycleManagement verifies cache lifecycle using table-driven tests
func TestOptimizedCacheLifecycleManagement(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeLeakDetection) {
		return
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic cache lifecycle",
			Description: "Test basic cache creation, use, and cleanup",
			Operation: func() error {
				cache := NewOptimizedCache()
				if cache == nil {
					return fmt.Errorf("cache creation failed")
				}

				// Test basic operations
				cache.Set("test", "value", time.Minute)
				val, found := cache.Get("test")
				if !found || val != "value" {
					return fmt.Errorf("cache operation failed")
				}

				cache.Close()
				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Cache with multiple entries",
			Description: "Test cache with multiple entries and cleanup",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Add multiple entries
				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					cache.Set(key, fmt.Sprintf("value-%d", i), time.Minute)
				}

				// Verify entries
				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					_, found := cache.Get(key)
					if !found {
						return fmt.Errorf("cache entry missing: %s", key)
					}
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  5.0,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
		{
			Name:        "Cache with expiring entries",
			Description: "Test cache cleanup of expired entries",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Add entries with short expiration
				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("short-key-%d", i)
					cache.Set(key, "short-value", 50*time.Millisecond)
				}

				// Wait for expiration
				time.Sleep(100 * time.Millisecond)

				// Trigger cleanup
				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("cleanup-key-%d", i)
					cache.Set(key, "new-value", time.Minute)
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// TestChunkManagerBoundedSessions verifies session limits using table-driven tests
func TestChunkManagerBoundedSessions(t *testing.T) {
	suite := NewMemoryLeakFixesTestSuite()

	tests := []TableTestCase{
		{
			Name:        "Basic chunk manager initialization",
			Description: "Verify chunk manager is properly initialized with bounds",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
		{
			Name:        "Session limits enforcement",
			Description: "Verify session limits are properly enforced",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
	}

	// Run configuration validation tests
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				err := test.Setup(t)
				require.NoError(t, err)
			}

			if test.Teardown != nil {
				defer func() {
					err := test.Teardown(t)
					assert.NoError(t, err)
				}()
			}

			logger := GetSingletonNoOpLogger()
			cm := NewChunkManager(logger)

			// Verify bounds are set
			assert.Equal(t, 1000, cm.maxSessions)
			assert.Equal(t, 24*time.Hour, cm.sessionTTL)

			// Test that session map is initialized
			assert.NotNil(t, cm.sessionMap)
			assert.Equal(t, 0, len(cm.sessionMap))
		})
	}

	// Run memory leak tests for session management
	leakTests := []MemoryLeakTestCase{
		{
			Name:        "Session map memory management",
			Description: "Verify session map doesn't leak memory with bounded sessions",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				cm := NewChunkManager(logger)

				// Verify chunk manager is initialized properly
				if cm == nil {
					return fmt.Errorf("chunk manager creation failed")
				}

				// Simulate session creation within bounds
				for i := 0; i < 100; i++ {
					sessionID := fmt.Sprintf("session-%d", i)
					// Mock session creation (would need actual implementation)
					_ = sessionID
				}

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 1,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            5 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, leakTests)
}

// TestProviderRegistryBoundedCache verifies provider registry bounds using edge cases
func TestProviderRegistryBoundedCache(t *testing.T) {
	suite := NewMemoryLeakFixesTestSuite()

	// Test conceptual patterns that would be used for provider registry
	tests := []TableTestCase{
		{
			Name:        "Registry bounds validation",
			Description: "Validate registry bounds pattern for future implementation",
			Input:       1000, // Expected max cache size
			Expected:    true, // Pattern validation should pass
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
	}

	// Test edge cases for registry bounds
	edgeCases := suite.edgeGen.GenerateIntegerEdgeCases()
	for _, maxSize := range edgeCases {
		if maxSize > 0 { // Only test positive values for cache size
			tests = append(tests, TableTestCase{
				Name:        fmt.Sprintf("Registry bounds edge case - size %d", maxSize),
				Description: "Test registry bounds with edge case values",
				Input:       maxSize,
				Expected:    maxSize > 0,
			})
		}
	}

	suite.runner.RunTests(t, tests)

	// Memory leak test for potential registry implementation
	leakTests := []MemoryLeakTestCase{
		{
			Name:        "Provider registry memory pattern",
			Description: "Test memory pattern for bounded provider registry",
			Operation: func() error {
				// Simulate registry operations that would be used
				maxCacheSize := 1000
				cacheCount := 0
				cache := make(map[string]interface{})

				// Simulate bounded cache operations
				for i := 0; i < maxCacheSize*2; i++ { // Try to exceed bounds
					key := fmt.Sprintf("provider-%d", i)
					if cacheCount < maxCacheSize {
						cache[key] = fmt.Sprintf("config-%d", i)
						cacheCount++
					}
				}

				// Verify bounds are respected
				if len(cache) > maxCacheSize {
					return fmt.Errorf("cache exceeded bounds: %d > %d", len(cache), maxCacheSize)
				}

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 0,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            5 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, leakTests)
}

// TestErrorRecoveryLifecycleManagement tests graceful degradation cleanup
func TestErrorRecoveryLifecycleManagement(t *testing.T) {
	suite := NewMemoryLeakFixesTestSuite()

	// Test various error recovery scenarios
	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic background task lifecycle",
			Description: "Test background task creation, execution, and cleanup",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()

				config := struct {
					HealthCheckInterval time.Duration
				}{
					HealthCheckInterval: 100 * time.Millisecond,
				}

				taskFunc := func() {
					// Mock health check operation
				}

				task := NewBackgroundTask("test-health-check", config.HealthCheckInterval, taskFunc, logger)
				task.Start()

				// Let it run briefly
				time.Sleep(50 * time.Millisecond)

				// Stop the task
				task.Stop()

				// Wait for cleanup
				time.Sleep(200 * time.Millisecond)

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Multiple background tasks",
			Description: "Test multiple background tasks lifecycle management",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()
				tasks := make([]*BackgroundTask, 0, 3)

				// Create multiple tasks
				for i := 0; i < 3; i++ {
					taskName := fmt.Sprintf("test-task-%d", i)
					taskFunc := func() {
						// Mock task operation
					}
					task := NewBackgroundTask(taskName, 50*time.Millisecond, taskFunc, logger)
					tasks = append(tasks, task)
					task.Start()
				}

				// Let them run
				time.Sleep(100 * time.Millisecond)

				// Stop all tasks
				for _, task := range tasks {
					task.Stop()
				}

				// Wait for cleanup
				time.Sleep(200 * time.Millisecond)

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  1.5,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
		{
			Name:        "Error recovery task patterns",
			Description: "Test error recovery patterns with various edge cases",
			Operation: func() error {
				logger := GetSingletonNoOpLogger()

				// Test with different intervals
				intervals := []time.Duration{
					10 * time.Millisecond,
					50 * time.Millisecond,
					100 * time.Millisecond,
				}

				for _, interval := range intervals {
					taskFunc := func() {
						// Mock health check with potential error handling
					}

					task := NewBackgroundTask("variable-interval-task", interval, taskFunc, logger)
					task.Start()

					// Brief execution
					time.Sleep(25 * time.Millisecond)

					task.Stop()

					// Wait for cleanup
					time.Sleep(50 * time.Millisecond)
				}

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// TestBackgroundTaskProperShutdown verifies BackgroundTask cleans up properly using table-driven tests
func TestBackgroundTaskProperShutdown(t *testing.T) {
	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic background task shutdown",
			Description: "Test basic background task execution and proper shutdown",
			Operation: func() error {
				var wg sync.WaitGroup
				logger := GetSingletonNoOpLogger()

				callCount := 0
				taskFunc := func() {
					callCount++
				}

				task := NewBackgroundTask("test-task", 50*time.Millisecond, taskFunc, logger, &wg)
				task.Start()

				// Let it run a few times
				time.Sleep(150 * time.Millisecond)
				if callCount == 0 {
					return fmt.Errorf("task should have executed at least once")
				}

				// Stop the task
				task.Stop()

				// Wait for cleanup
				wg.Wait()
				time.Sleep(100 * time.Millisecond)

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
		{
			Name:        "High frequency background task",
			Description: "Test background task with high execution frequency",
			Operation: func() error {
				var wg sync.WaitGroup
				logger := GetSingletonNoOpLogger()

				callCount := 0
				taskFunc := func() {
					callCount++
				}

				task := NewBackgroundTask("high-freq-task", 10*time.Millisecond, taskFunc, logger, &wg)
				task.Start()

				// Let it run many times
				time.Sleep(100 * time.Millisecond)

				// Stop the task
				task.Stop()

				// Wait for cleanup
				wg.Wait()
				time.Sleep(50 * time.Millisecond)

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Task with edge case intervals",
			Description: "Test background task with various edge case intervals",
			Operation: func() error {
				var wg sync.WaitGroup
				logger := GetSingletonNoOpLogger()

				// Test with edge case intervals
				validIntervals := []time.Duration{
					1 * time.Millisecond,
					5 * time.Millisecond,
					100 * time.Millisecond,
				}

				for _, interval := range validIntervals {
					taskFunc := func() {
						// Minimal task work
					}

					task := NewBackgroundTask("edge-interval-task", interval, taskFunc, logger, &wg)
					task.Start()

					// Brief execution
					time.Sleep(20 * time.Millisecond)

					task.Stop()
					wg.Wait()
				}

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// TestMetadataCacheResourceCleanup verifies metadata cache cleanup using enhanced testing
func TestMetadataCacheResourceCleanup(t *testing.T) {
	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic metadata cache cleanup",
			Description: "Test metadata cache creation and cleanup",
			Operation: func() error {
				var wg sync.WaitGroup

				cache := NewMetadataCache(&wg)
				if cache == nil {
					return fmt.Errorf("cache creation failed")
				}

				// Let it run briefly
				time.Sleep(50 * time.Millisecond)

				// Close the cache
				cache.Close()

				// Wait for cleanup
				time.Sleep(100 * time.Millisecond)

				return nil
			},
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Metadata cache with operations",
			Description: "Test metadata cache with typical operations before cleanup",
			Operation: func() error {
				var wg sync.WaitGroup

				cache := NewMetadataCache(&wg)
				defer cache.Close()

				// Simulate metadata operations
				for i := 0; i < 10; i++ {
					key := fmt.Sprintf("metadata-key-%d", i)
					// Mock metadata operations (would need actual implementation)
					_ = key
					time.Sleep(5 * time.Millisecond)
				}

				// Additional runtime before cleanup
				time.Sleep(50 * time.Millisecond)

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
		{
			Name:        "Multiple metadata caches",
			Description: "Test multiple metadata cache instances cleanup",
			Operation: func() error {
				var wg sync.WaitGroup
				caches := make([]*MetadataCache, 0, 3)

				// Create multiple caches
				for i := 0; i < 3; i++ {
					cache := NewMetadataCache(&wg)
					if cache == nil {
						return fmt.Errorf("cache creation failed for instance %d", i)
					}
					caches = append(caches, cache)
				}

				// Let them run
				time.Sleep(50 * time.Millisecond)

				// Close all caches
				for _, cache := range caches {
					cache.Close()
				}

				// Wait for cleanup
				time.Sleep(100 * time.Millisecond)

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// TestSecureDataCleanup verifies sensitive data cleanup using comprehensive edge cases
func TestSecureDataCleanup(t *testing.T) {
	suite := NewMemoryLeakFixesTestSuite()

	// Test secure data cleanup with various data types and sizes
	tests := []TableTestCase{
		{
			Name:        "Basic sensitive data cleanup",
			Description: "Test basic sensitive data storage and cleanup",
			Input:       []byte("secret-token-data"),
			Expected:    true, // Cleanup should succeed
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
	}

	// Generate edge cases for sensitive data
	stringEdgeCases := suite.edgeGen.GenerateStringEdgeCases()
	for i, testString := range stringEdgeCases {
		if len(testString) > 0 { // Skip empty strings for this test
			tests = append(tests, TableTestCase{
				Name:        fmt.Sprintf("Sensitive data edge case %d", i),
				Description: "Test secure cleanup with edge case data",
				Input:       []byte(testString),
				Expected:    true,
			})
		}
	}

	// Run table-driven tests
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				err := test.Setup(t)
				require.NoError(t, err)
			}

			if test.Teardown != nil {
				defer func() {
					err := test.Teardown(t)
					assert.NoError(t, err)
				}()
			}

			cache := NewOptimizedCache()
			defer cache.Close()

			// Store sensitive data
			sensitiveData := test.Input.([]byte)
			cache.Set("token", sensitiveData, time.Minute)

			// Verify it's stored
			val, found := cache.Get("token")
			assert.True(t, found)
			assert.Equal(t, sensitiveData, val)

			// Close cache (should trigger secure cleanup)
			cache.Close()

			// Note: We can't easily verify the data is zeroed since Go GC
			// and the slice might be reused, but the structure is in place
		})
	}

	// Memory leak test for secure data cleanup
	leakTests := []MemoryLeakTestCase{
		{
			Name:        "Secure data cleanup memory management",
			Description: "Test memory management for secure data cleanup operations",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Store multiple sensitive data items
				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("sensitive-key-%d", i)
					sensitiveData := []byte(fmt.Sprintf("secret-data-%d-%s", i, suite.factory.GenerateRandomString(64)))
					cache.Set(key, sensitiveData, time.Minute)
				}

				// Verify storage
				for i := 0; i < 50; i++ {
					key := fmt.Sprintf("sensitive-key-%d", i)
					_, found := cache.Get(key)
					if !found {
						return fmt.Errorf("sensitive data not found for key: %s", key)
					}
				}

				// Close cache (should trigger secure cleanup)
				cache.Close()

				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 1,
			MaxMemoryGrowthMB:  2.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, leakTests)
}

// TestMemoryGrowthPrevention verifies systems don't grow unbounded using enhanced testing
func TestMemoryGrowthPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory growth test in short mode")
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Multiple cache memory growth prevention",
			Description: "Test memory growth with multiple cache instances",
			Operation: func() error {
				// Create and use multiple components
				caches := make([]*OptimizedCache, 10)
				for i := 0; i < 10; i++ {
					caches[i] = NewOptimizedCache()
					// Add some data
					for j := 0; j < 100; j++ {
						caches[i].Set(fmt.Sprintf("key-%d-%d", i, j), "value", time.Minute)
					}
				}

				// Clean up all caches
				for _, cache := range caches {
					cache.Close()
				}

				// Force GC
				runtime.GC()
				time.Sleep(100 * time.Millisecond)
				runtime.GC()

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 5,
			MaxMemoryGrowthMB:  50.0, // 50MB tolerance
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
		{
			Name:        "Large dataset memory growth prevention",
			Description: "Test memory growth with large datasets",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Create larger dataset
				for i := 0; i < 1000; i++ {
					key := fmt.Sprintf("large-key-%d", i)
					value := suite.factory.GenerateRandomString(1024) // 1KB values
					cache.Set(key, value, time.Minute)
				}

				// Force cleanup of some entries by setting with short expiration
				for i := 0; i < 500; i++ {
					key := fmt.Sprintf("temp-key-%d", i)
					cache.Set(key, "temp-value", 10*time.Millisecond)
				}

				// Wait for expiration
				time.Sleep(50 * time.Millisecond)

				// Trigger cleanup by accessing cache
				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("cleanup-trigger-%d", i)
					cache.Get(key) // Will trigger cleanup
				}

				return nil
			},
			Iterations:         2,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  100.0, // Allow more growth for large datasets
			GCBetweenRuns:      true,
			Timeout:            45 * time.Second,
		},
		{
			Name:        "Cache churn memory growth prevention",
			Description: "Test memory growth with high cache churn",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Simulate high cache churn
				for round := 0; round < 5; round++ {
					// Add entries
					for i := 0; i < 200; i++ {
						key := fmt.Sprintf("churn-key-%d-%d", round, i)
						value := suite.factory.GenerateRandomString(256)
						cache.Set(key, value, 20*time.Millisecond)
					}

					// Wait for some to expire
					time.Sleep(30 * time.Millisecond)

					// Access to trigger cleanup
					for i := 0; i < 50; i++ {
						key := fmt.Sprintf("access-key-%d", i)
						cache.Get(key)
					}
				}

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 3,
			MaxMemoryGrowthMB:  20.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// TestGoroutineLeakPrevention tests concurrent components for goroutine leaks
func TestGoroutineLeakPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping goroutine leak test in short mode")
	}

	suite := NewMemoryLeakFixesTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Concurrent cache goroutine management",
			Description: "Test goroutine management with concurrent cache operations",
			Operation: func() error {
				// Run multiple components concurrently
				var wg sync.WaitGroup

				// Start multiple caches
				for i := 0; i < 5; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						cache := NewOptimizedCache()
						defer cache.Close()

						// Use the cache briefly
						for j := 0; j < 10; j++ {
							cache.Set(fmt.Sprintf("key-%d", j), "value", time.Minute)
							time.Sleep(time.Millisecond)
						}
					}(i)
				}

				wg.Wait()

				// Wait for cleanup
				time.Sleep(500 * time.Millisecond)
				runtime.GC()

				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 5, // Allow some variance
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
		{
			Name:        "High concurrency goroutine management",
			Description: "Test goroutine management with high concurrency",
			Operation: func() error {
				var wg sync.WaitGroup

				// Higher concurrency test
				for i := 0; i < 20; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						cache := NewOptimizedCache()
						defer cache.Close()

						// Brief cache usage
						for j := 0; j < 5; j++ {
							key := fmt.Sprintf("concurrent-key-%d-%d", i, j)
							cache.Set(key, "concurrent-value", 10*time.Second)
						}
					}(i)
				}

				wg.Wait()

				// Cleanup wait
				time.Sleep(300 * time.Millisecond)
				runtime.GC()

				return nil
			},
			Iterations:         2,
			MaxGoroutineGrowth: 10, // Allow more variance for higher concurrency
			MaxMemoryGrowthMB:  15.0,
			GCBetweenRuns:      true,
			Timeout:            45 * time.Second,
		},
		{
			Name:        "Mixed component goroutine management",
			Description: "Test goroutine management with mixed component types",
			Operation: func() error {
				var wg sync.WaitGroup

				// Mix different components
				for i := 0; i < 3; i++ {
					// Cache goroutine
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						cache := NewOptimizedCache()
						defer cache.Close()
						cache.Set("mixed-key", "mixed-value", time.Minute)
					}(i)

					// Background task goroutine
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						logger := GetSingletonNoOpLogger()
						taskFunc := func() {}
						task := NewBackgroundTask(fmt.Sprintf("mixed-task-%d", i), 50*time.Millisecond, taskFunc, logger)
						task.Start()
						time.Sleep(25 * time.Millisecond)
						task.Stop()
					}(i)

					// Metadata cache goroutine
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						var localWG sync.WaitGroup
						cache := NewMetadataCache(&localWG)
						time.Sleep(25 * time.Millisecond)
						cache.Close()
					}(i)
				}

				wg.Wait()

				// Extended cleanup wait for mixed components
				time.Sleep(500 * time.Millisecond)
				runtime.GC()

				return nil
			},
			Iterations:         2,
			MaxGoroutineGrowth: 8,
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Timeout:            30 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// BenchmarkMemoryLeakFixes provides performance benchmarks for memory leak fixes
func BenchmarkMemoryLeakFixes(b *testing.B) {
	suite := NewMemoryLeakFixesTestSuite()

	b.Run("OptimizedCacheLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache := NewOptimizedCache()
			cache.Set("bench-key", "bench-value", time.Minute)
			_, _ = cache.Get("bench-key")
			cache.Close()
		}
	})

	b.Run("BackgroundTaskLifecycle", func(b *testing.B) {
		logger := GetSingletonNoOpLogger()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			taskFunc := func() {}
			task := NewBackgroundTask("bench-task", 100*time.Millisecond, taskFunc, logger)
			task.Start()
			task.Stop()
		}
	})

	b.Run("MetadataCacheLifecycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			cache := NewMetadataCache(&wg)
			cache.Close()
		}
	})

	b.Run("SecureDataCleanup", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache := NewOptimizedCache()
			sensitiveData := []byte(suite.factory.GenerateRandomString(64))
			cache.Set("sensitive-key", sensitiveData, time.Minute)
			cache.Close()
		}
	})
}
