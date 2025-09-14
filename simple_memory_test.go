package traefikoidc

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SimpleMemoryTestSuite provides focused memory verification tests using unified infrastructure
type SimpleMemoryTestSuite struct {
	runner   *TestSuiteRunner
	factory  *TestDataFactory
	edgeGen  *EdgeCaseGenerator
	perfTest *PerformanceTestHelper
	logger   *Logger
}

// NewSimpleMemoryTestSuite creates a new test suite for simple memory verification
func NewSimpleMemoryTestSuite() *SimpleMemoryTestSuite {
	return &SimpleMemoryTestSuite{
		runner:   NewTestSuiteRunner(),
		factory:  NewTestDataFactory(),
		edgeGen:  NewEdgeCaseGenerator(),
		perfTest: NewPerformanceTestHelper(),
		logger:   GetSingletonNoOpLogger(),
	}
}

// TestSimpleCacheOperations verifies basic cache operations using table-driven tests
func TestSimpleCacheOperations(t *testing.T) {
	config := GetTestConfig()
	if config.ShouldSkipTest(t, TestTypeQuick) {
		return
	}

	suite := NewSimpleMemoryTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Basic cache creation and cleanup",
			Description: "Verify cache can be created, used briefly, and cleaned up without leaks",
			Operation: func() error {
				cache := NewOptimizedCache()
				if cache == nil {
					return fmt.Errorf("cache creation failed")
				}

				// Use the cache briefly
				cache.Set("test", "value", time.Minute)
				val, found := cache.Get("test")
				if !found {
					return fmt.Errorf("cache get failed: key not found")
				}
				if val != "value" {
					return fmt.Errorf("cache get failed: expected 'value', got %v", val)
				}

				// Close immediately
				cache.Close()

				// Brief wait for cleanup
				time.Sleep(50 * time.Millisecond)
				return nil
			},
			Iterations:         3,
			MaxGoroutineGrowth: 2,   // Allow minimal framework overhead
			MaxMemoryGrowthMB:  0.5, // Very strict for simple operations
			GCBetweenRuns:      true,
			Timeout:            5 * time.Second,
		},
		{
			Name:        "Cache with multiple quick operations",
			Description: "Test cache with rapid set/get operations",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Perform multiple quick operations
				for i := 0; i < 10; i++ {
					key := fmt.Sprintf("key-%d", i)
					value := fmt.Sprintf("value-%d", i)
					cache.Set(key, value, time.Minute)

					val, found := cache.Get(key)
					if !found {
						return fmt.Errorf("cache get failed for key %s", key)
					}
					if val != value {
						return fmt.Errorf("cache value mismatch for key %s: expected %s, got %v", key, value, val)
					}
				}
				return nil
			},
			Iterations:         5,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            8 * time.Second,
		},
		{
			Name:        "Cache with edge case values",
			Description: "Test cache with edge case string values",
			Operation: func() error {
				cache := NewOptimizedCache()
				defer cache.Close()

				// Test with edge case strings from the generator
				edgeCases := suite.edgeGen.GenerateStringEdgeCases()
				for i, value := range edgeCases[:5] { // Limit to first 5 for simplicity
					key := fmt.Sprintf("edge-key-%d", i)
					cache.Set(key, value, time.Minute)

					val, found := cache.Get(key)
					if !found {
						return fmt.Errorf("cache get failed for edge case key %s", key)
					}
					if val != value {
						return fmt.Errorf("cache value mismatch for edge case key %s", key)
					}
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

// TestChunkManagerInitialization verifies chunk manager initialization using table-driven tests
func TestChunkManagerInitialization(t *testing.T) {
	suite := NewSimpleMemoryTestSuite()

	tests := []TableTestCase{
		{
			Name:        "Basic chunk manager creation",
			Description: "Verify chunk manager can be created with proper defaults",
			Input:       nil, // No specific input needed
			Expected: map[string]interface{}{
				"maxSessions": 200,
				"sessionTTL":  15 * time.Minute,
				"notNil":      true,
			},
			Timeout: 5 * time.Second,
			Setup: func(t *testing.T) error {
				// No setup needed
				return nil
			},
			Teardown: func(t *testing.T) error {
				// No teardown needed
				return nil
			},
		},
		{
			Name:        "Chunk manager with logger verification",
			Description: "Verify chunk manager works correctly with singleton logger",
			Input:       "singleton_logger",
			Expected: map[string]interface{}{
				"hasLogger":   true,
				"maxSessions": 200,
				"sessionTTL":  15 * time.Minute,
			},
			Timeout: 5 * time.Second,
		},
	}

	// Custom test execution since TableTestCase doesn't have built-in logic
	for _, test := range tests {
		test := test // Capture loop variable

		t.Run(test.Name, func(t *testing.T) {
			if test.Setup != nil {
				require.NoError(t, test.Setup(t))
			}

			if test.Teardown != nil {
				defer func() {
					require.NoError(t, test.Teardown(t))
				}()
			}

			// Execute the actual test logic
			logger := suite.logger
			cm := NewChunkManager(logger)

			// Verify basic properties
			assert.NotNil(t, cm, "Chunk manager should not be nil")
			assert.NotNil(t, cm.sessionMap, "Session map should not be nil")

			// Verify expected values from test case
			expected := test.Expected.(map[string]interface{})
			assert.Equal(t, expected["maxSessions"], cm.maxSessions, "Max sessions should match expected value")
			assert.Equal(t, expected["sessionTTL"], cm.sessionTTL, "Session TTL should match expected value")

			if hasLogger, exists := expected["hasLogger"]; exists && hasLogger.(bool) {
				assert.NotNil(t, logger, "Logger should not be nil when expected")
			}
		})
	}
}

// TestSimpleMemoryLeakDetection provides memory leak detection using the infrastructure
func TestSimpleMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping simple memory leak detection in short mode")
	}

	suite := NewSimpleMemoryTestSuite()

	tests := []MemoryLeakTestCase{
		{
			Name:        "Repeated cache creation and destruction",
			Description: "Verify no leaks from repeated cache lifecycle",
			Operation: func() error {
				cache := NewOptimizedCache()
				cache.Set("test", "value", 100*time.Millisecond)
				_, _ = cache.Get("test")
				cache.Close()

				// Small delay to allow cleanup
				time.Sleep(20 * time.Millisecond)
				return nil
			},
			Iterations:         20,
			MaxGoroutineGrowth: 3,   // Slightly more tolerance for repeated operations
			MaxMemoryGrowthMB:  2.0, // Allow for some accumulation over iterations
			GCBetweenRuns:      true,
			Timeout:            15 * time.Second,
		},
		{
			Name:        "Chunk manager creation cycles",
			Description: "Verify no leaks from chunk manager creation",
			Operation: func() error {
				logger := suite.logger
				cm := NewChunkManager(logger)

				// Verify it was created properly
				if cm == nil {
					return fmt.Errorf("chunk manager creation failed")
				}

				if cm.sessionMap == nil {
					return fmt.Errorf("chunk manager session map not initialized")
				}

				// Properly shut down to prevent goroutine leaks
				cm.Shutdown()

				return nil
			},
			Iterations:         15,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  1.0,
			GCBetweenRuns:      true,
			Timeout:            10 * time.Second,
		},
	}

	suite.runner.RunMemoryLeakTests(t, tests)
}

// BenchmarkSimpleCacheOperations provides basic performance benchmarks
func BenchmarkSimpleCacheOperations(b *testing.B) {
	cache := NewOptimizedCache()
	defer cache.Close()

	b.Run("Set operations", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench-key-%d", i)
			cache.Set(key, "benchmark-value", time.Minute)
		}
	})

	b.Run("Get operations", func(b *testing.B) {
		// Pre-populate cache
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("bench-key-%d", i)
			cache.Set(key, "benchmark-value", time.Minute)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench-key-%d", i%1000)
			cache.Get(key)
		}
	})

	b.Run("Set and Get combined", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench-key-%d", i)
			cache.Set(key, "benchmark-value", time.Minute)
			cache.Get(key)
		}
	})
}

// BenchmarkChunkManagerCreation provides benchmarks for chunk manager operations
func BenchmarkChunkManagerCreation(b *testing.B) {
	logger := GetSingletonNoOpLogger()

	b.Run("Chunk manager creation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cm := NewChunkManager(logger)
			_ = cm // Avoid compiler optimization
		}
	})
}
