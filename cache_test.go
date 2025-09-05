package traefikoidc

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCacheBasicOperations tests the fundamental cache operations using table-driven tests
func TestCacheBasicOperations(t *testing.T) {
	runner := NewTestSuiteRunner()
	runner.SetTimeout(10 * time.Second)

	testCases := []TableTestCase{
		{
			Name:        "Set and Get - Valid Key",
			Description: "Basic set and get operation with valid data",
			Setup: func(t *testing.T) error {
				return nil
			},
			Teardown: func(t *testing.T) error {
				return nil
			},
		},
		{
			Name:        "Get Non-existent Key",
			Description: "Getting a key that doesn't exist should return false",
		},
		{
			Name:        "Set and Get - Zero Value",
			Description: "Test caching zero values like empty strings, nil, zero numbers",
		},
		{
			Name:        "Delete Existing Key",
			Description: "Delete should remove the key and make it unavailable",
		},
		{
			Name:        "Delete Non-existent Key",
			Description: "Deleting a non-existent key should not cause errors",
		},
	}

	// Execute basic operation tests with custom logic
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			cache := NewCache()
			defer cache.Close()

			switch tc.Name {
			case "Set and Get - Valid Key":
				testValue := "test-value-123"
				cache.Set("test-key", testValue, time.Hour)

				result, found := cache.Get("test-key")
				assert.True(t, found, "Expected key to be found")
				assert.Equal(t, testValue, result, "Expected values to match")

			case "Get Non-existent Key":
				result, found := cache.Get("non-existent")
				assert.False(t, found, "Expected key not to be found")
				assert.Nil(t, result, "Expected nil result for non-existent key")

			case "Set and Get - Zero Value":
				// Test various zero values
				cache.Set("empty-string", "", time.Hour)
				cache.Set("zero-int", 0, time.Hour)
				cache.Set("nil-value", nil, time.Hour)
				cache.Set("false-value", false, time.Hour)

				val, found := cache.Get("empty-string")
				assert.True(t, found)
				assert.Equal(t, "", val)

				val, found = cache.Get("zero-int")
				assert.True(t, found)
				assert.Equal(t, 0, val)

				val, found = cache.Get("nil-value")
				assert.True(t, found)
				assert.Nil(t, val)

				val, found = cache.Get("false-value")
				assert.True(t, found)
				assert.Equal(t, false, val)

			case "Delete Existing Key":
				cache.Set("delete-me", "value", time.Hour)
				_, found := cache.Get("delete-me")
				assert.True(t, found, "Key should exist before deletion")

				cache.Delete("delete-me")
				_, found = cache.Get("delete-me")
				assert.False(t, found, "Key should not exist after deletion")

			case "Delete Non-existent Key":
				// Should not panic or cause errors
				cache.Delete("does-not-exist")
				// If we reach here, the test passes
				assert.True(t, true)
			}
		})
	}
}

// TestCacheExpiration tests TTL functionality with edge cases
func TestCacheExpiration(t *testing.T) {
	edgeGen := NewEdgeCaseGenerator()
	expirationTimes := []time.Duration{
		10 * time.Millisecond,  // Very short but still measurable
		50 * time.Millisecond,  // Short
		100 * time.Millisecond, // Medium short
		500 * time.Millisecond, // Medium
		1 * time.Second,        // Long
		time.Hour,              // Very long
	}

	t.Run("Expiration Times", func(t *testing.T) {
		for _, expiration := range expirationTimes {
			expiration := expiration
			t.Run(fmt.Sprintf("Expiration_%s", expiration), func(t *testing.T) {
				cache := NewCache()
				defer cache.Close()

				key := fmt.Sprintf("test-key-%s", expiration)
				value := fmt.Sprintf("test-value-%s", expiration)

				cache.Set(key, value, expiration)

				// Immediate retrieval should work
				result, found := cache.Get(key)
				assert.True(t, found, "Key should be found immediately after set")
				assert.Equal(t, value, result)

				// Wait for expiration
				if expiration < time.Second {
					time.Sleep(expiration + 10*time.Millisecond)
				} else {
					// For long expiration times, don't actually wait
					t.Skip("Skipping long expiration test to save time")
				}

				// Should be expired now
				result, found = cache.Get(key)
				assert.False(t, found, "Key should not be found after expiration")
				assert.Nil(t, result)
			})
		}
	})

	t.Run("Expiration Edge Cases", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		// Test with edge case strings
		edgeCases := edgeGen.GenerateStringEdgeCases()
		for i, testStr := range edgeCases {
			if i > 5 { // Limit to first 5 to avoid too many tests
				break
			}
			key := fmt.Sprintf("edge-key-%d", i)
			cache.Set(key, testStr, 10*time.Millisecond)
		}

		// Wait for expiration
		time.Sleep(50 * time.Millisecond)

		// All should be expired
		for i := 0; i < 6; i++ {
			key := fmt.Sprintf("edge-key-%d", i)
			_, found := cache.Get(key)
			assert.False(t, found, "Edge case key %s should be expired", key)
		}
	})
}

// TestCacheSize tests size management and eviction policies
func TestCacheSize(t *testing.T) {
	t.Run("SetMaxSize Eviction", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		originalMaxSize := 10
		newMaxSize := 3

		// Add more items than the new max size
		for i := 0; i < originalMaxSize; i++ {
			key := fmt.Sprintf("key%c", rune('A'+i))
			cache.Set(key, i, time.Hour)
		}

		// Verify items were added
		for i := 0; i < originalMaxSize; i++ {
			key := fmt.Sprintf("key%c", rune('A'+i))
			_, exists := cache.Get(key)
			require.True(t, exists, "Expected key %s to exist before SetMaxSize", key)
		}

		// Change the max size to a smaller value
		cache.SetMaxSize(newMaxSize)

		// Count remaining items
		count := 0
		for i := 0; i < originalMaxSize; i++ {
			key := fmt.Sprintf("key%c", rune('A'+i))
			if _, exists := cache.Get(key); exists {
				count++
			}
		}

		// Check that the cache was reduced to the new max size
		assert.LessOrEqual(t, count, newMaxSize, "Cache size %d exceeds new max size %d after SetMaxSize", count, newMaxSize)

		// Check that the oldest items were evicted (keyA should be evicted)
		_, exists := cache.Get("keyA")
		assert.False(t, exists, "Expected oldest item 'keyA' to be evicted, but it still exists")
	})

	t.Run("Eviction With Mixed Expiration Times", func(t *testing.T) {
		cache := NewCache()
		cache.SetMaxSize(5)
		defer cache.Close()

		// Add items with different expiration times
		cache.Set("expired1", "val1", -time.Hour) // Already expired
		cache.Set("valid1", "val1", time.Hour)    // Valid
		cache.Set("expired2", "val2", -time.Hour) // Already expired
		cache.Set("valid2", "val2", time.Hour)    // Valid
		cache.Set("valid3", "val3", time.Hour)    // Valid

		// Add one more to trigger eviction (should preferably evict expired items)
		cache.Set("valid4", "val4", time.Hour)

		// Count valid items (should be 4 valid ones)
		validCount := 0
		expiredCount := 0
		keys := []string{"expired1", "valid1", "expired2", "valid2", "valid3", "valid4"}

		for _, key := range keys {
			if _, found := cache.Get(key); found {
				if len(key) >= 7 && key[:7] == "expired" {
					expiredCount++
				} else {
					validCount++
				}
			}
		}

		assert.LessOrEqual(t, validCount+expiredCount, 5, "Total items should not exceed max size")
		assert.LessOrEqual(t, expiredCount, 2, "Should prioritize evicting expired items")
	})
}

// TestCacheConcurrency tests concurrent operations and thread safety
func TestCacheConcurrency(t *testing.T) {
	t.Run("Concurrent Set and Get", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		const numGoroutines = 100
		const operationsPerGoroutine = 50
		var wg sync.WaitGroup

		// Statistics tracking
		var setOperations int64
		var getOperations int64
		var successfulGets int64

		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				defer wg.Done()

				for j := 0; j < operationsPerGoroutine; j++ {
					key := fmt.Sprintf("key-%d-%d", goroutineID, j)
					value := fmt.Sprintf("value-%d-%d", goroutineID, j)

					// Set operation
					cache.Set(key, value, time.Minute)
					atomic.AddInt64(&setOperations, 1)

					// Get operation
					if result, found := cache.Get(key); found {
						atomic.AddInt64(&successfulGets, 1)
						if result != value {
							t.Errorf("Got unexpected value: expected %s, got %s", value, result)
						}
					}
					atomic.AddInt64(&getOperations, 1)
				}
			}(i)
		}

		wg.Wait()

		totalExpectedOps := int64(numGoroutines * operationsPerGoroutine)
		assert.Equal(t, totalExpectedOps, atomic.LoadInt64(&setOperations), "All set operations should complete")
		assert.Equal(t, totalExpectedOps, atomic.LoadInt64(&getOperations), "All get operations should complete")

		// Most gets should succeed (allowing for some eviction)
		successRate := float64(atomic.LoadInt64(&successfulGets)) / float64(atomic.LoadInt64(&getOperations))
		assert.Greater(t, successRate, 0.7, "At least 70%% of gets should succeed")
	})

	t.Run("Concurrent Set and Delete", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		const numItems = 1000
		var wg sync.WaitGroup

		// Add items concurrently
		wg.Add(numItems)
		for i := 0; i < numItems; i++ {
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("concurrent-key-%d", id)
				cache.Set(key, fmt.Sprintf("value-%d", id), time.Minute)
			}(i)
		}
		wg.Wait()

		// Delete items concurrently
		wg.Add(numItems)
		for i := 0; i < numItems; i++ {
			go func(id int) {
				defer wg.Done()
				key := fmt.Sprintf("concurrent-key-%d", id)
				cache.Delete(key)
			}(i)
		}
		wg.Wait()

		// Verify all items are deleted
		for i := 0; i < numItems; i++ {
			key := fmt.Sprintf("concurrent-key-%d", i)
			_, found := cache.Get(key)
			assert.False(t, found, "Key %s should be deleted", key)
		}
	})
}

// TestCacheUnifiedMemoryLeaks tests for memory leaks using unified test infrastructure
func TestCacheUnifiedMemoryLeaks(t *testing.T) {
	runner := NewTestSuiteRunner()

	memoryLeakTests := []MemoryLeakTestCase{
		{
			Name:               "Cache Creation and Destruction",
			Description:        "Creating and destroying caches should not leak memory",
			Iterations:         50,
			MaxGoroutineGrowth: 2, // Allow some tolerance for test framework
			MaxMemoryGrowthMB:  5.0,
			GCBetweenRuns:      true,
			Operation: func() error {
				cache := NewCache()
				cache.Set("test", "value", time.Minute)
				_, _ = cache.Get("test")
				cache.Close()
				return nil
			},
		},
		{
			Name:               "Heavy Cache Usage",
			Description:        "Heavy cache usage should not accumulate memory",
			Iterations:         10,
			MaxGoroutineGrowth: 2,
			MaxMemoryGrowthMB:  10.0,
			GCBetweenRuns:      true,
			Operation: func() error {
				cache := NewCache()
				defer cache.Close()

				// Add many items
				for i := 0; i < 1000; i++ {
					key := fmt.Sprintf("key-%d", i)
					cache.Set(key, fmt.Sprintf("value-%d", i), time.Second)
				}

				// Access items randomly
				for i := 0; i < 500; i++ {
					key := fmt.Sprintf("key-%d", i%1000)
					cache.Get(key)
				}

				// Delete some items
				for i := 0; i < 250; i++ {
					key := fmt.Sprintf("key-%d", i*2)
					cache.Delete(key)
				}

				return nil
			},
		},
		{
			Name:               "Cleanup Functionality",
			Description:        "Manual cleanup should free memory properly",
			Iterations:         20,
			MaxGoroutineGrowth: 1,
			MaxMemoryGrowthMB:  3.0,
			GCBetweenRuns:      true,
			Operation: func() error {
				cache := NewCache()
				defer cache.Close()

				// Add items that will expire
				for i := 0; i < 100; i++ {
					key := fmt.Sprintf("key-%d", i)
					cache.Set(key, fmt.Sprintf("value-%d", i), -time.Hour) // Already expired
				}

				// Run cleanup
				cache.Cleanup()

				return nil
			},
		},
	}

	runner.RunMemoryLeakTests(t, memoryLeakTests)
}

// TestCachePerformance includes benchmarks and performance validation
func TestCachePerformance(t *testing.T) {
	t.Run("Basic Operations Performance", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		perfHelper := NewPerformanceTestHelper()

		// Test Set performance
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("perf-key-%d", i)
			value := fmt.Sprintf("perf-value-%d", i)

			perfHelper.Measure(func() {
				cache.Set(key, value, time.Hour)
			})
		}

		avgSetTime := perfHelper.GetAverageTime()
		t.Logf("Average Set time: %v", avgSetTime)
		assert.Less(t, avgSetTime.Nanoseconds(), int64(10*time.Microsecond), "Set operations should be fast")

		// Reset and test Get performance
		perfHelper.Reset()
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("perf-key-%d", i)

			perfHelper.Measure(func() {
				cache.Get(key)
			})
		}

		avgGetTime := perfHelper.GetAverageTime()
		t.Logf("Average Get time: %v", avgGetTime)
		assert.Less(t, avgGetTime.Nanoseconds(), int64(5*time.Microsecond), "Get operations should be very fast")
	})
}

// TestCacheEdgeCases tests various edge cases and error conditions
func TestCacheEdgeCases(t *testing.T) {
	edgeGen := NewEdgeCaseGenerator()

	t.Run("Edge Case Keys and Values", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		keys := edgeGen.GenerateStringEdgeCases()
		values := edgeGen.GenerateStringEdgeCases()

		// Test combinations of edge case keys and values
		for i, key := range keys[:5] { // Limit to first 5 for performance
			for j, value := range values[:3] { // Limit to first 3 for performance
				testName := fmt.Sprintf("Key_%d_Value_%d", i, j)
				t.Run(testName, func(t *testing.T) {
					cache.Set(key, value, time.Minute)
					result, found := cache.Get(key)

					assert.True(t, found, "Should find edge case key")
					assert.Equal(t, value, result, "Should get correct edge case value")

					// Clean up
					cache.Delete(key)
					_, found = cache.Get(key)
					assert.False(t, found, "Should not find deleted edge case key")
				})
			}
		}
	})

	t.Run("Boundary Conditions", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		// Test with zero and negative TTL
		cache.Set("zero-ttl", "value", 0)
		cache.Set("negative-ttl", "value", -time.Hour)

		// Should be immediately expired
		_, found := cache.Get("zero-ttl")
		assert.False(t, found, "Zero TTL should expire immediately")

		_, found = cache.Get("negative-ttl")
		assert.False(t, found, "Negative TTL should expire immediately")

		// Test max size boundaries
		cache.SetMaxSize(1)
		cache.Set("first", "value1", time.Hour)
		cache.Set("second", "value2", time.Hour)

		// Should only have one item
		firstFound := false
		secondFound := false
		if _, found := cache.Get("first"); found {
			firstFound = true
		}
		if _, found := cache.Get("second"); found {
			secondFound = true
		}

		assert.True(t, firstFound != secondFound, "Should have exactly one item when max size is 1")
	})

	t.Run("Invalid Operations", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		// Test invalid max size
		cache.SetMaxSize(0)   // Should be ignored
		cache.SetMaxSize(-10) // Should be ignored

		// Cache should still work
		cache.Set("test", "value", time.Hour)
		result, found := cache.Get("test")
		assert.True(t, found)
		assert.Equal(t, "value", result)
	})
}

// TestCacheLRUBehavior specifically tests the LRU (Least Recently Used) eviction policy
func TestCacheLRUBehavior(t *testing.T) {
	t.Run("LRU Eviction Order", func(t *testing.T) {
		cache := NewCache()
		cache.SetMaxSize(3)
		defer cache.Close()

		// Add items in order
		cache.Set("first", "1", time.Hour)
		cache.Set("second", "2", time.Hour)
		cache.Set("third", "3", time.Hour)

		// Access first item to make it recently used
		cache.Get("first")

		// Add fourth item, should evict "second" (least recently used)
		cache.Set("fourth", "4", time.Hour)

		// Verify eviction order
		_, found := cache.Get("first")
		assert.True(t, found, "First should still exist (recently accessed)")

		_, found = cache.Get("second")
		assert.False(t, found, "Second should be evicted (least recently used)")

		_, found = cache.Get("third")
		assert.True(t, found, "Third should still exist")

		_, found = cache.Get("fourth")
		assert.True(t, found, "Fourth should exist (just added)")
	})

	t.Run("LRU Update on Set", func(t *testing.T) {
		cache := NewCache()
		cache.SetMaxSize(3)
		defer cache.Close()

		// Add items
		cache.Set("a", "1", time.Hour)
		cache.Set("b", "2", time.Hour)
		cache.Set("c", "3", time.Hour)

		// Update existing item (should move to end of LRU)
		cache.Set("a", "updated", time.Hour)

		// Add new item, should evict "b" (now least recently used)
		cache.Set("d", "4", time.Hour)

		_, found := cache.Get("a")
		assert.True(t, found, "A should still exist (recently updated)")

		_, found = cache.Get("b")
		assert.False(t, found, "B should be evicted")

		_, found = cache.Get("c")
		assert.True(t, found, "C should still exist")

		_, found = cache.Get("d")
		assert.True(t, found, "D should exist")
	})
}

// BenchmarkCache provides performance benchmarks
func BenchmarkCache(b *testing.B) {
	cache := NewCache()
	defer cache.Close()

	b.Run("Set", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("benchmark-key-%d", i)
			cache.Set(key, fmt.Sprintf("value-%d", i), time.Hour)
		}
	})

	b.Run("Get", func(b *testing.B) {
		// Pre-populate cache
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("benchmark-key-%d", i)
			cache.Set(key, fmt.Sprintf("value-%d", i), time.Hour)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("benchmark-key-%d", i%1000)
			cache.Get(key)
		}
	})

	b.Run("Delete", func(b *testing.B) {
		// Pre-populate cache
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("benchmark-delete-key-%d", i)
			cache.Set(key, fmt.Sprintf("value-%d", i), time.Hour)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("benchmark-delete-key-%d", i)
			cache.Delete(key)
		}
	})

	b.Run("Concurrent", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("concurrent-key-%d", i)
				value := fmt.Sprintf("concurrent-value-%d", i)

				cache.Set(key, value, time.Minute)
				cache.Get(key)

				if i%10 == 0 {
					cache.Delete(key)
				}

				i++
			}
		})
	})
}

// TestCache_Cleanup tests the specific cleanup functionality (converted from original test)
func TestCache_Cleanup(t *testing.T) {
	c := NewCache()
	defer c.Close()

	// Add some items with different expiration times
	now := time.Now()
	pastTime := now.Add(-1 * time.Hour)  // Already expired
	futureTime := now.Add(1 * time.Hour) // Not expired

	c.Set("expired", "expired-value", pastTime.Sub(now))
	c.Set("valid", "valid-value", futureTime.Sub(now))

	// Call cleanup, which should only remove expired items
	c.Cleanup()

	// Check that only the expired item was removed
	if _, exists := c.Get("expired"); exists {
		t.Error("Expired item was not removed by Cleanup()")
	}

	if _, exists := c.Get("valid"); !exists {
		t.Error("Valid item was incorrectly removed by Cleanup()")
	}
}

// TestCache_SetMaxSize tests the specific max size functionality (converted from original test)
func TestCache_SetMaxSize(t *testing.T) {
	c := NewCache()
	defer c.Close()

	// Set a lower max size
	originalMaxSize := 10
	newMaxSize := 3

	// Add more items than the new max size
	for i := 0; i < originalMaxSize; i++ {
		key := "key" + string(rune('A'+i))
		c.Set(key, i, 1*time.Hour)
	}

	// Verify items were added by checking a few keys
	for i := 0; i < originalMaxSize; i++ {
		key := "key" + string(rune('A'+i))
		if _, exists := c.Get(key); !exists {
			t.Errorf("Expected key %s to exist before SetMaxSize", key)
		}
	}

	// Change the max size to a smaller value
	c.SetMaxSize(newMaxSize)

	// Count remaining items
	count := 0
	for i := 0; i < originalMaxSize; i++ {
		key := "key" + string(rune('A'+i))
		if _, exists := c.Get(key); exists {
			count++
		}
	}

	// Check that the cache was reduced to the new max size
	if count > newMaxSize {
		t.Errorf("Cache size %d exceeds new max size %d after SetMaxSize", count, newMaxSize)
	}

	// Check that the oldest items were evicted (keyA should be evicted)
	if _, exists := c.Get("keyA"); exists {
		t.Error("Expected oldest item 'keyA' to be evicted, but it still exists")
	}
}
