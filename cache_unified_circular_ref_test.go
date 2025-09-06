package traefikoidc

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLRUCache_NoCircularReferences tests that ListNode structures don't create circular references
// that prevent garbage collection
func TestLRUCache_NoCircularReferences(t *testing.T) {
	tests := []struct {
		name        string
		cacheSize   int
		itemCount   int
		description string
	}{
		{
			name:        "small_cache",
			cacheSize:   10,
			itemCount:   20,
			description: "Small cache with evictions should not have circular references",
		},
		{
			name:        "medium_cache",
			cacheSize:   100,
			itemCount:   200,
			description: "Medium cache with evictions should not have circular references",
		},
		{
			name:        "large_cache",
			cacheSize:   500,
			itemCount:   1000,
			description: "Large cache with evictions should not have circular references",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Force GC and get baseline memory
			runtime.GC()
			runtime.GC()
			debug.FreeOSMemory()
			var m1 runtime.MemStats
			runtime.ReadMemStats(&m1)

			// Create cache with LRU strategy
			config := DefaultUnifiedCacheConfig()
			config.MaxSize = tt.cacheSize
			config.Strategy = NewLRUStrategy(tt.cacheSize)
			config.EnableAutoCleanup = false // Disable to control cleanup timing

			cache := NewUnifiedCache(config)

			// Fill cache beyond capacity to trigger evictions
			for i := 0; i < tt.itemCount; i++ {
				key := generateCacheKey(i)
				value := generateCacheValue(i)
				cache.Set(key, value, time.Hour)

				// Periodic verification during population
				if i > 0 && i%50 == 0 {
					verifyLRUStructureIntegrity(t, cache, "during_population")
				}
			}

			// Verify cache is at expected size
			metrics := cache.GetMetrics()
			currentSize := metrics["item_count"].(int)
			if currentSize > tt.cacheSize {
				t.Errorf("Cache size exceeded limit: %d > %d", currentSize, tt.cacheSize)
			}

			// Access some items to modify LRU order
			for i := 0; i < tt.cacheSize/2; i++ {
				key := generateCacheKey(i)
				cache.Get(key)
			}

			// Verify structure integrity after access
			verifyLRUStructureIntegrity(t, cache, "after_access")

			// Add more items to cause more evictions
			for i := tt.itemCount; i < tt.itemCount+50; i++ {
				key := generateCacheKey(i)
				value := generateCacheValue(i)
				cache.Set(key, value, time.Hour)
			}

			// Verify structure integrity after more evictions
			verifyLRUStructureIntegrity(t, cache, "after_more_evictions")

			// Close cache to test cleanup
			cache.Close()

			// Force GC multiple times to detect circular references
			runtime.GC()
			runtime.GC()
			runtime.GC()
			debug.FreeOSMemory()
			time.Sleep(10 * time.Millisecond) // Allow GC to complete
			runtime.GC()
			debug.FreeOSMemory()

			// Measure final memory
			var m2 runtime.MemStats
			runtime.ReadMemStats(&m2)

			memoryGrowth := int64(m2.Alloc) - int64(m1.Alloc)

			// Memory should be mostly freed if no circular references
			maxExpectedMemory := int64(tt.cacheSize * 1024) // 1KB per item tolerance
			if memoryGrowth > maxExpectedMemory {
				t.Errorf("Potential circular references detected: %s\n"+
					"Memory growth: %d bytes (max expected: %d)\n"+
					"Initial alloc: %d, Final alloc: %d",
					tt.description, memoryGrowth, maxExpectedMemory, m1.Alloc, m2.Alloc)
			}

			t.Logf("Test %s: Items %d, Cache size %d, Memory growth: %d bytes",
				tt.name, tt.itemCount, currentSize, memoryGrowth)
		})
	}
}

// TestLRUCache_ProperGarbageCollection tests that evicted items are properly garbage collected
func TestLRUCache_ProperGarbageCollection(t *testing.T) {
	// Create cache with small size to force frequent evictions
	config := DefaultUnifiedCacheConfig()
	config.MaxSize = 50
	config.Strategy = NewLRUStrategy(50)
	config.EnableAutoCleanup = false

	cache := NewUnifiedCache(config)

	// Record baseline memory
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	// Populate cache multiple times (each iteration should evict previous items)
	const iterations = 10
	const itemsPerIteration = 100

	for iter := 0; iter < iterations; iter++ {
		// Add items that should evict previous ones
		for i := 0; i < itemsPerIteration; i++ {
			key := generateCacheKeyWithIteration(iter, i)
			value := generateLargeCacheValue(i) // Use larger values to make memory impact visible
			cache.Set(key, value, time.Hour)
		}

		// Verify cache size is still bounded
		metrics := cache.GetMetrics()
		currentSize := metrics["item_count"].(int)
		if currentSize > config.MaxSize {
			t.Errorf("Cache size exceeded in iteration %d: %d > %d", iter, currentSize, config.MaxSize)
		}

		// Force GC and check memory growth isn't excessive
		if iter%3 == 2 {
			runtime.GC()
			runtime.GC()
			var current runtime.MemStats
			runtime.ReadMemStats(&current)

			memoryGrowth := int64(current.Alloc) - int64(baseline.Alloc)
			maxExpectedMemory := int64(config.MaxSize * 2048) // 2KB per item in cache

			if memoryGrowth > maxExpectedMemory*2 { // 2x tolerance
				t.Errorf("Memory growth suggests poor garbage collection in iteration %d: %d bytes (max expected: %d)",
					iter, memoryGrowth, maxExpectedMemory)
			}

			t.Logf("Iteration %d: Cache size %d, Memory growth: %d bytes",
				iter, currentSize, memoryGrowth)
		}
	}

	// Final cleanup and verification
	cache.Close()
	runtime.GC()
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()
	time.Sleep(50 * time.Millisecond)

	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	finalGrowth := int64(final.Alloc) - int64(baseline.Alloc)

	// After cache closure and GC, memory should be mostly freed
	maxFinalMemory := int64(config.MaxSize * 512) // 512 bytes per item tolerance
	if finalGrowth > maxFinalMemory {
		t.Errorf("Poor garbage collection after cache closure: %d bytes growth (max expected: %d)",
			finalGrowth, maxFinalMemory)
	}

	t.Logf("Garbage collection test completed: %d iterations, Final memory growth: %d bytes",
		iterations, finalGrowth)
}

// TestLRUCache_ConcurrentAccessCircularReferences tests that concurrent access doesn't create
// circular references or corruption
func TestLRUCache_ConcurrentAccessCircularReferences(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	config.MaxSize = 100
	config.Strategy = NewLRUStrategy(100)
	config.EnableAutoCleanup = false

	cache := NewUnifiedCache(config)
	defer cache.Close()

	// Record baseline
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const numGoroutines = 10
	const operationsPerGoroutine = 100
	var wg sync.WaitGroup

	// Run concurrent operations
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for op := 0; op < operationsPerGoroutine; op++ {
				switch op % 4 {
				case 0: // Set operation
					key := generateConcurrentCacheKey(goroutineID, op)
					value := generateCacheValue(op)
					cache.Set(key, value, time.Hour)

				case 1: // Get operation
					key := generateConcurrentCacheKey(goroutineID, op/2)
					cache.Get(key)

				case 2: // Delete operation
					key := generateConcurrentCacheKey(goroutineID, op/4)
					cache.Delete(key)

				case 3: // Cleanup operation
					cache.Cleanup()
				}

				// Occasional structure verification
				if op%50 == 49 {
					verifyLRUStructureIntegrity(t, cache, "concurrent_access")
				}
			}
		}(g)
	}

	wg.Wait()

	// Final structure verification
	verifyLRUStructureIntegrity(t, cache, "after_concurrent_access")

	// Force GC to detect any circular references
	runtime.GC()
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	memoryGrowth := int64(m2.Alloc) - int64(m1.Alloc)

	// Memory growth should be reasonable
	maxExpectedMemory := int64(config.MaxSize * 1024) // 1KB per cached item
	if memoryGrowth > maxExpectedMemory*2 {
		t.Errorf("Excessive memory growth with concurrent access: %d bytes (max expected: %d)",
			memoryGrowth, maxExpectedMemory)
	}

	t.Logf("Concurrent access test: %d goroutines, %d ops each, Memory growth: %d bytes",
		numGoroutines, operationsPerGoroutine, memoryGrowth)
}

// TestLRUCache_SizeLimitsEnforced tests that cache size limits are strictly enforced
// and don't allow unbounded growth
func TestLRUCache_SizeLimitsEnforced(t *testing.T) {
	tests := []struct {
		name      string
		maxSize   int
		itemCount int
	}{
		{"tiny_cache", 5, 20},
		{"small_cache", 25, 100},
		{"medium_cache", 100, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultUnifiedCacheConfig()
			config.MaxSize = tt.maxSize
			config.Strategy = NewLRUStrategy(tt.maxSize)
			config.EnableAutoCleanup = false

			cache := NewUnifiedCache(config)
			defer cache.Close()

			// Record memory before population
			runtime.GC()
			var m1 runtime.MemStats
			runtime.ReadMemStats(&m1)

			// Add many more items than the limit
			for i := 0; i < tt.itemCount; i++ {
				key := generateCacheKey(i)
				value := generateCacheValue(i)
				cache.Set(key, value, time.Hour)

				// Verify size limits during population
				if i > tt.maxSize {
					metrics := cache.GetMetrics()
					currentSize := metrics["item_count"].(int)
					if currentSize > tt.maxSize {
						t.Errorf("Cache size limit exceeded during population at item %d: %d > %d",
							i, currentSize, tt.maxSize)
					}
				}
			}

			// Final size verification
			metrics := cache.GetMetrics()
			finalSize := metrics["item_count"].(int)
			if finalSize > tt.maxSize {
				t.Errorf("Final cache size exceeded limit: %d > %d", finalSize, tt.maxSize)
			}

			// Memory verification
			runtime.GC()
			var m2 runtime.MemStats
			runtime.ReadMemStats(&m2)
			memoryGrowth := int64(m2.Alloc) - int64(m1.Alloc)

			// Memory should be bounded by cache size, not total items added
			maxExpectedMemory := int64(tt.maxSize * 2048) // 2KB per item with overhead
			if memoryGrowth > maxExpectedMemory {
				t.Errorf("Memory not properly bounded: %d bytes (max expected: %d)\n"+
					"Added %d items to cache limited to %d items",
					memoryGrowth, maxExpectedMemory, tt.itemCount, tt.maxSize)
			}

			t.Logf("Size limit test %s: Added %d items, Final size: %d, Memory: %d bytes",
				tt.name, tt.itemCount, finalSize, memoryGrowth)
		})
	}
}

// TestLRUCache_EvictedItemsReleased tests that evicted items are properly released from memory
func TestLRUCache_EvictedItemsReleased(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	config.MaxSize = 10
	config.Strategy = NewLRUStrategy(10)
	config.EnableAutoCleanup = false

	cache := NewUnifiedCache(config)
	defer cache.Close()

	// Create items with identifiable content for leak detection
	const itemSize = 1024 * 10 // 10KB per item

	// Phase 1: Fill cache with large items
	for i := 0; i < config.MaxSize; i++ {
		key := generateCacheKey(i)
		value := strings.Repeat(fmt.Sprintf("item%d-", i), itemSize/10)
		cache.Set(key, value, time.Hour)
	}

	// Force GC and measure memory after first phase
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Phase 2: Add more items to force eviction of all original items
	for i := config.MaxSize; i < config.MaxSize*3; i++ {
		key := generateCacheKey(i)
		value := strings.Repeat(fmt.Sprintf("item%d-", i), itemSize/10)
		cache.Set(key, value, time.Hour)
	}

	// Force GC and measure memory after evictions
	runtime.GC()
	runtime.GC()
	runtime.GC()
	debug.FreeOSMemory()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	memoryDiff := int64(m2.Alloc) - int64(m1.Alloc)

	// Memory should not grow significantly - evicted items should be GC'd
	// Allow for some overhead but not full retention of evicted items
	maxExpectedGrowth := int64(config.MaxSize * itemSize / 2) // 50% of one cache worth
	if memoryDiff > maxExpectedGrowth {
		t.Errorf("Evicted items may not be released: memory growth %d bytes (max expected: %d)",
			memoryDiff, maxExpectedGrowth)
	}

	// Verify cache still contains correct number of items
	metrics := cache.GetMetrics()
	currentSize := metrics["item_count"].(int)
	if currentSize != config.MaxSize {
		t.Errorf("Cache size incorrect after evictions: %d (expected: %d)",
			currentSize, config.MaxSize)
	}

	t.Logf("Evicted items test: Memory growth after evictions: %d bytes, Cache size: %d",
		memoryDiff, currentSize)
}

// Verification helper function
func verifyLRUStructureIntegrity(t *testing.T, cache *UnifiedCache, phase string) {
	// Get the LRU strategy
	cache.mutex.RLock()
	strategy, ok := cache.strategy.(*LRUStrategy)
	cache.mutex.RUnlock()

	if !ok {
		return // Not an LRU strategy, skip verification
	}

	strategy.mutex.Lock()
	defer strategy.mutex.Unlock()

	// Verify doubly-linked list integrity
	if strategy.order == nil {
		t.Errorf("LRU order list is nil during %s", phase)
		return
	}

	// Count nodes by traversing forward
	forwardCount := 0
	current := strategy.order.head.next
	visited := make(map[*ListNode]bool)

	for current != strategy.order.tail && forwardCount < strategy.maxSize*2 {
		if visited[current] {
			t.Errorf("Circular reference detected in forward traversal during %s", phase)
			return
		}
		visited[current] = true

		if current.prev == nil || current.next == nil {
			t.Errorf("Node with nil prev/next pointers during %s", phase)
			return
		}

		if current.next.prev != current {
			t.Errorf("Broken backward link during %s", phase)
			return
		}

		current = current.next
		forwardCount++
	}

	// Verify map consistency
	mapSize := len(strategy.elements)
	if mapSize != forwardCount {
		t.Errorf("LRU map/list size mismatch during %s: map=%d, list=%d",
			phase, mapSize, forwardCount)
	}

	// Verify all map entries point to valid nodes
	for key, node := range strategy.elements {
		if node == nil {
			t.Errorf("Map contains nil node for key %s during %s", key, phase)
			continue
		}
		if node.Key != key {
			t.Errorf("Map key mismatch for key %s during %s", key, phase)
		}
		if !visited[node] {
			t.Errorf("Map node not in list for key %s during %s", key, phase)
		}
	}
}

// Helper functions for generating test data

func generateCacheKey(id int) string {
	return fmt.Sprintf("cache_key_%d", id)
}

func generateCacheValue(id int) string {
	return fmt.Sprintf("cache_value_%d", id)
}

func generateLargeCacheValue(id int) string {
	return fmt.Sprintf("large_cache_value_%d_%s", id, strings.Repeat("data", 100))
}

func generateCacheKeyWithIteration(iter, id int) string {
	return fmt.Sprintf("cache_key_iter_%d_id_%d", iter, id)
}

func generateConcurrentCacheKey(goroutineID, op int) string {
	return fmt.Sprintf("concurrent_key_g%d_op%d", goroutineID, op)
}

// BenchmarkLRUCache_MemoryEfficiency benchmarks memory efficiency of LRU cache operations
func BenchmarkLRUCache_MemoryEfficiency(b *testing.B) {
	config := DefaultUnifiedCacheConfig()
	config.MaxSize = 1000
	config.Strategy = NewLRUStrategy(1000)
	config.EnableAutoCleanup = false

	cache := NewUnifiedCache(config)
	defer cache.Close()

	// Record baseline memory
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := generateCacheKey(i)
		value := generateCacheValue(i)
		cache.Set(key, value, time.Hour)

		// Occasional reads to test LRU behavior
		if i%10 == 9 {
			cache.Get(generateCacheKey(i - 5))
		}

		// Periodic memory check to detect leaks
		if i%10000 == 9999 {
			runtime.GC()
			var current runtime.MemStats
			runtime.ReadMemStats(&current)

			memoryGrowth := current.Alloc - baseline.Alloc
			maxExpected := uint64(config.MaxSize * 1024) // 1KB per item

			if memoryGrowth > maxExpected*2 {
				b.Fatalf("Memory leak detected at iteration %d: %d bytes (max: %d)",
					i, memoryGrowth, maxExpected)
			}
		}
	}
}
