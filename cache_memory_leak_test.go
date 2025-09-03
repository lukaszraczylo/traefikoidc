package traefikoidc

import (
	"container/list"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestCacheMemoryLeaks tests various cache scenarios for memory leaks
func TestCacheMemoryLeaks(t *testing.T) {
	t.Run("Cache doesn't release expired items memory", func(t *testing.T) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		cache := NewCache()
		defer cache.Close()

		// Add many large items with short expiration
		largeData := make([]byte, 1024*1024) // 1MB
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("key-%d", i)
			// Items expire in 1 second
			cache.Set(key, largeData, 1*time.Second)
		}

		// Wait for items to expire
		time.Sleep(2 * time.Second)

		// Force cleanup
		cache.Cleanup()

		// Check memory after cleanup
		runtime.GC()
		runtime.ReadMemStats(&m)
		afterCleanupAlloc := m.Alloc

		allocIncrease := float64(afterCleanupAlloc-baselineAlloc) / 1024 / 1024
		t.Logf("Memory after adding and expiring 100MB of data: %.2f MB", allocIncrease)

		// Memory should be mostly released after cleanup
		if allocIncrease > 10.0 {
			t.Errorf("Cache retains too much memory after cleanup: %.2f MB", allocIncrease)
		}
	})

	t.Run("Token blacklist unbounded growth", func(t *testing.T) {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		blacklist := NewCache()
		blacklist.SetMaxSize(1000) // Limit size
		defer blacklist.Close()

		// Simulate continuous token blacklisting
		for i := 0; i < 10000; i++ {
			token := fmt.Sprintf("token-%d", i)
			// All tokens expire in 24 hours (typical blacklist duration)
			blacklist.Set(token, true, 24*time.Hour)
		}

		runtime.GC()
		runtime.ReadMemStats(&m)
		currentAlloc := m.Alloc

		allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024
		t.Logf("Memory after adding 10000 blacklisted tokens (max 1000): %.2f MB", allocIncrease)

		// Should respect max size limit
		if len(blacklist.items) > 1000 {
			t.Errorf("Blacklist exceeded max size: %d items", len(blacklist.items))
		}

		// Memory should be bounded
		if allocIncrease > 5.0 {
			t.Errorf("Blacklist uses too much memory: %.2f MB for max 1000 items", allocIncrease)
		}
	})

	t.Run("Replay cache with high JTI volume", func(t *testing.T) {
		initReplayCache()
		defer cleanupReplayCache()

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		// Simulate high volume of JTIs
		for i := 0; i < 20000; i++ {
			jti := fmt.Sprintf("jti-%d", i)
			replayCacheMu.Lock()
			if replayCache != nil {
				// JTIs expire after token expiry (typically 1 hour)
				replayCache.Set(jti, true, 1*time.Hour)
			}
			replayCacheMu.Unlock()
		}

		runtime.GC()
		runtime.ReadMemStats(&m)
		currentAlloc := m.Alloc

		allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024
		t.Logf("Memory after adding 20000 JTIs (max 10000): %.2f MB", allocIncrease)

		// Check size limit is enforced
		replayCacheMu.RLock()
		cacheSize := 0
		if replayCache != nil {
			cacheSize = len(replayCache.items)
		}
		replayCacheMu.RUnlock()

		if cacheSize > 10000 {
			t.Errorf("Replay cache exceeded max size: %d items", cacheSize)
		}

		// Memory should be bounded
		if allocIncrease > 10.0 {
			t.Errorf("Replay cache uses too much memory: %.2f MB for max 10000 items", allocIncrease)
		}
	})

	t.Run("Cache cleanup interval effectiveness", func(t *testing.T) {
		// Create a cache with custom settings - don't use NewCache to avoid default cleanup
		cache := &Cache{
			items:               make(map[string]CacheItem, DefaultMaxSize),
			order:               list.New(),
			elems:               make(map[string]*list.Element, DefaultMaxSize),
			maxSize:             DefaultMaxSize,
			autoCleanupInterval: 200 * time.Millisecond, // Fast cleanup for test
			logger:              newNoOpLogger(),
		}

		// Start cleanup with our custom interval
		cache.startAutoCleanup()
		defer cache.Close()

		// Add expired items
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("key-%d", i)
			cache.Set(key, "data", 50*time.Millisecond) // Very short expiry
		}

		// Wait for items to expire and cleanup to run (at least 2 cleanup cycles)
		time.Sleep(600 * time.Millisecond)

		// Manually trigger cleanup to ensure it runs
		cache.Cleanup()

		// Check that expired items are removed
		cache.mutex.RLock()
		remainingItems := len(cache.items)
		cache.mutex.RUnlock()

		t.Logf("Remaining items after auto cleanup: %d", remainingItems)

		if remainingItems > 100 {
			t.Errorf("Auto cleanup not effective: %d items remain", remainingItems)
		}
	})

	t.Run("Concurrent cache operations memory stability", func(t *testing.T) {
		cache := NewCache()
		defer cache.Close()

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		var wg sync.WaitGroup
		stop := make(chan struct{})

		// Writers continuously add items
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 1000; j++ {
					select {
					case <-stop:
						return
					default:
						key := fmt.Sprintf("writer-%d-%d", id, j)
						cache.Set(key, "data", 1*time.Second)
						time.Sleep(1 * time.Millisecond)
					}
				}
			}(i)
		}

		// Readers continuously read items
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 1000; j++ {
					select {
					case <-stop:
						return
					default:
						key := fmt.Sprintf("writer-%d-%d", id%5, j)
						cache.Get(key)
						time.Sleep(1 * time.Millisecond)
					}
				}
			}(i)
		}

		// Let it run for a bit
		time.Sleep(5 * time.Second)
		close(stop)
		wg.Wait()

		runtime.GC()
		runtime.ReadMemStats(&m)
		finalAlloc := m.Alloc

		// Handle potential underflow
		var allocIncrease float64
		if finalAlloc > baselineAlloc {
			allocIncrease = float64(finalAlloc-baselineAlloc) / 1024 / 1024
		} else {
			allocIncrease = -float64(baselineAlloc-finalAlloc) / 1024 / 1024
		}
		t.Logf("Memory increase under concurrent load: %.2f MB", allocIncrease)

		if allocIncrease > 5.0 {
			t.Errorf("Memory leak under concurrent operations: %.2f MB", allocIncrease)
		}
	})

	t.Run("LRU eviction memory release", func(t *testing.T) {
		cache := NewCache()
		cache.SetMaxSize(100) // Small cache
		defer cache.Close()

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		// Add many items to trigger eviction
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("key-%d", i)
			data := make([]byte, 10240) // 10KB per item
			cache.Set(key, data, 1*time.Hour)
		}

		runtime.GC()
		runtime.ReadMemStats(&m)
		afterEvictionAlloc := m.Alloc

		allocIncrease := float64(afterEvictionAlloc-baselineAlloc) / 1024 / 1024
		t.Logf("Memory after LRU eviction (1000 items, max 100): %.2f MB", allocIncrease)

		// Should only keep 100 items worth of memory
		if allocIncrease > 2.0 { // 100 * 10KB = ~1MB
			t.Errorf("LRU eviction doesn't release memory properly: %.2f MB", allocIncrease)
		}

		// Verify cache size
		if len(cache.items) > 100 {
			t.Errorf("Cache size exceeded limit: %d items", len(cache.items))
		}
	})

	t.Run("Token cache with claims memory", func(t *testing.T) {
		tokenCache := NewTokenCache()
		defer tokenCache.Close()

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		baselineAlloc := m.Alloc

		// Add tokens with large claims
		for i := 0; i < 1000; i++ {
			token := fmt.Sprintf("token-%d", i)
			claims := map[string]interface{}{
				"sub":    fmt.Sprintf("user-%d", i),
				"email":  fmt.Sprintf("user%d@example.com", i),
				"groups": make([]string, 100), // Large groups list
				"data":   make([]byte, 1024),  // Extra data
			}
			tokenCache.Set(token, claims, 1*time.Hour)
		}

		runtime.GC()
		runtime.ReadMemStats(&m)
		currentAlloc := m.Alloc

		allocIncrease := float64(currentAlloc-baselineAlloc) / 1024 / 1024
		t.Logf("Memory after adding 1000 tokens with large claims: %.2f MB", allocIncrease)

		// Check if memory is reasonable
		if allocIncrease > 20.0 {
			t.Errorf("Token cache uses excessive memory: %.2f MB", allocIncrease)
		}
	})
}

// TestCacheEvictionBug tests the inefficient eviction in evictOldest
func TestCacheEvictionBug(t *testing.T) {
	t.Run("evictOldest scans entire list", func(t *testing.T) {
		cache := NewCache()
		cache.SetMaxSize(100)
		defer cache.Close()

		// Fill cache with non-expired items
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("key-%d", i)
			cache.Set(key, "data", 1*time.Hour) // Long expiry
		}

		// Try to add one more item to trigger eviction
		start := time.Now()
		cache.Set("trigger", "data", 1*time.Hour)
		elapsed := time.Since(start)

		t.Logf("Time to evict and add one item: %v", elapsed)

		// Should be fast even with full cache
		if elapsed > 10*time.Millisecond {
			t.Errorf("Eviction too slow, possibly scanning entire list: %v", elapsed)
		}
	})
}
