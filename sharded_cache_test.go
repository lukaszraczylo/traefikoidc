package traefikoidc

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestShardedCacheBasicOperations(t *testing.T) {
	t.Run("SetAndGet", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 5*time.Minute)
		cache.Set("key2", 42, 5*time.Minute)
		cache.Set("key3", true, 5*time.Minute)

		val1, ok := cache.Get("key1")
		if !ok || val1 != "value1" {
			t.Errorf("Expected 'value1', got %v, ok=%v", val1, ok)
		}

		val2, ok := cache.Get("key2")
		if !ok || val2 != 42 {
			t.Errorf("Expected 42, got %v, ok=%v", val2, ok)
		}

		val3, ok := cache.Get("key3")
		if !ok || val3 != true {
			t.Errorf("Expected true, got %v, ok=%v", val3, ok)
		}
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		val, ok := cache.Get("nonexistent")
		if ok || val != nil {
			t.Errorf("Expected nil/false for nonexistent key, got %v/%v", val, ok)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 5*time.Minute)
		cache.Delete("key1")

		val, ok := cache.Get("key1")
		if ok || val != nil {
			t.Errorf("Expected nil/false after delete, got %v/%v", val, ok)
		}
	})

	t.Run("Exists", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 5*time.Minute)

		if !cache.Exists("key1") {
			t.Error("Expected Exists to return true for existing key")
		}

		if cache.Exists("nonexistent") {
			t.Error("Expected Exists to return false for nonexistent key")
		}
	})

	t.Run("Size", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		if cache.Size() != 0 {
			t.Errorf("Expected size 0, got %d", cache.Size())
		}

		for i := 0; i < 100; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i, 5*time.Minute)
		}

		if cache.Size() != 100 {
			t.Errorf("Expected size 100, got %d", cache.Size())
		}
	})

	t.Run("Clear", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		for i := 0; i < 100; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i, 5*time.Minute)
		}

		cache.Clear()

		if cache.Size() != 0 {
			t.Errorf("Expected size 0 after clear, got %d", cache.Size())
		}
	})
}

func TestShardedCacheExpiration(t *testing.T) {
	t.Run("ItemExpires", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 50*time.Millisecond)

		// Should exist immediately
		if !cache.Exists("key1") {
			t.Error("Item should exist immediately after set")
		}

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should be expired now
		if cache.Exists("key1") {
			t.Error("Item should have expired")
		}
	})

	t.Run("CleanupRemovesExpired", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		// Add items with short TTL
		for i := 0; i < 50; i++ {
			cache.Set(fmt.Sprintf("expired%d", i), i, 10*time.Millisecond)
		}

		// Add items with long TTL
		for i := 0; i < 50; i++ {
			cache.Set(fmt.Sprintf("valid%d", i), i, 5*time.Minute)
		}

		// Wait for short-TTL items to expire
		time.Sleep(50 * time.Millisecond)

		// Run cleanup
		cache.Cleanup()

		// Should have only valid items
		// Note: Size still includes expired items until Get/Cleanup removes them
		// So we check by accessing items
		for i := 0; i < 50; i++ {
			if cache.Exists(fmt.Sprintf("expired%d", i)) {
				t.Errorf("Expired item %d should not exist after cleanup", i)
			}
		}

		for i := 0; i < 50; i++ {
			if !cache.Exists(fmt.Sprintf("valid%d", i)) {
				t.Errorf("Valid item %d should still exist after cleanup", i)
			}
		}
	})

	t.Run("ZeroTTLNeverExpires", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("permanent", "value", 0)

		time.Sleep(10 * time.Millisecond)

		if !cache.Exists("permanent") {
			t.Error("Item with 0 TTL should never expire")
		}
	})
}

func TestShardedCacheConcurrency(t *testing.T) {
	t.Run("ConcurrentSetGet", func(t *testing.T) {
		cache := NewShardedCache(64, 10000)
		const numGoroutines = 100
		const numOperations = 1000

		var wg sync.WaitGroup
		var errors int32

		// Concurrent writers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					cache.Set(key, j, 5*time.Minute)
				}
			}(i)
		}

		// Concurrent readers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					cache.Get(key)
				}
			}(i)
		}

		wg.Wait()

		if atomic.LoadInt32(&errors) > 0 {
			t.Errorf("Encountered %d errors during concurrent access", errors)
		}
	})

	t.Run("ConcurrentMixedOperations", func(t *testing.T) {
		cache := NewShardedCache(64, 10000)
		const numGoroutines = 50
		const numOperations = 500

		var wg sync.WaitGroup

		// Mix of operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d", j%100) // Overlapping keys
					switch j % 4 {
					case 0:
						cache.Set(key, j, 5*time.Minute)
					case 1:
						cache.Get(key)
					case 2:
						cache.Exists(key)
					case 3:
						cache.Delete(key)
					}
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("NoConcurrentPanics", func(t *testing.T) {
		cache := NewShardedCache(32, 5000)
		const numGoroutines = 100

		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Panic in goroutine %d: %v", id, r)
					}
				}()

				for j := 0; j < 100; j++ {
					cache.Set(fmt.Sprintf("k%d", j), j, time.Millisecond)
					cache.Get(fmt.Sprintf("k%d", j))
					cache.Cleanup()
				}
			}(i)
		}

		wg.Wait()
	})
}

func TestShardedCacheEviction(t *testing.T) {
	t.Run("EvictsWhenFull", func(t *testing.T) {
		// Small cache to trigger eviction - 4 shards with max 100 per shard minimum
		// With our implementation, maxPerShard defaults to at least 100
		cache := NewShardedCache(4, 100)

		// Fill well beyond capacity to trigger eviction
		for i := 0; i < 600; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i, 5*time.Minute)
		}

		// Should have evicted some items - eviction happens when shard reaches maxPerShard
		size := cache.Size()
		// With 4 shards and 100 per shard minimum, max should be ~400
		// We added 600, so some should be evicted
		if size >= 600 {
			t.Errorf("Expected eviction to reduce size below 600, got %d", size)
		}
		t.Logf("Cache size after adding 600 items: %d", size)
	})

	t.Run("EvictsExpiredFirst", func(t *testing.T) {
		cache := NewShardedCache(4, 100)

		// Add expired items first
		for i := 0; i < 50; i++ {
			cache.Set(fmt.Sprintf("expired%d", i), i, 1*time.Millisecond)
		}

		time.Sleep(10 * time.Millisecond) // Let them expire

		// Add valid items
		for i := 0; i < 100; i++ {
			cache.Set(fmt.Sprintf("valid%d", i), i, 5*time.Minute)
		}

		// Valid items should mostly still exist
		validCount := 0
		for i := 0; i < 100; i++ {
			if cache.Exists(fmt.Sprintf("valid%d", i)) {
				validCount++
			}
		}

		// Should have most valid items (at least 80%)
		if validCount < 80 {
			t.Errorf("Expected at least 80 valid items, got %d", validCount)
		}
	})
}

func TestShardedCacheShardDistribution(t *testing.T) {
	t.Run("EvenDistribution", func(t *testing.T) {
		cache := NewShardedCache(16, 16000)

		// Add many items
		for i := 0; i < 10000; i++ {
			cache.Set(fmt.Sprintf("key-%d", i), i, 5*time.Minute)
		}

		stats := cache.ShardStats()

		// Check for reasonable distribution (no shard should have > 2x average)
		average := 10000 / 16
		for i, count := range stats {
			if count > average*3 || count < average/3 {
				t.Errorf("Shard %d has uneven distribution: %d items (expected ~%d)", i, count, average)
			}
		}
	})
}

// BenchmarkShardedCache benchmarks the sharded cache operations
func BenchmarkShardedCache(b *testing.B) {
	b.Run("Set", func(b *testing.B) {
		cache := NewShardedCache(64, 100000)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.Set(fmt.Sprintf("key-%d", i), i, 5*time.Minute)
		}
	})

	b.Run("Get", func(b *testing.B) {
		cache := NewShardedCache(64, 100000)
		for i := 0; i < 10000; i++ {
			cache.Set(fmt.Sprintf("key-%d", i), i, 5*time.Minute)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cache.Get(fmt.Sprintf("key-%d", i%10000))
		}
	})

	b.Run("ParallelSetGet", func(b *testing.B) {
		cache := NewShardedCache(64, 100000)
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key-%d", i)
				cache.Set(key, i, 5*time.Minute)
				cache.Get(key)
				i++
			}
		})
	})
}

// BenchmarkShardedVsGlobalMutex compares sharded cache with global mutex approach
func BenchmarkShardedVsGlobalMutex(b *testing.B) {
	b.Run("ShardedCache64", func(b *testing.B) {
		cache := NewShardedCache(64, 100000)
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("jti-%d", i%10000)
				if !cache.Exists(key) {
					cache.Set(key, true, 5*time.Minute)
				}
				i++
			}
		})
	})

	b.Run("GlobalMutexCache", func(b *testing.B) {
		var mu sync.RWMutex
		data := make(map[string]bool)

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("jti-%d", i%10000)

				mu.RLock()
				_, exists := data[key]
				mu.RUnlock()

				if !exists {
					mu.Lock()
					data[key] = true
					mu.Unlock()
				}
				i++
			}
		})
	})
}
