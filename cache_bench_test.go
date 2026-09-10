package traefikoidc

import (
	"fmt"
	"testing"
	"time"
)

// =============================================================================
// UNIVERSAL CACHE BENCHMARKS
// =============================================================================

func BenchmarkCacheSet(b *testing.B) {
	cache := NewUniversalCache(createTestCacheConfig())
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 1*time.Hour)
			i++
		}
	})
}

func BenchmarkCacheGet(b *testing.B) {
	cache := NewUniversalCache(createTestCacheConfig())
	defer cache.Close()

	for i := 0; i < 1000; i++ {
		cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 1*time.Hour)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Get(fmt.Sprintf("key%d", i%1000))
			i++
		}
	})
}

func BenchmarkCacheSetGet(b *testing.B) {
	cache := NewUniversalCache(createTestCacheConfig())
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key%d", i)
			cache.Set(key, fmt.Sprintf("value%d", i), 1*time.Hour)
			cache.Get(key)
			i++
		}
	})
}

func BenchmarkCacheLRUEviction(b *testing.B) {
	config := createTestCacheConfig()
	config.MaxSize = 100
	cache := NewUniversalCache(config)
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 1*time.Hour)
	}
}

func BenchmarkCacheConcurrent(b *testing.B) {
	cache := NewUniversalCache(createTestCacheConfig())
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			switch i % 3 {
			case 0:
				cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 1*time.Hour)
			case 1:
				cache.Get(fmt.Sprintf("key%d", i))
			case 2:
				cache.Delete(fmt.Sprintf("key%d", i))
			}
			i++
		}
	})
}

// =============================================================================
// CACHE MANAGER BENCHMARKS
// =============================================================================

func BenchmarkCacheInterfaceWrapper_Set(b *testing.B) {
	t := &testing.T{}
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set("benchmark-key", "benchmark-value", time.Hour)
	}
}

func BenchmarkCacheInterfaceWrapper_Get(b *testing.B) {
	t := &testing.T{}
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	cache.Set("benchmark-key", "benchmark-value", time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("benchmark-key")
	}
}

func BenchmarkCacheInterfaceWrapper_Delete(b *testing.B) {
	t := &testing.T{}
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		key := fmt.Sprintf("benchmark-key-%d", i)
		cache.Set(key, "value", time.Hour)
		b.StartTimer()

		cache.Delete(key)
	}
}

// =============================================================================
// CACHE COMPATIBILITY BENCHMARKS
// =============================================================================

func BenchmarkNewBoundedCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewBoundedCache(1000)
	}
}

func BenchmarkNewOptimizedCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewOptimizedCache()
	}
}

func BenchmarkLRUStrategy_EstimateSize(b *testing.B) {
	strategy := NewLRUStrategy(1000)
	item := "test-item"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.EstimateSize(item)
	}
}
