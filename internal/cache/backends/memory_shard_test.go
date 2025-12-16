package backends

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShardedCache_ShardDistribution tests that keys are distributed across shards
func TestShardedCache_ShardDistribution(t *testing.T) {
	t.Parallel()

	// Create a cache with large enough size to have multiple shards
	config := DefaultConfig()
	config.MaxSize = 10000
	config.MaxMemoryBytes = 100 * 1024 * 1024 // 100MB

	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Add many items to see distribution
	numItems := 1000
	for i := 0; i < numItems; i++ {
		key := fmt.Sprintf("dist-key-%d", i)
		value := []byte(fmt.Sprintf("dist-value-%d", i))
		err := backend.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)
	}

	// Check that items are distributed across multiple shards
	shardStats := backend.MemoryCacheBackend.GetShardStats()
	nonEmptyShards := 0
	for _, stat := range shardStats {
		if stat["size"] > 0 {
			nonEmptyShards++
		}
	}

	// With good hash distribution, we should have items in multiple shards
	assert.Greater(t, nonEmptyShards, 1, "Items should be distributed across multiple shards")
}

// TestShardedCache_ShardCount tests that shard count adapts to cache size
func TestShardedCache_ShardCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		maxSize         int
		expectLowShards bool
	}{
		{5, true},      // Very small cache should have fewer shards
		{100, true},    // Small cache should have fewer shards
		{10000, false}, // Large cache should have default shards
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("MaxSize_%d", tt.maxSize), func(t *testing.T) {
			config := DefaultConfig()
			config.MaxSize = tt.maxSize

			backend, err := NewMemoryBackend(config)
			require.NoError(t, err)
			defer backend.Close()

			shardCount := backend.MemoryCacheBackend.GetShardCount()

			if tt.expectLowShards {
				assert.Less(t, shardCount, uint32(256), "Small cache should have fewer shards")
			} else {
				assert.Equal(t, uint32(256), shardCount, "Large cache should have default shard count")
			}
		})
	}
}

// TestShardedCache_ConcurrentSameKey tests concurrent access to the same key
func TestShardedCache_ConcurrentSameKey(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	key := "concurrent-same-key"
	initialValue := []byte("initial-value")

	err = backend.Set(ctx, key, initialValue, time.Minute)
	require.NoError(t, err)

	var wg sync.WaitGroup
	goroutines := 50
	iterations := 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Mix of reads and writes
				if j%3 == 0 {
					newValue := []byte(fmt.Sprintf("value-%d-%d", id, j))
					err := backend.Set(ctx, key, newValue, time.Minute)
					assert.NoError(t, err)
				} else {
					_, _, _, err := backend.Get(ctx, key)
					assert.NoError(t, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Key should still exist
	exists, err := backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
}

// TestShardedCache_GlobalLRUEviction tests that global LRU is maintained
func TestShardedCache_GlobalLRUEviction(t *testing.T) {
	t.Parallel()

	// Create a small cache to force eviction
	config := DefaultConfig()
	config.MaxSize = 10

	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Add items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("global-lru-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := backend.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)
		// Small delay to ensure different access times
		time.Sleep(time.Millisecond)
	}

	// Access some items to make them recently used
	for i := 5; i < 10; i++ {
		key := fmt.Sprintf("global-lru-%d", i)
		_, _, _, err := backend.Get(ctx, key)
		require.NoError(t, err)
	}

	// Add more items to trigger eviction
	for i := 10; i < 15; i++ {
		key := fmt.Sprintf("global-lru-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := backend.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)
	}

	// Recently accessed items (5-9) should still exist
	for i := 5; i < 10; i++ {
		key := fmt.Sprintf("global-lru-%d", i)
		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists, "Recently accessed item %d should exist", i)
	}

	// Check eviction stats
	stats := backend.GetStats()
	evictions := stats["evictions"].(int64)
	assert.Greater(t, evictions, int64(0), "Should have evictions")
}

// TestShardedCache_StatsAggregation tests that stats are aggregated correctly
func TestShardedCache_StatsAggregation(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.MaxSize = 10000

	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Add items to multiple shards
	numItems := 100
	for i := 0; i < numItems; i++ {
		key := fmt.Sprintf("stats-key-%d", i)
		value := []byte(fmt.Sprintf("stats-value-%d", i))
		err := backend.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)
	}

	// Read some items
	for i := 0; i < numItems/2; i++ {
		key := fmt.Sprintf("stats-key-%d", i)
		backend.Get(ctx, key)
	}

	// Read non-existent items
	for i := 0; i < 10; i++ {
		backend.Get(ctx, fmt.Sprintf("nonexistent-%d", i))
	}

	stats := backend.GetStats()

	// Verify stats
	assert.Equal(t, int64(numItems), stats["sets"].(int64), "Sets should match")
	assert.Equal(t, int64(numItems/2), stats["hits"].(int64), "Hits should match")
	assert.Equal(t, int64(10), stats["misses"].(int64), "Misses should match")
	assert.Equal(t, int64(numItems), stats["size"].(int64), "Size should match")

	// Verify hit rate
	hitRate := stats["hit_rate"].(float64)
	expectedHitRate := float64(numItems/2) / float64(numItems/2+10)
	assert.InDelta(t, expectedHitRate, hitRate, 0.01, "Hit rate should match")
}

// BenchmarkShardedCache_Parallel benchmarks parallel access
func BenchmarkShardedCache_Parallel(b *testing.B) {
	config := DefaultConfig()
	config.MaxSize = 100000
	config.MaxMemoryBytes = 100 * 1024 * 1024

	backend, _ := NewMemoryBackend(config)
	defer backend.Close()

	ctx := context.Background()

	// Pre-populate cache
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("bench-key-%d", i)
		value := []byte(fmt.Sprintf("bench-value-%d", i))
		backend.Set(ctx, key, value, time.Hour)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-key-%d", i%10000)
			backend.Get(ctx, key)
			i++
		}
	})
}

// BenchmarkShardedCache_MixedOps benchmarks mixed operations
func BenchmarkShardedCache_MixedOps(b *testing.B) {
	config := DefaultConfig()
	config.MaxSize = 100000
	config.MaxMemoryBytes = 100 * 1024 * 1024

	backend, _ := NewMemoryBackend(config)
	defer backend.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("mixed-key-%d", i%1000)
			if i%3 == 0 {
				value := []byte(fmt.Sprintf("mixed-value-%d", i))
				backend.Set(ctx, key, value, time.Hour)
			} else {
				backend.Get(ctx, key)
			}
			i++
		}
	})
}
