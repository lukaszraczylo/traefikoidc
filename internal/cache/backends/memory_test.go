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

// TestMemoryBackend_BasicOperations tests basic CRUD operations
func TestMemoryBackend_BasicOperations(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("SetAndGet", func(t *testing.T) {
		key := "test-key"
		value := []byte("test-value")
		ttl := 1 * time.Minute

		err := backend.Set(ctx, key, value, ttl)
		require.NoError(t, err)

		retrieved, remainingTTL, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
		assert.Greater(t, remainingTTL, 50*time.Second)
		assert.LessOrEqual(t, remainingTTL, ttl)
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		_, _, exists, err := backend.Get(ctx, "non-existent")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Delete", func(t *testing.T) {
		key := "delete-key"
		value := []byte("delete-value")

		err := backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)

		deleted, err := backend.Delete(ctx, key)
		require.NoError(t, err)
		assert.True(t, deleted)

		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		deleted, err := backend.Delete(ctx, "non-existent-delete")
		require.NoError(t, err)
		assert.False(t, deleted)
	})

	t.Run("Exists", func(t *testing.T) {
		key := "exists-key"
		value := []byte("exists-value")

		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)

		err = backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)

		exists, err = backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("Clear", func(t *testing.T) {
		// Add multiple items
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("clear-key-%d", i)
			value := []byte(fmt.Sprintf("clear-value-%d", i))
			err := backend.Set(ctx, key, value, 1*time.Minute)
			require.NoError(t, err)
		}

		err := backend.Clear(ctx)
		require.NoError(t, err)

		stats := backend.GetStats()
		size := stats["size"].(int64)
		assert.Equal(t, int64(0), size)
	})
}

// TestMemoryBackend_TTLExpiration tests TTL and expiration
func TestMemoryBackend_TTLExpiration(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.CleanupInterval = 50 * time.Millisecond
	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("ShortTTL", func(t *testing.T) {
		key := "short-ttl-key"
		value := []byte("short-ttl-value")
		shortTTL := 100 * time.Millisecond

		err := backend.Set(ctx, key, value, shortTTL)
		require.NoError(t, err)

		// Verify exists immediately
		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired
		_, _, exists, err = backend.Get(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("TTLDecrement", func(t *testing.T) {
		key := "ttl-decrement-key"
		value := []byte("ttl-decrement-value")
		ttl := 2 * time.Second

		err := backend.Set(ctx, key, value, ttl)
		require.NoError(t, err)

		// Check TTL immediately
		_, ttl1, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		// Wait a bit
		time.Sleep(500 * time.Millisecond)

		// Check TTL again - should be less
		_, ttl2, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Less(t, ttl2, ttl1, "TTL should decrease over time")
	})

	t.Run("CleanupExpiredItems", func(t *testing.T) {
		// Set multiple items with short TTL
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("cleanup-key-%d", i)
			value := []byte(fmt.Sprintf("cleanup-value-%d", i))
			err := backend.Set(ctx, key, value, 50*time.Millisecond)
			require.NoError(t, err)
		}

		// Wait for cleanup to run
		time.Sleep(200 * time.Millisecond)

		// All items should be cleaned up
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("cleanup-key-%d", i)
			exists, err := backend.Exists(ctx, key)
			require.NoError(t, err)
			assert.False(t, exists, "Expired items should be cleaned up")
		}
	})
}

// TestMemoryBackend_LRUEviction tests LRU eviction
func TestMemoryBackend_LRUEviction(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.MaxSize = 5
	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Fill cache to max size
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("lru-key-%d", i)
		value := []byte(fmt.Sprintf("lru-value-%d", i))
		err := backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)
	}

	// Access first item to make it most recently used
	_, _, exists, err := backend.Get(ctx, "lru-key-0")
	require.NoError(t, err)
	assert.True(t, exists)

	// Add a new item - should evict lru-key-1 (least recently used)
	err = backend.Set(ctx, "lru-key-new", []byte("new-value"), 1*time.Minute)
	require.NoError(t, err)

	// lru-key-0 should still exist (was accessed recently)
	exists, err = backend.Exists(ctx, "lru-key-0")
	require.NoError(t, err)
	assert.True(t, exists, "Recently accessed item should not be evicted")

	// lru-key-1 should be evicted
	exists, err = backend.Exists(ctx, "lru-key-1")
	require.NoError(t, err)
	assert.False(t, exists, "Least recently used item should be evicted")

	// Check eviction count
	stats := backend.GetStats()
	evictions := stats["evictions"].(int64)
	assert.Greater(t, evictions, int64(0), "Should have evictions")
}

// TestMemoryBackend_MemoryLimit tests memory-based eviction
func TestMemoryBackend_MemoryLimit(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.MaxSize = 100
	config.MaxMemoryBytes = 1024 // 1KB limit
	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Add items until memory limit is reached
	largeValue := make([]byte, 512) // 512 bytes each
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("mem-key-%d", i)
		err := backend.Set(ctx, key, largeValue, 1*time.Minute)
		require.NoError(t, err)
	}

	stats := backend.GetStats()
	memory := stats["memory"].(int64)
	assert.LessOrEqual(t, memory, config.MaxMemoryBytes, "Memory should not exceed limit")

	evictions := stats["evictions"].(int64)
	assert.Greater(t, evictions, int64(0), "Should have memory-based evictions")
}

// TestMemoryBackend_ConcurrentAccess tests thread safety
func TestMemoryBackend_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	goroutines := 20
	iterations := 50

	// Concurrent writes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
				value := []byte(fmt.Sprintf("concurrent-value-%d-%d", id, j))

				err := backend.Set(ctx, key, value, 1*time.Minute)
				assert.NoError(t, err)

				// Read back
				retrieved, _, exists, err := backend.Get(ctx, key)
				assert.NoError(t, err)
				if exists {
					assert.Equal(t, value, retrieved)
				}

				// Random deletes
				if j%5 == 0 {
					backend.Delete(ctx, key)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify stats are consistent
	stats := backend.GetStats()
	hits := stats["hits"].(int64)
	misses := stats["misses"].(int64)
	assert.Greater(t, hits+misses, int64(0), "Should have cache operations")
}

// TestMemoryBackend_UpdateExisting tests updating existing keys
func TestMemoryBackend_UpdateExisting(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	key := "update-key"
	value1 := []byte("original-value")
	value2 := []byte("updated-value")

	// Set original
	err = backend.Set(ctx, key, value1, 1*time.Minute)
	require.NoError(t, err)

	// Update
	err = backend.Set(ctx, key, value2, 2*time.Minute)
	require.NoError(t, err)

	// Verify updated
	retrieved, ttl, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, value2, retrieved)
	assert.Greater(t, ttl, 1*time.Minute, "TTL should be updated")

	// Size should not increase (same key)
	stats := backend.GetStats()
	size := stats["size"].(int64)
	assert.Equal(t, int64(1), size, "Size should be 1 for one key")
}

// TestMemoryBackend_Stats tests statistics tracking
func TestMemoryBackend_Stats(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Initial stats
	stats := backend.GetStats()
	assert.Equal(t, int64(0), stats["hits"].(int64))
	assert.Equal(t, int64(0), stats["misses"].(int64))

	// Add items and track hits/misses
	backend.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	backend.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	// Hit
	backend.Get(ctx, "key1")
	// Miss
	backend.Get(ctx, "non-existent")

	stats = backend.GetStats()
	assert.Equal(t, int64(1), stats["hits"].(int64))
	assert.Equal(t, int64(1), stats["misses"].(int64))

	hitRate := stats["hit_rate"].(float64)
	assert.InDelta(t, 0.5, hitRate, 0.01)
}

// TestMemoryBackend_EmptyValues tests handling of empty values
func TestMemoryBackend_EmptyValues(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	key := "empty-key"
	emptyValue := []byte{}

	err = backend.Set(ctx, key, emptyValue, 1*time.Minute)
	require.NoError(t, err)

	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, 0, len(retrieved))
}

// TestMemoryBackend_LargeValues tests handling of large values
func TestMemoryBackend_LargeValues(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.MaxMemoryBytes = 10 * 1024 * 1024 // 10MB
	backend, err := NewMemoryBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	key := "large-key"
	largeValue := make([]byte, 1024*1024) // 1MB

	err = backend.Set(ctx, key, largeValue, 1*time.Minute)
	require.NoError(t, err)

	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, len(largeValue), len(retrieved))
}

// TestMemoryBackend_Close tests proper cleanup on close
func TestMemoryBackend_Close(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)

	ctx := context.Background()

	// Add some items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("close-key-%d", i)
		value := []byte(fmt.Sprintf("close-value-%d", i))
		backend.Set(ctx, key, value, 1*time.Minute)
	}

	// Close
	err = backend.Close()
	require.NoError(t, err)

	// Operations after close should fail
	err = backend.Set(ctx, "after-close", []byte("value"), 1*time.Minute)
	assert.Error(t, err)
	assert.Equal(t, ErrBackendClosed, err)

	_, _, _, err = backend.Get(ctx, "close-key-0")
	assert.Error(t, err)
	assert.Equal(t, ErrBackendClosed, err)

	// Closing again should be safe
	err = backend.Close()
	assert.NoError(t, err)
}

// TestMemoryBackend_Ping tests ping operation
func TestMemoryBackend_Ping(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	err = backend.Ping(ctx)
	assert.NoError(t, err)

	// Close and ping should fail
	backend.Close()
	err = backend.Ping(ctx)
	assert.Error(t, err)
}

// TestMemoryBackend_ValueIsolation tests that returned values are isolated
func TestMemoryBackend_ValueIsolation(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	key := "isolation-key"
	originalValue := []byte("original-value")

	err = backend.Set(ctx, key, originalValue, 1*time.Minute)
	require.NoError(t, err)

	// Get value and modify it
	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)

	// Modify retrieved value
	if len(retrieved) > 0 {
		retrieved[0] = 'X'
	}

	// Get again - should be unchanged
	retrieved2, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, originalValue, retrieved2, "Original value should not be modified")
}
