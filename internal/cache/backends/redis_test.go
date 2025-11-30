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

// TestRedisBackend_BasicOperations tests basic Redis operations
func TestRedisBackend_BasicOperations(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("SetAndGet", func(t *testing.T) {
		key := "redis-test-key"
		value := []byte("redis-test-value")
		ttl := 1 * time.Minute

		err := backend.Set(ctx, key, value, ttl)
		require.NoError(t, err)

		retrieved, remainingTTL, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
		assert.Greater(t, remainingTTL, 50*time.Second)
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		_, _, exists, err := backend.Get(ctx, "non-existent-redis-key")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Delete", func(t *testing.T) {
		key := "redis-delete-key"
		value := []byte("redis-delete-value")

		err := backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)

		deleted, err := backend.Delete(ctx, key)
		require.NoError(t, err)
		assert.True(t, deleted)

		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Exists", func(t *testing.T) {
		key := "redis-exists-key"
		value := []byte("redis-exists-value")

		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)

		err = backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)

		exists, err = backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
	})
}

// TestRedisBackend_KeyPrefixing tests key namespace prefixing
func TestRedisBackend_KeyPrefixing(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	config.RedisPrefix = "test:prefix:"
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	key := "my-key"
	value := []byte("my-value")

	err = backend.Set(ctx, key, value, 1*time.Minute)
	require.NoError(t, err)

	// Check that key is stored with prefix
	keys := mr.CheckKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, "test:prefix:my-key", keys[0])

	// Get should work without prefix
	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, value, retrieved)
}

// TestRedisBackend_TTLExpiration tests TTL handling
func TestRedisBackend_TTLExpiration(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("ShortTTL", func(t *testing.T) {
		key := "ttl-key"
		value := []byte("ttl-value")
		shortTTL := 100 * time.Millisecond

		err := backend.Set(ctx, key, value, shortTTL)
		require.NoError(t, err)

		// Exists immediately
		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		// Fast forward time in miniredis
		mr.FastForward(150 * time.Millisecond)

		// Should be expired
		exists, err = backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("TTLRemaining", func(t *testing.T) {
		key := "ttl-remaining-key"
		value := []byte("ttl-remaining-value")
		ttl := 10 * time.Second

		err := backend.Set(ctx, key, value, ttl)
		require.NoError(t, err)

		// Get immediately
		_, ttl1, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)

		// Fast forward 2 seconds
		mr.FastForward(2 * time.Second)

		// Check TTL is less
		_, ttl2, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Less(t, ttl2, ttl1)
	})
}

// TestRedisBackend_Clear tests clearing all keys
func TestRedisBackend_Clear(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	config.RedisPrefix = "clear-test:"
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Add multiple keys
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("clear-key-%d", i)
		value := []byte(fmt.Sprintf("clear-value-%d", i))
		err := backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)
	}

	// Verify keys exist
	keys := mr.CheckKeys()
	assert.Len(t, keys, 10)

	// Clear all
	err = backend.Clear(ctx)
	require.NoError(t, err)

	// Verify all keys are gone
	keys = mr.CheckKeys()
	assert.Len(t, keys, 0)
}

// TestRedisBackend_ConnectionFailure tests behavior on connection failure
func TestRedisBackend_ConnectionFailure(t *testing.T) {
	t.Parallel()

	// Try to connect to non-existent Redis
	config := DefaultRedisConfig("localhost:9999")
	_, err := NewRedisBackend(config)
	assert.Error(t, err, "Should fail to connect to non-existent Redis")
}

// TestRedisBackend_RedisErrors tests handling of Redis errors
func TestRedisBackend_RedisErrors(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Simulate Redis error
	mr.SetError("simulated error")

	// Operations should fail
	err = backend.Set(ctx, "error-key", []byte("error-value"), 1*time.Minute)
	assert.Error(t, err)

	// Clear error
	mr.ClearError()

	// Operations should work again
	err = backend.Set(ctx, "success-key", []byte("success-value"), 1*time.Minute)
	assert.NoError(t, err)
}

// TestRedisBackend_ConcurrentAccess tests thread safety
func TestRedisBackend_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()
	var wg sync.WaitGroup
	goroutines := 20
	iterations := 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
				value := []byte(fmt.Sprintf("concurrent-value-%d-%d", id, j))

				err := backend.Set(ctx, key, value, 1*time.Minute)
				assert.NoError(t, err)

				retrieved, _, exists, err := backend.Get(ctx, key)
				assert.NoError(t, err)
				if exists {
					assert.Equal(t, value, retrieved)
				}

				if j%5 == 0 {
					backend.Delete(ctx, key)
				}
			}
		}(i)
	}

	wg.Wait()

	stats := backend.GetStats()
	hits := stats["hits"].(int64)
	misses := stats["misses"].(int64)
	assert.Greater(t, hits+misses, int64(0))
}

// TestRedisBackend_Stats tests statistics tracking
func TestRedisBackend_Stats(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	// Initial stats
	stats := backend.GetStats()
	assert.Equal(t, int64(0), stats["hits"].(int64))
	assert.Equal(t, int64(0), stats["misses"].(int64))

	// Add and access items
	backend.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	backend.Get(ctx, "key1")         // Hit
	backend.Get(ctx, "non-existent") // Miss

	stats = backend.GetStats()
	assert.Equal(t, int64(1), stats["hits"].(int64))
	assert.Equal(t, int64(1), stats["misses"].(int64))

	hitRate := stats["hit_rate"].(float64)
	assert.InDelta(t, 0.5, hitRate, 0.01)
}

// TestRedisBackend_Ping tests health check
func TestRedisBackend_Ping(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
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

// TestRedisBackend_Close tests proper cleanup
func TestRedisBackend_Close(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Add items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("close-key-%d", i)
		value := []byte(fmt.Sprintf("close-value-%d", i))
		backend.Set(ctx, key, value, 1*time.Minute)
	}

	// Close
	err = backend.Close()
	require.NoError(t, err)

	// Operations should fail
	err = backend.Set(ctx, "after-close", []byte("value"), 1*time.Minute)
	assert.Error(t, err)
	assert.Equal(t, ErrBackendClosed, err)

	// Double close should be safe
	err = backend.Close()
	assert.NoError(t, err)
}

// TestRedisBackend_UpdateExisting tests updating existing keys
func TestRedisBackend_UpdateExisting(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
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
	assert.Greater(t, ttl, 1*time.Minute)
}

// TestRedisBackend_LargeValues tests handling of large values
func TestRedisBackend_LargeValues(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
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

// TestRedisBackend_EmptyValues tests handling of empty values
func TestRedisBackend_EmptyValues(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
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

// TestRedisBackend_PipelineOperations tests batch operations
func TestRedisBackend_PipelineOperations(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	t.Run("SetMany", func(t *testing.T) {
		items := make(map[string][]byte)
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("batch-key-%d", i)
			value := []byte(fmt.Sprintf("batch-value-%d", i))
			items[key] = value
		}

		err := backend.SetMany(ctx, items, 1*time.Minute)
		require.NoError(t, err)

		// Verify all items were set
		for key, expectedValue := range items {
			retrieved, _, exists, err := backend.Get(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists)
			assert.Equal(t, expectedValue, retrieved)
		}
	})

	t.Run("GetMany", func(t *testing.T) {
		// Set test data
		testData := GenerateTestData(5)
		for key, value := range testData {
			backend.Set(ctx, key, value, 1*time.Minute)
		}

		// Get all keys
		keys := make([]string, 0, len(testData))
		for key := range testData {
			keys = append(keys, key)
		}

		results, err := backend.GetMany(ctx, keys)
		require.NoError(t, err)
		assert.Len(t, results, len(testData))

		for key, expectedValue := range testData {
			retrievedValue, exists := results[key]
			assert.True(t, exists)
			assert.Equal(t, expectedValue, retrievedValue)
		}
	})

	t.Run("GetManyWithNonExistent", func(t *testing.T) {
		keys := []string{"exists-1", "non-existent", "exists-2"}

		backend.Set(ctx, "exists-1", []byte("value-1"), 1*time.Minute)
		backend.Set(ctx, "exists-2", []byte("value-2"), 1*time.Minute)

		results, err := backend.GetMany(ctx, keys)
		require.NoError(t, err)
		assert.Len(t, results, 2) // Only existing keys
		assert.Equal(t, []byte("value-1"), results["exists-1"])
		assert.Equal(t, []byte("value-2"), results["exists-2"])
		_, exists := results["non-existent"]
		assert.False(t, exists)
	})
}

// TestRedisBackend_NoPrefix tests operation without prefix
func TestRedisBackend_NoPrefix(t *testing.T) {
	t.Parallel()

	mr := NewMiniredisServer(t)
	config := DefaultRedisConfig(mr.GetAddr())
	config.RedisPrefix = "" // No prefix
	backend, err := NewRedisBackend(config)
	require.NoError(t, err)
	defer backend.Close()

	ctx := context.Background()

	key := "no-prefix-key"
	value := []byte("no-prefix-value")

	err = backend.Set(ctx, key, value, 1*time.Minute)
	require.NoError(t, err)

	// Check key is stored without prefix
	keys := mr.CheckKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, key, keys[0])
}
