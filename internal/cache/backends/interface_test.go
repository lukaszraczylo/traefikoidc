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

// TestCacheBackendContract defines a set of tests that all CacheBackend implementations must pass
// This ensures that Memory, Redis, and Hybrid backends all behave consistently
func TestCacheBackendContract(t *testing.T) {
	// Test suite will be run against each backend type
	t.Run("MemoryBackend", func(t *testing.T) {
		backend := setupMemoryBackend(t)
		runContractTests(t, backend)
	})

	t.Run("RedisBackend", func(t *testing.T) {
		backend := setupRedisBackend(t)
		runContractTests(t, backend)
	})

	t.Run("HybridBackend", func(t *testing.T) {
		backend := setupHybridBackend(t)
		runContractTests(t, backend)
	})
}

// runContractTests executes all contract tests against a backend
func runContractTests(t *testing.T, backend CacheBackend) {
	t.Helper()

	ctx := context.Background()

	t.Run("BasicSetGet", func(t *testing.T) {
		testBasicSetGet(t, ctx, backend)
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		testGetNonExistent(t, ctx, backend)
	})

	t.Run("UpdateExisting", func(t *testing.T) {
		testUpdateExisting(t, ctx, backend)
	})

	t.Run("Delete", func(t *testing.T) {
		testDelete(t, ctx, backend)
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		testDeleteNonExistent(t, ctx, backend)
	})

	t.Run("Exists", func(t *testing.T) {
		testExists(t, ctx, backend)
	})

	t.Run("TTLExpiration", func(t *testing.T) {
		testTTLExpiration(t, ctx, backend)
	})

	t.Run("Clear", func(t *testing.T) {
		testClear(t, ctx, backend)
	})

	t.Run("Ping", func(t *testing.T) {
		testPing(t, ctx, backend)
	})

	t.Run("Stats", func(t *testing.T) {
		testStats(t, ctx, backend)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		testConcurrentAccess(t, ctx, backend)
	})

	t.Run("LargeValues", func(t *testing.T) {
		testLargeValues(t, ctx, backend)
	})

	t.Run("EmptyValues", func(t *testing.T) {
		testEmptyValues(t, ctx, backend)
	})

	t.Run("SpecialCharactersInKeys", func(t *testing.T) {
		testSpecialCharactersInKeys(t, ctx, backend)
	})
}

// testBasicSetGet verifies basic set and get operations
func testBasicSetGet(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "test-key-1"
	value := []byte("test-value-1")
	ttl := 1 * time.Minute

	// Set value
	err := backend.Set(ctx, key, value, ttl)
	require.NoError(t, err, "Set should not return error")

	// Get value
	retrieved, remainingTTL, exists, err := backend.Get(ctx, key)
	require.NoError(t, err, "Get should not return error")
	assert.True(t, exists, "Key should exist")
	assert.Equal(t, value, retrieved, "Retrieved value should match")
	assert.Greater(t, remainingTTL, 50*time.Second, "TTL should be close to original")
	assert.LessOrEqual(t, remainingTTL, ttl, "TTL should not exceed original")
}

// testGetNonExistent verifies behavior when getting non-existent keys
func testGetNonExistent(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "non-existent-key"

	retrieved, ttl, exists, err := backend.Get(ctx, key)
	require.NoError(t, err, "Get should not return error for non-existent key")
	assert.False(t, exists, "Key should not exist")
	assert.Nil(t, retrieved, "Value should be nil")
	assert.Equal(t, time.Duration(0), ttl, "TTL should be zero")
}

// testUpdateExisting verifies updating an existing key
func testUpdateExisting(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "update-key"
	value1 := []byte("original-value")
	value2 := []byte("updated-value")
	ttl := 1 * time.Minute

	// Set initial value
	err := backend.Set(ctx, key, value1, ttl)
	require.NoError(t, err)

	// Update value
	err = backend.Set(ctx, key, value2, ttl)
	require.NoError(t, err)

	// Verify updated value
	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, value2, retrieved, "Value should be updated")
}

// testDelete verifies delete operation
func testDelete(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "delete-key"
	value := []byte("delete-value")

	// Set value
	err := backend.Set(ctx, key, value, 1*time.Minute)
	require.NoError(t, err)

	// Verify exists
	exists, err := backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete
	deleted, err := backend.Delete(ctx, key)
	require.NoError(t, err)
	assert.True(t, deleted, "Delete should return true for existing key")

	// Verify deleted
	exists, err = backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists, "Key should not exist after delete")
}

// testDeleteNonExistent verifies deleting non-existent keys
func testDeleteNonExistent(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "non-existent-delete-key"

	deleted, err := backend.Delete(ctx, key)
	require.NoError(t, err)
	assert.False(t, deleted, "Delete should return false for non-existent key")
}

// testExists verifies the Exists operation
func testExists(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "exists-key"
	value := []byte("exists-value")

	// Check non-existent key
	exists, err := backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists, "Key should not exist initially")

	// Set value
	err = backend.Set(ctx, key, value, 1*time.Minute)
	require.NoError(t, err)

	// Check existing key
	exists, err = backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists, "Key should exist after Set")
}

// testTTLExpiration verifies TTL expiration behavior
func testTTLExpiration(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "ttl-key"
	value := []byte("ttl-value")
	shortTTL := 100 * time.Millisecond

	// Set with short TTL
	err := backend.Set(ctx, key, value, shortTTL)
	require.NoError(t, err)

	// Verify exists immediately
	exists, err := backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists, "Key should exist immediately after Set")

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Verify expired
	exists, err = backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists, "Key should not exist after TTL expiration")
}

// testClear verifies Clear operation
func testClear(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	// Set multiple keys
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("clear-key-%d", i)
		value := []byte(fmt.Sprintf("clear-value-%d", i))
		err := backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)
	}

	// Clear all
	err := backend.Clear(ctx)
	require.NoError(t, err)

	// Verify all keys are gone
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("clear-key-%d", i)
		exists, err := backend.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists, "Key should not exist after Clear")
	}
}

// testPing verifies Ping operation
func testPing(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	err := backend.Ping(ctx)
	assert.NoError(t, err, "Ping should succeed on healthy backend")
}

// testStats verifies GetStats operation
func testStats(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	stats := backend.GetStats()
	assert.NotNil(t, stats, "Stats should not be nil")

	// Stats should contain basic metrics
	_, hasHits := stats["hits"]
	_, hasMisses := stats["misses"]
	assert.True(t, hasHits || hasMisses, "Stats should contain hits or misses")
}

// testConcurrentAccess verifies thread safety
func testConcurrentAccess(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	var wg sync.WaitGroup
	goroutines := 10
	iterations := 20

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
			}
		}(i)
	}

	wg.Wait()
}

// testLargeValues verifies handling of large values
func testLargeValues(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "large-value-key"
	value := GenerateLargeValue(1024 * 1024) // 1MB

	err := backend.Set(ctx, key, value, 1*time.Minute)
	require.NoError(t, err, "Should handle large values")

	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, len(value), len(retrieved), "Large value should be retrieved intact")
}

// testEmptyValues verifies handling of empty values
func testEmptyValues(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	key := "empty-value-key"
	value := []byte{}

	err := backend.Set(ctx, key, value, 1*time.Minute)
	require.NoError(t, err, "Should handle empty values")

	retrieved, _, exists, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists, "Empty value should exist")
	assert.Equal(t, 0, len(retrieved), "Retrieved value should be empty")
}

// testSpecialCharactersInKeys verifies handling of special characters in keys
func testSpecialCharactersInKeys(t *testing.T, ctx context.Context, backend CacheBackend) {
	t.Helper()

	specialKeys := []string{
		"key:with:colons",
		"key/with/slashes",
		"key-with-dashes",
		"key_with_underscores",
		"key.with.dots",
		"key|with|pipes",
	}

	for _, key := range specialKeys {
		value := []byte(fmt.Sprintf("value-for-%s", key))

		err := backend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err, "Should handle special character in key: %s", key)

		retrieved, _, exists, err := backend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists, "Key with special characters should exist: %s", key)
		assert.Equal(t, value, retrieved)
	}
}

// Helper functions to setup different backend types
// These will be implemented in respective test files

func setupMemoryBackend(t *testing.T) CacheBackend {
	t.Helper()
	// This will be implemented in memory_test.go
	// For now, return nil to allow compilation
	t.Skip("MemoryBackend implementation pending")
	return nil
}

func setupRedisBackend(t *testing.T) CacheBackend {
	t.Helper()
	// This will be implemented in redis_test.go
	// For now, return nil to allow compilation
	t.Skip("RedisBackend implementation pending")
	return nil
}

func setupHybridBackend(t *testing.T) CacheBackend {
	t.Helper()
	// This will be implemented in hybrid_test.go
	// For now, return nil to allow compilation
	t.Skip("HybridBackend implementation pending")
	return nil
}
