package traefikoidc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedisIntegration_MultipleInstances tests cache sharing across multiple instances
func TestRedisIntegration_MultipleInstances(t *testing.T) {
	t.Parallel()

	// Start miniredis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	// Create two backend instances sharing the same Redis
	config1 := backends.DefaultRedisConfig(mr.Addr())
	config1.RedisPrefix = "shared:"
	backend1, err := backends.NewRedisBackend(config1)
	require.NoError(t, err)
	defer backend1.Close()

	config2 := backends.DefaultRedisConfig(mr.Addr())
	config2.RedisPrefix = "shared:"
	backend2, err := backends.NewRedisBackend(config2)
	require.NoError(t, err)
	defer backend2.Close()

	t.Run("ShareTokenBlacklist", func(t *testing.T) {
		// Instance 1 blacklists a JTI
		jti := "test-jti-12345"
		err := backend1.Set(ctx, "jti:"+jti, []byte("blacklisted"), 10*time.Minute)
		require.NoError(t, err)

		// Instance 2 should see the blacklisted JTI
		_, _, exists, err := backend2.Get(ctx, "jti:"+jti)
		require.NoError(t, err)
		assert.True(t, exists, "JTI should be visible across instances")
	})

	t.Run("ShareTokenCache", func(t *testing.T) {
		// Instance 1 caches a token
		token := "access-token-xyz"
		tokenData := []byte(`{"sub":"user123","exp":1234567890}`)
		err := backend1.Set(ctx, "token:"+token, tokenData, 5*time.Minute)
		require.NoError(t, err)

		// Instance 2 retrieves the cached token
		retrieved, _, exists, err := backend2.Get(ctx, "token:"+token)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, tokenData, retrieved)
	})

	t.Run("ShareMetadataCache", func(t *testing.T) {
		// Instance 1 caches provider metadata
		metadataKey := "metadata:provider123"
		metadata := []byte(`{"issuer":"https://example.com","jwks_uri":"https://example.com/jwks"}`)
		err := backend1.Set(ctx, metadataKey, metadata, 1*time.Hour)
		require.NoError(t, err)

		// Instance 2 retrieves the metadata
		retrieved, ttl, exists, err := backend2.Get(ctx, metadataKey)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, metadata, retrieved)
		assert.Greater(t, ttl, 50*time.Minute)
	})
}

// TestRedisIntegration_JTIReplayDetection tests JTI replay detection across instances
func TestRedisIntegration_JTIReplayDetection(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	// Multiple Traefik instances
	instances := make([]*backends.RedisBackend, 3)
	for i := 0; i < 3; i++ {
		config := backends.DefaultRedisConfig(mr.Addr())
		config.RedisPrefix = "jti:"
		instances[i], err = backends.NewRedisBackend(config)
		require.NoError(t, err)
		defer instances[i].Close()
	}

	t.Run("PreventReplayAcrossInstances", func(t *testing.T) {
		jti := "replay-test-jti"

		// First instance processes token and blacklists JTI
		err := instances[0].Set(ctx, jti, []byte("used"), 24*time.Hour)
		require.NoError(t, err)

		// Other instances should detect the used JTI
		for i := 1; i < 3; i++ {
			exists, err := instances[i].Exists(ctx, jti)
			require.NoError(t, err)
			assert.True(t, exists, "Instance %d should see blacklisted JTI", i)
		}
	})

	t.Run("ConcurrentJTIChecks", func(t *testing.T) {
		jtiBase := "concurrent-jti"
		var wg sync.WaitGroup

		// Simulate concurrent token processing across instances
		for instanceID := 0; instanceID < 3; instanceID++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					jti := fmt.Sprintf("%s-%d-%d", jtiBase, id, j)

					// Check if JTI exists
					exists, _ := instances[id].Exists(ctx, jti)
					if !exists {
						// Mark as used
						instances[id].Set(ctx, jti, []byte("used"), 1*time.Hour)
					}
				}
			}(instanceID)
		}

		wg.Wait()

		// Verify all JTIs were recorded
		for instanceID := 0; instanceID < 3; instanceID++ {
			for j := 0; j < 10; j++ {
				jti := fmt.Sprintf("%s-%d-%d", jtiBase, instanceID, j)
				exists, err := instances[0].Exists(ctx, jti)
				require.NoError(t, err)
				assert.True(t, exists, "JTI %s should exist", jti)
			}
		}
	})
}

// TestRedisIntegration_Failover tests failover scenarios
func TestRedisIntegration_Failover(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	config := backends.DefaultRedisConfig(mr.Addr())
	redisBackend, err := backends.NewRedisBackend(config)
	require.NoError(t, err)
	defer redisBackend.Close()

	t.Run("RedisTemporaryFailure", func(t *testing.T) {
		// Set some data
		key := "failover-key"
		value := []byte("failover-value")
		err := redisBackend.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)

		// Simulate Redis error
		mr.SetError("simulated connection error")

		// Operations should fail gracefully
		_, _, exists, err := redisBackend.Get(ctx, key)
		assert.Error(t, err)
		assert.False(t, exists)

		// Clear error
		mr.SetError("")

		// Operations should work again
		retrieved, _, exists, err := redisBackend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, value, retrieved)
	})
}

// TestRedisIntegration_HighLoad tests high load scenarios
func TestRedisIntegration_HighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high load test in short mode")
	}

	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	config := backends.DefaultRedisConfig(mr.Addr())
	config.PoolSize = 20
	redisBackend, err := backends.NewRedisBackend(config)
	require.NoError(t, err)
	defer redisBackend.Close()

	t.Run("HighConcurrency", func(t *testing.T) {
		var wg sync.WaitGroup
		goroutines := 50
		operations := 100

		errors := make(chan error, goroutines*operations)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < operations; j++ {
					key := fmt.Sprintf("high-load-key-%d-%d", id, j)
					value := []byte(fmt.Sprintf("high-load-value-%d-%d", id, j))

					// Write
					if err := redisBackend.Set(ctx, key, value, 1*time.Minute); err != nil {
						errors <- err
						continue
					}

					// Read
					retrieved, _, exists, err := redisBackend.Get(ctx, key)
					if err != nil {
						errors <- err
						continue
					}
					if !exists {
						errors <- fmt.Errorf("key %s does not exist", key)
						continue
					}
					if string(retrieved) != string(value) {
						errors <- fmt.Errorf("value mismatch for key %s", key)
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		errorCount := 0
		for err := range errors {
			t.Logf("Operation error: %v", err)
			errorCount++
		}

		// Allow small error rate (< 1%)
		totalOps := goroutines * operations
		errorRate := float64(errorCount) / float64(totalOps)
		assert.Less(t, errorRate, 0.01, "Error rate should be less than 1%%")
	})
}

// TestRedisIntegration_TTLConsistency tests TTL consistency across operations
func TestRedisIntegration_TTLConsistency(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	config := backends.DefaultRedisConfig(mr.Addr())
	redisBackend, err := backends.NewRedisBackend(config)
	require.NoError(t, err)
	defer redisBackend.Close()

	t.Run("TTLAccuracy", func(t *testing.T) {
		key := "ttl-test-key"
		value := []byte("ttl-test-value")
		ttl := 5 * time.Second

		err := redisBackend.Set(ctx, key, value, ttl)
		require.NoError(t, err)

		// Check TTL immediately
		_, ttl1, exists, err := redisBackend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Greater(t, ttl1, 4*time.Second)
		assert.LessOrEqual(t, ttl1, ttl)

		// Fast forward 2 seconds
		mr.FastForward(2 * time.Second)

		// Check TTL again
		_, ttl2, exists, err := redisBackend.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Less(t, ttl2, ttl1)
		assert.Greater(t, ttl2, 2*time.Second)

		// Fast forward past expiration
		mr.FastForward(4 * time.Second)

		// Should be expired
		_, _, exists, err = redisBackend.Get(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

// TestRedisIntegration_MemoryUsage tests memory efficiency
func TestRedisIntegration_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory usage test in short mode")
	}

	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	config := backends.DefaultRedisConfig(mr.Addr())
	redisBackend, err := backends.NewRedisBackend(config)
	require.NoError(t, err)
	defer redisBackend.Close()

	t.Run("LargeDataset", func(t *testing.T) {
		// Store 10,000 items
		itemCount := 10000
		for i := 0; i < itemCount; i++ {
			key := fmt.Sprintf("memory-test-key-%d", i)
			value := []byte(fmt.Sprintf("memory-test-value-%d-with-some-padding-to-make-it-larger", i))
			err := redisBackend.Set(ctx, key, value, 10*time.Minute)
			require.NoError(t, err)

			// Log progress
			if i%1000 == 0 {
				t.Logf("Stored %d items", i)
			}
		}

		// Verify all items exist
		for i := 0; i < itemCount; i += 100 {
			key := fmt.Sprintf("memory-test-key-%d", i)
			exists, err := redisBackend.Exists(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists)
		}

		// Check stats
		stats := redisBackend.GetStats()
		t.Logf("Redis backend stats: %+v", stats)
	})
}

// TestRedisIntegration_Cleanup tests cache cleanup functionality
func TestRedisIntegration_Cleanup(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	ctx := context.Background()

	config := backends.DefaultRedisConfig(mr.Addr())
	config.RedisPrefix = "cleanup-test:"
	redisBackend, err := backends.NewRedisBackend(config)
	require.NoError(t, err)
	defer redisBackend.Close()

	t.Run("BulkCleanup", func(t *testing.T) {
		// Add many items
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("cleanup-key-%d", i)
			value := []byte(fmt.Sprintf("cleanup-value-%d", i))
			err := redisBackend.Set(ctx, key, value, 1*time.Minute)
			require.NoError(t, err)
		}

		// Clear all
		err := redisBackend.Clear(ctx)
		require.NoError(t, err)

		// Verify all items are gone
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("cleanup-key-%d", i)
			exists, err := redisBackend.Exists(ctx, key)
			require.NoError(t, err)
			assert.False(t, exists)
		}
	})
}
