package backends

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestRedis creates a miniredis instance for testing
func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *RedisBackend) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	t.Cleanup(func() {
		mr.Close()
	})

	backend, err := NewRedisBackend(&Config{
		RedisAddr:   mr.Addr(),
		RedisPrefix: "test:",
		PoolSize:    5,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		backend.Close()
	})

	return mr, backend
}

// TestPipeline_Basic tests basic pipeline functionality
func TestPipeline_Basic(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	config := &PoolConfig{
		Address:        mr.Addr(),
		MaxConnections: 5,
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	defer pool.Put(conn)

	t.Run("SingleCommand", func(t *testing.T) {
		pipeline := conn.NewPipeline()
		pipeline.Queue("SET", "single-key", "single-value")

		responses, err := pipeline.Execute()
		require.NoError(t, err)
		require.Len(t, responses, 1)
		assert.Equal(t, "OK", responses[0])
	})

	t.Run("MultipleCommands", func(t *testing.T) {
		pipeline := conn.NewPipeline()
		pipeline.Queue("SET", "key1", "value1")
		pipeline.Queue("SET", "key2", "value2")
		pipeline.Queue("SET", "key3", "value3")
		pipeline.Queue("GET", "key1")
		pipeline.Queue("GET", "key2")
		pipeline.Queue("GET", "key3")

		responses, err := pipeline.Execute()
		require.NoError(t, err)
		require.Len(t, responses, 6)

		// First 3 are SET responses
		assert.Equal(t, "OK", responses[0])
		assert.Equal(t, "OK", responses[1])
		assert.Equal(t, "OK", responses[2])

		// Last 3 are GET responses
		assert.Equal(t, "value1", responses[3])
		assert.Equal(t, "value2", responses[4])
		assert.Equal(t, "value3", responses[5])
	})

	t.Run("EmptyPipeline", func(t *testing.T) {
		pipeline := conn.NewPipeline()

		responses, err := pipeline.Execute()
		require.NoError(t, err)
		assert.Nil(t, responses)
	})

	t.Run("NilResponses", func(t *testing.T) {
		pipeline := conn.NewPipeline()
		pipeline.Queue("GET", "nonexistent-key")

		responses, err := pipeline.Execute()
		require.NoError(t, err)
		require.Len(t, responses, 1)
		assert.Nil(t, responses[0])
	})
}

// TestPipeline_SetMany tests pipelined SetMany
func TestPipeline_SetMany(t *testing.T) {
	t.Parallel()

	_, backend := setupTestRedis(t)
	ctx := context.Background()

	t.Run("SetManyItems", func(t *testing.T) {
		items := make(map[string][]byte)
		for i := 0; i < 10; i++ {
			items[fmt.Sprintf("setmany-key-%d", i)] = []byte(fmt.Sprintf("value-%d", i))
		}

		err := backend.SetMany(ctx, items, time.Minute)
		require.NoError(t, err)

		// Verify all items were set
		for key, expectedValue := range items {
			value, _, exists, err := backend.Get(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists, "Key %s should exist", key)
			assert.Equal(t, expectedValue, value)
		}
	})

	t.Run("SetManyEmpty", func(t *testing.T) {
		err := backend.SetMany(ctx, map[string][]byte{}, time.Minute)
		require.NoError(t, err)
	})

	t.Run("SetManySingleItem", func(t *testing.T) {
		items := map[string][]byte{
			"single-setmany": []byte("single-value"),
		}

		err := backend.SetMany(ctx, items, time.Minute)
		require.NoError(t, err)

		value, _, exists, err := backend.Get(ctx, "single-setmany")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, []byte("single-value"), value)
	})

	t.Run("SetManyNoTTL", func(t *testing.T) {
		items := map[string][]byte{
			"nottl-key1": []byte("value1"),
			"nottl-key2": []byte("value2"),
		}

		err := backend.SetMany(ctx, items, 0)
		require.NoError(t, err)

		// Keys should exist
		for key := range items {
			exists, err := backend.Exists(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists)
		}
	})
}

// TestPipeline_GetMany tests pipelined GetMany
func TestPipeline_GetMany(t *testing.T) {
	t.Parallel()

	_, backend := setupTestRedis(t)
	ctx := context.Background()

	// Pre-populate cache
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("getmany-key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := backend.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)
	}

	t.Run("GetManyExisting", func(t *testing.T) {
		keys := make([]string, 10)
		for i := 0; i < 10; i++ {
			keys[i] = fmt.Sprintf("getmany-key-%d", i)
		}

		results, err := backend.GetMany(ctx, keys)
		require.NoError(t, err)
		assert.Len(t, results, 10)

		for i, key := range keys {
			assert.Equal(t, []byte(fmt.Sprintf("value-%d", i)), results[key])
		}
	})

	t.Run("GetManyMixed", func(t *testing.T) {
		keys := []string{
			"getmany-key-0",     // exists
			"nonexistent-key-1", // doesn't exist
			"getmany-key-2",     // exists
			"nonexistent-key-2", // doesn't exist
		}

		results, err := backend.GetMany(ctx, keys)
		require.NoError(t, err)
		assert.Len(t, results, 2) // Only existing keys

		assert.Equal(t, []byte("value-0"), results["getmany-key-0"])
		assert.Equal(t, []byte("value-2"), results["getmany-key-2"])
		assert.NotContains(t, results, "nonexistent-key-1")
		assert.NotContains(t, results, "nonexistent-key-2")
	})

	t.Run("GetManyEmpty", func(t *testing.T) {
		results, err := backend.GetMany(ctx, []string{})
		require.NoError(t, err)
		assert.NotNil(t, results)
		assert.Len(t, results, 0)
	})

	t.Run("GetManySingleKey", func(t *testing.T) {
		results, err := backend.GetMany(ctx, []string{"getmany-key-5"})
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, []byte("value-5"), results["getmany-key-5"])
	})

	t.Run("GetManyAllNonexistent", func(t *testing.T) {
		keys := []string{
			"nonexistent-1",
			"nonexistent-2",
			"nonexistent-3",
		}

		results, err := backend.GetMany(ctx, keys)
		require.NoError(t, err)
		assert.Len(t, results, 0)
	})
}

// TestPipeline_LargeBatch tests pipelining with large batches
func TestPipeline_LargeBatch(t *testing.T) {
	t.Parallel()

	_, backend := setupTestRedis(t)
	ctx := context.Background()

	t.Run("SetMany100Items", func(t *testing.T) {
		items := make(map[string][]byte)
		for i := 0; i < 100; i++ {
			items[fmt.Sprintf("large-batch-%d", i)] = []byte(fmt.Sprintf("value-%d", i))
		}

		err := backend.SetMany(ctx, items, time.Minute)
		require.NoError(t, err)

		// Verify random samples
		for _, i := range []int{0, 25, 50, 75, 99} {
			key := fmt.Sprintf("large-batch-%d", i)
			value, _, exists, err := backend.Get(ctx, key)
			require.NoError(t, err)
			assert.True(t, exists)
			assert.Equal(t, []byte(fmt.Sprintf("value-%d", i)), value)
		}
	})

	t.Run("GetMany100Items", func(t *testing.T) {
		keys := make([]string, 100)
		for i := 0; i < 100; i++ {
			keys[i] = fmt.Sprintf("large-batch-%d", i)
		}

		results, err := backend.GetMany(ctx, keys)
		require.NoError(t, err)
		assert.Len(t, results, 100)
	})
}

// TestPipeline_Stats tests that stats are tracked correctly with pipelining
func TestPipeline_Stats(t *testing.T) {
	t.Parallel()

	_, backend := setupTestRedis(t)
	ctx := context.Background()

	// Set some items
	items := map[string][]byte{
		"stats-key-1": []byte("value1"),
		"stats-key-2": []byte("value2"),
	}
	err := backend.SetMany(ctx, items, time.Minute)
	require.NoError(t, err)

	// Get items (some exist, some don't)
	keys := []string{
		"stats-key-1",
		"stats-key-2",
		"stats-key-nonexistent",
	}
	results, err := backend.GetMany(ctx, keys)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// Check stats
	stats := backend.GetStats()
	hits := stats["hits"].(int64)
	misses := stats["misses"].(int64)

	assert.Equal(t, int64(2), hits, "Should have 2 hits")
	assert.Equal(t, int64(1), misses, "Should have 1 miss")
}

// BenchmarkPipeline_SetMany benchmarks SetMany with pipelining
func BenchmarkPipeline_SetMany(b *testing.B) {
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer mr.Close()

	backend, err := NewRedisBackend(&Config{
		RedisAddr:   mr.Addr(),
		RedisPrefix: "bench:",
		PoolSize:    10,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Prepare items
	items := make(map[string][]byte)
	for i := 0; i < 100; i++ {
		items[fmt.Sprintf("bench-key-%d", i)] = []byte(fmt.Sprintf("bench-value-%d", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = backend.SetMany(ctx, items, time.Minute)
	}
}

// BenchmarkPipeline_GetMany benchmarks GetMany with pipelining
func BenchmarkPipeline_GetMany(b *testing.B) {
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer mr.Close()

	backend, err := NewRedisBackend(&Config{
		RedisAddr:   mr.Addr(),
		RedisPrefix: "bench:",
		PoolSize:    10,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Pre-populate cache
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("bench-key-%d", i)
		value := []byte(fmt.Sprintf("bench-value-%d", i))
		backend.Set(ctx, key, value, time.Hour)
	}

	// Prepare keys
	keys := make([]string, 100)
	for i := 0; i < 100; i++ {
		keys[i] = fmt.Sprintf("bench-key-%d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = backend.GetMany(ctx, keys)
	}
}

// BenchmarkPipeline_VsSequential benchmarks pipeline vs sequential operations
func BenchmarkPipeline_VsSequential(b *testing.B) {
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer mr.Close()

	backend, err := NewRedisBackend(&Config{
		RedisAddr:   mr.Addr(),
		RedisPrefix: "bench:",
		PoolSize:    10,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Prepare items
	items := make(map[string][]byte)
	keys := make([]string, 50)
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("compare-key-%d", i)
		keys[i] = key
		items[key] = []byte(fmt.Sprintf("compare-value-%d", i))
	}

	b.Run("Pipelined-Set", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = backend.SetMany(ctx, items, time.Minute)
		}
	})

	b.Run("Sequential-Set", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for key, value := range items {
				_ = backend.Set(ctx, key, value, time.Minute)
			}
		}
	})

	// Pre-populate for get benchmarks
	_ = backend.SetMany(ctx, items, time.Hour)

	b.Run("Pipelined-Get", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = backend.GetMany(ctx, keys)
		}
	})

	b.Run("Sequential-Get", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, key := range keys {
				_, _, _, _ = backend.Get(ctx, key)
			}
		}
	})
}
