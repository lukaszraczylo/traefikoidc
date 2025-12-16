package backends

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSingleflightCache_BasicGetOrFetch tests basic GetOrFetch functionality
func TestSingleflightCache_BasicGetOrFetch(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()

	t.Run("CacheHit", func(t *testing.T) {
		key := "existing-key"
		value := []byte("existing-value")

		// Pre-populate cache
		err := cache.Set(ctx, key, value, time.Minute)
		require.NoError(t, err)

		var fetchCalled bool
		fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
			fetchCalled = true
			return []byte("fetched-value"), time.Minute, nil
		}

		result, err := cache.GetOrFetch(ctx, key, fetcher)
		require.NoError(t, err)
		assert.Equal(t, value, result)
		assert.False(t, fetchCalled, "Fetcher should not be called on cache hit")
	})

	t.Run("CacheMiss", func(t *testing.T) {
		key := "missing-key"
		expectedValue := []byte("fetched-value")

		var fetchCalled bool
		fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
			fetchCalled = true
			return expectedValue, time.Minute, nil
		}

		result, err := cache.GetOrFetch(ctx, key, fetcher)
		require.NoError(t, err)
		assert.Equal(t, expectedValue, result)
		assert.True(t, fetchCalled, "Fetcher should be called on cache miss")

		// Verify value was stored in cache
		cached, _, exists, err := cache.Get(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, expectedValue, cached)
	})

	t.Run("FetcherError", func(t *testing.T) {
		key := "error-key"
		expectedErr := errors.New("fetch failed")

		fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
			return nil, 0, expectedErr
		}

		result, err := cache.GetOrFetch(ctx, key, fetcher)
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, result)

		// Verify nothing was stored in cache
		_, _, exists, err := cache.Get(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

// TestSingleflightCache_Deduplication tests that concurrent calls are deduplicated
func TestSingleflightCache_Deduplication(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()
	key := "dedup-key"
	expectedValue := []byte("dedup-value")

	var fetchCount atomic.Int32
	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		fetchCount.Add(1)
		// Simulate slow fetch
		time.Sleep(100 * time.Millisecond)
		return expectedValue, time.Minute, nil
	}

	// Launch multiple concurrent requests
	concurrency := 10
	var wg sync.WaitGroup
	results := make([][]byte, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = cache.GetOrFetch(ctx, key, fetcher)
		}(i)
	}

	wg.Wait()

	// Verify all requests got the same result
	for i := 0; i < concurrency; i++ {
		assert.NoError(t, errs[i])
		assert.Equal(t, expectedValue, results[i])
	}

	// Verify fetcher was only called once
	assert.Equal(t, int32(1), fetchCount.Load(), "Fetcher should only be called once")

	// Verify deduplication stats
	stats := cache.GetStats()
	deduped := stats["singleflight_deduplicated"].(int64)
	assert.Equal(t, int64(concurrency-1), deduped, "Should have deduplicated N-1 calls")
}

// TestSingleflightCache_DifferentKeys tests that different keys can fetch in parallel
func TestSingleflightCache_DifferentKeys(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()

	var fetchCount atomic.Int32
	fetchStarted := make(chan struct{}, 3)
	fetchComplete := make(chan struct{})

	fetcher := func(key string) Fetcher {
		return func(ctx context.Context) ([]byte, time.Duration, error) {
			fetchCount.Add(1)
			fetchStarted <- struct{}{}
			<-fetchComplete // Wait for signal
			return []byte("value-" + key), time.Minute, nil
		}
	}

	// Launch concurrent requests for different keys
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", idx)
			_, _ = cache.GetOrFetch(ctx, key, fetcher(key))
		}(i)
	}

	// Wait for all fetches to start
	for i := 0; i < 3; i++ {
		<-fetchStarted
	}

	// All 3 fetches should be running in parallel
	assert.Equal(t, int32(3), fetchCount.Load(), "All three fetches should run in parallel")

	// Release all fetches
	close(fetchComplete)
	wg.Wait()
}

// TestSingleflightCache_ContextCancellation tests context cancellation
func TestSingleflightCache_ContextCancellation(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	key := "cancel-key"
	fetchStarted := make(chan struct{})

	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		close(fetchStarted)
		// Simulate slow fetch
		time.Sleep(500 * time.Millisecond)
		return []byte("value"), time.Minute, nil
	}

	// Start first request with long timeout
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()
		_, _ = cache.GetOrFetch(ctx, key, fetcher)
	}()

	// Wait for fetch to start
	<-fetchStarted

	// Start second request with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = cache.GetOrFetch(ctx, key, fetcher)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)

	wg.Wait()
}

// TestSingleflightCache_ErrorPropagation tests that errors are properly propagated
func TestSingleflightCache_ErrorPropagation(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()
	key := "error-prop-key"
	expectedErr := errors.New("intentional error")

	var fetchCount atomic.Int32
	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		fetchCount.Add(1)
		time.Sleep(50 * time.Millisecond)
		return nil, 0, expectedErr
	}

	// Launch multiple concurrent requests
	concurrency := 5
	var wg sync.WaitGroup
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = cache.GetOrFetch(ctx, key, fetcher)
		}(i)
	}

	wg.Wait()

	// Verify all requests got the same error
	for i := 0; i < concurrency; i++ {
		assert.Error(t, errs[i])
		assert.Equal(t, expectedErr, errs[i])
	}

	// Verify fetcher was only called once
	assert.Equal(t, int32(1), fetchCount.Load())
}

// TestSingleflightCache_PassthroughMethods tests that passthrough methods work
func TestSingleflightCache_PassthroughMethods(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()

	t.Run("Set", func(t *testing.T) {
		err := cache.Set(ctx, "set-key", []byte("set-value"), time.Minute)
		require.NoError(t, err)

		val, _, exists, err := cache.Get(ctx, "set-key")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, []byte("set-value"), val)
	})

	t.Run("Get", func(t *testing.T) {
		err := cache.Set(ctx, "get-key", []byte("get-value"), time.Minute)
		require.NoError(t, err)

		val, ttl, exists, err := cache.Get(ctx, "get-key")
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, []byte("get-value"), val)
		assert.Greater(t, ttl, time.Duration(0))
	})

	t.Run("Delete", func(t *testing.T) {
		err := cache.Set(ctx, "delete-key", []byte("delete-value"), time.Minute)
		require.NoError(t, err)

		deleted, err := cache.Delete(ctx, "delete-key")
		require.NoError(t, err)
		assert.True(t, deleted)

		exists, err := cache.Exists(ctx, "delete-key")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Exists", func(t *testing.T) {
		exists, err := cache.Exists(ctx, "nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)

		err = cache.Set(ctx, "exists-key", []byte("value"), time.Minute)
		require.NoError(t, err)

		exists, err = cache.Exists(ctx, "exists-key")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("Clear", func(t *testing.T) {
		err := cache.Set(ctx, "clear-key", []byte("value"), time.Minute)
		require.NoError(t, err)

		err = cache.Clear(ctx)
		require.NoError(t, err)

		exists, err := cache.Exists(ctx, "clear-key")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Ping", func(t *testing.T) {
		err := cache.Ping(ctx)
		require.NoError(t, err)
	})
}

// TestSingleflightCache_Stats tests statistics tracking
func TestSingleflightCache_Stats(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()

	// Make some calls
	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		time.Sleep(50 * time.Millisecond)
		return []byte("value"), time.Minute, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.GetOrFetch(ctx, "stats-key", fetcher)
		}()
	}
	wg.Wait()

	stats := cache.GetStats()

	// Check singleflight stats exist
	assert.Contains(t, stats, "singleflight_total_calls")
	assert.Contains(t, stats, "singleflight_deduplicated")
	assert.Contains(t, stats, "singleflight_dedup_rate")
	assert.Contains(t, stats, "singleflight_inflight")

	// Verify values
	assert.Equal(t, int64(5), stats["singleflight_total_calls"])
	assert.Equal(t, int64(4), stats["singleflight_deduplicated"])

	// Also check underlying backend stats are included
	assert.Contains(t, stats, "hits")
	assert.Contains(t, stats, "misses")
}

// TestSingleflightCache_ResetStats tests stats reset
func TestSingleflightCache_ResetStats(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()

	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		return []byte("value"), time.Minute, nil
	}

	// Make some calls
	_, _ = cache.GetOrFetch(ctx, "key1", fetcher)
	_, _ = cache.GetOrFetch(ctx, "key2", fetcher)

	stats := cache.GetStats()
	assert.Greater(t, stats["singleflight_total_calls"].(int64), int64(0))

	// Reset stats
	cache.ResetStats()

	stats = cache.GetStats()
	assert.Equal(t, int64(0), stats["singleflight_total_calls"])
	assert.Equal(t, int64(0), stats["singleflight_deduplicated"])
}

// TestSingleflightCache_GetBackend tests GetBackend method
func TestSingleflightCache_GetBackend(t *testing.T) {
	t.Parallel()

	backend, err := NewMemoryBackend(DefaultConfig())
	require.NoError(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	assert.Equal(t, backend, cache.GetBackend())
}

// BenchmarkSingleflightCache_Sequential benchmarks sequential access
func BenchmarkSingleflightCache_Sequential(b *testing.B) {
	backend, _ := NewMemoryBackend(DefaultConfig())
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()
	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		return []byte("benchmark-value"), time.Minute, nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%100)
		_, _ = cache.GetOrFetch(ctx, key, fetcher)
	}
}

// BenchmarkSingleflightCache_Concurrent benchmarks concurrent access
func BenchmarkSingleflightCache_Concurrent(b *testing.B) {
	backend, _ := NewMemoryBackend(DefaultConfig())
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()
	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		time.Sleep(time.Millisecond) // Simulate slow fetch
		return []byte("benchmark-value"), time.Minute, nil
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d", i%10) // Only 10 unique keys to force deduplication
			_, _ = cache.GetOrFetch(ctx, key, fetcher)
			i++
		}
	})
}

// BenchmarkSingleflightCache_HighContention benchmarks high contention scenario
func BenchmarkSingleflightCache_HighContention(b *testing.B) {
	backend, _ := NewMemoryBackend(DefaultConfig())
	defer backend.Close()

	cache := NewSingleflightCache(backend)

	ctx := context.Background()
	fetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		time.Sleep(10 * time.Millisecond) // Slow fetch to force queuing
		return []byte("benchmark-value"), time.Minute, nil
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// All goroutines hit the same key
			_, _ = cache.GetOrFetch(ctx, "hot-key", fetcher)
		}
	})
}
