package traefikoidc

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewLazyBackgroundTaskUnit tests LazyBackgroundTask creation without leak detection
func TestNewLazyBackgroundTaskUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	callCount := 0
	taskFunc := func() {
		callCount++
	}

	task := NewLazyBackgroundTask("test-task", 50*time.Millisecond, taskFunc, logger)

	require.NotNil(t, task)
	assert.NotNil(t, task.BackgroundTask)
	assert.False(t, task.started)

	// Should not execute before StartIfNeeded
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, callCount, "task should not execute before StartIfNeeded")

	// Cleanup
	if task.started {
		task.Stop()
	}
}

// TestLazyBackgroundTaskStartIfNeededUnit tests the StartIfNeeded method
func TestLazyBackgroundTaskStartIfNeededUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	callCount := 0
	var mu sync.Mutex
	taskFunc := func() {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	task := NewLazyBackgroundTask("test-start", 30*time.Millisecond, taskFunc, logger)
	require.NotNil(t, task)

	// Start the task
	task.StartIfNeeded()
	assert.True(t, task.started)

	// Wait for execution
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	firstCount := callCount
	mu.Unlock()
	assert.Greater(t, firstCount, 0, "task should execute after StartIfNeeded")

	// Multiple calls should be idempotent
	task.StartIfNeeded()
	task.StartIfNeeded()

	// Cleanup
	task.Stop()
}

// TestLazyBackgroundTaskStopUnit tests the Stop method
func TestLazyBackgroundTaskStopUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	callCount := 0
	var mu sync.Mutex
	taskFunc := func() {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	task := NewLazyBackgroundTask("test-stop", 30*time.Millisecond, taskFunc, logger)
	require.NotNil(t, task)

	// Start and let it run
	task.StartIfNeeded()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	countAfterStart := callCount
	mu.Unlock()
	assert.Greater(t, countAfterStart, 0)

	// Stop the task
	task.Stop()
	assert.False(t, task.started)

	// Wait and verify it stopped
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	countAfterStop := callCount
	mu.Unlock()

	// Allow 1 in-flight execution
	assert.LessOrEqual(t, countAfterStop, countAfterStart+1, "task should stop executing")
}

// TestNewLazyCacheUnit tests NewLazyCache creation
func TestNewLazyCacheUnit(t *testing.T) {
	cache := NewLazyCache()

	require.NotNil(t, cache)

	// Test basic operations
	cache.Set("test-key", "test-value", time.Minute)
	val, found := cache.Get("test-key")

	assert.True(t, found)
	assert.Equal(t, "test-value", val)
}

// TestNewLazyCacheWithLoggerUnit tests NewLazyCacheWithLogger creation
func TestNewLazyCacheWithLoggerUnit(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cache := NewLazyCacheWithLogger(logger)

	require.NotNil(t, cache)

	// Test with multiple entries
	for i := 0; i < 10; i++ {
		key := "key-" + string(rune('0'+i))
		cache.Set(key, i, time.Minute)
	}

	// Verify entries
	for i := 0; i < 10; i++ {
		key := "key-" + string(rune('0'+i))
		val, found := cache.Get(key)
		assert.True(t, found, "should find key %s", key)
		assert.Equal(t, i, val, "should get correct value for key %s", key)
	}
}

// TestNewLazyCacheWithLoggerNilUnit tests NewLazyCacheWithLogger with nil logger
func TestNewLazyCacheWithLoggerNilUnit(t *testing.T) {
	cache := NewLazyCacheWithLogger(nil)

	require.NotNil(t, cache)

	// Should work with nil logger (uses no-op logger)
	cache.Set("nil-test", "value", time.Minute)
	val, found := cache.Get("nil-test")

	assert.True(t, found)
	assert.Equal(t, "value", val)
}

// TestCleanupIdleConnectionsUnit tests CleanupIdleConnections function
func TestCleanupIdleConnectionsUnit(t *testing.T) {
	t.Run("basic cleanup cycle", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
			},
		}

		stopChan := make(chan struct{})

		// Start cleanup in background
		go CleanupIdleConnections(client, 40*time.Millisecond, stopChan)

		// Let it run a couple of cycles
		time.Sleep(100 * time.Millisecond)

		// Stop cleanup
		close(stopChan)

		// Wait for cleanup to finish
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("immediate stop", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		stopChan := make(chan struct{})

		// Start and immediately stop
		go CleanupIdleConnections(client, 100*time.Millisecond, stopChan)
		time.Sleep(10 * time.Millisecond)
		close(stopChan)

		// Wait for cleanup
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("nil transport", func(t *testing.T) {
		client := &http.Client{
			Transport: nil,
		}

		stopChan := make(chan struct{})

		// Should handle gracefully
		go CleanupIdleConnections(client, 40*time.Millisecond, stopChan)
		time.Sleep(80 * time.Millisecond)
		close(stopChan)
		time.Sleep(50 * time.Millisecond)
	})
}

// TestDefaultOptimizedConfigUnit tests DefaultOptimizedConfig function (already has 100% coverage)
func TestDefaultOptimizedConfigUnit(t *testing.T) {
	config := DefaultOptimizedConfig()

	require.NotNil(t, config)
	assert.True(t, config.DelayBackgroundTasks)
	assert.True(t, config.ReducedCleanupIntervals)
	assert.True(t, config.AggressiveConnectionCleanup)
	assert.True(t, config.MinimalCacheSize)
}
