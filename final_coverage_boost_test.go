package traefikoidc

import (
	"testing"
	"time"
)

// Final focused tests to reach 85% coverage target
func TestFinalCoverageBoost(t *testing.T) {
	// Test DefaultOptimizedConfig
	t.Run("DefaultOptimizedConfig", func(t *testing.T) {
		config := DefaultOptimizedConfig()
		if config == nil {
			t.Error("Expected non-nil default config")
		}
	})

	// Test NewLazyCache and operations
	t.Run("LazyCache operations", func(t *testing.T) {
		cache := NewLazyCache()
		if cache == nil {
			t.Error("Expected non-nil lazy cache")
		}

		// Test basic operations
		cache.Set("test1", "value1", time.Minute)
		value, found := cache.Get("test1")
		if !found {
			t.Error("Expected to find cached value")
		}
		if value != "value1" {
			t.Errorf("Expected 'value1', got %v", value)
		}

		cache.Delete("test1")
		_, found = cache.Get("test1")
		if found {
			t.Error("Expected value to be deleted")
		}

		cache.Close()
	})

	// Test NewLazyCacheWithLogger
	t.Run("LazyCache with logger", func(t *testing.T) {
		logger := NewLogger("debug")
		cache := NewLazyCacheWithLogger(logger)
		if cache == nil {
			t.Error("Expected non-nil lazy cache with logger")
		}

		cache.Set("test2", "value2", time.Minute)
		cache.Close()
	})

	// Test additional cache operations
	t.Run("OptimizedCache additional operations", func(t *testing.T) {
		cache := NewOptimizedCache()

		// Set some values
		cache.Set("key1", "value1", time.Minute)
		cache.Set("key2", "value2", time.Minute)

		// Test cleanup
		cache.Cleanup()

		// Test close
		cache.Close()
	})

	// Test UnifiedCache with various operations
	t.Run("UnifiedCache comprehensive", func(t *testing.T) {
		config := DefaultUnifiedCacheConfig()
		cache := NewUnifiedCache(config)

		// Test various operations
		cache.Set("unified1", "value1", time.Minute)
		cache.Set("unified2", "value2", time.Minute)

		value, found := cache.Get("unified1")
		if !found {
			t.Error("Expected to find cached value in unified cache")
		}
		if value != "value1" {
			t.Errorf("Expected 'value1', got %v", value)
		}

		cache.Delete("unified1")
		cache.SetMaxSize(100)

		cache.Close()
	})
}

// Test Cache Adapter pattern
func TestCacheAdapterOperations(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	unifiedCache := NewUnifiedCache(config)
	adapter := NewCacheAdapter(unifiedCache)
	if adapter == nil {
		t.Error("Expected non-nil cache adapter")
	}

	// Test operations
	adapter.Set("adapter1", "value1", time.Minute)
	adapter.Set("adapter2", "value2", time.Minute)

	value, found := adapter.Get("adapter1")
	if !found {
		t.Error("Expected to find value in cache adapter")
	}
	if value != "value1" {
		t.Errorf("Expected 'value1', got %v", value)
	}

	adapter.Delete("adapter1")
	adapter.Cleanup()
	adapter.Close()
}

// Test BackgroundTask operations to increase coverage
func TestBackgroundTaskCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	logger := NewLogger("debug")
	counter := 0

	// Create a background task
	task := NewBackgroundTask("coverage-test", 50*time.Millisecond, func() {
		counter++
	}, logger)

	if task == nil {
		t.Fatal("Expected non-nil background task")
	}

	// Start the task
	task.Start()

	// Let it run a few times
	time.Sleep(150 * time.Millisecond)

	// Stop the task
	task.Stop()

	if counter == 0 {
		t.Error("Expected background task to increment counter")
	}
}

// Test createDefaultHTTPClient for backward compatibility
func TestCreateDefaultHTTPClient(t *testing.T) {
	client := createDefaultHTTPClient()
	if client == nil {
		t.Fatal("Expected non-nil HTTP client")
	}

	// Test that it has reasonable defaults
	if client.Timeout <= 0 {
		t.Error("Expected positive timeout")
	}
}
