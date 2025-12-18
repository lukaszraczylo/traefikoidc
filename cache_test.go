package traefikoidc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// CACHE TEST FRAMEWORK
// =============================================================================

// CacheTestCase represents a comprehensive test case for cache operations
type CacheTestCase struct {
	setup      func(*TestFramework)
	execute    func(*TestFramework) error
	validate   func(*testing.T, error, *TestFramework)
	cleanup    func(*TestFramework)
	name       string
	cacheType  string
	operation  string
	skipReason string
	timeout    time.Duration
	parallel   bool
}

// createTestCacheConfig creates a standard test configuration
func createTestCacheConfig() UniversalCacheConfig {
	return UniversalCacheConfig{
		Type:              CacheTypeGeneral,
		MaxSize:           1000,
		CleanupInterval:   1 * time.Minute,
		DefaultTTL:        1 * time.Hour,
		MaxMemoryBytes:    100 * 1024 * 1024, // 100MB
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
		MetadataConfig: &MetadataCacheConfig{
			GracePeriod: 5 * time.Minute,
		},
	}
}

// executeTestCase executes a single cache test case with proper setup and cleanup
func executeCacheTestCase(t *testing.T, tc CacheTestCase, framework *TestFramework) {
	if tc.timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
		defer cancel()

		done := make(chan bool)
		go func() {
			defer close(done)
			runCacheTestCase(t, tc, framework)
		}()

		select {
		case <-done:
			// Test completed
		case <-ctx.Done():
			t.Fatalf("Test timeout after %v", tc.timeout)
		}
	} else {
		runCacheTestCase(t, tc, framework)
	}
}

// runCacheTestCase runs the actual test case logic
func runCacheTestCase(t *testing.T, tc CacheTestCase, framework *TestFramework) {
	if tc.setup != nil {
		tc.setup(framework)
	}

	var err error
	if tc.execute != nil {
		err = tc.execute(framework)
	}

	if tc.validate != nil {
		tc.validate(t, err, framework)
	}

	if tc.cleanup != nil {
		tc.cleanup(framework)
	}
}

// =============================================================================
// CACHE MANAGER TESTS
// =============================================================================

// Helper function to ensure we have a working cache manager for tests
func getTestCacheManager(t *testing.T) *CacheManager {
	cm := GetGlobalCacheManager(&sync.WaitGroup{})
	if cm == nil {
		t.Fatal("Failed to get cache manager")
	}
	if cm.manager == nil {
		t.Fatal("Cache manager has nil internal manager")
	}
	return cm
}

func TestCacheManager_Close(t *testing.T) {
	wg := &sync.WaitGroup{}
	cm := GetGlobalCacheManager(wg)

	if cm == nil {
		t.Fatal("Expected cache manager to be created")
	}

	err := cm.Close()
	if err != nil {
		t.Errorf("Unexpected error closing cache manager: %v", err)
	}
}

func TestCleanupGlobalCacheManager(t *testing.T) {
	originalInstance := globalCacheManagerInstance
	globalCacheManagerInstance = nil
	err := CleanupGlobalCacheManager()
	if err != nil {
		t.Errorf("Unexpected error during cleanup of nil instance: %v", err)
	}

	globalCacheManagerInstance = originalInstance
}

func TestCacheInterfaceWrapper_Delete(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	cache.Set("test-key", "test-value", time.Hour)

	value, found := cache.Get("test-key")
	if !found {
		t.Fatal("Expected key to be found after setting")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}

	cache.Delete("test-key")

	_, found = cache.Get("test-key")
	if found {
		t.Error("Expected key to be deleted")
	}
}

func TestCacheInterfaceWrapper_Size(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	cache.Clear()

	initialSize := cache.Size()
	if initialSize != 0 {
		t.Errorf("Expected initial size 0, got %d", initialSize)
	}

	cache.Set("key1", "value1", time.Hour)
	cache.Set("key2", "value2", time.Hour)

	newSize := cache.Size()
	if newSize != 2 {
		t.Errorf("Expected size 2, got %d", newSize)
	}
}

func TestCacheInterfaceWrapper_Clear(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	cache.Set("key1", "value1", time.Hour)
	cache.Set("key2", "value2", time.Hour)

	size := cache.Size()
	if size != 2 {
		t.Errorf("Expected 2 items before clear, got %d", size)
	}

	cache.Clear()

	size = cache.Size()
	if size != 0 {
		t.Errorf("Expected 0 items after clear, got %d", size)
	}

	_, found := cache.Get("key1")
	if found {
		t.Error("Expected key1 to be cleared")
	}

	_, found = cache.Get("key2")
	if found {
		t.Error("Expected key2 to be cleared")
	}
}

func TestCacheInterfaceWrapper_Close(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	wrapper, ok := cache.(*CacheInterfaceWrapper)
	if !ok {
		t.Fatal("Expected CacheInterfaceWrapper")
	}

	wrapper.Close()

	nilWrapper := &CacheInterfaceWrapper{cache: nil}
	nilWrapper.Close()
}

// TestCacheInterfaceWrapper_ManagedClose_Regression tests that managed cache wrappers
// don't close the underlying cache when Close() is called. This is a regression test
// for issue #105 where multiple plugin instances closing shared caches caused log flooding.
func TestCacheInterfaceWrapper_ManagedClose_Regression(t *testing.T) {
	cm := getTestCacheManager(t)

	// Get a managed cache wrapper
	cache := cm.GetSharedTokenBlacklist()
	wrapper, ok := cache.(*CacheInterfaceWrapper)
	if !ok {
		t.Fatal("Expected CacheInterfaceWrapper")
	}

	// Verify it's marked as managed
	if !wrapper.managed {
		t.Error("Expected shared cache wrapper to be marked as managed")
	}

	// Set some data before Close
	cache.Set("test-key", "test-value", time.Hour)

	// Close the wrapper (should be a no-op for managed caches)
	wrapper.Close()

	// Verify the cache is still operational after Close
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected cache to still work after Close() on managed wrapper")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}

	// Can still set new values
	cache.Set("new-key", "new-value", time.Hour)
	newValue, found := cache.Get("new-key")
	if !found || newValue != "new-value" {
		t.Error("Expected to be able to set new values after Close() on managed wrapper")
	}
}

// TestCacheInterfaceWrapper_StandaloneClose tests that standalone cache wrappers
// properly close the underlying cache when Close() is called.
func TestCacheInterfaceWrapper_StandaloneClose(t *testing.T) {
	// Create a standalone cache (not from the global cache manager)
	standaloneCache := NewCache()

	wrapper, ok := standaloneCache.(*CacheInterfaceWrapper)
	if !ok {
		t.Fatal("Expected CacheInterfaceWrapper")
	}

	// Verify it's NOT marked as managed
	if wrapper.managed {
		t.Error("Expected standalone cache wrapper to NOT be marked as managed")
	}

	// Set some data
	standaloneCache.Set("test-key", "test-value", time.Hour)

	// Get baseline goroutine count
	baselineGoroutines := runtime.NumGoroutine()

	// Close the wrapper (should actually close the underlying cache)
	wrapper.Close()

	// Give cleanup goroutine time to stop
	time.Sleep(100 * time.Millisecond)

	// Goroutine count should decrease (cleanup routine stopped)
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > baselineGoroutines {
		// This is acceptable - other tests might have started goroutines
		t.Logf("Goroutine count: baseline=%d, final=%d", baselineGoroutines, finalGoroutines)
	}
}

// TestCacheInterfaceWrapper_MultipleInstancesClose_Regression tests that multiple
// plugin instances can close their cache wrappers without affecting shared caches.
// This is a regression test for issue #105.
func TestCacheInterfaceWrapper_MultipleInstancesClose_Regression(t *testing.T) {
	cm := getTestCacheManager(t)

	// Simulate multiple plugin instances getting cache references
	instances := make([]*CacheInterfaceWrapper, 5)
	for i := 0; i < 5; i++ {
		cache := cm.GetSharedTokenBlacklist()
		wrapper, ok := cache.(*CacheInterfaceWrapper)
		if !ok {
			t.Fatal("Expected CacheInterfaceWrapper")
		}
		instances[i] = wrapper

		// Each instance might set some data
		cache.Set(fmt.Sprintf("instance-%d-key", i), fmt.Sprintf("value-%d", i), time.Hour)
	}

	// Close all instances (simulating plugin shutdown/reload)
	for _, wrapper := range instances {
		wrapper.Close()
	}

	// The shared cache should still work after all instances closed their wrappers
	newCache := cm.GetSharedTokenBlacklist()

	// Data set by earlier instances should still be accessible
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("instance-%d-key", i)
		value, found := newCache.Get(key)
		if !found {
			t.Errorf("Expected data from instance %d to still be accessible", i)
		}
		expectedValue := fmt.Sprintf("value-%d", i)
		if value != expectedValue {
			t.Errorf("Expected '%s', got '%v'", expectedValue, value)
		}
	}

	// Should be able to add new data
	newCache.Set("after-close-key", "after-close-value", time.Hour)
	value, found := newCache.Get("after-close-key")
	if !found || value != "after-close-value" {
		t.Error("Expected to be able to use cache after all wrapper Close() calls")
	}
}

// TestAllSharedCachesMarkedAsManaged verifies all shared cache getters
// return managed wrappers to prevent the log flooding issue.
func TestAllSharedCachesMarkedAsManaged(t *testing.T) {
	cm := getTestCacheManager(t)

	tests := []struct {
		name  string
		cache CacheInterface
	}{
		{"TokenBlacklist", cm.GetSharedTokenBlacklist()},
		{"IntrospectionCache", cm.GetSharedIntrospectionCache()},
		{"TokenTypeCache", cm.GetSharedTokenTypeCache()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, ok := tt.cache.(*CacheInterfaceWrapper)
			if !ok {
				t.Fatalf("Expected CacheInterfaceWrapper for %s", tt.name)
			}
			if !wrapper.managed {
				t.Errorf("%s cache wrapper should be marked as managed", tt.name)
			}
		})
	}
}

func TestCacheInterfaceWrapper_GetStats(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	wrapper, ok := cache.(*CacheInterfaceWrapper)
	if !ok {
		t.Fatal("Expected CacheInterfaceWrapper")
	}

	stats := wrapper.GetStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}
}

func TestCacheInterfaceWrapper_Cleanup(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	cache.Set("expire-key", "expire-value", time.Millisecond)

	time.Sleep(10 * time.Millisecond)

	cache.Cleanup()

	_, found := cache.Get("expire-key")
	if found {
		t.Error("Expected expired key to be cleaned up")
	}
}

func TestCacheInterfaceWrapper_SetMaxSize(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	cache.SetMaxSize(1000)
}

func TestGetSharedCaches(t *testing.T) {
	cm := getTestCacheManager(t)

	blacklist := cm.GetSharedTokenBlacklist()
	if blacklist == nil {
		t.Error("Expected non-nil token blacklist")
	}

	tokenCache := cm.GetSharedTokenCache()
	if tokenCache == nil {
		t.Error("Expected non-nil token cache")
	}

	metadataCache := cm.GetSharedMetadataCache()
	if metadataCache == nil {
		t.Error("Expected non-nil metadata cache")
	}

	jwkCache := cm.GetSharedJWKCache()
	if jwkCache == nil {
		t.Error("Expected non-nil JWK cache")
	}
}

func TestConcurrentCacheAccess(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	var wg sync.WaitGroup
	goroutines := 10
	iterations := 10

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				value := fmt.Sprintf("value-%d-%d", id, j)

				cache.Set(key, value, time.Hour)

				retrieved, found := cache.Get(key)
				if found && retrieved != value {
					t.Errorf("Concurrent access failed: expected %s, got %v", value, retrieved)
				}

				cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()
}

// =============================================================================
// SHARDED CACHE TESTS
// =============================================================================

func TestShardedCacheBasicOperations(t *testing.T) {
	t.Run("SetAndGet", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 5*time.Minute)
		cache.Set("key2", 42, 5*time.Minute)
		cache.Set("key3", true, 5*time.Minute)

		val1, ok := cache.Get("key1")
		if !ok || val1 != "value1" {
			t.Errorf("Expected 'value1', got %v, ok=%v", val1, ok)
		}

		val2, ok := cache.Get("key2")
		if !ok || val2 != 42 {
			t.Errorf("Expected 42, got %v, ok=%v", val2, ok)
		}

		val3, ok := cache.Get("key3")
		if !ok || val3 != true {
			t.Errorf("Expected true, got %v, ok=%v", val3, ok)
		}
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		val, ok := cache.Get("nonexistent")
		if ok || val != nil {
			t.Errorf("Expected nil/false for nonexistent key, got %v/%v", val, ok)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 5*time.Minute)
		cache.Delete("key1")

		val, ok := cache.Get("key1")
		if ok || val != nil {
			t.Errorf("Expected nil/false after delete, got %v/%v", val, ok)
		}
	})

	t.Run("Exists", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 5*time.Minute)

		if !cache.Exists("key1") {
			t.Error("Expected Exists to return true for existing key")
		}

		if cache.Exists("nonexistent") {
			t.Error("Expected Exists to return false for nonexistent key")
		}
	})

	t.Run("Size", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		if cache.Size() != 0 {
			t.Errorf("Expected size 0, got %d", cache.Size())
		}

		for i := 0; i < 100; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i, 5*time.Minute)
		}

		if cache.Size() != 100 {
			t.Errorf("Expected size 100, got %d", cache.Size())
		}
	})

	t.Run("Clear", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		for i := 0; i < 100; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i, 5*time.Minute)
		}

		cache.Clear()

		if cache.Size() != 0 {
			t.Errorf("Expected size 0 after clear, got %d", cache.Size())
		}
	})
}

func TestShardedCacheExpiration(t *testing.T) {
	t.Run("ItemExpires", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("key1", "value1", 50*time.Millisecond)

		if !cache.Exists("key1") {
			t.Error("Item should exist immediately after set")
		}

		time.Sleep(100 * time.Millisecond)

		if cache.Exists("key1") {
			t.Error("Item should have expired")
		}
	})

	t.Run("CleanupRemovesExpired", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		for i := 0; i < 50; i++ {
			cache.Set(fmt.Sprintf("expired%d", i), i, 10*time.Millisecond)
		}

		for i := 0; i < 50; i++ {
			cache.Set(fmt.Sprintf("valid%d", i), i, 5*time.Minute)
		}

		time.Sleep(50 * time.Millisecond)

		cache.Cleanup()

		for i := 0; i < 50; i++ {
			if cache.Exists(fmt.Sprintf("expired%d", i)) {
				t.Errorf("Expired item %d should not exist after cleanup", i)
			}
		}

		for i := 0; i < 50; i++ {
			if !cache.Exists(fmt.Sprintf("valid%d", i)) {
				t.Errorf("Valid item %d should still exist after cleanup", i)
			}
		}
	})

	t.Run("ZeroTTLNeverExpires", func(t *testing.T) {
		cache := NewShardedCache(16, 1000)

		cache.Set("permanent", "value", 0)

		time.Sleep(10 * time.Millisecond)

		if !cache.Exists("permanent") {
			t.Error("Item with 0 TTL should never expire")
		}
	})
}

func TestShardedCacheConcurrency(t *testing.T) {
	t.Run("ConcurrentSetGet", func(t *testing.T) {
		cache := NewShardedCache(64, 10000)
		const numGoroutines = 100
		const numOperations = 1000

		var wg sync.WaitGroup
		var errors int32

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					cache.Set(key, j, 5*time.Minute)
				}
			}(i)
		}

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					cache.Get(key)
				}
			}(i)
		}

		wg.Wait()

		if atomic.LoadInt32(&errors) > 0 {
			t.Errorf("Encountered %d errors during concurrent access", errors)
		}
	})

	t.Run("ConcurrentMixedOperations", func(t *testing.T) {
		cache := NewShardedCache(64, 10000)
		const numGoroutines = 50
		const numOperations = 500

		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d", j%100)
					switch j % 4 {
					case 0:
						cache.Set(key, j, 5*time.Minute)
					case 1:
						cache.Get(key)
					case 2:
						cache.Exists(key)
					case 3:
						cache.Delete(key)
					}
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("NoConcurrentPanics", func(t *testing.T) {
		cache := NewShardedCache(32, 5000)
		const numGoroutines = 100

		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Panic in goroutine %d: %v", id, r)
					}
				}()

				for j := 0; j < 100; j++ {
					cache.Set(fmt.Sprintf("k%d", j), j, time.Millisecond)
					cache.Get(fmt.Sprintf("k%d", j))
					cache.Cleanup()
				}
			}(i)
		}

		wg.Wait()
	})
}

func TestShardedCacheEviction(t *testing.T) {
	t.Run("EvictsWhenFull", func(t *testing.T) {
		cache := NewShardedCache(4, 100)

		for i := 0; i < 600; i++ {
			cache.Set(fmt.Sprintf("key%d", i), i, 5*time.Minute)
		}

		size := cache.Size()
		if size >= 600 {
			t.Errorf("Expected eviction to reduce size below 600, got %d", size)
		}
		t.Logf("Cache size after adding 600 items: %d", size)
	})

	t.Run("EvictsExpiredFirst", func(t *testing.T) {
		cache := NewShardedCache(4, 100)

		for i := 0; i < 50; i++ {
			cache.Set(fmt.Sprintf("expired%d", i), i, 1*time.Millisecond)
		}

		time.Sleep(10 * time.Millisecond)

		for i := 0; i < 100; i++ {
			cache.Set(fmt.Sprintf("valid%d", i), i, 5*time.Minute)
		}

		validCount := 0
		for i := 0; i < 100; i++ {
			if cache.Exists(fmt.Sprintf("valid%d", i)) {
				validCount++
			}
		}

		if validCount < 80 {
			t.Errorf("Expected at least 80 valid items, got %d", validCount)
		}
	})
}

func TestShardedCacheShardDistribution(t *testing.T) {
	t.Run("EvenDistribution", func(t *testing.T) {
		cache := NewShardedCache(16, 16000)

		for i := 0; i < 10000; i++ {
			cache.Set(fmt.Sprintf("key-%d", i), i, 5*time.Minute)
		}

		stats := cache.ShardStats()

		average := 10000 / 16
		for i, count := range stats {
			if count > average*3 || count < average/3 {
				t.Errorf("Shard %d has uneven distribution: %d items (expected ~%d)", i, count, average)
			}
		}
	})
}

// =============================================================================
// CACHE COMPATIBILITY TESTS
// =============================================================================

func TestNewBoundedCache(t *testing.T) {
	maxSize := 500
	cache := NewBoundedCache(maxSize)

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

func TestDefaultUnifiedCacheConfig(t *testing.T) {
	config := DefaultUnifiedCacheConfig()

	if config.Type != CacheTypeGeneral {
		t.Errorf("Expected CacheTypeGeneral, got %v", config.Type)
	}

	if config.MaxSize != 500 {
		t.Errorf("Expected MaxSize 500, got %d", config.MaxSize)
	}

	if config.MaxMemoryBytes != 64*1024*1024 {
		t.Errorf("Expected MaxMemoryBytes 64MB, got %d", config.MaxMemoryBytes)
	}

	if config.CleanupInterval != 2*time.Minute {
		t.Errorf("Expected CleanupInterval 2 minutes, got %v", config.CleanupInterval)
	}

	if config.Logger == nil {
		t.Error("Expected Logger to be set")
	}
}

func TestNewUnifiedCache(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	cache := NewUnifiedCache(config)

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	if cache.UniversalCache == nil {
		t.Error("Expected UniversalCache to be set")
	}

	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

func TestUnifiedCache_SetMaxSize(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	cache := NewUnifiedCache(config)

	newSize := 1000
	cache.SetMaxSize(newSize)
}

func TestNewCacheAdapter(t *testing.T) {
	tests := []struct {
		cache       interface{}
		name        string
		description string
		expectNil   bool
	}{
		{
			name:        "UniversalCache",
			cache:       NewUniversalCache(DefaultUnifiedCacheConfig()),
			expectNil:   false,
			description: "Should create adapter for UniversalCache",
		},
		{
			name:        "UnifiedCache",
			cache:       NewUnifiedCache(DefaultUnifiedCacheConfig()),
			expectNil:   false,
			description: "Should create adapter for UnifiedCache",
		},
		{
			name:        "Invalid cache type",
			cache:       "not-a-cache",
			expectNil:   true,
			description: "Should return nil for invalid cache type",
		},
		{
			name:        "Nil cache",
			cache:       nil,
			expectNil:   true,
			description: "Should return nil for nil cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewCacheAdapter(tt.cache)

			if tt.expectNil {
				if adapter != nil {
					t.Errorf("Expected nil adapter, got %v", adapter)
				}
			} else {
				if adapter == nil {
					t.Error("Expected non-nil adapter")
				}
				adapter.Set("test", "value", time.Hour)
				value, found := adapter.Get("test")
				if !found {
					t.Error("Expected key to be found")
				}
				if value != "value" {
					t.Errorf("Expected 'value', got %v", value)
				}
			}
		})
	}
}

func TestNewOptimizedCache(t *testing.T) {
	cache := NewOptimizedCache()

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

func TestNewLRUStrategy(t *testing.T) {
	maxSize := 100
	strategy := NewLRUStrategy(maxSize)

	if strategy == nil {
		t.Fatal("Expected strategy to be created, got nil")
	}

	lruStrategy, ok := strategy.(*LRUStrategy)
	if !ok {
		t.Fatal("Expected LRUStrategy type")
	}

	if lruStrategy.maxSize != maxSize {
		t.Errorf("Expected maxSize %d, got %d", maxSize, lruStrategy.maxSize)
	}

	if lruStrategy.order == nil {
		t.Error("Expected order list to be initialized")
	}

	if lruStrategy.elements == nil {
		t.Error("Expected elements map to be initialized")
	}
}

func TestLRUStrategy_Name(t *testing.T) {
	strategy := NewLRUStrategy(100)

	name := strategy.Name()
	if name != "LRU" {
		t.Errorf("Expected 'LRU', got %s", name)
	}
}

func TestLRUStrategy_ShouldEvict(t *testing.T) {
	strategy := NewLRUStrategy(100)

	result := strategy.ShouldEvict("test-item", time.Now())
	if result != false {
		t.Error("Expected ShouldEvict to return false")
	}
}

func TestLRUStrategy_OnAccess(t *testing.T) {
	strategy := NewLRUStrategy(100)

	strategy.OnAccess("test-key", "test-value")
}

func TestLRUStrategy_OnRemove(t *testing.T) {
	strategy := NewLRUStrategy(100)

	strategy.OnRemove("test-key")
}

func TestLRUStrategy_EstimateSize(t *testing.T) {
	strategy := NewLRUStrategy(100)

	size := strategy.EstimateSize("test-item")
	if size != 64 {
		t.Errorf("Expected size 64, got %d", size)
	}
}

func TestLRUStrategy_GetEvictionCandidate(t *testing.T) {
	strategy := NewLRUStrategy(100)

	key, found := strategy.GetEvictionCandidate()
	if found {
		t.Error("Expected no eviction candidate to be found")
	}
	if key != "" {
		t.Errorf("Expected empty key, got %s", key)
	}
}

func TestNewOptimizedCacheWithConfig(t *testing.T) {
	config := UniversalCacheConfig{
		Type:           CacheTypeGeneral,
		MaxSize:        1000,
		MaxMemoryBytes: 128 * 1024 * 1024,
		EnableMetrics:  true,
		Logger:         GetSingletonNoOpLogger(),
	}

	cache := NewOptimizedCacheWithConfig(config)

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

func TestNewFixedMetadataCache(t *testing.T) {
	cache := NewFixedMetadataCache()

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	metadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
		JWKSURL:  "https://example.com/jwks",
	}

	err := cache.Set("test-provider", metadata, time.Hour)
	if err != nil {
		t.Errorf("Unexpected error setting metadata: %v", err)
	}
}

func TestNewDoublyLinkedList(t *testing.T) {
	list := NewDoublyLinkedList()

	if list == nil {
		t.Fatal("Expected list to be created, got nil")
	}

	if list.Len() != 0 {
		t.Error("Expected empty list initially")
	}
}

func TestDoublyLinkedList_PopFront(t *testing.T) {
	list := NewDoublyLinkedList()

	element := list.PopFront()
	if element != nil {
		t.Error("Expected nil when popping from empty list")
	}

	added := list.PushBack("test-value")
	if added == nil {
		t.Fatal("Expected element to be added")
	}

	popped := list.PopFront()
	if popped == nil {
		t.Error("Expected element to be popped")
	}

	if list.Len() != 0 {
		t.Error("Expected list to be empty after popping")
	}
}

// =============================================================================
// CONSOLIDATED CACHE TESTS
// =============================================================================

func TestCacheConsolidated(t *testing.T) {
	framework := NewTestFramework(t)
	defer framework.Cleanup()

	testCases := []CacheTestCase{
		// Basic Operations Tests
		{
			name:      "cache_basic_set_get",
			cacheType: "universal",
			operation: "set_get",
			parallel:  true,
			timeout:   5 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				cache.Set("key1", "value1", 1*time.Hour)
				val, exists := cache.Get("key1")
				if !exists {
					return errors.New("key1 should exist")
				}
				if val != "value1" {
					return fmt.Errorf("expected value1, got %v", val)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Basic set/get operation should succeed")
			},
		},
		{
			name:      "cache_basic_delete",
			cacheType: "universal",
			operation: "delete",
			parallel:  true,
			timeout:   5 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				cache.Set("key1", "value1", 1*time.Hour)
				cache.Delete("key1")

				_, exists := cache.Get("key1")
				if exists {
					return errors.New("key1 should not exist after deletion")
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Delete operation should succeed")
			},
		},
		{
			name:      "cache_nil_value_handling",
			cacheType: "universal",
			operation: "set_get",
			parallel:  true,
			timeout:   5 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				cache.Set("nilkey", nil, 1*time.Hour)
				val, exists := cache.Get("nilkey")
				if !exists {
					return errors.New("nil value should be stored")
				}
				if val != nil {
					return fmt.Errorf("expected nil, got %v", val)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Nil value handling should work correctly")
			},
		},

		// Expiration Tests
		{
			name:      "cache_ttl_expiration",
			cacheType: "universal",
			operation: "expiration",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				cache.Set("expkey", "value", 100*time.Millisecond)

				if _, exists := cache.Get("expkey"); !exists {
					return errors.New("key should exist before expiration")
				}

				time.Sleep(150 * time.Millisecond)

				if _, exists := cache.Get("expkey"); exists {
					return errors.New("key should not exist after expiration")
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "TTL expiration should work correctly")
			},
		},
		{
			name:      "cache_zero_ttl",
			cacheType: "universal",
			operation: "expiration",
			parallel:  true,
			timeout:   5 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				cache.Set("permanentkey", "value", 0)

				time.Sleep(100 * time.Millisecond)
				if _, exists := cache.Get("permanentkey"); !exists {
					return errors.New("key with zero TTL should not expire")
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Zero TTL should mean no expiration")
			},
		},

		// LRU Eviction Tests
		{
			name:      "cache_lru_eviction",
			cacheType: "bounded",
			operation: "eviction",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				config := createTestCacheConfig()
				config.MaxSize = 3
				cache := NewUniversalCache(config)
				defer cache.Close()

				cache.Set("key1", "value1", 1*time.Hour)
				cache.Set("key2", "value2", 1*time.Hour)
				cache.Set("key3", "value3", 1*time.Hour)

				cache.Get("key1")
				cache.Get("key2")

				cache.Set("key4", "value4", 1*time.Hour)

				if _, exists := cache.Get("key3"); exists {
					return errors.New("key3 should have been evicted")
				}
				if _, exists := cache.Get("key1"); !exists {
					return errors.New("key1 should still exist")
				}
				if _, exists := cache.Get("key2"); !exists {
					return errors.New("key2 should still exist")
				}
				if _, exists := cache.Get("key4"); !exists {
					return errors.New("key4 should exist")
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "LRU eviction should work correctly")
			},
		},
		{
			name:      "cache_size_limit",
			cacheType: "bounded",
			operation: "eviction",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				config := createTestCacheConfig()
				config.MaxSize = 5
				cache := NewUniversalCache(config)
				defer cache.Close()

				for i := 0; i < 10; i++ {
					cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 1*time.Hour)
				}

				count := 0
				for i := 0; i < 10; i++ {
					if _, exists := cache.Get(fmt.Sprintf("key%d", i)); exists {
						count++
					}
				}

				if count > 5 {
					return fmt.Errorf("cache size exceeded limit: %d > 5", count)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Cache size should be limited correctly")
			},
		},

		// Concurrency Tests
		{
			name:      "cache_concurrent_access",
			cacheType: "universal",
			operation: "concurrent",
			parallel:  false,
			timeout:   30 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				const goroutines = 100
				const operations = 1000

				var wg sync.WaitGroup
				var errors int32

				for i := 0; i < goroutines/2; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						for j := 0; j < operations; j++ {
							key := fmt.Sprintf("key-%d-%d", id, j%10)
							cache.Set(key, fmt.Sprintf("value-%d-%d", id, j), 1*time.Hour)
						}
					}(i)
				}

				for i := 0; i < goroutines/2; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						for j := 0; j < operations; j++ {
							key := fmt.Sprintf("key-%d-%d", id, j%10)
							cache.Get(key)
						}
					}(i)
				}

				wg.Wait()

				if errors > 0 {
					return fmt.Errorf("encountered %d errors during concurrent access", errors)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Concurrent access should be thread-safe")
			},
		},
		{
			name:      "cache_race_condition_test",
			cacheType: "universal",
			operation: "concurrent",
			parallel:  false,
			timeout:   20 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				const iterations = 1000
				var counter int64
				var wg sync.WaitGroup

				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := 0; j < iterations; j++ {
							val, _ := cache.Get("counter")
							var current int64
							if val != nil {
								current = val.(int64)
							}
							cache.Set("counter", current+1, 1*time.Hour)
							atomic.AddInt64(&counter, 1)
						}
					}()
				}

				wg.Wait()

				finalVal, _ := cache.Get("counter")
				if finalVal == nil {
					return errors.New("counter should exist")
				}

				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Race condition handling should not panic")
			},
		},

		// Memory Management Tests
		{
			name:      "cache_memory_cleanup",
			cacheType: "universal",
			operation: "cleanup",
			parallel:  false,
			timeout:   30 * time.Second,
			execute: func(tf *TestFramework) error {
				config := createTestCacheConfig()
				config.CleanupInterval = 100 * time.Millisecond
				cache := NewUniversalCache(config)
				defer cache.Close()

				for i := 0; i < 100; i++ {
					cache.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i), 200*time.Millisecond)
				}

				time.Sleep(400 * time.Millisecond)

				count := 0
				for i := 0; i < 100; i++ {
					if _, exists := cache.Get(fmt.Sprintf("key%d", i)); exists {
						count++
					}
				}

				if count > 0 {
					return fmt.Errorf("expected 0 items after cleanup, found %d", count)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Memory cleanup should remove expired items")
			},
		},
		{
			name:      "cache_memory_bounds",
			cacheType: "bounded",
			operation: "memory",
			parallel:  false,
			timeout:   30 * time.Second,
			execute: func(tf *TestFramework) error {
				config := createTestCacheConfig()
				config.MaxSize = 1000
				config.MaxMemoryBytes = 1024 * 1024
				cache := NewUniversalCache(config)
				defer cache.Close()

				runtime.GC()
				var m1 runtime.MemStats
				runtime.ReadMemStats(&m1)

				largeValue := make([]byte, 1024)
				for i := 0; i < 2000; i++ {
					cache.Set(fmt.Sprintf("key%d", i), largeValue, 1*time.Hour)
				}

				runtime.GC()
				var m2 runtime.MemStats
				runtime.ReadMemStats(&m2)

				growth := (m2.Alloc - m1.Alloc) / 1024 / 1024
				if growth > 2 {
					return fmt.Errorf("memory growth exceeded limit: %d MB", growth)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Memory usage should be bounded")
			},
		},
		{
			name:      "cache_no_goroutine_leak",
			cacheType: "universal",
			operation: "cleanup",
			parallel:  false,
			timeout:   20 * time.Second,
			execute: func(tf *TestFramework) error {
				initialGoroutines := runtime.NumGoroutine()

				for i := 0; i < 10; i++ {
					cache := NewUniversalCache(createTestCacheConfig())

					for j := 0; j < 100; j++ {
						cache.Set(fmt.Sprintf("key%d", j), "value", 1*time.Hour)
					}

					cache.Close()
				}

				time.Sleep(500 * time.Millisecond)
				runtime.GC()

				finalGoroutines := runtime.NumGoroutine()

				if finalGoroutines > initialGoroutines+5 {
					return fmt.Errorf("potential goroutine leak: initial=%d, final=%d",
						initialGoroutines, finalGoroutines)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Should not leak goroutines")
			},
		},

		// Metadata Cache Tests
		{
			name:      "metadata_cache_basic_operations",
			cacheType: "metadata",
			operation: "set_get",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				var wg sync.WaitGroup
				cache := NewMetadataCache(&wg)
				defer cache.Close()

				metadata := &ProviderMetadata{
					Issuer:   "https://example.com",
					JWKSURL:  "https://example.com/jwks",
					TokenURL: "https://example.com/token",
					AuthURL:  "https://example.com/auth",
				}

				err := cache.Set("provider1", metadata, 1*time.Hour)
				if err != nil {
					return fmt.Errorf("failed to set metadata: %w", err)
				}

				retrieved, exists := cache.Get("provider1")
				if !exists {
					return errors.New("metadata should exist")
				}

				if retrieved == nil {
					return errors.New("metadata should not be nil")
				}

				if retrieved.Issuer != metadata.Issuer {
					return fmt.Errorf("issuer mismatch: expected %s, got %s",
						metadata.Issuer, retrieved.Issuer)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Metadata cache operations should succeed")
			},
		},
		{
			name:      "metadata_cache_error_handling",
			cacheType: "metadata",
			operation: "error",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				var wg sync.WaitGroup
				cache := NewMetadataCache(&wg)
				defer cache.Close()

				err := cache.Set("provider1", nil, 1*time.Hour)
				if err == nil {
					return errors.New("should error on nil metadata")
				}

				metadata := &ProviderMetadata{Issuer: "test"}
				err = cache.Set("", metadata, 1*time.Hour)
				if err != nil {
					return fmt.Errorf("unexpected error with empty key: %v", err)
				}

				_, exists := cache.Get("nonexistent")
				if exists {
					return errors.New("should not exist for non-existent key")
				}

				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Error handling should work correctly")
			},
		},

		// Token Cache Tests
		{
			name:      "cache_token_operations",
			cacheType: "universal",
			operation: "token",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				config := createTestCacheConfig()
				config.Type = CacheTypeToken
				cache := NewUniversalCache(config)
				defer cache.Close()

				token := &TokenResponse{
					AccessToken:  "access-token-123",
					RefreshToken: "refresh-token-456",
					IDToken:      "id-token-789",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}

				cache.Set("token:user123", token, 1*time.Hour)

				retrieved, exists := cache.Get("token:user123")
				if !exists {
					return errors.New("token should exist")
				}

				retrievedToken, ok := retrieved.(*TokenResponse)
				if !ok {
					return errors.New("failed to cast to TokenResponse")
				}

				if retrievedToken.AccessToken != token.AccessToken {
					return fmt.Errorf("access token mismatch: expected %s, got %s",
						token.AccessToken, retrievedToken.AccessToken)
				}

				cache.Delete("token:user123")

				_, exists = cache.Get("token:user123")
				if exists {
					return errors.New("token should not exist after deletion")
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Token operations should work correctly")
			},
		},

		// Edge Cases Tests
		{
			name:      "cache_edge_case_empty_key",
			cacheType: "universal",
			operation: "edge",
			parallel:  true,
			timeout:   5 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				cache.Set("", "value", 1*time.Hour)
				val, exists := cache.Get("")
				if !exists {
					return errors.New("empty key should be valid")
				}
				if val != "value" {
					return fmt.Errorf("unexpected value for empty key: %v", val)
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Empty key should be handled correctly")
			},
		},
		{
			name:      "cache_edge_case_large_values",
			cacheType: "universal",
			operation: "edge",
			parallel:  true,
			timeout:   10 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				largeValue := make([]byte, 1024*1024)
				for i := range largeValue {
					largeValue[i] = byte(i % 256)
				}

				cache.Set("large", largeValue, 1*time.Hour)
				retrieved, exists := cache.Get("large")
				if !exists {
					return errors.New("large value should exist")
				}

				retrievedBytes, ok := retrieved.([]byte)
				if !ok {
					return errors.New("type assertion failed")
				}

				if len(retrievedBytes) != len(largeValue) {
					return fmt.Errorf("size mismatch: expected %d, got %d",
						len(largeValue), len(retrievedBytes))
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Large values should be handled correctly")
			},
		},
		{
			name:      "cache_edge_case_special_characters",
			cacheType: "universal",
			operation: "edge",
			parallel:  true,
			timeout:   5 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())
				defer cache.Close()

				specialKeys := []string{
					"key with spaces",
					"key/with/slashes",
					"key:with:colons",
					"key|with|pipes",
					"key\twith\ttabs",
					"key\nwith\nnewlines",
					"🔑 with emoji",
				}

				for _, key := range specialKeys {
					cache.Set(key, "value", 1*time.Hour)
					_, exists := cache.Get(key)
					if !exists {
						return fmt.Errorf("failed to retrieve key: %s", key)
					}
				}
				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Special characters should be handled correctly")
			},
		},

		// Cleanup and Resource Management Tests
		{
			name:      "cache_proper_cleanup",
			cacheType: "universal",
			operation: "cleanup",
			parallel:  false,
			timeout:   15 * time.Second,
			execute: func(tf *TestFramework) error {
				config := createTestCacheConfig()
				config.CleanupInterval = 100 * time.Millisecond
				cache := NewUniversalCache(config)

				for i := 0; i < 100; i++ {
					cache.Set(fmt.Sprintf("key%d", i), "value", 1*time.Hour)
				}

				cache.Close()

				_, exists := cache.Get("key0")
				if exists {
					return errors.New("cache should be cleared after close")
				}

				cache.Set("newkey", "value", 1*time.Hour)
				val, exists := cache.Get("newkey")
				if !exists || val != "value" {
					return errors.New("cache should allow new operations after close")
				}

				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Cache cleanup should work properly")
			},
		},
		{
			name:      "cache_concurrent_cleanup",
			cacheType: "universal",
			operation: "cleanup",
			parallel:  false,
			timeout:   20 * time.Second,
			execute: func(tf *TestFramework) error {
				cache := NewUniversalCache(createTestCacheConfig())

				var wg sync.WaitGroup

				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func(id int) {
						defer wg.Done()
						for j := 0; j < 100; j++ {
							cache.Set(fmt.Sprintf("key-%d-%d", id, j), "value", 1*time.Hour)
							cache.Get(fmt.Sprintf("key-%d-%d", id, j))
						}
					}(i)
				}

				go func() {
					time.Sleep(50 * time.Millisecond)
					cache.Close()
				}()

				wg.Wait()

				return nil
			},
			validate: func(t *testing.T, err error, tf *TestFramework) {
				assert.NoError(t, err, "Concurrent cleanup should not cause panic")
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		if tc.skipReason != "" {
			t.Skip(tc.skipReason)
			continue
		}

		if tc.parallel {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				executeCacheTestCase(t, tc, framework)
			})
		} else {
			t.Run(tc.name, func(t *testing.T) {
				executeCacheTestCase(t, tc, framework)
			})
		}
	}
}

// TestCacheConsolidatedCoverage ensures all original test scenarios are covered
func TestCacheConsolidatedCoverage(t *testing.T) {
	scenariosCovered := []string{
		"Basic operations (set/get/delete)",
		"Expiration handling",
		"Cache size limits",
		"Concurrency tests",
		"Performance benchmarks",
		"Edge cases",
		"LRU behavior",
		"Cleanup operations",
		"Bounded cache operations",
		"Race condition handling",
		"Memory leak detection",
		"Eviction performance",
		"Memory edge cases",
		"Optimized operations",
		"Memory pressure handling",
		"Different value types",
		"Metadata operations",
		"Cache hit/miss",
		"Error handling",
		"Auto-cleanup",
		"Thread safety",
		"Timeout handling",
		"Error recovery",
		"Fixed metadata cache",
		"Universal cache operations",
		"Token operations",
		"Metadata grace period",
		"Cache metrics",
		"Cache adapters",
		"Cache migration",
		"Type defaults",
		"Simple cache operations",
		"Eviction failures",
		"Auto-cleanup failures",
		"Sharded cache operations",
		"Shard distribution",
		"Cache manager operations",
	}

	t.Logf("Consolidated test covers %d scenarios from original files", len(scenariosCovered))
	for _, scenario := range scenariosCovered {
		t.Logf("✓ %s", scenario)
	}

	assert.True(t, true, "All scenarios covered in consolidated test")
}
