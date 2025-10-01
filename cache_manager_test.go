package traefikoidc

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

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

// TestCacheManager_Close tests cache manager close functionality
func TestCacheManager_Close(t *testing.T) {
	// Get a fresh cache manager
	wg := &sync.WaitGroup{}
	cm := GetGlobalCacheManager(wg)

	if cm == nil {
		t.Fatal("Expected cache manager to be created")
	}

	// Test closing the cache manager
	err := cm.Close()
	if err != nil {
		t.Errorf("Unexpected error closing cache manager: %v", err)
	}
}

// TestCleanupGlobalCacheManager tests global cleanup
func TestCleanupGlobalCacheManager(t *testing.T) {
	// Test cleanup when no instance exists (should not error)
	originalInstance := globalCacheManagerInstance
	globalCacheManagerInstance = nil
	err := CleanupGlobalCacheManager()
	if err != nil {
		t.Errorf("Unexpected error during cleanup of nil instance: %v", err)
	}

	// Restore original instance
	globalCacheManagerInstance = originalInstance
}

// TestCacheInterfaceWrapper_Delete tests delete functionality
func TestCacheInterfaceWrapper_Delete(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Add an item
	cache.Set("test-key", "test-value", time.Hour)

	// Verify it exists
	value, found := cache.Get("test-key")
	if !found {
		t.Fatal("Expected key to be found after setting")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}

	// Delete it
	cache.Delete("test-key")

	// Verify it's gone
	_, found = cache.Get("test-key")
	if found {
		t.Error("Expected key to be deleted")
	}
}

// TestCacheInterfaceWrapper_Size tests size functionality
func TestCacheInterfaceWrapper_Size(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Clear cache first
	cache.Clear()

	// Check initial size
	initialSize := cache.Size()
	if initialSize != 0 {
		t.Errorf("Expected initial size 0, got %d", initialSize)
	}

	// Add some items
	cache.Set("key1", "value1", time.Hour)
	cache.Set("key2", "value2", time.Hour)

	// Check size increased
	newSize := cache.Size()
	if newSize != 2 {
		t.Errorf("Expected size 2, got %d", newSize)
	}
}

// TestCacheInterfaceWrapper_Clear tests clear functionality
func TestCacheInterfaceWrapper_Clear(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Add some items
	cache.Set("key1", "value1", time.Hour)
	cache.Set("key2", "value2", time.Hour)

	// Verify items exist
	size := cache.Size()
	if size != 2 {
		t.Errorf("Expected 2 items before clear, got %d", size)
	}

	// Clear all
	cache.Clear()

	// Verify cache is empty
	size = cache.Size()
	if size != 0 {
		t.Errorf("Expected 0 items after clear, got %d", size)
	}

	// Verify specific items are gone
	_, found := cache.Get("key1")
	if found {
		t.Error("Expected key1 to be cleared")
	}

	_, found = cache.Get("key2")
	if found {
		t.Error("Expected key2 to be cleared")
	}
}

// TestCacheInterfaceWrapper_Close tests wrapper close functionality
func TestCacheInterfaceWrapper_Close(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Test close - should not panic
	wrapper, ok := cache.(*CacheInterfaceWrapper)
	if !ok {
		t.Fatal("Expected CacheInterfaceWrapper")
	}

	wrapper.Close() // Should not panic

	// Test close with nil cache
	nilWrapper := &CacheInterfaceWrapper{cache: nil}
	nilWrapper.Close() // Should not panic
}

// TestCacheInterfaceWrapper_GetStats tests stats functionality
func TestCacheInterfaceWrapper_GetStats(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	wrapper, ok := cache.(*CacheInterfaceWrapper)
	if !ok {
		t.Fatal("Expected CacheInterfaceWrapper")
	}

	// Get stats
	stats := wrapper.GetStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}

	// Stats should be accessible (len() never returns negative values)
	// Just verify it's accessible by checking it's not nil (already done above)
}

// TestCacheInterfaceWrapper_Cleanup tests cleanup functionality
func TestCacheInterfaceWrapper_Cleanup(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Add an item that will expire quickly
	cache.Set("expire-key", "expire-value", time.Millisecond)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Trigger cleanup
	cache.Cleanup()

	// Item should be cleaned up
	_, found := cache.Get("expire-key")
	if found {
		t.Error("Expected expired key to be cleaned up")
	}
}

// TestCacheInterfaceWrapper_SetMaxSize tests max size setting
func TestCacheInterfaceWrapper_SetMaxSize(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Test setting max size (should not panic)
	cache.SetMaxSize(1000)

	// We can't easily verify the size was set without exposing internals,
	// but we can ensure the method doesn't panic
}

// TestGetSharedCaches tests getting shared cache instances
func TestGetSharedCaches(t *testing.T) {
	cm := getTestCacheManager(t)

	// Test getting shared token blacklist
	blacklist := cm.GetSharedTokenBlacklist()
	if blacklist == nil {
		t.Error("Expected non-nil token blacklist")
	}

	// Test getting shared token cache
	tokenCache := cm.GetSharedTokenCache()
	if tokenCache == nil {
		t.Error("Expected non-nil token cache")
	}

	// Test getting shared metadata cache
	metadataCache := cm.GetSharedMetadataCache()
	if metadataCache == nil {
		t.Error("Expected non-nil metadata cache")
	}

	// Test getting shared JWK cache
	jwkCache := cm.GetSharedJWKCache()
	if jwkCache == nil {
		t.Error("Expected non-nil JWK cache")
	}
}

// TestConcurrentCacheAccess tests thread safety
func TestConcurrentCacheAccess(t *testing.T) {
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	var wg sync.WaitGroup
	goroutines := 10
	iterations := 10

	// Concurrent operations
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

// Benchmark tests for performance
func BenchmarkCacheInterfaceWrapper_Set(b *testing.B) {
	t := &testing.T{}
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set("benchmark-key", "benchmark-value", time.Hour)
	}
}

func BenchmarkCacheInterfaceWrapper_Get(b *testing.B) {
	t := &testing.T{}
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	// Pre-populate cache
	cache.Set("benchmark-key", "benchmark-value", time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("benchmark-key")
	}
}

func BenchmarkCacheInterfaceWrapper_Delete(b *testing.B) {
	t := &testing.T{}
	cm := getTestCacheManager(t)
	cache := cm.GetSharedTokenBlacklist()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		key := fmt.Sprintf("benchmark-key-%d", i)
		cache.Set(key, "value", time.Hour)
		b.StartTimer()

		cache.Delete(key)
	}
}
