package traefikoidc

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestOptimizedCacheBasicOperations tests basic cache operations
func TestOptimizedCacheBasicOperations(t *testing.T) {
	cache := NewOptimizedCache()

	// Test Set and Get
	cache.Set("key1", "value1", 10*time.Minute)

	value, found := cache.Get("key1")
	if !found {
		t.Error("Expected to find key1")
	}
	if value != "value1" {
		t.Errorf("Expected 'value1', got '%v'", value)
	}

	// Test Get non-existent key
	_, found = cache.Get("nonexistent")
	if found {
		t.Error("Expected not to find nonexistent key")
	}

	// Test Delete
	cache.Delete("key1")
	_, found = cache.Get("key1")
	if found {
		t.Error("Expected key1 to be deleted")
	}
}

// TestOptimizedCacheExpiration tests cache entry expiration
func TestOptimizedCacheExpiration(t *testing.T) {
	cache := NewOptimizedCache()

	// Test immediate expiration
	cache.Set("expired_key", "value", 1*time.Millisecond)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	_, found := cache.Get("expired_key")
	if found {
		t.Error("Expected expired key not to be found")
	}

	// Test non-expiring entry (expiration = 0)
	cache.Set("permanent_key", "permanent_value", 0)

	value, found := cache.Get("permanent_key")
	if !found {
		t.Error("Expected permanent key to be found")
	}
	if value != "permanent_value" {
		t.Errorf("Expected 'permanent_value', got '%v'", value)
	}
}

// TestOptimizedCacheLRUEviction tests LRU eviction behavior
func TestOptimizedCacheLRUEviction(t *testing.T) {
	// Create small cache to trigger eviction
	logger := newNoOpLogger()
	cache := NewOptimizedCacheWithConfig(3, 1, logger) // Max 3 items

	// Fill cache to capacity
	cache.Set("key1", "value1", 10*time.Minute)
	cache.Set("key2", "value2", 10*time.Minute)
	cache.Set("key3", "value3", 10*time.Minute)

	// Access key1 to make it most recently used
	cache.Get("key1")

	// Add another item, should evict key2 (least recently used)
	cache.Set("key4", "value4", 10*time.Minute)

	// key2 should be evicted
	_, found := cache.Get("key2")
	if found {
		t.Error("Expected key2 to be evicted")
	}

	// key1 should still exist (was recently accessed)
	_, found = cache.Get("key1")
	if !found {
		t.Error("Expected key1 to still exist")
	}

	// key3 and key4 should exist
	_, found = cache.Get("key3")
	if !found {
		t.Error("Expected key3 to still exist")
	}
	_, found = cache.Get("key4")
	if !found {
		t.Error("Expected key4 to exist")
	}
}

// TestOptimizedCacheMemoryPressure tests memory-based eviction
func TestOptimizedCacheMemoryPressure(t *testing.T) {
	logger := newNoOpLogger()
	cache := NewOptimizedCacheWithConfig(1000, 1, logger) // 1 MB memory limit

	// Create large values to trigger memory pressure
	largeValue := strings.Repeat("a", 256*1024) // 256KB each

	// Add several large values
	cache.Set("large1", largeValue, 10*time.Minute)
	cache.Set("large2", largeValue, 10*time.Minute)
	cache.Set("large3", largeValue, 10*time.Minute)
	cache.Set("large4", largeValue, 10*time.Minute)
	cache.Set("large5", largeValue, 10*time.Minute) // This should trigger eviction

	// Force garbage collection to get accurate memory reading
	runtime.GC()

	// Check that some entries were evicted due to memory pressure
	count := 0
	for i := 1; i <= 5; i++ {
		if _, found := cache.Get(formatString("large%d", i)); found {
			count++
		}
	}

	// Should have fewer than 5 items due to memory pressure eviction
	if count >= 5 {
		t.Errorf("Expected some items to be evicted due to memory pressure, but found %d items", count)
	}
}

// TestOptimizedCacheCleanup tests manual cleanup functionality
func TestOptimizedCacheCleanup(t *testing.T) {
	cache := NewOptimizedCache()

	// Add expired and non-expired items
	cache.Set("expired1", "value1", 1*time.Millisecond)
	cache.Set("expired2", "value2", 1*time.Millisecond)
	cache.Set("valid", "value", 10*time.Minute)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Manual cleanup should remove expired items
	cache.Cleanup()

	// Expired items should be gone
	_, found := cache.Get("expired1")
	if found {
		t.Error("Expected expired1 to be cleaned up")
	}
	_, found = cache.Get("expired2")
	if found {
		t.Error("Expected expired2 to be cleaned up")
	}

	// Valid item should remain
	_, found = cache.Get("valid")
	if !found {
		t.Error("Expected valid item to remain after cleanup")
	}
}

// TestOptimizedCacheConcurrency tests thread safety
func TestOptimizedCacheConcurrency(t *testing.T) {
	cache := NewOptimizedCache()
	var wg sync.WaitGroup

	// Number of goroutines for each operation type
	numGoroutines := 10
	numOperations := 100

	// Test concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := formatString("write_%d_%d", id, j)
				cache.Set(key, formatString("value_%d_%d", id, j), 10*time.Minute)
			}
		}(i)
	}

	// Test concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := formatString("write_%d_%d", id, j)
				cache.Get(key) // Don't care about result, just testing concurrency
			}
		}(i)
	}

	// Test concurrent deletes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := formatString("delete_%d_%d", id, j)
				cache.Set(key, "value", 10*time.Minute)
				cache.Delete(key)
			}
		}(i)
	}

	// Test concurrent cleanup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			cache.Cleanup()
			time.Sleep(1 * time.Millisecond)
		}
	}()

	wg.Wait()

	// If we reach here without deadlock or panic, concurrency test passed
	t.Log("Concurrency test completed successfully")
}

// TestOptimizedCacheEdgeCases tests edge cases and error conditions
func TestOptimizedCacheEdgeCases(t *testing.T) {
	cache := NewOptimizedCache()

	// Test empty key
	cache.Set("", "empty_key_value", 10*time.Minute)
	value, found := cache.Get("")
	if !found || value != "empty_key_value" {
		t.Error("Expected to handle empty key correctly")
	}

	// Test nil value
	cache.Set("nil_key", nil, 10*time.Minute)
	value, found = cache.Get("nil_key")
	if !found || value != nil {
		t.Error("Expected to handle nil value correctly")
	}

	// Test overwriting existing key
	cache.Set("overwrite", "original", 10*time.Minute)
	cache.Set("overwrite", "new_value", 10*time.Minute)
	value, found = cache.Get("overwrite")
	if !found || value != "new_value" {
		t.Error("Expected key to be overwritten with new value")
	}

	// Test delete non-existent key (should not panic)
	cache.Delete("nonexistent")

	// Test very long key
	longKey := strings.Repeat("a", 1000)
	cache.Set(longKey, "long_key_value", 10*time.Minute)
	value, found = cache.Get(longKey)
	if !found || value != "long_key_value" {
		t.Error("Expected to handle very long key correctly")
	}
}

// TestOptimizedCacheWithDifferentValueTypes tests cache with various value types
func TestOptimizedCacheWithDifferentValueTypes(t *testing.T) {
	cache := NewOptimizedCache()

	// Test string value
	cache.Set("string", "test_string", 10*time.Minute)

	// Test int value
	cache.Set("int", 42, 10*time.Minute)

	// Test slice value
	cache.Set("slice", []string{"a", "b", "c"}, 10*time.Minute)

	// Test map value
	cache.Set("map", map[string]int{"key1": 1, "key2": 2}, 10*time.Minute)

	// Test struct value
	type TestStruct struct {
		Name string
		Age  int
	}
	cache.Set("struct", TestStruct{Name: "John", Age: 30}, 10*time.Minute)

	// Verify all types can be retrieved correctly
	if val, found := cache.Get("string"); !found || val != "test_string" {
		t.Error("Failed to retrieve string value")
	}

	if val, found := cache.Get("int"); !found || val != 42 {
		t.Error("Failed to retrieve int value")
	}

	if val, found := cache.Get("slice"); !found {
		t.Error("Failed to retrieve slice value")
	} else if slice, ok := val.([]string); !ok || len(slice) != 3 || slice[0] != "a" {
		t.Error("Retrieved slice value is incorrect")
	}

	if val, found := cache.Get("map"); !found {
		t.Error("Failed to retrieve map value")
	} else if mapVal, ok := val.(map[string]int); !ok || mapVal["key1"] != 1 {
		t.Error("Retrieved map value is incorrect")
	}

	if val, found := cache.Get("struct"); !found {
		t.Error("Failed to retrieve struct value")
	} else if structVal, ok := val.(TestStruct); !ok || structVal.Name != "John" || structVal.Age != 30 {
		t.Error("Retrieved struct value is incorrect")
	}
}

// Helper to create a formatted string key
func formatString(format string, args ...interface{}) string {
	// Simple sprintf implementation for tests
	result := format
	for _, arg := range args {
		if strings.Contains(result, "%d") {
			if intVal, ok := arg.(int); ok {
				result = strings.Replace(result, "%d", intToString(intVal), 1)
			}
		} else if strings.Contains(result, "%s") {
			if strVal, ok := arg.(string); ok {
				result = strings.Replace(result, "%s", strVal, 1)
			}
		}
	}
	return result
}

// Helper to convert int to string
func intToString(i int) string {
	if i == 0 {
		return "0"
	}

	negative := i < 0
	if negative {
		i = -i
	}

	var result []byte
	for i > 0 {
		result = append([]byte{byte('0' + (i % 10))}, result...)
		i /= 10
	}

	if negative {
		result = append([]byte{'-'}, result...)
	}

	return string(result)
}
