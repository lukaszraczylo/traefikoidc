package traefikoidc

import (
	"testing"
	"time"
)

func TestCache_Cleanup(t *testing.T) {
	c := NewCache()

	// Add some items with different expiration times
	now := time.Now()
	pastTime := now.Add(-1 * time.Hour)  // Already expired
	futureTime := now.Add(1 * time.Hour) // Not expired

	// Create test items
	c.items["expired"] = CacheItem{
		Value:     "expired-value",
		ExpiresAt: pastTime,
	}

	c.items["valid"] = CacheItem{
		Value:     "valid-value",
		ExpiresAt: futureTime,
	}

	// Store original elements in the order list to match items
	c.elems["expired"] = c.order.PushBack(lruEntry{key: "expired"})
	c.elems["valid"] = c.order.PushBack(lruEntry{key: "valid"})

	// Call cleanup, which should only remove expired items
	c.Cleanup()

	// Check that only the expired item was removed
	if _, exists := c.items["expired"]; exists {
		t.Error("Expired item was not removed by Cleanup()")
	}

	if _, exists := c.items["valid"]; !exists {
		t.Error("Valid item was incorrectly removed by Cleanup()")
	}
}

func TestCache_SetMaxSize(t *testing.T) {
	c := NewCache()

	// Set a lower max size
	originalMaxSize := c.maxSize
	newMaxSize := 3

	// Add more items than the new max size
	for i := range originalMaxSize {
		key := "key" + string(rune('A'+i))
		c.Set(key, i, 1*time.Hour)
	}

	// Verify items were added
	if len(c.items) != originalMaxSize {
		t.Errorf("Expected %d items before SetMaxSize, got %d", originalMaxSize, len(c.items))
	}

	// Change the max size to a smaller value
	c.SetMaxSize(newMaxSize)

	// Check that the cache was reduced to the new max size
	if len(c.items) > newMaxSize {
		t.Errorf("Cache size %d exceeds new max size %d after SetMaxSize", len(c.items), newMaxSize)
	}

	if c.maxSize != newMaxSize {
		t.Errorf("Cache maxSize not updated, expected %d, got %d", newMaxSize, c.maxSize)
	}

	// Check that the oldest items were evicted (should keep "keyC", "keyD", "keyE", etc.)
	if _, exists := c.items["keyA"]; exists {
		t.Error("Expected oldest item 'keyA' to be evicted, but it still exists")
	}
}

func TestJWKCache_WithInternalCache(t *testing.T) {
	cache := NewJWKCache()

	// Check that the internal cache is properly initialized
	if cache.internalCache == nil {
		t.Error("internalCache field was not initialized")
	}

	// Test max size configuration
	testSize := 50
	cache.SetMaxSize(testSize)

	if cache.maxSize != testSize {
		t.Errorf("JWKCache maxSize not updated, expected %d, got %d", testSize, cache.maxSize)
	}

	if cache.internalCache.maxSize != testSize {
		t.Errorf("internalCache maxSize not updated, expected %d, got %d", testSize, cache.internalCache.maxSize)
	}
}
