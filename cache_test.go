package traefikoidc

import (
	"testing"
	"time"
)

func TestCache_Cleanup(t *testing.T) {
	c := NewCache()
	defer c.Close() // Stop the auto-cleanup goroutine

	// Add some items with different expiration times
	now := time.Now()
	pastTime := now.Add(-1 * time.Hour)  // Already expired
	futureTime := now.Add(1 * time.Hour) // Not expired

	// Use the Set method to properly add items with synchronization
	c.Set("expired", "expired-value", pastTime.Sub(now))
	c.Set("valid", "valid-value", futureTime.Sub(now))

	// Call cleanup, which should only remove expired items
	c.Cleanup()

	// Check that only the expired item was removed
	if _, exists := c.Get("expired"); exists {
		t.Error("Expired item was not removed by Cleanup()")
	}

	if _, exists := c.Get("valid"); !exists {
		t.Error("Valid item was incorrectly removed by Cleanup()")
	}
}

func TestCache_SetMaxSize(t *testing.T) {
	c := NewCache()
	defer c.Close() // Stop the auto-cleanup goroutine

	// Set a lower max size
	originalMaxSize := 10
	newMaxSize := 3

	// Add more items than the new max size
	for i := 0; i < originalMaxSize; i++ {
		key := "key" + string(rune('A'+i))
		c.Set(key, i, 1*time.Hour)
	}

	// Verify items were added by checking a few keys
	for i := 0; i < originalMaxSize; i++ {
		key := "key" + string(rune('A'+i))
		if _, exists := c.Get(key); !exists {
			t.Errorf("Expected key %s to exist before SetMaxSize", key)
		}
	}

	// Change the max size to a smaller value
	c.SetMaxSize(newMaxSize)

	// Count remaining items
	count := 0
	for i := 0; i < originalMaxSize; i++ {
		key := "key" + string(rune('A'+i))
		if _, exists := c.Get(key); exists {
			count++
		}
	}

	// Check that the cache was reduced to the new max size
	if count > newMaxSize {
		t.Errorf("Cache size %d exceeds new max size %d after SetMaxSize", count, newMaxSize)
	}

	// Check that the oldest items were evicted (keyA should be evicted)
	if _, exists := c.Get("keyA"); exists {
		t.Error("Expected oldest item 'keyA' to be evicted, but it still exists")
	}
}
