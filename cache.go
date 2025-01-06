package traefikoidc

import (
	"sync"
	"time"
)

// CacheItem represents an item stored in the cache with its associated metadata.
type CacheItem struct {
	// Value is the cached data of any type
	Value interface{}

	// ExpiresAt is the timestamp when this item should be considered expired
	// and removed from the cache during cleanup operations
	ExpiresAt time.Time
}

// Cache provides a thread-safe in-memory caching mechanism with expiration support.
// It uses a read-write mutex to ensure safe concurrent access to the cached items.
type Cache struct {
	// items stores the cached data with string keys
	items map[string]CacheItem

	// mutex protects concurrent access to the items map
	// Use RLock/RUnlock for reads and Lock/Unlock for writes
	mutex sync.RWMutex
}

// NewCache creates a new empty cache instance.
// The cache is immediately ready for use and is thread-safe.
func NewCache() *Cache {
	return &Cache{
		items: make(map[string]CacheItem),
	}
}

// Set adds or updates an item in the cache with the specified expiration duration.
// Parameters:
//   - key: Unique identifier for the cached item
//   - value: The data to cache (can be of any type)
//   - expiration: How long the item should remain in the cache
// Thread-safe: Uses write locking to ensure safe concurrent access.
func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.items[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(expiration),
	}
}

// Get retrieves an item from the cache if it exists and hasn't expired.
// Parameters:
//   - key: The identifier of the item to retrieve
// Returns:
//   - value: The cached data (nil if not found or expired)
//   - found: true if the item was found and is valid, false otherwise
// Thread-safe: Uses read locking to ensure safe concurrent access.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	item, found := c.items[key]
	if !found {
		return nil, false
	}
	if time.Now().After(item.ExpiresAt) {
		delete(c.items, key)
		return nil, false
	}
	return item.Value, true
}

// Delete removes an item from the cache if it exists.
// If the item doesn't exist, this operation is a no-op.
// Thread-safe: Uses write locking to ensure safe concurrent access.
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.items, key)
}

// Cleanup removes all expired items from the cache.
// This should be called periodically to prevent memory leaks from
// expired items that haven't been accessed (and thus not removed during Get operations).
// Thread-safe: Uses write locking to ensure safe concurrent access.
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := time.Now()
	for key, item := range c.items {
		if now.After(item.ExpiresAt) {
			delete(c.items, key)
		}
	}
}
