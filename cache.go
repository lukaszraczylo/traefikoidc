package traefikoidc

import (
	"sync"
	"time"
)

// CacheItem represents an item in the cache
type CacheItem struct {
	Value     interface{}
	ExpiresAt int64 // Changed to int64 for faster comparisons
}

// Cache is a simple in-memory cache
type Cache struct {
	items map[string]CacheItem
	mutex sync.RWMutex
}

// NewCache creates a new Cache
func NewCache() *Cache {
	return &Cache{
		items: make(map[string]CacheItem),
	}
}

// Set adds an item to the cache
func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	c.mutex.Lock()
	// Removed defer for slightly better performance
	c.items[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(expiration).UnixNano(), // Store as UnixNano for faster comparisons
	}
	c.mutex.Unlock()
}

// Get retrieves an item from the cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	item, found := c.items[key]
	if !found {
		c.mutex.RUnlock()
		return nil, false
	}
	if time.Now().UnixNano() > item.ExpiresAt {
		c.mutex.RUnlock()
		// Use a separate goroutine to delete expired items to avoid blocking
		go c.Delete(key)
		return nil, false
	}
	c.mutex.RUnlock()
	return item.Value, true
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	delete(c.items, key)
	c.mutex.Unlock()
}

// Cleanup removes expired items from the cache
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	now := time.Now().UnixNano()
	for key, item := range c.items {
		if now > item.ExpiresAt {
			delete(c.items, key)
		}
	}
	c.mutex.Unlock()
}
