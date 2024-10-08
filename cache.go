package traefikoidc

import (
	"sync"
	"time"
)

// CacheItem represents an item in the cache
type CacheItem struct {
	Value     interface{}
	ExpiresAt time.Time
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
	defer c.mutex.Unlock()
	c.items[key] = CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(expiration),
	}
}

// Get retrieves an item from the cache
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

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.items, key)
}

// Cleanup removes expired items from the cache
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
