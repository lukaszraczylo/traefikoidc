package traefikoidc

import (
	"container/list"
	"sync"
	"time"
)

// CacheItem represents an item stored in the cache with its associated metadata.
type CacheItem struct {
	// Value is the cached data of any type.
	Value interface{}

	// ExpiresAt is the timestamp when this item should be considered expired.
	ExpiresAt time.Time
}

// lruEntry represents an entry in the LRU list.
type lruEntry struct {
	key string
}

// Cache provides a thread-safe in-memory caching mechanism with expiration support.
// It implements an LRU (Least Recently Used) eviction policy using a doubly-linked list for efficiency.
type Cache struct {
	// items stores the cached data with string keys.
	items map[string]CacheItem

	// order maintains the usage order; most recently used items are at the back.
	order *list.List

	// elems maps keys to their corresponding list elements for O(1) access.
	elems map[string]*list.Element

	// mutex protects concurrent access to the cache.
	mutex sync.RWMutex

	// maxSize is the maximum number of items allowed in the cache.
	maxSize int
}

// DefaultMaxSize is the default maximum number of items in the cache.
const DefaultMaxSize = 1000

// NewCache creates a new empty cache instance that is ready for use.
func NewCache() *Cache {
	return &Cache{
		items:   make(map[string]CacheItem, DefaultMaxSize),
		order:   list.New(),
		elems:   make(map[string]*list.Element, DefaultMaxSize),
		maxSize: DefaultMaxSize,
	}
}

// Set adds or updates an item in the cache with the specified expiration duration.
// It moves the item to the most recently used position.
func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	expTime := now.Add(expiration)

	// Update existing item.
	if _, exists := c.items[key]; exists {
		c.items[key] = CacheItem{
			Value:     value,
			ExpiresAt: expTime,
		}
		if elem, ok := c.elems[key]; ok {
			c.order.MoveToBack(elem)
		}
		return
	}

	// Evict oldest item if cache is full.
	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	// Add new item.
	c.items[key] = CacheItem{
		Value:     value,
		ExpiresAt: expTime,
	}
	elem := c.order.PushBack(lruEntry{key: key})
	c.elems[key] = elem
}

// Get retrieves an item from the cache if it exists and hasn't expired.
// Moving the accessed item to the most recently used position.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	// Check for expiration.
	if time.Now().After(item.ExpiresAt) {
		c.removeItem(key)
		return nil, false
	}

	// Move item to the back (most recently used).
	if elem, ok := c.elems[key]; ok {
		c.order.MoveToBack(elem)
	}

	return item.Value, true
}

// Delete removes an item from the cache.
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.removeItem(key)
}

// Cleanup removes all expired items from the cache. This should be called periodically
// to prevent memory bloat from expired entries.
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, item := range c.items {
		// Only remove items that are already expired
		if now.After(item.ExpiresAt) {
			c.removeItem(key)
		}
	}
}

// evictOldest removes the least recently used item from the cache.
func (c *Cache) evictOldest() {
	now := time.Now()
	elem := c.order.Front()
	
	// First try to find an expired item from the front
	for elem != nil {
		entry := elem.Value.(lruEntry)
		if item, exists := c.items[entry.key]; exists {
			if now.After(item.ExpiresAt) {
				c.removeItem(entry.key)
				return
			}
		}
		elem = elem.Next()
	}

	// If no expired items found, remove the oldest item
	if elem = c.order.Front(); elem != nil {
		entry := elem.Value.(lruEntry)
		c.removeItem(entry.key)
	}
}

// removeItem removes an item from both the cache and the LRU tracking structures.
func (c *Cache) removeItem(key string) {
	delete(c.items, key)
	if elem, ok := c.elems[key]; ok {
		c.order.Remove(elem)
		delete(c.elems, key)
	}
}
