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
	// autoCleanupInterval defines how often Cleanup is called automatically.
	autoCleanupInterval time.Duration
	// stopCleanup channel to terminate the auto cleanup goroutine.
	stopCleanup chan struct{}
}

// DefaultMaxSize is the default maximum number of items in the cache.
const DefaultMaxSize = 500

// NewCache creates a new empty cache instance with default settings.
// It initializes the internal maps and list, sets the default maximum size,
// and starts the automatic cleanup goroutine.
func NewCache() *Cache {
	c := &Cache{
		items:               make(map[string]CacheItem, DefaultMaxSize),
		order:               list.New(),
		elems:               make(map[string]*list.Element, DefaultMaxSize),
		maxSize:             DefaultMaxSize,
		autoCleanupInterval: 5 * time.Minute,
		stopCleanup:         make(chan struct{}),
	}
	go c.startAutoCleanup()
	return c
}

// Set adds or updates an item in the cache with the specified key, value, and expiration duration.
// If the key already exists, its value and expiration time are updated, and it's moved
// to the most recently used position in the LRU list.
// If the key does not exist and the cache is full, the least recently used item is evicted
// before adding the new item.
// The expiration duration is relative to the time Set is called.
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

// Get retrieves an item from the cache by its key.
// If the item exists and has not expired, its value and true are returned.
// Accessing an item moves it to the most recently used position in the LRU list.
// If the item does not exist or has expired, nil and false are returned, and the
// expired item is removed from the cache.
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

// Delete removes an item from the cache by its key.
// If the key exists, the corresponding item is removed from the cache storage
// and the LRU list.
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.removeItem(key)
}

// Cleanup iterates through the cache and removes all items that have expired.
// An item is considered expired if the current time is after its ExpiresAt timestamp.
// This method is called automatically by the auto-cleanup goroutine, but can also
// be called manually.
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, item := range c.items {
		// Remove items that are expired
		if now.After(item.ExpiresAt) {
			c.removeItem(key)
		}
	}
}

// evictOldest removes the least recently used (oldest) item from the cache.
// It first attempts to find and remove an expired item from the front of the LRU list.
// If no expired items are found at the front, it removes the absolute oldest item (front of the list).
// This method is called internally by Set when the cache reaches its maximum size.
// Note: This function assumes the write lock is already held.
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

// SetMaxSize changes the maximum number of items the cache can hold.
// If the new size is smaller than the current number of items in the cache,
// oldest items will be evicted until the cache size is within the new limit.
func (c *Cache) SetMaxSize(size int) {
	if size <= 0 {
		return // Invalid size, ignore
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.maxSize = size

	// If cache exceeds the new max size, evict oldest items
	for len(c.items) > c.maxSize {
		c.evictOldest()
	}
}

// removeItem removes an item specified by the key from the cache's internal storage (items map)
// and its corresponding entry from the LRU list (order list and elems map).
// Note: This function assumes the write lock is already held.
func (c *Cache) removeItem(key string) {
	delete(c.items, key)
	if elem, ok := c.elems[key]; ok {
		c.order.Remove(elem)
		delete(c.elems, key)
	}
}

// startAutoCleanup starts the background goroutine that automatically calls the Cleanup method
// at the interval specified by c.autoCleanupInterval.
// It uses the autoCleanupRoutine helper function.
func (c *Cache) startAutoCleanup() {
	autoCleanupRoutine(c.autoCleanupInterval, c.stopCleanup, c.Cleanup)
}

// Close stops the automatic cleanup goroutine associated with this cache instance.
// It should be called when the cache is no longer needed to prevent resource leaks.
func (c *Cache) Close() {
	close(c.stopCleanup)
}
