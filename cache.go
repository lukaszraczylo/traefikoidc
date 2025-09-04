package traefikoidc

import (
	"container/list"
	"sync"
	"time"
)

// CacheItem represents an item stored in the cache with its associated metadata.
// It stores the cached value along with expiration time for automatic cleanup.
type CacheItem struct {
	// Value is the cached data of any type
	Value interface{}
	// ExpiresAt defines when this cache entry should be considered expired
	ExpiresAt time.Time
}

// lruEntry represents an entry in the LRU (Least Recently Used) list.
// It stores only the key to minimize memory usage in the LRU tracking structure.
type lruEntry struct {
	// key is the cache key associated with this LRU entry
	key string
}

// Cache provides a thread-safe, TTL-aware cache with LRU eviction policy.
// It implements an LRU (Least Recently Used) eviction policy using a doubly-linked list for efficiency.
// Features automatic cleanup of expired entries and bounded memory usage.
type Cache struct {
	// items stores the actual cache data indexed by key
	items map[string]CacheItem
	// order maintains the LRU ordering using a doubly-linked list
	order *list.List
	// elems provides O(1) access to list elements for LRU updates
	elems map[string]*list.Element
	// cleanupTask runs periodic cleanup of expired entries
	cleanupTask *BackgroundTask
	// logger for debugging and monitoring cache operations
	logger *Logger
	// maxSize limits the number of items to prevent unbounded growth
	maxSize int
	// autoCleanupInterval defines how often expired entries are cleaned
	autoCleanupInterval time.Duration
	// mutex protects all cache operations for thread safety
	mutex sync.RWMutex
}

// DefaultMaxSize is the default maximum number of items in the cache.
// This value provides a reasonable balance between memory usage and performance.
const DefaultMaxSize = 500

// NewCache creates a new cache with default configuration and no logger.
// It initializes the internal maps and list and sets the default maximum size.
func NewCache() *Cache {
	return NewCacheWithLogger(nil)
}

// NewCacheWithLogger creates a new cache with the specified logger for debugging.
// If logger is nil, a no-op logger is used. The cache starts with automatic cleanup enabled.
func NewCacheWithLogger(logger *Logger) *Cache {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	c := &Cache{
		items:               make(map[string]CacheItem, DefaultMaxSize),
		order:               list.New(),
		elems:               make(map[string]*list.Element, DefaultMaxSize),
		maxSize:             DefaultMaxSize,
		autoCleanupInterval: 2 * time.Minute,
		logger:              logger,
	}
	c.startAutoCleanup()
	return c
}

// Set stores a value in the cache with the specified expiration duration.
// If the key already exists, it updates the value and expiration time.
// When the cache is full, the least recently used item is evicted.
// The expiration duration is relative to the time Set is called.
func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	expTime := now.Add(expiration)

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

	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[key] = CacheItem{
		Value:     value,
		ExpiresAt: expTime,
	}
	elem := c.order.PushBack(lruEntry{key: key})
	c.elems[key] = elem
}

// Get retrieves a value from the cache and updates its LRU position.
// Returns the value and true if found and not expired, or nil and false otherwise.
// If an item is found but expired, the expired item is removed from the cache.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(item.ExpiresAt) {
		c.removeItem(key)
		return nil, false
	}

	if elem, ok := c.elems[key]; ok {
		c.order.MoveToBack(elem)
	}

	return item.Value, true
}

// Delete removes an item from the cache, cleaning up both the items map
// and the LRU list. This is a manual removal that bypasses expiration checking.
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.removeItem(key)
}

// Cleanup removes all expired items from the cache.
// This method is called automatically by the background cleanup task but can also
// be called manually for immediate cleanup of expired entries.
func (c *Cache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, item := range c.items {
		if now.After(item.ExpiresAt) {
			c.removeItem(key)
		}
	}
}

// evictOldest removes the least recently used item from the cache.
// It first attempts to find expired items to evict before removing valid ones.
// Note: This function assumes the write lock is already held.
func (c *Cache) evictOldest() {
	now := time.Now()
	elem := c.order.Front()

	// This limits the search overhead while still finding expired items efficiently
	const maxExpiredCheck = 5
	checked := 0

	for elem != nil && checked < maxExpiredCheck {
		entry := elem.Value.(lruEntry)
		if item, exists := c.items[entry.key]; exists {
			if now.After(item.ExpiresAt) {
				c.removeItem(entry.key)
				return
			}
		}
		elem = elem.Next()
		checked++
	}

	if elem = c.order.Front(); elem != nil {
		entry := elem.Value.(lruEntry)
		c.removeItem(entry.key)
	}
}

// SetMaxSize updates the maximum number of items the cache can hold.
// If the new size is smaller than the current cache size, the
// oldest items will be evicted until the cache size is within the new limit.
func (c *Cache) SetMaxSize(size int) {
	if size <= 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.maxSize = size

	for len(c.items) > c.maxSize {
		c.evictOldest()
	}
}

// removeItem removes an item from both the cache and LRU structures.
// It handles cleanup of all associated data structures for the given key.
// Note: This function assumes the write lock is already held.
func (c *Cache) removeItem(key string) {
	delete(c.items, key)
	if elem, ok := c.elems[key]; ok {
		c.order.Remove(elem)
		delete(c.elems, key)
	}
}

// startAutoCleanup begins the background cleanup task that periodically
// removes expired entries from the cache. The task runs continuously
// at the interval specified by c.autoCleanupInterval.
func (c *Cache) startAutoCleanup() {
	c.cleanupTask = NewBackgroundTask("cache-cleanup", c.autoCleanupInterval, c.Cleanup, c.logger)
	c.cleanupTask.Start()
}

// Close stops the background cleanup task and releases associated resources.
// It should be called when the cache is no longer needed to prevent resource leaks.
func (c *Cache) Close() {
	if c.cleanupTask != nil {
		c.cleanupTask.Stop()
		c.cleanupTask = nil
	}
}
