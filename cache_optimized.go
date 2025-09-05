package traefikoidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// MaxKeyLength defines the maximum allowed cache key length
// to prevent memory exhaustion from excessively long keys.
const MaxKeyLength = 256

// OptimizedCacheEntry represents a cache entry in the optimized cache implementation.
// It uses intrusive linked list design to eliminate separate list nodes,
// reducing memory overhead by approximately 66% compared to traditional implementations.
type OptimizedCacheEntry struct {
	ExpiresAt time.Time
	Value     interface{}
	prev      *OptimizedCacheEntry
	next      *OptimizedCacheEntry
	Key       string
}

// OptimizedCache provides a memory-efficient, thread-safe cache with LRU eviction.
// It uses an intrusive doubly-linked list design for O(1) LRU operations.
// The cache supports both item count and memory size limits.
type OptimizedCache struct {
	// items maps keys to cache entries
	items map[string]*OptimizedCacheEntry
	// head, tail are sentinel nodes for the LRU doubly-linked list
	head, tail *OptimizedCacheEntry
	// cleanupTask handles background cleanup of expired entries
	cleanupTask *BackgroundTask
	// logger for debugging and monitoring
	logger *Logger
	// maxSize limits the number of cache entries
	maxSize int
	// maxMemoryBytes limits total memory usage in bytes
	maxMemoryBytes int64
	// currentMemoryBytes tracks estimated memory usage
	currentMemoryBytes int64
	// autoCleanupInterval defines cleanup frequency
	autoCleanupInterval time.Duration
	// mutex provides thread safety for all operations
	mutex sync.RWMutex
	// ctx provides context for background operations
	ctx context.Context
	// cancel cancels background operations
	cancel context.CancelFunc
	// wg tracks background goroutines
	wg sync.WaitGroup
	// closed indicates if cache has been closed
	closed bool
}

// normalizeKey ensures keys are within reasonable limits by hashing long keys.
// This prevents memory exhaustion while still allowing long keys to be used.
func (c *OptimizedCache) normalizeKey(key string) string {
	if len(key) <= MaxKeyLength {
		return key
	}

	// Hash long keys to create a fixed-size key
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return "hash:" + hex.EncodeToString(hasher.Sum(nil))
}

// NewOptimizedCache creates a new optimized cache with default settings.
// It uses the default maximum size and 64MB memory limit.
func NewOptimizedCache() *OptimizedCache {
	return NewOptimizedCacheWithConfig(DefaultMaxSize, 0, nil)
}

// NewOptimizedCacheWithConfig creates a new optimized cache with custom configuration.
// Parameters:
//   - maxSize: Maximum number of entries (0 uses default)
//   - maxMemoryMB: Memory limit in megabytes (0 uses 64MB default)
//   - logger: Logger instance for debugging (nil creates no-op logger)
//
// Returns:
//   - A new OptimizedCache instance
func NewOptimizedCacheWithConfig(maxSize int, maxMemoryMB int, logger *Logger) *OptimizedCache {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	// Use default max size if not specified
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}

	head := &OptimizedCacheEntry{}
	tail := &OptimizedCacheEntry{}
	head.next = tail
	tail.prev = head

	maxMemoryBytes := int64(maxMemoryMB) * 1024 * 1024
	if maxMemoryBytes == 0 {
		maxMemoryBytes = 64 * 1024 * 1024
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &OptimizedCache{
		items:               make(map[string]*OptimizedCacheEntry, maxSize),
		head:                head,
		tail:                tail,
		maxSize:             maxSize,
		maxMemoryBytes:      maxMemoryBytes,
		autoCleanupInterval: 2 * time.Minute,
		logger:              logger,
		ctx:                 ctx,
		cancel:              cancel,
	}

	c.startAutoCleanup()
	return c
}

// Set stores a value in the optimized cache with memory tracking and LRU management.
// Keys longer than MaxKeyLength are rejected to prevent memory exhaustion.
// If the cache exceeds size or memory limits, least recently used items are evicted.
// Parameters:
//   - key: The cache key (must be <= MaxKeyLength)
//   - value: The value to store
//   - expiration: Time until the item expires
func (c *OptimizedCache) Set(key string, value interface{}, expiration time.Duration) {
	c.mutex.RLock()
	if c.closed {
		c.mutex.RUnlock()
		return
	}
	c.mutex.RUnlock()
	// Normalize the key to handle long keys
	normalizedKey := c.normalizeKey(key)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	var expTime time.Time
	if expiration == 0 {
		// Permanent entry - set to far future to avoid expiration
		expTime = now.Add(100 * 365 * 24 * time.Hour) // 100 years
	} else {
		expTime = now.Add(expiration)
	}

	if entry, exists := c.items[normalizedKey]; exists {
		oldSize := c.estimateEntrySize(entry)
		entry.Value = value
		entry.ExpiresAt = expTime
		newSize := c.estimateEntrySize(entry)
		c.currentMemoryBytes += newSize - oldSize
		c.moveToTail(entry)
		return
	}

	entry := &OptimizedCacheEntry{
		Value:     value,
		ExpiresAt: expTime,
		Key:       normalizedKey,
	}

	entrySize := c.estimateEntrySize(entry)

	for (c.currentMemoryBytes+entrySize > c.maxMemoryBytes || len(c.items) >= c.maxSize) && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}

	c.items[normalizedKey] = entry
	c.currentMemoryBytes += entrySize
	c.addToTail(entry)
}

// Get retrieves an item from the cache with memory-efficient access tracking.
// It moves accessed items to the tail (most recently used position) and
// automatically removes expired items when encountered.
// Returns the value and true if found and valid, or nil and false otherwise.
func (c *OptimizedCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	if c.closed {
		c.mutex.RUnlock()
		return nil, false
	}
	c.mutex.RUnlock()
	// Normalize the key to handle long keys
	normalizedKey := c.normalizeKey(key)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.items[normalizedKey]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		c.removeEntry(entry)
		return nil, false
	}

	c.moveToTail(entry)
	return entry.Value, true
}

// Delete removes an item from the cache, freeing its memory and updating tracking.
// This is a manual removal that updates both the hash map and LRU list.
func (c *OptimizedCache) Delete(key string) {
	// Normalize the key to handle long keys
	normalizedKey := c.normalizeKey(key)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, exists := c.items[normalizedKey]; exists {
		c.removeEntry(entry)
	}
}

// Cleanup removes expired items and performs memory optimization.
// It scans the LRU list for expired entries and enforces memory limits
// by evicting least recently used items if necessary.
func (c *OptimizedCache) Cleanup() {
	if c == nil {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if cache is closed - if so, exit early
	if c.closed || c.items == nil || c.head == nil || c.tail == nil {
		return
	}

	now := time.Now()
	toRemove := make([]*OptimizedCacheEntry, 0, len(c.items)/10)

	for entry := c.head.next; entry != nil && entry != c.tail; entry = entry.next {
		if entry != nil && now.After(entry.ExpiresAt) {
			toRemove = append(toRemove, entry)
		}
	}

	for _, entry := range toRemove {
		if entry != nil {
			c.removeEntry(entry)
		}
	}

	for c.currentMemoryBytes > c.maxMemoryBytes && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}
}

// evictOldest removes the least recently used item from the cache.
// Returns true if an item was evicted, false if the cache is empty.
// Returns false if no items to evict.
func (c *OptimizedCache) evictOldest() bool {
	if c.head.next == c.tail {
		return false
	}

	oldest := c.head.next
	c.removeEntry(oldest)
	return true
}

// removeEntry removes an entry from both the map and linked list.
// It updates memory tracking and clears references to prevent memory leaks.
// Note: This function assumes the write lock is already held.
func (c *OptimizedCache) removeEntry(entry *OptimizedCacheEntry) {
	delete(c.items, entry.Key)

	c.currentMemoryBytes -= c.estimateEntrySize(entry)

	entry.prev.next = entry.next
	entry.next.prev = entry.prev

	entry.prev = nil
	entry.next = nil
	entry.Value = nil
}

// addToTail adds an entry to the tail (most recently used position) of the LRU list.
// This marks the entry as the most recently accessed item.
func (c *OptimizedCache) addToTail(entry *OptimizedCacheEntry) {
	entry.prev = c.tail.prev
	entry.next = c.tail
	c.tail.prev.next = entry
	c.tail.prev = entry
}

// moveToTail moves an existing entry to the tail (mark as most recently used).
// This updates the LRU order when an item is accessed.
func (c *OptimizedCache) moveToTail(entry *OptimizedCacheEntry) {
	entry.prev.next = entry.next
	entry.next.prev = entry.prev

	c.addToTail(entry)
}

// estimateEntrySize calculates the approximate memory footprint of a cache entry.
// Uses conservative estimates since unsafe.Sizeof is not allowed in Yaegi.
// It accounts for the entry struct, key string, and value based on type.
func (c *OptimizedCache) estimateEntrySize(entry *OptimizedCacheEntry) int64 {
	size := int64(80) + int64(len(entry.Key))

	if entry.Value != nil {
		switch v := entry.Value.(type) {
		case string:
			size += int64(len(v))
		case []byte:
			size += int64(len(v))
		case map[string]interface{}:
			size += int64(len(v)) * 64
			for key, val := range v {
				size += int64(len(key))
				switch val := val.(type) {
				case string:
					size += int64(len(val))
				case []byte:
					size += int64(len(val))
				default:
					size += 32
				}
			}
		case []string:
			for _, s := range v {
				size += int64(len(s)) + 16
			}
		default:
			size += 64
		}
	}

	return size
}

// securelyZeroEntry securely clears sensitive data from a cache entry
func (c *OptimizedCache) securelyZeroEntry(entry *OptimizedCacheEntry) {
	if entry == nil {
		return
	}

	// Zero out the key - Cannot modify string directly, but we can ensure it's cleared by GC
	_ = entry.Key

	// Securely zero value if it contains sensitive data
	switch v := entry.Value.(type) {
	case []byte:
		for i := range v {
			v[i] = 0
		}
	case string:
		// For string values that might contain tokens, we can't modify directly
		// but we set to empty to help GC
		entry.Value = ""
	case map[string]interface{}:
		for key, val := range v {
			switch val := val.(type) {
			case []byte:
				for i := range val {
					val[i] = 0
				}
			case string:
				v[key] = ""
			}
		}
	}

	// Clear references to help GC
	entry.Value = nil
	entry.prev = nil
	entry.next = nil
}

// SetMaxSize changes the maximum number of items the cache can hold.
// If the new limit is smaller than current size, least recently used items are evicted.
func (c *OptimizedCache) SetMaxSize(size int) {
	if size <= 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.maxSize = size

	for len(c.items) > c.maxSize && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}
}

// SetMaxMemory sets the maximum memory budget in MB.
// If current usage exceeds the new limit, least recently used items are evicted.
func (c *OptimizedCache) SetMaxMemory(maxMemoryMB int) {
	if maxMemoryMB <= 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.maxMemoryBytes = int64(maxMemoryMB) * 1024 * 1024

	for c.currentMemoryBytes > c.maxMemoryBytes && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}
}

// startAutoCleanup starts the background cleanup task for automatic maintenance.
// The task runs periodically to remove expired entries and enforce memory limits.
func (c *OptimizedCache) startAutoCleanup() {
	c.cleanupTask = NewBackgroundTask("optimized-cache-cleanup", c.autoCleanupInterval, c.Cleanup, c.logger, &c.wg)
	c.cleanupTask.Start()
}

// Close stops the automatic cleanup task and releases resources.
// Should be called when the cache is no longer needed to prevent resource leaks.
func (c *OptimizedCache) Close() {
	// First, mark as closed and cancel context without holding the lock
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		return
	}
	c.closed = true

	// Cancel context to stop all background operations
	if c.cancel != nil {
		c.cancel()
	}

	// Get reference to cleanup task before unlocking
	cleanupTask := c.cleanupTask
	c.mutex.Unlock()

	// Stop the cleanup task WITHOUT holding the lock to avoid deadlock
	if cleanupTask != nil {
		cleanupTask.Stop()
	}

	// Wait for all background operations to complete
	c.wg.Wait()

	// Now safely clear all cache entries with lock
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear the cleanup task reference
	c.cleanupTask = nil

	// Securely clear all cache entries containing sensitive data
	for key, entry := range c.items {
		c.securelyZeroEntry(entry)
		delete(c.items, key)
	}

	if c.logger != nil {
		c.logger.Debug("OptimizedCache closed and resources cleaned up")
	}
}
