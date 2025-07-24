package traefikoidc

import (
	"sync"
	"time"
)

// MaxKeyLength defines the maximum allowed length for cache keys
// to prevent memory exhaustion from excessively long keys.
const MaxKeyLength = 256

// OptimizedCacheEntry represents a single cache entry with embedded LRU linked list pointers.
// This design eliminates the need for separate data structures (list.List and map[string]*list.Element)
// and reduces memory overhead by approximately 66% compared to traditional implementations.
type OptimizedCacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
	Key       string

	// Embedded doubly-linked list pointers for LRU ordering
	prev, next *OptimizedCacheEntry
}

// OptimizedCache provides a memory-efficient, thread-safe cache with LRU eviction policy.
// It uses a single map with entries containing embedded doubly-linked list pointers,
// eliminating the memory overhead of maintaining separate data structures.
// The cache supports both item count and memory size limits.
type OptimizedCache struct {
	items               map[string]*OptimizedCacheEntry
	head, tail          *OptimizedCacheEntry // LRU sentinel nodes
	cleanupTask         *BackgroundTask
	logger              *Logger
	maxSize             int
	maxMemoryBytes      int64 // Memory budget limit
	currentMemoryBytes  int64 // Current estimated memory usage
	autoCleanupInterval time.Duration
	mutex               sync.RWMutex
}

// NewOptimizedCache creates a new memory-efficient cache with default settings.
// It uses the default maximum size and no memory limit.
func NewOptimizedCache() *OptimizedCache {
	return NewOptimizedCacheWithConfig(DefaultMaxSize, 0, nil)
}

// NewOptimizedCacheWithConfig creates a cache with specified configuration.
//
// Parameters:
//   - maxSize: Maximum number of items in the cache.
//   - maxMemoryMB: Maximum memory usage in megabytes (0 for default 64MB).
//   - logger: Logger instance for debug output (nil for no-op logger).
//
// Returns:
//   - A new OptimizedCache instance.
func NewOptimizedCacheWithConfig(maxSize int, maxMemoryMB int, logger *Logger) *OptimizedCache {
	if logger == nil {
		logger = newNoOpLogger()
	}

	// Create sentinel nodes for the doubly-linked list
	head := &OptimizedCacheEntry{}
	tail := &OptimizedCacheEntry{}
	head.next = tail
	tail.prev = head

	maxMemoryBytes := int64(maxMemoryMB) * 1024 * 1024 // Convert MB to bytes
	if maxMemoryBytes == 0 {
		maxMemoryBytes = 64 * 1024 * 1024 // Default 64MB
	}

	c := &OptimizedCache{
		items:               make(map[string]*OptimizedCacheEntry, maxSize),
		head:                head,
		tail:                tail,
		maxSize:             maxSize,
		maxMemoryBytes:      maxMemoryBytes,
		autoCleanupInterval: 5 * time.Minute,
		logger:              logger,
	}

	c.startAutoCleanup()
	return c
}

// Set adds or updates an item in the cache with the specified expiration.
// It validates key length and enforces both item count and memory limits.
// When limits are exceeded, the least recently used items are evicted.
//
// Parameters:
//   - key: The cache key (must be <= MaxKeyLength).
//   - value: The value to cache.
//   - expiration: Time until the item expires.
func (c *OptimizedCache) Set(key string, value interface{}, expiration time.Duration) {
	// Validate key length to prevent memory bloat
	if len(key) > MaxKeyLength {
		c.logger.Debugf("Cache key too long (%d > %d), ignoring", len(key), MaxKeyLength)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	expTime := now.Add(expiration)

	// Update existing item
	if entry, exists := c.items[key]; exists {
		oldSize := c.estimateEntrySize(entry)
		entry.Value = value
		entry.ExpiresAt = expTime
		newSize := c.estimateEntrySize(entry)
		c.currentMemoryBytes += newSize - oldSize
		c.moveToTail(entry)
		return
	}

	// Create new entry
	entry := &OptimizedCacheEntry{
		Value:     value,
		ExpiresAt: expTime,
		Key:       key,
	}

	entrySize := c.estimateEntrySize(entry)

	// Check memory budget and evict if necessary
	for (c.currentMemoryBytes+entrySize > c.maxMemoryBytes || len(c.items) >= c.maxSize) && len(c.items) > 0 {
		if !c.evictOldest() {
			break // No more items to evict
		}
	}

	// Add new entry
	c.items[key] = entry
	c.currentMemoryBytes += entrySize
	c.addToTail(entry)
}

// Get retrieves an item from the cache with memory-efficient access tracking
func (c *OptimizedCache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.items[key]
	if !exists {
		return nil, false
	}

	// Check for expiration
	if time.Now().After(entry.ExpiresAt) {
		c.removeEntry(entry)
		return nil, false
	}

	// Move to tail (most recently used)
	c.moveToTail(entry)
	return entry.Value, true
}

// Delete removes an item from the cache
func (c *OptimizedCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, exists := c.items[key]; exists {
		c.removeEntry(entry)
	}
}

// Cleanup removes expired items and performs memory optimization
func (c *OptimizedCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	toRemove := make([]*OptimizedCacheEntry, 0, len(c.items)/10) // Pre-allocate for efficiency

	// Collect expired entries (start from head - oldest items)
	for entry := c.head.next; entry != c.tail; entry = entry.next {
		if now.After(entry.ExpiresAt) {
			toRemove = append(toRemove, entry)
		}
	}

	// Remove expired entries
	for _, entry := range toRemove {
		c.removeEntry(entry)
	}

	// Perform memory pressure eviction if needed
	for c.currentMemoryBytes > c.maxMemoryBytes && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}
}

// evictOldest removes the least recently used item
// Returns false if no items to evict
func (c *OptimizedCache) evictOldest() bool {
	if c.head.next == c.tail {
		return false // Empty cache
	}

	oldest := c.head.next
	c.removeEntry(oldest)
	return true
}

// removeEntry removes an entry from both the map and linked list
func (c *OptimizedCache) removeEntry(entry *OptimizedCacheEntry) {
	// Remove from map
	delete(c.items, entry.Key)

	// Update memory usage
	c.currentMemoryBytes -= c.estimateEntrySize(entry)

	// Remove from linked list
	entry.prev.next = entry.next
	entry.next.prev = entry.prev

	// Clear references to help GC
	entry.prev = nil
	entry.next = nil
	entry.Value = nil
}

// addToTail adds an entry to the tail (most recently used position)
func (c *OptimizedCache) addToTail(entry *OptimizedCacheEntry) {
	entry.prev = c.tail.prev
	entry.next = c.tail
	c.tail.prev.next = entry
	c.tail.prev = entry
}

// moveToTail moves an existing entry to the tail (mark as most recently used)
func (c *OptimizedCache) moveToTail(entry *OptimizedCacheEntry) {
	// Remove from current position
	entry.prev.next = entry.next
	entry.next.prev = entry.prev

	// Add to tail
	c.addToTail(entry)
}

// estimateEntrySize estimates the memory usage of a cache entry
// Uses conservative estimates since unsafe.Sizeof is not allowed in Yaegi
func (c *OptimizedCache) estimateEntrySize(entry *OptimizedCacheEntry) int64 {
	// Conservative estimate for OptimizedCacheEntry struct overhead
	// (3 pointers + time.Time + string) ≈ 80 bytes on 64-bit systems
	size := int64(80) + int64(len(entry.Key))

	// Estimate value size based on type
	if entry.Value != nil {
		switch v := entry.Value.(type) {
		case string:
			size += int64(len(v))
		case []byte:
			size += int64(len(v))
		case map[string]interface{}:
			// Rough estimate for map overhead + keys + values
			size += int64(len(v)) * 64 // 64 bytes per entry estimate
			for key, val := range v {
				size += int64(len(key))
				// Estimate value size
				switch val := val.(type) {
				case string:
					size += int64(len(val))
				case []byte:
					size += int64(len(val))
				default:
					size += 32 // Default estimate for other types
				}
			}
		case []string:
			for _, s := range v {
				size += int64(len(s)) + 16 // 16 bytes slice overhead per string
			}
		default:
			// Generic estimate for unknown types
			size += 64
		}
	}

	return size
}

// SetMaxSize changes the maximum number of items the cache can hold
func (c *OptimizedCache) SetMaxSize(size int) {
	if size <= 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.maxSize = size

	// Evict excess items if necessary
	for len(c.items) > c.maxSize && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}
}

// SetMaxMemory sets the maximum memory budget in MB
func (c *OptimizedCache) SetMaxMemory(maxMemoryMB int) {
	if maxMemoryMB <= 0 {
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.maxMemoryBytes = int64(maxMemoryMB) * 1024 * 1024

	// Evict items if over memory budget
	for c.currentMemoryBytes > c.maxMemoryBytes && len(c.items) > 0 {
		if !c.evictOldest() {
			break
		}
	}
}

// startAutoCleanup starts the background cleanup task
func (c *OptimizedCache) startAutoCleanup() {
	c.cleanupTask = NewBackgroundTask("optimized-cache-cleanup", c.autoCleanupInterval, c.Cleanup, c.logger)
	c.cleanupTask.Start()
}

// Close stops the automatic cleanup task
func (c *OptimizedCache) Close() {
	if c.cleanupTask != nil {
		c.cleanupTask.Stop()
		c.cleanupTask = nil
	}
}
