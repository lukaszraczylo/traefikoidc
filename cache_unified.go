package traefikoidc

import (
	"sync"
	"time"
)

// DefaultMaxSize is the default maximum number of items in cache
const DefaultMaxSize = 500

// CacheStrategy defines the caching strategy interface
type CacheStrategy interface {
	// Name returns the strategy name for debugging
	Name() string
	// ShouldEvict determines if an item should be evicted
	ShouldEvict(item interface{}, now time.Time) bool
	// OnAccess is called when an item is accessed
	OnAccess(key string, item interface{})
	// OnRemove is called when an item is removed
	OnRemove(key string)
	// EstimateSize estimates the memory size of an item
	EstimateSize(item interface{}) int64
	// GetEvictionCandidate returns the best candidate for eviction
	GetEvictionCandidate() (key string, found bool)
}

// UnifiedCacheConfig provides configuration for the unified cache
type UnifiedCacheConfig struct {
	MaxSize           int
	MaxMemoryBytes    int64
	CleanupInterval   time.Duration
	Strategy          CacheStrategy
	EnableMemoryLimit bool
	EnableAutoCleanup bool
	Logger            *Logger
}

// DefaultUnifiedCacheConfig returns default cache configuration
func DefaultUnifiedCacheConfig() UnifiedCacheConfig {
	return UnifiedCacheConfig{
		MaxSize:           DefaultMaxSize,
		MaxMemoryBytes:    64 * 1024 * 1024, // 64MB default
		CleanupInterval:   2 * time.Minute,
		EnableMemoryLimit: false,
		EnableAutoCleanup: true,
		Logger:            nil,
	}
}

// UnifiedCache provides a single, flexible cache implementation
// that can be configured with different strategies and features
type UnifiedCache struct {
	items              map[string]interface{}
	strategy           CacheStrategy
	cleanupTask        *BackgroundTask
	logger             *Logger
	config             UnifiedCacheConfig
	currentMemoryBytes int64
	mutex              sync.RWMutex
}

// NewUnifiedCache creates a new unified cache with the given configuration
func NewUnifiedCache(config UnifiedCacheConfig) *UnifiedCache {
	if config.Logger == nil {
		config.Logger = GetSingletonNoOpLogger()
	}

	if config.Strategy == nil {
		config.Strategy = NewLRUStrategy(config.MaxSize)
	}

	c := &UnifiedCache{
		items:    make(map[string]interface{}, config.MaxSize),
		strategy: config.Strategy,
		config:   config,
		logger:   config.Logger,
	}

	if config.EnableAutoCleanup {
		c.startAutoCleanup()
	}

	return c
}

// NewUnifiedCacheSimple creates a unified cache with default configuration
// This is a drop-in replacement for the old NewCache() function
func NewUnifiedCacheSimple() *UnifiedCache {
	config := DefaultUnifiedCacheConfig()
	return NewUnifiedCache(config)
}

// Set stores a value in the cache
func (c *UnifiedCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Wrap the value with metadata
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	} else if ttl == 0 {
		// Zero TTL means no expiration - set to far future
		expiresAt = time.Now().Add(100 * 365 * 24 * time.Hour) // 100 years
	} else {
		// Negative TTL means already expired
		expiresAt = time.Now().Add(ttl) // This will be in the past
	}

	item := &CacheEntry{
		Value:     value,
		ExpiresAt: expiresAt,
		Key:       key,
	}

	// Check memory limits if enabled
	if c.config.EnableMemoryLimit {
		itemSize := c.strategy.EstimateSize(item)

		// Evict items if necessary
		for (c.currentMemoryBytes+itemSize > c.config.MaxMemoryBytes ||
			len(c.items) >= c.config.MaxSize) && len(c.items) > 0 {
			if !c.evictOne() {
				break
			}
		}

		c.currentMemoryBytes += itemSize
	} else if len(c.items) >= c.config.MaxSize {
		c.evictOne()
	}

	c.items[key] = item
	c.strategy.OnAccess(key, item)
}

// Get retrieves a value from the cache
func (c *UnifiedCache) Get(key string) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	item, exists := c.items[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	entry, ok := item.(*CacheEntry)
	if !ok {
		return nil, false
	}

	if c.strategy.ShouldEvict(entry, time.Now()) {
		c.removeItem(key)
		return nil, false
	}

	c.strategy.OnAccess(key, entry)
	return entry.Value, true
}

// Delete removes an item from the cache
func (c *UnifiedCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.removeItem(key)
}

// Cleanup removes expired entries
func (c *UnifiedCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	toRemove := make([]string, 0)

	for key, item := range c.items {
		if c.strategy.ShouldEvict(item, now) {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		c.removeItem(key)
	}
}

// Close stops the cache and cleans up resources
func (c *UnifiedCache) Close() {
	// Stop the cleanup task first before acquiring the lock to avoid deadlock
	var taskToStop *BackgroundTask
	c.mutex.Lock()
	taskToStop = c.cleanupTask
	c.cleanupTask = nil
	c.mutex.Unlock()

	// Stop the task outside of the lock
	if taskToStop != nil {
		taskToStop.Stop()
	}

	// Now acquire the lock again to clear items
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clear all items to help with garbage collection
	for key := range c.items {
		delete(c.items, key)
	}
	c.currentMemoryBytes = 0
}

// SetMaxSize updates the maximum cache size
func (c *UnifiedCache) SetMaxSize(size int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.config.MaxSize = size

	// Evict excess items
	for len(c.items) > size && len(c.items) > 0 {
		if !c.evictOne() {
			break
		}
	}
}

// SetMaxMemory updates the maximum memory limit
func (c *UnifiedCache) SetMaxMemory(bytes int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.config.MaxMemoryBytes = bytes
	c.config.EnableMemoryLimit = bytes > 0
}

// GetMetrics returns cache metrics
func (c *UnifiedCache) GetMetrics() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return map[string]interface{}{
		"item_count":   len(c.items),
		"memory_bytes": c.currentMemoryBytes,
		"max_size":     c.config.MaxSize,
		"strategy":     c.strategy.Name(),
		"has_cleanup":  c.cleanupTask != nil,
	}
}

// removeItem removes an item and updates memory tracking
func (c *UnifiedCache) removeItem(key string) {
	if item, exists := c.items[key]; exists {
		if c.config.EnableMemoryLimit {
			c.currentMemoryBytes -= c.strategy.EstimateSize(item)
		}
		delete(c.items, key)
		if c.strategy != nil {
			c.strategy.OnRemove(key)
		}
	}
}

// evictOne evicts one item based on strategy
func (c *UnifiedCache) evictOne() bool {
	// Try to use strategy's eviction candidate first
	if c.strategy != nil {
		if key, found := c.strategy.GetEvictionCandidate(); found {
			c.removeItem(key)
			return true
		}
	}

	// Fallback: evict any item
	for key := range c.items {
		c.removeItem(key)
		return true
	}
	return false
}

// startAutoCleanup starts the background cleanup task
func (c *UnifiedCache) startAutoCleanup() {
	c.cleanupTask = NewBackgroundTask(
		"unified-cache-cleanup",
		c.config.CleanupInterval,
		c.Cleanup,
		c.logger,
	)
	c.cleanupTask.Start()
}

// CacheEntry wraps cached values with metadata
type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
	Key       string
}

// LRUStrategy implements LRU eviction strategy
type LRUStrategy struct {
	order    *DoublyLinkedList
	elements map[string]*ListNode
	maxSize  int
	mutex    sync.Mutex
}

// NewLRUStrategy creates a new LRU strategy
func NewLRUStrategy(maxSize int) *LRUStrategy {
	return &LRUStrategy{
		order:    NewDoublyLinkedList(),
		elements: make(map[string]*ListNode, maxSize),
		maxSize:  maxSize,
	}
}

// Name returns the strategy name
func (s *LRUStrategy) Name() string {
	return "LRU"
}

// ShouldEvict checks if an item should be evicted
func (s *LRUStrategy) ShouldEvict(item interface{}, now time.Time) bool {
	if entry, ok := item.(*CacheEntry); ok {
		return now.After(entry.ExpiresAt)
	}
	return false
}

// OnAccess updates LRU order when item is accessed
func (s *LRUStrategy) OnAccess(key string, item interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if node, exists := s.elements[key]; exists {
		s.order.MoveToBack(node)
	} else {
		node := s.order.PushBack(key)
		s.elements[key] = node
	}
}

// OnRemove removes item from LRU tracking
func (s *LRUStrategy) OnRemove(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if node, exists := s.elements[key]; exists {
		s.order.Remove(node)
		delete(s.elements, key)
	}
}

// EstimateSize estimates memory size of an item
func (s *LRUStrategy) EstimateSize(item interface{}) int64 {
	// Basic size estimation
	size := int64(80) // Base object overhead

	if entry, ok := item.(*CacheEntry); ok {
		size += int64(len(entry.Key))

		switch v := entry.Value.(type) {
		case string:
			size += int64(len(v))
		case []byte:
			size += int64(len(v))
		case map[string]interface{}:
			size += int64(len(v)) * 64
			for key, val := range v {
				size += int64(len(key))
				if str, ok := val.(string); ok {
					size += int64(len(str))
				} else {
					size += 32
				}
			}
		default:
			size += 64
		}
	}

	return size
}

// GetEvictionCandidate returns the least recently used item
func (s *LRUStrategy) GetEvictionCandidate() (key string, found bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// The actual first element is head.next (head is a sentinel)
	if s.order.head != nil && s.order.head.next != nil && s.order.head.next != s.order.tail {
		return s.order.head.next.Key, true
	}
	return "", false
}

// DoublyLinkedList provides a simple doubly-linked list for LRU
type DoublyLinkedList struct {
	head, tail *ListNode
	size       int
}

// ListNode represents a node in the doubly-linked list
type ListNode struct {
	Key  string
	prev *ListNode
	next *ListNode
}

// NewDoublyLinkedList creates a new doubly-linked list
func NewDoublyLinkedList() *DoublyLinkedList {
	head := &ListNode{}
	tail := &ListNode{}
	head.next = tail
	tail.prev = head
	return &DoublyLinkedList{
		head: head,
		tail: tail,
		size: 0,
	}
}

// PushBack adds a key to the back of the list
func (l *DoublyLinkedList) PushBack(key string) *ListNode {
	node := &ListNode{Key: key}
	node.prev = l.tail.prev
	node.next = l.tail
	l.tail.prev.next = node
	l.tail.prev = node
	l.size++
	return node
}

// MoveToBack moves a node to the back of the list
func (l *DoublyLinkedList) MoveToBack(node *ListNode) {
	// Remove from current position
	node.prev.next = node.next
	node.next.prev = node.prev

	// Add to back
	node.prev = l.tail.prev
	node.next = l.tail
	l.tail.prev.next = node
	l.tail.prev = node
}

// PopFront removes and returns the front node
func (l *DoublyLinkedList) PopFront() *ListNode {
	if l.head.next == l.tail {
		return nil
	}

	front := l.head.next
	l.head.next = front.next
	front.next.prev = l.head
	l.size--

	front.prev = nil
	front.next = nil
	return front
}

// Remove removes a node from the list
func (l *DoublyLinkedList) Remove(node *ListNode) {
	if node == nil || node.prev == nil || node.next == nil {
		return
	}
	node.prev.next = node.next
	node.next.prev = node.prev
	node.prev = nil
	node.next = nil
	l.size--
}

// CacheAdapter provides backward compatibility with existing cache interfaces
type CacheAdapter struct {
	unified *UnifiedCache
}

// NewCacheAdapter creates an adapter for the unified cache
func NewCacheAdapter(unified *UnifiedCache) *CacheAdapter {
	return &CacheAdapter{unified: unified}
}

// Set adapts the Set method
func (a *CacheAdapter) Set(key string, value interface{}, expiration time.Duration) {
	a.unified.Set(key, value, expiration)
}

// Get adapts the Get method
func (a *CacheAdapter) Get(key string) (interface{}, bool) {
	return a.unified.Get(key)
}

// Delete adapts the Delete method
func (a *CacheAdapter) Delete(key string) {
	a.unified.Delete(key)
}

// Cleanup adapts the Cleanup method
func (a *CacheAdapter) Cleanup() {
	a.unified.Cleanup()
}

// Close adapts the Close method
func (a *CacheAdapter) Close() {
	a.unified.Close()
}

// SetMaxSize adapts the SetMaxSize method
func (a *CacheAdapter) SetMaxSize(size int) {
	a.unified.SetMaxSize(size)
}

// SetMaxMemory adapts the SetMaxMemory method
func (a *CacheAdapter) SetMaxMemory(bytes int64) {
	a.unified.SetMaxMemory(bytes)
}
