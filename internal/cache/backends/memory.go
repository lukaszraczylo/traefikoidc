// Package backend provides cache backend implementations for the Traefik OIDC plugin.
package backends

import (
	"container/list"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// memoryCacheItem represents an item in the memory cache
type memoryCacheItem struct {
	expiresAt   time.Time
	createdAt   time.Time
	accessedAt  time.Time
	value       interface{}
	element     *list.Element
	key         string
	accessCount int64
	size        int64
}

// isExpired checks if the item is expired
func (item *memoryCacheItem) isExpired() bool {
	if item.expiresAt.IsZero() {
		return false
	}
	return time.Now().After(item.expiresAt)
}

// MemoryCacheBackend implements the CacheBackend interface using in-memory storage
type MemoryCacheBackend struct {
	startTime       time.Time
	lastErrorTime   time.Time
	items           map[string]*memoryCacheItem
	lruList         *list.List
	cleanupDone     chan bool
	cleanupTicker   *time.Ticker
	evictionPolicy  string
	lastError       string
	currentMemory   int64
	misses          atomic.Int64
	deletes         atomic.Int64
	evictions       atomic.Int64
	errors          atomic.Int64
	totalGetTime    atomic.Int64
	totalSetTime    atomic.Int64
	getCount        atomic.Int64
	setCount        atomic.Int64
	sets            atomic.Int64
	hits            atomic.Int64
	maxSize         int64
	currentSize     int64
	maxMemory       int64
	cleanupInterval time.Duration
	mu              sync.RWMutex
	closed          atomic.Bool
}

// NewMemoryCacheBackend creates a new memory cache backend
func NewMemoryCacheBackend(maxSize int64, maxMemory int64, cleanupInterval time.Duration) *MemoryCacheBackend {
	if maxSize <= 0 {
		maxSize = 10000 // Default to 10k items
	}
	if maxMemory <= 0 {
		maxMemory = 100 * 1024 * 1024 // Default to 100MB
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	m := &MemoryCacheBackend{
		items:           make(map[string]*memoryCacheItem),
		lruList:         list.New(),
		maxSize:         maxSize,
		maxMemory:       maxMemory,
		startTime:       time.Now(),
		cleanupInterval: cleanupInterval,
		evictionPolicy:  "lru",
		cleanupDone:     make(chan bool),
	}

	// Start cleanup goroutine
	m.cleanupTicker = time.NewTicker(cleanupInterval)
	go m.cleanupLoop()

	return m
}

// cleanupLoop runs periodic cleanup of expired items
func (m *MemoryCacheBackend) cleanupLoop() {
	for {
		select {
		case <-m.cleanupTicker.C:
			m.cleanupExpired()
		case <-m.cleanupDone:
			return
		}
	}
}

// cleanupExpired removes all expired items from the cache
func (m *MemoryCacheBackend) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var keysToDelete []string
	for key, item := range m.items {
		if item.isExpired() {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		m.deleteItemLocked(key)
	}
}

// Get retrieves a value from the cache
func (m *MemoryCacheBackend) Get(ctx context.Context, key string) (interface{}, error) {
	if m.closed.Load() {
		return nil, ErrBackendUnavailable
	}

	start := time.Now()
	defer func() {
		duration := time.Since(start).Nanoseconds()
		m.totalGetTime.Add(duration)
		m.getCount.Add(1)
	}()

	m.mu.RLock()
	item, exists := m.items[key]
	m.mu.RUnlock()

	if !exists {
		m.misses.Add(1)
		return nil, ErrCacheMiss
	}

	if item.isExpired() {
		m.mu.Lock()
		m.deleteItemLocked(key)
		m.mu.Unlock()
		m.misses.Add(1)
		return nil, ErrCacheMiss
	}

	// Update access time and count
	m.mu.Lock()
	item.accessedAt = time.Now()
	item.accessCount++
	// Move to front of LRU list
	if m.evictionPolicy == "lru" && item.element != nil {
		m.lruList.MoveToFront(item.element)
	}
	m.mu.Unlock()

	m.hits.Add(1)
	return item.value, nil
}

// Set stores a value in the cache with optional TTL
func (m *MemoryCacheBackend) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	start := time.Now()
	defer func() {
		duration := time.Since(start).Nanoseconds()
		m.totalSetTime.Add(duration)
		m.setCount.Add(1)
	}()

	// Calculate item size (simplified estimation)
	itemSize := int64(len(key)) + estimateValueSize(value)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we need to evict items
	if m.currentSize >= m.maxSize || m.currentMemory+itemSize > m.maxMemory {
		m.evictLocked()
	}

	// Check if key exists
	if oldItem, exists := m.items[key]; exists {
		m.currentMemory -= oldItem.size
		if oldItem.element != nil {
			m.lruList.Remove(oldItem.element)
		}
	} else {
		m.currentSize++
	}

	now := time.Now()
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}

	item := &memoryCacheItem{
		key:         key,
		value:       value,
		expiresAt:   expiresAt,
		createdAt:   now,
		accessedAt:  now,
		accessCount: 0,
		size:        itemSize,
	}

	// Add to LRU list
	if m.evictionPolicy == "lru" {
		item.element = m.lruList.PushFront(item)
	}

	m.items[key] = item
	m.currentMemory += itemSize
	m.sets.Add(1)

	return nil
}

// Delete removes a key from the cache
func (m *MemoryCacheBackend) Delete(ctx context.Context, key string) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.items[key]; !exists {
		return nil
	}

	m.deleteItemLocked(key)
	m.deletes.Add(1)
	return nil
}

// deleteItemLocked deletes an item without acquiring the lock (must be called with lock held)
func (m *MemoryCacheBackend) deleteItemLocked(key string) {
	if item, exists := m.items[key]; exists {
		m.currentMemory -= item.size
		m.currentSize--
		if item.element != nil {
			m.lruList.Remove(item.element)
		}
		delete(m.items, key)
	}
}

// evictLocked evicts items based on the eviction policy (must be called with lock held)
func (m *MemoryCacheBackend) evictLocked() {
	if m.evictionPolicy == "lru" && m.lruList.Len() > 0 {
		// Evict least recently used item
		element := m.lruList.Back()
		if element != nil {
			item := element.Value.(*memoryCacheItem)
			m.deleteItemLocked(item.key)
			m.evictions.Add(1)
		}
	}
}

// Exists checks if a key exists in the cache
func (m *MemoryCacheBackend) Exists(ctx context.Context, key string) (bool, error) {
	if m.closed.Load() {
		return false, ErrBackendUnavailable
	}

	m.mu.RLock()
	item, exists := m.items[key]
	m.mu.RUnlock()

	if !exists {
		return false, nil
	}

	return !item.isExpired(), nil
}

// Clear removes all items from the cache
func (m *MemoryCacheBackend) Clear(ctx context.Context) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.items = make(map[string]*memoryCacheItem)
	m.lruList = list.New()
	m.currentSize = 0
	m.currentMemory = 0

	return nil
}

// Keys returns all keys matching the pattern (use "*" for all keys)
func (m *MemoryCacheBackend) Keys(ctx context.Context, pattern string) ([]string, error) {
	if m.closed.Load() {
		return nil, ErrBackendUnavailable
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for key, item := range m.items {
		if !item.isExpired() && matchPattern(pattern, key) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Size returns the number of items in the cache
func (m *MemoryCacheBackend) Size(ctx context.Context) (int64, error) {
	if m.closed.Load() {
		return 0, ErrBackendUnavailable
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.currentSize, nil
}

// TTL returns the remaining time-to-live for a key
func (m *MemoryCacheBackend) TTL(ctx context.Context, key string) (time.Duration, error) {
	if m.closed.Load() {
		return 0, ErrBackendUnavailable
	}

	m.mu.RLock()
	item, exists := m.items[key]
	m.mu.RUnlock()

	if !exists || item.isExpired() {
		return 0, ErrCacheMiss
	}

	if item.expiresAt.IsZero() {
		return 0, nil // No expiration
	}

	remaining := time.Until(item.expiresAt)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}

// Expire updates the TTL for an existing key
func (m *MemoryCacheBackend) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	item, exists := m.items[key]
	if !exists || item.isExpired() {
		return ErrCacheMiss
	}

	if ttl > 0 {
		item.expiresAt = time.Now().Add(ttl)
	} else {
		item.expiresAt = time.Time{} // Remove expiration
	}

	return nil
}

// GetStats returns statistics about the cache backend
func (m *MemoryCacheBackend) GetStats(ctx context.Context) (*BackendStats, error) {
	if m.closed.Load() {
		return nil, ErrBackendUnavailable
	}

	m.mu.RLock()
	lastError := m.lastError
	lastErrorTime := m.lastErrorTime
	m.mu.RUnlock()

	avgGetLatency := time.Duration(0)
	if getCount := m.getCount.Load(); getCount > 0 {
		avgGetLatency = time.Duration(m.totalGetTime.Load() / getCount)
	}

	avgSetLatency := time.Duration(0)
	if setCount := m.setCount.Load(); setCount > 0 {
		avgSetLatency = time.Duration(m.totalSetTime.Load() / setCount)
	}

	return &BackendStats{
		Type:              TypeMemory,
		Hits:              m.hits.Load(),
		Misses:            m.misses.Load(),
		Sets:              m.sets.Load(),
		Deletes:           m.deletes.Load(),
		Errors:            m.errors.Load(),
		Evictions:         m.evictions.Load(),
		CurrentSize:       m.currentSize,
		MaxSize:           m.maxSize,
		MemoryUsage:       m.currentMemory,
		AverageGetLatency: avgGetLatency,
		AverageSetLatency: avgSetLatency,
		LastError:         lastError,
		LastErrorTime:     lastErrorTime,
		Uptime:            time.Since(m.startTime),
		StartTime:         m.startTime,
	}, nil
}

// Ping checks if the backend is healthy
func (m *MemoryCacheBackend) Ping(ctx context.Context) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}
	return nil
}

// Close closes the backend and releases resources
func (m *MemoryCacheBackend) Close() error {
	if m.closed.Swap(true) {
		return nil // Already closed
	}

	m.cleanupTicker.Stop()
	close(m.cleanupDone)

	m.mu.Lock()
	m.items = nil
	m.lruList = nil
	m.mu.Unlock()

	return nil
}

// IsHealthy returns true if the backend is healthy
func (m *MemoryCacheBackend) IsHealthy() bool {
	return !m.closed.Load()
}

// Type returns the backend type
func (m *MemoryCacheBackend) Type() BackendType {
	return TypeMemory
}

// Capabilities returns the backend capabilities
func (m *MemoryCacheBackend) Capabilities() *BackendCapabilities {
	return &BackendCapabilities{
		Distributed:         false,
		Persistent:          false,
		Eviction:            true,
		TTL:                 true,
		MaxKeySize:          1024,     // 1KB
		MaxValueSize:        10485760, // 10MB
		MaxKeys:             m.maxSize,
		SupportsExpire:      true,
		SupportsMultiGet:    true,
		SupportsTransaction: false,
		SupportsCompression: false,
		RequiresSerialize:   false,
	}
}

// Helper functions

// estimateValueSize estimates the size of a value in bytes
func estimateValueSize(value interface{}) int64 {
	// This is a simplified estimation
	// In production, you might want to use a more accurate method
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case int, int32, int64, uint, uint32, uint64:
		return 8
	case float32, float64:
		return 8
	case bool:
		return 1
	default:
		// For complex types, use a default estimate
		return 256
	}
}

// matchPattern checks if a key matches a pattern (simplified glob matching)
func matchPattern(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	// Simplified pattern matching - in production, use a proper glob library
	return key == pattern || (len(pattern) > 0 && pattern[0] == '*' &&
		len(key) >= len(pattern)-1 && key[len(key)-len(pattern)+1:] == pattern[1:])
}
