// Package backend provides cache backend implementations for the Traefik OIDC plugin.
package backends

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Default configuration values
const (
	defaultShardCount      = 256
	defaultMaxSize         = int64(10000)
	defaultMaxMemory       = int64(100 * 1024 * 1024) // 100MB
	defaultCleanupInterval = 5 * time.Minute
)

// memoryCacheItem represents an item in the memory cache
type memoryCacheItem struct {
	expiresAt   time.Time
	createdAt   time.Time
	accessedAt  time.Time
	value       interface{}
	element     interface{} // *list.Element, using interface{} to avoid import cycle
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

// MemoryCacheBackend implements the CacheBackend interface using sharded in-memory storage
// The sharded design reduces lock contention by partitioning keys across multiple shards,
// each with its own lock.
type MemoryCacheBackend struct {
	shards          []*cacheShard
	startTime       time.Time
	lastErrorTime   time.Time
	cleanupDone     chan struct{}
	cleanupTicker   *time.Ticker
	lastError       string
	shardCount      uint32
	shardMask       uint32
	maxSize         int64
	maxMemory       int64
	cleanupInterval time.Duration

	// Global stats (aggregated from shards)
	hits      atomic.Int64
	misses    atomic.Int64
	sets      atomic.Int64
	deletes   atomic.Int64
	evictions atomic.Int64
	errors    atomic.Int64

	// Latency tracking
	totalGetTime atomic.Int64
	totalSetTime atomic.Int64
	getCount     atomic.Int64
	setCount     atomic.Int64

	// State
	closed atomic.Bool
	mu     sync.RWMutex // For global operations like stats and error tracking
}

// NewMemoryCacheBackend creates a new sharded memory cache backend
func NewMemoryCacheBackend(maxSize int64, maxMemory int64, cleanupInterval time.Duration) *MemoryCacheBackend {
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}
	if maxMemory <= 0 {
		maxMemory = defaultMaxMemory
	}
	if cleanupInterval <= 0 {
		cleanupInterval = defaultCleanupInterval
	}

	shardCount := uint32(defaultShardCount)

	// For very small caches, reduce shard count to maintain sensible per-shard limits
	// Ensure each shard can hold at least 2 items for proper LRU behavior
	for shardCount > 1 && maxSize/int64(shardCount) < 2 {
		shardCount /= 2
	}
	if shardCount < 1 {
		shardCount = 1
	}

	// Per-shard limits are soft hints; global limits are enforced
	// Give shards 2x the average to allow for uneven distribution
	shardMaxSize := (maxSize * 2) / int64(shardCount)
	if shardMaxSize < 4 {
		shardMaxSize = 4
	}
	shardMaxMemory := (maxMemory * 2) / int64(shardCount)
	if shardMaxMemory < 4096 {
		shardMaxMemory = 4096 // Minimum 4KB per shard
	}

	m := &MemoryCacheBackend{
		shards:          make([]*cacheShard, shardCount),
		shardCount:      shardCount,
		shardMask:       shardCount - 1, // For fast modulo with power-of-2
		maxSize:         maxSize,
		maxMemory:       maxMemory,
		startTime:       time.Now(),
		cleanupInterval: cleanupInterval,
		cleanupDone:     make(chan struct{}),
	}

	// Initialize shards
	for i := uint32(0); i < shardCount; i++ {
		m.shards[i] = newCacheShard(shardMaxSize, shardMaxMemory)
	}

	// Start cleanup goroutine
	m.cleanupTicker = time.NewTicker(cleanupInterval)
	go m.cleanupLoop()

	return m
}

// getShard returns the shard for a given key
func (m *MemoryCacheBackend) getShard(key string) *cacheShard {
	hash := fnv32(key)
	return m.shards[hash&m.shardMask]
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

// cleanupExpired removes all expired items from all shards
func (m *MemoryCacheBackend) cleanupExpired() {
	if m.closed.Load() {
		return
	}

	totalRemoved := 0
	for _, shard := range m.shards {
		totalRemoved += shard.cleanup()
	}

	if totalRemoved > 0 {
		m.evictions.Add(int64(totalRemoved))
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

	shard := m.getShard(key)
	value, exists, expired := shard.get(key)

	if expired {
		// Clean up expired item
		shard.delete(key)
		m.misses.Add(1)
		return nil, ErrCacheMiss
	}

	if !exists {
		m.misses.Add(1)
		return nil, ErrCacheMiss
	}

	m.hits.Add(1)
	return value, nil
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

	// Calculate item size
	itemSize := int64(len(key)) + estimateValueSize(value)

	// Enforce global limits before adding new item
	m.enforceGlobalLimits(itemSize)

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	shard := m.getShard(key)
	shard.set(key, value, expiresAt, itemSize)

	m.sets.Add(1)
	return nil
}

// enforceGlobalLimits ensures global size and memory limits are respected
// by evicting from shards when necessary
func (m *MemoryCacheBackend) enforceGlobalLimits(newItemSize int64) {
	// Check and enforce size limit
	for {
		totalSize, totalMemory := m.getGlobalStats()

		needsSizeEviction := m.maxSize > 0 && totalSize >= m.maxSize
		needsMemoryEviction := m.maxMemory > 0 && totalMemory+newItemSize > m.maxMemory

		if !needsSizeEviction && !needsMemoryEviction {
			break
		}

		// Find the shard with the most items and evict from it
		evicted := m.evictFromLargestShard()
		if !evicted {
			break // No more items to evict
		}
		m.evictions.Add(1)
	}
}

// getGlobalStats returns the total size and memory usage across all shards
func (m *MemoryCacheBackend) getGlobalStats() (totalSize, totalMemory int64) {
	for _, shard := range m.shards {
		size, memory := shard.stats()
		totalSize += size
		totalMemory += memory
	}
	return
}

// evictFromLargestShard evicts the globally oldest item across all shards
// This provides true LRU behavior even with sharding
func (m *MemoryCacheBackend) evictFromLargestShard() bool {
	var oldestShard *cacheShard
	var oldestTime time.Time

	for _, shard := range m.shards {
		accessTime := shard.getOldestAccessTime()
		// Skip empty shards
		if accessTime.IsZero() {
			continue
		}
		// Find the shard with the oldest (earliest) access time
		if oldestShard == nil || accessTime.Before(oldestTime) {
			oldestTime = accessTime
			oldestShard = shard
		}
	}

	if oldestShard == nil {
		return false
	}

	return oldestShard.evictOne()
}

// Delete removes a key from the cache
func (m *MemoryCacheBackend) Delete(ctx context.Context, key string) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	shard := m.getShard(key)
	if shard.delete(key) {
		m.deletes.Add(1)
	}

	return nil
}

// Exists checks if a key exists in the cache
func (m *MemoryCacheBackend) Exists(ctx context.Context, key string) (bool, error) {
	if m.closed.Load() {
		return false, ErrBackendUnavailable
	}

	shard := m.getShard(key)
	return shard.exists(key), nil
}

// Clear removes all items from the cache
func (m *MemoryCacheBackend) Clear(ctx context.Context) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	for _, shard := range m.shards {
		shard.clear()
	}

	return nil
}

// Keys returns all keys matching the pattern (use "*" for all keys)
func (m *MemoryCacheBackend) Keys(ctx context.Context, pattern string) ([]string, error) {
	if m.closed.Load() {
		return nil, ErrBackendUnavailable
	}

	var allKeys []string
	for _, shard := range m.shards {
		keys := shard.keys(pattern)
		allKeys = append(allKeys, keys...)
	}

	return allKeys, nil
}

// Size returns the total number of items in the cache
func (m *MemoryCacheBackend) Size(ctx context.Context) (int64, error) {
	if m.closed.Load() {
		return 0, ErrBackendUnavailable
	}

	var total int64
	for _, shard := range m.shards {
		size, _ := shard.stats()
		total += size
	}

	return total, nil
}

// TTL returns the remaining time-to-live for a key
func (m *MemoryCacheBackend) TTL(ctx context.Context, key string) (time.Duration, error) {
	if m.closed.Load() {
		return 0, ErrBackendUnavailable
	}

	shard := m.getShard(key)
	ttl, exists := shard.ttl(key)
	if !exists {
		return 0, ErrCacheMiss
	}

	return ttl, nil
}

// Expire updates the TTL for an existing key
func (m *MemoryCacheBackend) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if m.closed.Load() {
		return ErrBackendUnavailable
	}

	shard := m.getShard(key)
	if !shard.expire(key, ttl) {
		return ErrCacheMiss
	}

	return nil
}

// GetStats returns statistics about the cache backend
func (m *MemoryCacheBackend) GetStats(ctx context.Context) (*BackendStats, error) {
	if m.closed.Load() {
		return nil, ErrBackendUnavailable
	}

	// Aggregate stats from all shards
	var totalSize, totalMemory int64
	for _, shard := range m.shards {
		size, memory := shard.stats()
		totalSize += size
		totalMemory += memory
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
		CurrentSize:       totalSize,
		MaxSize:           m.maxSize,
		MemoryUsage:       totalMemory,
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

	// Clear all shards
	for _, shard := range m.shards {
		shard.clear()
	}

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

// GetShardCount returns the number of shards (for testing/monitoring)
func (m *MemoryCacheBackend) GetShardCount() uint32 {
	return m.shardCount
}

// GetShardStats returns per-shard statistics (for monitoring)
func (m *MemoryCacheBackend) GetShardStats() []map[string]int64 {
	stats := make([]map[string]int64, m.shardCount)
	for i, shard := range m.shards {
		size, memory := shard.stats()
		stats[i] = map[string]int64{
			"size":   size,
			"memory": memory,
		}
	}
	return stats
}

// Helper functions

// estimateValueSize estimates the size of a value in bytes
func estimateValueSize(value interface{}) int64 {
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
	// Simplified pattern matching
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(key) >= len(suffix) && key[len(key)-len(suffix):] == suffix
	}
	return key == pattern
}
