package traefikoidc

import (
	"hash/fnv"
	"sync"
	"time"
)

// ShardedCache provides a thread-safe cache with sharded locks to reduce contention.
// Instead of a single global mutex, it distributes entries across multiple shards,
// each with its own mutex. This dramatically reduces lock contention under high load.
type ShardedCache struct {
	shards      []*cacheShard
	numShards   uint32
	maxPerShard int
}

// cacheShard represents a single shard with its own mutex and data map.
type cacheShard struct {
	items map[string]*shardedCacheItem
	mu    sync.RWMutex
}

// shardedCacheItem represents an item in the sharded cache with expiration.
type shardedCacheItem struct {
	value     interface{}
	expiresAt time.Time
}

// NewShardedCache creates a new sharded cache with the specified number of shards.
// More shards = less contention but more memory overhead.
// Recommended: 32-256 shards depending on expected concurrency.
func NewShardedCache(numShards int, maxSize int) *ShardedCache {
	if numShards <= 0 {
		numShards = 64 // Default to 64 shards
	}
	if maxSize <= 0 {
		maxSize = 10000 // Default max size
	}

	shards := make([]*cacheShard, numShards)
	maxPerShard := maxSize / numShards
	if maxPerShard < 100 {
		maxPerShard = 100 // Minimum 100 per shard
	}

	for i := 0; i < numShards; i++ {
		shards[i] = &cacheShard{
			items: make(map[string]*shardedCacheItem),
		}
	}

	return &ShardedCache{
		shards: shards,
		// #nosec G115 -- numShards is validated to be positive and small (typically 32-256)
		numShards:   uint32(numShards),
		maxPerShard: maxPerShard,
	}
}

// getShard returns the shard for a given key using FNV-1a hash.
// FNV-1a is fast and provides good distribution.
func (c *ShardedCache) getShard(key string) *cacheShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key)) // hash.Hash.Write never returns an error
	return c.shards[h.Sum32()%c.numShards]
}

// Get retrieves an item from the cache.
// Returns the value and true if found and not expired, nil and false otherwise.
func (c *ShardedCache) Get(key string) (interface{}, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	item, exists := shard.items[key]
	shard.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Check expiration
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		// Item expired - remove it lazily
		c.Delete(key)
		return nil, false
	}

	return item.value, true
}

// Set adds or updates an item in the cache with a TTL.
// If ttl is 0 or negative, the item never expires.
func (c *ShardedCache) Set(key string, value interface{}, ttl time.Duration) {
	shard := c.getShard(key)

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	shard.mu.Lock()
	// Check if we need to evict items
	if len(shard.items) >= c.maxPerShard {
		// Simple eviction: remove expired items first, then oldest
		c.evictFromShardLocked(shard)
	}

	shard.items[key] = &shardedCacheItem{
		value:     value,
		expiresAt: expiresAt,
	}
	shard.mu.Unlock()
}

// Delete removes an item from the cache.
func (c *ShardedCache) Delete(key string) {
	shard := c.getShard(key)
	shard.mu.Lock()
	delete(shard.items, key)
	shard.mu.Unlock()
}

// Exists checks if a key exists in the cache and is not expired.
func (c *ShardedCache) Exists(key string) bool {
	_, exists := c.Get(key)
	return exists
}

// evictFromShardLocked removes expired items from a shard.
// Must be called with shard.mu held.
func (c *ShardedCache) evictFromShardLocked(shard *cacheShard) {
	now := time.Now()
	evicted := 0
	maxEvict := len(shard.items) / 4 // Evict up to 25% of items
	if maxEvict < 10 {
		maxEvict = 10
	}

	// First pass: remove expired items
	for key, item := range shard.items {
		if !item.expiresAt.IsZero() && now.After(item.expiresAt) {
			delete(shard.items, key)
			evicted++
			if evicted >= maxEvict {
				return
			}
		}
	}

	// If still over capacity, remove some items (FIFO approximation via map iteration)
	// This is an approximation since Go maps don't maintain insertion order
	remaining := len(shard.items) - c.maxPerShard + 10 // Leave some headroom
	if remaining > 0 {
		for key := range shard.items {
			delete(shard.items, key)
			remaining--
			if remaining <= 0 {
				break
			}
		}
	}
}

// Cleanup removes all expired items from all shards.
// Call this periodically to prevent memory growth.
func (c *ShardedCache) Cleanup() {
	now := time.Now()
	for _, shard := range c.shards {
		shard.mu.Lock()
		for key, item := range shard.items {
			if !item.expiresAt.IsZero() && now.After(item.expiresAt) {
				delete(shard.items, key)
			}
		}
		shard.mu.Unlock()
	}
}

// Size returns the total number of items across all shards.
func (c *ShardedCache) Size() int {
	total := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		total += len(shard.items)
		shard.mu.RUnlock()
	}
	return total
}

// Clear removes all items from all shards.
func (c *ShardedCache) Clear() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.items = make(map[string]*shardedCacheItem)
		shard.mu.Unlock()
	}
}

// ShardStats returns statistics about each shard for debugging/monitoring.
func (c *ShardedCache) ShardStats() []int {
	stats := make([]int, len(c.shards))
	for i, shard := range c.shards {
		shard.mu.RLock()
		stats[i] = len(shard.items)
		shard.mu.RUnlock()
	}
	return stats
}
