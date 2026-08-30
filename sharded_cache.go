package traefikoidc

import (
	"hash/fnv"
	"sort"
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
	// nextSeq is a monotonically increasing insertion counter used to evict
	// the OLDEST entries first (FIFO). without an explicit order, Go map
	// iteration order is random, so the old eviction could drop a just-
	// written still-valid entry (e.g. a fresh replay-protection JTI) before
	// its TTL had any effect.
	nextSeq uint64
}

// shardedCacheItem represents an item in the sharded cache with expiration.
type shardedCacheItem struct {
	value     interface{}
	expiresAt time.Time
	seq       uint64 // insertion order; lower = older
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
		// Item expired — remove it lazily, but ONLY if this is still the
		// same entry. A concurrent Set/SetIfAbsent that refreshed the key
		// (e.g. a freshly-recorded replay JTI) since this read must not be
		// removed, else the just-recorded JTI is lost and a duplicate token
		// could pass (R129; matches deleteIfExpired in
		// internal/cache/backends/memory_shard.go).
		shard.mu.Lock()
		if cur, ok := shard.items[key]; ok && cur == item {
			delete(shard.items, key)
		}
		shard.mu.Unlock()
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
	// Overwriting an existing key needs no free slot; only evict when
	// inserting a genuinely new key at capacity, so an overwrite never
	// drops an unrelated oldest still-valid entry and shrinks the shard
	// by one (repeats the R57 hazard) (R153).
	if _, present := shard.items[key]; !present && len(shard.items) >= c.maxPerShard {
		c.evictFromShardLocked(shard)
	}

	shard.items[key] = &shardedCacheItem{
		value:     value,
		expiresAt: expiresAt,
		seq:       shard.nextSeq,
	}
	shard.nextSeq++
	shard.mu.Unlock()
}

// SetIfAbsent atomically inserts the item only if the key is not already
// present and unexpired. Returns true if inserted, false if the key already
// existed (including when a concurrent caller already inserted it). Unlike
// the separate Exists()+Set() check-then-act, this holds the shard lock
// across both operations, closing the double-accept race in replay
// detection where two concurrent requests carrying the same fresh JTI could
// both observe it absent and both be accepted.
func (c *ShardedCache) SetIfAbsent(key string, value interface{}, ttl time.Duration) bool {
	shard := c.getShard(key)

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}

	shard.mu.Lock()
	defer shard.mu.Unlock()

	_, found := shard.items[key]
	if it, exists := shard.items[key]; exists {
		// Present and not expired -> duplicate.
		if it.expiresAt.IsZero() || !time.Now().After(it.expiresAt) {
			return false
		}
		// Present but expired -> treat as absent and replace below.
	}

	// The replace-an-expired path needs no free slot; only evict when the
	// key is absent and the shard is at capacity (R153).
	if !found && len(shard.items) >= c.maxPerShard {
		c.evictFromShardLocked(shard)
	}

	shard.items[key] = &shardedCacheItem{
		value:     value,
		expiresAt: expiresAt,
		seq:       shard.nextSeq,
	}
	shard.nextSeq++
	return true
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

	// If still over capacity, evict the OLDEST entries (lowest insertion seq)
	// until we're at capacity. Evicting by insertion order keeps fresh, still-
	// valid items (e.g. replay-protection JTIs) alive for their full TTL,
	// unlike the previous random-over-eviction which dropped a just-written
	// entry and left each shard ~9 slots under capacity.
	remaining := len(shard.items) - c.maxPerShard + 1
	if remaining > 0 {
		oldest := make([]string, 0, len(shard.items))
		for key := range shard.items {
			oldest = append(oldest, key)
		}
		sort.Slice(oldest, func(i, j int) bool {
			return shard.items[oldest[i]].seq < shard.items[oldest[j]].seq
		})
		for _, key := range oldest[:remaining] {
			delete(shard.items, key)
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
