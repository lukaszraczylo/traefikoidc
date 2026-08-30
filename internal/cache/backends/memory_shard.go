package backends

import (
	"container/list"
	"sync"
	"time"
)

// cacheShard represents a single shard of the sharded cache
// Each shard has its own lock for reduced contention
type cacheShard struct {
	items      map[string]*memoryCacheItem
	lruList    *list.List
	mu         sync.RWMutex
	maxSize    int64
	maxMemory  int64
	size       int64
	memoryUsed int64
}

// newCacheShard creates a new cache shard
func newCacheShard(maxSize, maxMemory int64) *cacheShard {
	return &cacheShard{
		items:     make(map[string]*memoryCacheItem),
		lruList:   list.New(),
		maxSize:   maxSize,
		maxMemory: maxMemory,
	}
}

// get retrieves a value from this shard
// Returns: value, exists, expired
// peekSize returns the size of the existing entry for key and whether it
// exists, without touching LRU state. Used by the global limit enforcer
// to decide whether a Set is a replacement (count-neutral) or a new item.
func (s *cacheShard) peekSize(key string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, exists := s.items[key]
	if !exists {
		return 0, false
	}
	return item.size, true
}

func (s *cacheShard) get(key string) (interface{}, bool, bool) {
	s.mu.RLock()
	item, exists := s.items[key]
	expired := exists && item.isExpired()
	s.mu.RUnlock()

	if !exists {
		return nil, false, false
	}

	if expired {
		return nil, true, true // exists but expired
	}

	// Update access time and LRU position under write lock
	s.mu.Lock()
	// Re-check item exists (could have been deleted)
	item, exists = s.items[key]
	if exists {
		expired = item.isExpired()
		if !expired {
			item.accessedAt = time.Now()
			item.accessCount++
			if elem, ok := item.element.(*list.Element); ok && elem != nil {
				s.lruList.MoveToFront(elem)
			}
		}
	}
	s.mu.Unlock()

	if !exists || expired {
		return nil, false, false
	}

	return item.value, true, false
}

// set stores a value in this shard
func (s *cacheShard) set(key string, value interface{}, expiresAt time.Time, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Snapshot the existing entry so the eviction decisions account for
	// replacement: refreshing an existing key neither grows the count nor
	// adds its full size, so at capacity it must not evict an unrelated
	// LRU entry (R139 F2).
	oldItem, exists := s.items[key]
	var oldSize int64
	if exists {
		oldSize = oldItem.size
	}

	if s.maxSize > 0 && !exists && s.size >= s.maxSize {
		s.evictLRULocked()
	}
	if s.maxMemory > 0 {
		if net := size - oldSize; net > 0 && s.memoryUsed+net > s.maxMemory {
			s.evictLRULocked()
		}
	}

	// Remove old item if it still exists (it may have been the LRU victim
	// of an eviction above; re-check so we don't double-account).
	if oldItem, exists := s.items[key]; exists {
		s.memoryUsed -= oldItem.size
		if elem, ok := oldItem.element.(*list.Element); ok && elem != nil {
			s.lruList.Remove(elem)
		}
		s.size--
	}

	now := time.Now()
	item := &memoryCacheItem{
		key:         key,
		value:       value,
		expiresAt:   expiresAt,
		createdAt:   now,
		accessedAt:  now,
		accessCount: 0,
		size:        size,
	}

	item.element = s.lruList.PushFront(item)
	s.items[key] = item
	s.size++
	s.memoryUsed += size
}

// delete removes a key from this shard
// Returns true if the key was deleted
func (s *cacheShard) delete(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.items[key]
	if !exists {
		return false
	}

	s.deleteItemLocked(item)
	return true
}

// deleteIfExpired removes a key only if the entry still present is expired.
// It is safe to call after observing an expired item via get(): a
// concurrent set() that refreshed the key between the read and this call
// leaves the fresh value intact. Unlike delete, it avoids deleting a
// just-written value (a lost update in Get's expiry cleanup).
func (s *cacheShard) deleteIfExpired(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.items[key]
	if !exists || !item.isExpired() {
		return false
	}

	s.deleteItemLocked(item)
	return true
}

// exists checks if a key exists (and is not expired)
func (s *cacheShard) exists(key string) bool {
	s.mu.RLock()
	item, exists := s.items[key]
	expired := exists && item.isExpired()
	s.mu.RUnlock()

	return exists && !expired
}

// ttl returns the remaining TTL for a key
func (s *cacheShard) ttl(key string) (time.Duration, bool) {
	s.mu.RLock()
	item, exists := s.items[key]
	expired := exists && item.isExpired()
	var expiresAt time.Time
	if exists {
		expiresAt = item.expiresAt
	}
	s.mu.RUnlock()

	if !exists || expired {
		return 0, false
	}

	if expiresAt.IsZero() {
		return 0, true // No expiration
	}

	remaining := time.Until(expiresAt)
	if remaining < 0 {
		return 0, false
	}

	return remaining, true
}

// expire updates the TTL for an existing key
func (s *cacheShard) expire(key string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.items[key]
	if !exists || item.isExpired() {
		return false
	}

	if ttl > 0 {
		item.expiresAt = time.Now().Add(ttl)
	} else {
		item.expiresAt = time.Time{} // Remove expiration
	}

	return true
}

// keys returns all non-expired keys matching the pattern
func (s *cacheShard) keys(pattern string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	for key, item := range s.items {
		if !item.isExpired() && matchPattern(pattern, key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// clear removes all items from this shard
func (s *cacheShard) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[string]*memoryCacheItem)
	s.lruList.Init()
	s.size = 0
	s.memoryUsed = 0
}

// cleanup removes expired items
// Returns the number of items removed
func (s *cacheShard) cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toRemove []*memoryCacheItem
	for _, item := range s.items {
		if item.isExpired() {
			toRemove = append(toRemove, item)
		}
	}

	for _, item := range toRemove {
		s.deleteItemLocked(item)
	}

	return len(toRemove)
}

// stats returns statistics for this shard
func (s *cacheShard) stats() (size, memory int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.size, s.memoryUsed
}

// deleteItemLocked removes an item (must be called with lock held)
func (s *cacheShard) deleteItemLocked(item *memoryCacheItem) {
	if elem, ok := item.element.(*list.Element); ok && elem != nil {
		s.lruList.Remove(elem)
	}
	delete(s.items, item.key)
	s.size--
	s.memoryUsed -= item.size
}

// evictLRULocked evicts the least recently used item (must be called with lock held)
func (s *cacheShard) evictLRULocked() bool {
	if s.lruList.Len() == 0 {
		return false
	}

	element := s.lruList.Back()
	if element != nil {
		item, ok := element.Value.(*memoryCacheItem)
		if ok {
			s.deleteItemLocked(item)
			return true
		}
	}
	return false
}

// evictOne evicts one item from this shard (for global limit enforcement)
func (s *cacheShard) evictOne() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictLRULocked()
}

// getOldestAccessTime returns the access time of the LRU item (oldest) in this shard
// Returns zero time if shard is empty
func (s *cacheShard) getOldestAccessTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lruList.Len() == 0 {
		return time.Time{}
	}

	element := s.lruList.Back()
	if element != nil {
		item, ok := element.Value.(*memoryCacheItem)
		if ok {
			return item.accessedAt
		}
	}
	return time.Time{}
}

// fnv32 computes FNV-1a hash of a string
// This is a fast, well-distributed hash function
func fnv32(key string) uint32 {
	const (
		offset32 = uint32(2166136261)
		prime32  = uint32(16777619)
	)

	hash := offset32
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= prime32
	}
	return hash
}
