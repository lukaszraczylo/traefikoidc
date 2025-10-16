package cache

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Type defines the type of cache for optimized behavior
type Type string

const (
	TypeToken    Type = "token"
	TypeMetadata Type = "metadata"
	TypeJWK      Type = "jwk"
	TypeSession  Type = "session"
	TypeGeneral  Type = "general"
)

// Logger interface for cache operations
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

// Config provides configuration for the cache
type Config struct {
	Type              Type
	MaxSize           int
	MaxMemoryBytes    int64
	DefaultTTL        time.Duration
	CleanupInterval   time.Duration
	EnableCompression bool
	EnableMetrics     bool
	EnableAutoCleanup bool
	EnableMemoryLimit bool
	Logger            Logger

	// Type-specific configurations
	TokenConfig    *TokenConfig
	MetadataConfig *MetadataConfig
	JWKConfig      *JWKConfig
}

// TokenConfig provides token-specific cache configuration
type TokenConfig struct {
	BlacklistTTL        time.Duration
	RefreshTokenTTL     time.Duration
	EnableTokenRotation bool
}

// MetadataConfig provides metadata-specific cache configuration
type MetadataConfig struct {
	GracePeriod                    time.Duration
	ExtendedGracePeriod            time.Duration
	MaxGracePeriod                 time.Duration
	SecurityCriticalMaxGracePeriod time.Duration
	SecurityCriticalFields         []string
}

// JWKConfig provides JWK-specific cache configuration
type JWKConfig struct {
	RefreshInterval time.Duration
	MinRefreshTime  time.Duration
	MaxKeyAge       time.Duration
}

// Item represents a single cache entry
type Item struct {
	Key          string
	Value        interface{}
	Size         int64
	ExpiresAt    time.Time
	LastAccessed time.Time
	AccessCount  int64
	CacheType    Type

	// Type-specific metadata
	Metadata map[string]interface{}

	// LRU list element reference
	element *list.Element
}

// Cache provides a single, unified cache implementation
type Cache struct {
	mu      sync.RWMutex
	items   map[string]*Item
	lruList *list.List
	config  Config
	logger  Logger

	// Memory management
	currentSize   int64
	currentMemory int64

	// Metrics
	hits      int64
	misses    int64
	evictions int64
	sets      int64

	// Lifecycle management
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	stopCleanup chan bool
	closed      int32
}

// DefaultConfig returns a default cache configuration
func DefaultConfig() Config {
	return Config{
		Type:              TypeGeneral,
		MaxSize:           1000,
		MaxMemoryBytes:    64 * 1024 * 1024, // 64MB
		DefaultTTL:        10 * time.Minute,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
	}
}

// New creates a new cache instance
func New(config Config) *Cache {
	if config.Logger == nil {
		config.Logger = &noOpLogger{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &Cache{
		items:   make(map[string]*Item),
		lruList: list.New(),
		config:  config,
		logger:  config.Logger,
		ctx:     ctx,
		cancel:  cancel,
	}

	if config.EnableAutoCleanup && config.CleanupInterval > 0 {
		c.stopCleanup = make(chan bool)
		c.startCleanupRoutine()
	}

	return c
}

// Set stores a value with TTL
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) error {
	if atomic.LoadInt32(&c.closed) == 1 {
		return fmt.Errorf("cache is closed")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate size
	size := c.estimateSize(value)

	// Check memory limit
	if c.config.EnableMemoryLimit && c.currentMemory+size > c.config.MaxMemoryBytes {
		c.evictLRU()
	}

	// Check size limit
	if c.config.MaxSize > 0 && len(c.items) >= c.config.MaxSize {
		c.evictLRU()
	}

	// Create or update item
	item := &Item{
		Key:          key,
		Value:        value,
		Size:         size,
		ExpiresAt:    time.Now().Add(ttl),
		LastAccessed: time.Now(),
		AccessCount:  0,
		CacheType:    c.config.Type,
		Metadata:     make(map[string]interface{}),
	}

	// Remove old item if exists
	if oldItem, exists := c.items[key]; exists {
		c.lruList.Remove(oldItem.element)
		c.currentMemory -= oldItem.Size
		c.currentSize--
	}

	// Add new item
	item.element = c.lruList.PushFront(item)
	c.items[key] = item
	c.currentMemory += size
	c.currentSize++
	atomic.AddInt64(&c.sets, 1)

	c.logger.Debugf("Cache: Set key=%s, size=%d, ttl=%v", key, size, ttl)
	return nil
}

// Get retrieves a value from cache
func (c *Cache) Get(key string) (interface{}, bool) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item, exists := c.items[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Check expiration
	if time.Now().After(item.ExpiresAt) {
		c.removeItem(key, item)
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Update LRU
	c.lruList.MoveToFront(item.element)
	item.LastAccessed = time.Now()
	item.AccessCount++
	atomic.AddInt64(&c.hits, 1)

	return item.Value, true
}

// Delete removes a key from cache
func (c *Cache) Delete(key string) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.items[key]; exists {
		c.removeItem(key, item)
	}
}

// Clear removes all items from cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*Item)
	c.lruList.Init()
	c.currentSize = 0
	c.currentMemory = 0
}

// Size returns the number of items in cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// SetMaxSize updates the maximum cache size
func (c *Cache) SetMaxSize(size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.MaxSize = size

	// Evict items if necessary
	for len(c.items) > size && c.lruList.Len() > 0 {
		c.evictLRU()
	}
}

// GetStats returns cache statistics
func (c *Cache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"size":       c.currentSize,
		"memory":     c.currentMemory,
		"hits":       atomic.LoadInt64(&c.hits),
		"misses":     atomic.LoadInt64(&c.misses),
		"evictions":  atomic.LoadInt64(&c.evictions),
		"sets":       atomic.LoadInt64(&c.sets),
		"hit_rate":   c.calculateHitRate(),
		"cache_type": string(c.config.Type),
	}
}

// Close gracefully shuts down the cache
func (c *Cache) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return fmt.Errorf("cache already closed")
	}

	c.cancel()
	if c.config.EnableAutoCleanup {
		close(c.stopCleanup)
		c.wg.Wait()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Clear inline to avoid double locking
	c.items = make(map[string]*Item)
	c.lruList.Init()
	c.currentSize = 0
	c.currentMemory = 0

	return nil
}

// Cleanup removes expired items
func (c *Cache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for key, item := range c.items {
		if now.After(item.ExpiresAt) {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		if item, exists := c.items[key]; exists {
			c.removeItem(key, item)
		}
	}

	c.logger.Debugf("Cache cleanup: removed %d expired items", len(toRemove))
}

// Private methods

func (c *Cache) removeItem(key string, item *Item) {
	c.lruList.Remove(item.element)
	delete(c.items, key)
	c.currentMemory -= item.Size
	c.currentSize--
}

func (c *Cache) evictLRU() {
	if elem := c.lruList.Back(); elem != nil {
		item, _ := elem.Value.(*Item) // Safe to ignore: type assertion from known type
		c.removeItem(item.Key, item)
		atomic.AddInt64(&c.evictions, 1)
		c.logger.Debugf("Cache: Evicted LRU item key=%s", item.Key)
	}
}

func (c *Cache) estimateSize(value interface{}) int64 {
	// Simple size estimation
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case map[string]interface{}:
		// Rough estimation for maps
		data, _ := json.Marshal(v)
		return int64(len(data))
	default:
		// Default size for unknown types
		return 256
	}
}

func (c *Cache) calculateHitRate() float64 {
	hits := atomic.LoadInt64(&c.hits)
	misses := atomic.LoadInt64(&c.misses)
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total)
}

func (c *Cache) startCleanupRoutine() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.config.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.Cleanup()
			case <-c.stopCleanup:
				return
			case <-c.ctx.Done():
				return
			}
		}
	}()
}

// noOpLogger provides a no-op logger implementation
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string)                                {}
func (l *noOpLogger) Debugf(format string, args ...interface{})       {}
func (l *noOpLogger) Info(msg string)                                 {}
func (l *noOpLogger) Infof(format string, args ...interface{})        {}
func (l *noOpLogger) Error(msg string)                                {}
func (l *noOpLogger) Errorf(format string, args ...interface{})       {}
func (l *noOpLogger) Warn(msg string)                                 {}
func (l *noOpLogger) Warnf(format string, args ...interface{})        {}
func (l *noOpLogger) Fatal(msg string)                                {}
func (l *noOpLogger) Fatalf(format string, args ...interface{})       {}
func (l *noOpLogger) WithField(key string, value interface{}) Logger  { return l }
func (l *noOpLogger) WithFields(fields map[string]interface{}) Logger { return l }
