package traefikoidc

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// CacheType defines the type of cache for optimized behavior
type CacheType string

const (
	CacheTypeToken    CacheType = "token"
	CacheTypeMetadata CacheType = "metadata"
	CacheTypeJWK      CacheType = "jwk"
	CacheTypeSession  CacheType = "session"
	CacheTypeGeneral  CacheType = "general"
)

// UniversalCacheConfig provides configuration for the universal cache
type UniversalCacheConfig struct {
	Type              CacheType
	MaxSize           int
	MaxMemoryBytes    int64
	DefaultTTL        time.Duration
	CleanupInterval   time.Duration
	EnableCompression bool
	EnableMetrics     bool
	EnableAutoCleanup bool // For backward compatibility
	EnableMemoryLimit bool // For backward compatibility
	Logger            *Logger
	Strategy          CacheStrategy // For backward compatibility

	// SkipAutoCleanup skips starting the per-cache cleanup goroutine.
	// Use this when cleanup is managed externally (e.g., by UniversalCacheManager)
	// to reduce goroutine count and consolidate cleanup operations.
	SkipAutoCleanup bool

	// Type-specific configurations
	TokenConfig    *TokenCacheConfig
	MetadataConfig *MetadataCacheConfig
	JWKConfig      *JWKCacheConfig
}

// TokenCacheConfig provides token-specific cache configuration
type TokenCacheConfig struct {
	BlacklistTTL        time.Duration
	RefreshTokenTTL     time.Duration
	EnableTokenRotation bool
}

// MetadataCacheConfig provides metadata-specific cache configuration
type MetadataCacheConfig struct {
	GracePeriod                    time.Duration
	ExtendedGracePeriod            time.Duration
	MaxGracePeriod                 time.Duration
	SecurityCriticalMaxGracePeriod time.Duration
	SecurityCriticalFields         []string
}

// JWKCacheConfig provides JWK-specific cache configuration
type JWKCacheConfig struct {
	RefreshInterval time.Duration
	MinRefreshTime  time.Duration
	MaxKeyAge       time.Duration
}

// CacheItem represents a single cache entry
type CacheItem struct {
	Key          string
	Value        interface{}
	Size         int64
	ExpiresAt    time.Time
	LastAccessed time.Time
	AccessCount  int64
	CacheType    CacheType

	// Type-specific metadata
	Metadata map[string]interface{}

	// LRU list element reference
	element *list.Element
}

// UniversalCache provides a single, unified cache implementation
// that replaces all other cache types
type UniversalCache struct {
	mu      sync.RWMutex
	items   map[string]*CacheItem
	lruList *list.List
	config  UniversalCacheConfig
	logger  *Logger

	// Backend for distributed caching (NEW)
	backend     backends.CacheBackend
	ownsBackend bool // If true, cache should close backend on Close(); if false, backend is shared

	// Memory management
	currentSize   int64
	currentMemory int64

	// Metrics
	hits      int64
	misses    int64
	evictions int64

	// Lifecycle management
	ctx           context.Context
	cancel        context.CancelFunc
	cleanupTicker *time.Ticker
	wg            sync.WaitGroup
}

// NewUniversalCache creates a new universal cache instance
func NewUniversalCache(config UniversalCacheConfig) *UniversalCache {
	return createUniversalCache(config)
}

// NewUniversalCacheWithBackend creates a new universal cache with a specific backend
func NewUniversalCacheWithBackend(config UniversalCacheConfig, cacheBackend backends.CacheBackend) *UniversalCache {
	cache := createUniversalCache(config)
	cache.backend = cacheBackend
	cache.ownsBackend = false // Shared backend, managed externally
	return cache
}

// createUniversalCache is the internal constructor
func createUniversalCache(config UniversalCacheConfig) *UniversalCache {
	// Apply type-specific defaults first (including MaxSize)
	applyTypeDefaults(&config)

	// Set general defaults only if not already set by type defaults
	if config.MaxSize <= 0 {
		config.MaxSize = 1000
	}
	if config.MaxMemoryBytes <= 0 {
		config.MaxMemoryBytes = 50 * 1024 * 1024 // 50MB default
	}
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = 1 * time.Hour
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = GetSingletonNoOpLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	cache := &UniversalCache{
		items:   make(map[string]*CacheItem),
		lruList: list.New(),
		config:  config,
		logger:  config.Logger,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup routine only if not skipped
	// When cleanup is managed externally (e.g., by UniversalCacheManager),
	// skip per-cache cleanup to reduce goroutine count
	if !config.SkipAutoCleanup {
		cache.startCleanup()
	}

	return cache
}

// applyTypeDefaults applies type-specific default configurations
func applyTypeDefaults(config *UniversalCacheConfig) {
	switch config.Type {
	case CacheTypeToken:
		if config.TokenConfig == nil {
			config.TokenConfig = &TokenCacheConfig{
				BlacklistTTL:        24 * time.Hour,
				RefreshTokenTTL:     7 * 24 * time.Hour,
				EnableTokenRotation: true,
			}
		}
		if config.MaxSize == 0 {
			config.MaxSize = 5000 // Tokens need more entries
		}

	case CacheTypeMetadata:
		if config.MetadataConfig == nil {
			config.MetadataConfig = &MetadataCacheConfig{
				GracePeriod:                    5 * time.Minute,
				ExtendedGracePeriod:            15 * time.Minute,
				MaxGracePeriod:                 30 * time.Minute,
				SecurityCriticalMaxGracePeriod: 15 * time.Minute,
				SecurityCriticalFields: []string{
					"jwks_uri",
					"token_endpoint",
					"authorization_endpoint",
					"issuer",
				},
			}
		}
		// Only set defaults if not already specified
		if config.MaxSize == 0 {
			config.MaxSize = 100 // Fewer providers
		}
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 1 * time.Hour
		}

	case CacheTypeJWK:
		if config.JWKConfig == nil {
			config.JWKConfig = &JWKCacheConfig{
				RefreshInterval: 1 * time.Hour,
				MinRefreshTime:  5 * time.Minute,
				MaxKeyAge:       24 * time.Hour,
			}
		}
		if config.MaxSize == 0 {
			config.MaxSize = 200 // Limited number of keys
		}
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 1 * time.Hour
		}

	case CacheTypeSession:
		if config.MaxSize == 0 {
			config.MaxSize = 10000 // Many concurrent sessions
		}
		if config.DefaultTTL == 0 {
			config.DefaultTTL = 30 * time.Minute
		}

	default:
		// General cache defaults already set
	}
}

// Set stores a value in the cache
func (c *UniversalCache) Set(key string, value interface{}, ttl time.Duration) error {
	// Only use default TTL if ttl is exactly zero (not specified)
	// Negative TTL means the item should expire in the past
	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	// If we have a backend, use it for distributed caching
	if c.backend != nil {
		// Serialize the value
		data, err := c.serialize(value)
		if err != nil {
			c.logger.Errorf("Failed to serialize value for key %s: %v", key, err)
			return err
		}

		// Store in backend
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		if err := c.backend.Set(ctx, c.prefixKey(key), data, ttl); err != nil {
			c.logger.Infof("Backend set error for key %s: %v", key, err)
			// Continue with local cache even if backend fails
		}
	}

	size := c.estimateSize(value)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check memory limits
	if c.config.MaxMemoryBytes > 0 {
		// Evict items if necessary to make room
		for c.currentMemory+size > c.config.MaxMemoryBytes && c.lruList.Len() > 0 {
			c.evictOldest()
		}
	}

	// Check size limits
	if c.lruList.Len() >= c.config.MaxSize {
		c.evictOldest()
	}

	// Update or create item
	now := time.Now()
	if existing, exists := c.items[key]; exists {
		// Update existing item
		c.currentMemory -= existing.Size
		c.lruList.Remove(existing.element)

		existing.Value = value
		existing.Size = size
		existing.ExpiresAt = now.Add(ttl)
		existing.LastAccessed = now
		existing.AccessCount++

		// Move to front
		existing.element = c.lruList.PushFront(key)
		c.currentMemory += size
	} else {
		// Create new item
		item := &CacheItem{
			Key:          key,
			Value:        value,
			Size:         size,
			ExpiresAt:    now.Add(ttl),
			LastAccessed: now,
			AccessCount:  1,
			CacheType:    c.config.Type,
			Metadata:     make(map[string]interface{}),
		}

		item.element = c.lruList.PushFront(key)
		c.items[key] = item

		c.currentSize++
		c.currentMemory += size
	}

	c.logger.Debugf("UniversalCache[%s]: Set key=%s, ttl=%v, size=%d bytes",
		c.config.Type, key, ttl, size)

	return nil
}

// Get retrieves a value from the cache
func (c *UniversalCache) Get(key string) (interface{}, bool) {
	// Try backend first if available (for distributed consistency)
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		data, _, exists, err := c.backend.Get(ctx, c.prefixKey(key))
		if err != nil {
			c.logger.Debugf("Backend get error for key %s: %v", key, err)
			// Fall through to local cache
		} else if exists {
			// Deserialize the value
			var value interface{}
			if err := c.deserialize(data, &value); err != nil {
				c.logger.Errorf("Failed to deserialize value for key %s: %v", key, err)
				// Fall through to local cache
			} else {
				atomic.AddInt64(&c.hits, 1)
				// Update local cache with backend value
				go func() {
					_ = c.updateLocalCache(key, value, c.config.DefaultTTL)
				}()
				return value, true
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item, exists := c.items[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Check expiration
	now := time.Now()
	if now.After(item.ExpiresAt) {
		// For metadata cache, check if we should apply grace period
		// Grace periods are only extended if explicitly marked or if this is a retry after failure
		if c.config.Type == CacheTypeMetadata && c.config.MetadataConfig != nil {
			// Check if grace period has been explicitly activated (e.g., due to provider outage)
			if gracePeriod, ok := item.Metadata["grace_period_active"].(bool); ok && gracePeriod {
				if c.shouldExtendGracePeriod(item, now) {
					newExpiry := c.calculateNewExpiry(item, now)
					item.ExpiresAt = newExpiry
					c.logger.Infof("UniversalCache[%s]: Extended grace period for key=%s until %v",
						c.config.Type, key, newExpiry)
					// Continue to return the cached value during grace period
				} else {
					// Grace period has expired completely
					c.removeItem(key, item)
					atomic.AddInt64(&c.misses, 1)
					return nil, false
				}
			} else {
				// No grace period active, remove expired item
				c.removeItem(key, item)
				atomic.AddInt64(&c.misses, 1)
				return nil, false
			}
		} else {
			// Non-metadata cache or no grace period config
			c.removeItem(key, item)
			atomic.AddInt64(&c.misses, 1)
			return nil, false
		}
	}

	// Update access time and count
	item.LastAccessed = now
	item.AccessCount++

	// Move to front of LRU
	c.lruList.MoveToFront(item.element)

	atomic.AddInt64(&c.hits, 1)
	return item.Value, true
}

// Delete removes a key from the cache
func (c *UniversalCache) Delete(key string) bool {
	// Delete from backend if available
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		if _, err := c.backend.Delete(ctx, c.prefixKey(key)); err != nil {
			c.logger.Debugf("Backend delete error for key %s: %v", key, err)
			// Continue with local delete
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	item, exists := c.items[key]
	if !exists {
		return false
	}

	c.removeItem(key, item)
	return true
}

// Clear removes all items from the cache
func (c *UniversalCache) Clear() {
	// Clear backend if available
	if c.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		if err := c.backend.Clear(ctx); err != nil {
			c.logger.Infof("Backend clear error: %v", err)
			// Continue with local clear
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*CacheItem)
	c.lruList.Init()
	c.currentSize = 0
	c.currentMemory = 0

	c.logger.Infof("UniversalCache[%s]: Cleared all items", c.config.Type)
}

// Size returns the number of items in the cache
func (c *UniversalCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int(c.currentSize)
}

// MemoryUsage returns the current memory usage in bytes
func (c *UniversalCache) MemoryUsage() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentMemory
}

// GetMetrics returns cache metrics
func (c *UniversalCache) GetMetrics() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hitRate := float64(0)
	total := atomic.LoadInt64(&c.hits) + atomic.LoadInt64(&c.misses)
	if total > 0 {
		hitRate = float64(atomic.LoadInt64(&c.hits)) / float64(total)
	}

	return map[string]interface{}{
		"type":       c.config.Type,
		"size":       c.currentSize,
		"entries":    c.currentSize, // Alias for backward compatibility
		"memory":     c.currentMemory,
		"hits":       atomic.LoadInt64(&c.hits),
		"misses":     atomic.LoadInt64(&c.misses),
		"evictions":  atomic.LoadInt64(&c.evictions),
		"hit_rate":   hitRate,
		"max_size":   c.config.MaxSize,
		"max_memory": c.config.MaxMemoryBytes,
	}
}

// Cleanup manually triggers cleanup of expired items
func (c *UniversalCache) Cleanup() {
	c.cleanup()
}

// Close shuts down the cache
func (c *UniversalCache) Close() error {
	c.cancel()

	// Stop cleanup ticker
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}

	// Wait for cleanup routine to finish with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Cleanup routine finished normally
	case <-time.After(2 * time.Second):
		// Timeout waiting for cleanup routine
		c.logger.Debug("UniversalCache[%s]: Timeout waiting for cleanup routine", c.config.Type)
	}

	// Clear all items
	c.Clear()

	// Close backend only if this cache owns it (not shared)
	if c.backend != nil && c.ownsBackend {
		if err := c.backend.Close(); err != nil {
			c.logger.Infof("Failed to close cache backend: %v", err)
		}
	}

	c.logger.Debugf("UniversalCache[%s]: Closed", c.config.Type)
	return nil
}

// removeItem removes an item from the cache (must be called with lock held)
func (c *UniversalCache) removeItem(key string, item *CacheItem) {
	delete(c.items, key)
	c.lruList.Remove(item.element)
	c.currentSize--
	c.currentMemory -= item.Size
}

// evictOldest evicts the oldest item from the cache (must be called with lock held)
func (c *UniversalCache) evictOldest() {
	if elem := c.lruList.Back(); elem != nil {
		key, _ := elem.Value.(string) // Safe to ignore: cache internal type assertion
		if item, exists := c.items[key]; exists {
			c.removeItem(key, item)
			atomic.AddInt64(&c.evictions, 1)
			c.logger.Debugf("UniversalCache[%s]: Evicted key=%s", c.config.Type, key)
		}
	}
}

// SetMaxSize sets the maximum size and evicts items if necessary
func (c *UniversalCache) SetMaxSize(newSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldSize := c.config.MaxSize
	c.config.MaxSize = newSize

	// If the new size is smaller, evict items until we meet the new limit
	if newSize < oldSize {
		for c.lruList.Len() > newSize {
			c.evictOldest()
		}
		c.logger.Infof("UniversalCache[%s]: Resized from %d to %d, evicted %d items",
			c.config.Type, oldSize, newSize, oldSize-c.lruList.Len())
	}
}

// ActivateGracePeriod activates grace period for a specific key (e.g., due to provider outage)
func (c *UniversalCache) ActivateGracePeriod(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.items[key]; exists {
		item.Metadata["grace_period_active"] = true
		c.logger.Infof("UniversalCache[%s]: Activated grace period for key=%s", c.config.Type, key)
	}
}

// startCleanup starts the background cleanup routine
func (c *UniversalCache) startCleanup() {
	c.cleanupTicker = time.NewTicker(c.config.CleanupInterval)
	c.wg.Add(1)

	go func() {
		defer c.wg.Done()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.cleanupTicker.C:
				c.cleanup()
			}
		}
	}()
}

// cleanup removes expired items from the cache
func (c *UniversalCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for key, item := range c.items {
		if now.After(item.ExpiresAt) {
			// Special handling for metadata cache grace periods
			if c.config.Type == CacheTypeMetadata && c.config.MetadataConfig != nil {
				// Only keep items that have active grace period and are still within limits
				if gracePeriod, ok := item.Metadata["grace_period_active"].(bool); ok && gracePeriod {
					if !c.shouldExtendGracePeriod(item, now) {
						toRemove = append(toRemove, key)
					}
				} else {
					// No grace period active, remove expired item
					toRemove = append(toRemove, key)
				}
			} else {
				toRemove = append(toRemove, key)
			}
		}
	}

	for _, key := range toRemove {
		if item, exists := c.items[key]; exists {
			c.removeItem(key, item)
		}
	}

	if len(toRemove) > 0 {
		c.logger.Debugf("UniversalCache[%s]: Cleaned up %d expired items",
			c.config.Type, len(toRemove))
	}
}

// estimateSize estimates the memory size of a value
func (c *UniversalCache) estimateSize(value interface{}) int64 {
	// Basic size estimation - can be enhanced based on type
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case map[string]interface{}:
		// Rough estimate for maps
		return int64(len(v) * 100)
	default:
		// Default estimate
		return 64
	}
}

// shouldExtendGracePeriod determines if grace period should be extended
func (c *UniversalCache) shouldExtendGracePeriod(item *CacheItem, now time.Time) bool {
	if c.config.MetadataConfig == nil {
		return false
	}

	// Check if we're within the maximum grace period
	maxGrace := c.config.MetadataConfig.MaxGracePeriod

	// Check if this is a security-critical field
	if fieldName, ok := item.Metadata["field"].(string); ok {
		for _, critical := range c.config.MetadataConfig.SecurityCriticalFields {
			if fieldName == critical {
				maxGrace = c.config.MetadataConfig.SecurityCriticalMaxGracePeriod
				break
			}
		}
	}

	// Calculate how long since the item originally expired
	timeSinceExpiry := now.Sub(item.ExpiresAt)
	return timeSinceExpiry <= maxGrace
}

// calculateNewExpiry calculates the new expiry time with progressive grace periods
func (c *UniversalCache) calculateNewExpiry(item *CacheItem, now time.Time) time.Time {
	if c.config.MetadataConfig == nil {
		return now.Add(c.config.DefaultTTL)
	}

	// Progressive grace period based on access count
	var gracePeriod time.Duration
	switch {
	case item.AccessCount < 5:
		gracePeriod = c.config.MetadataConfig.GracePeriod
	case item.AccessCount < 10:
		gracePeriod = c.config.MetadataConfig.ExtendedGracePeriod
	default:
		gracePeriod = c.config.MetadataConfig.MaxGracePeriod
	}

	// Apply security limits
	if fieldName, ok := item.Metadata["field"].(string); ok {
		for _, critical := range c.config.MetadataConfig.SecurityCriticalFields {
			if fieldName == critical && gracePeriod > c.config.MetadataConfig.SecurityCriticalMaxGracePeriod {
				gracePeriod = c.config.MetadataConfig.SecurityCriticalMaxGracePeriod
				break
			}
		}
	}

	return now.Add(gracePeriod)
}

// Type-specific helper methods

// SetWithMetadata sets a value with additional metadata
func (c *UniversalCache) SetWithMetadata(key string, value interface{}, ttl time.Duration, metadata map[string]interface{}) error {
	err := c.Set(key, value, ttl)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if item, exists := c.items[key]; exists {
		for k, v := range metadata {
			item.Metadata[k] = v
		}
	}

	return nil
}

// GetTyped retrieves a typed value from the cache
func GetTyped[T any](c *UniversalCache, key string) (T, bool) {
	var zero T
	value, exists := c.Get(key)
	if !exists {
		return zero, false
	}

	typed, ok := value.(T)
	if !ok {
		return zero, false
	}

	return typed, true
}

// TokenCacheOperations provides token-specific operations
func (c *UniversalCache) BlacklistToken(token string, ttl time.Duration) error {
	if c.config.Type != CacheTypeToken {
		return fmt.Errorf("blacklist operation only available for token cache")
	}

	if ttl <= 0 && c.config.TokenConfig != nil {
		ttl = c.config.TokenConfig.BlacklistTTL
	}

	return c.SetWithMetadata(token, true, ttl, map[string]interface{}{
		"blacklisted":    true,
		"blacklisted_at": time.Now(),
	})
}

// IsTokenBlacklisted checks if a token is blacklisted
func (c *UniversalCache) IsTokenBlacklisted(token string) bool {
	if c.config.Type != CacheTypeToken {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if item, exists := c.items[token]; exists {
		if blacklisted, ok := item.Metadata["blacklisted"].(bool); ok {
			return blacklisted
		}
	}

	return false
}

// Getters for backward compatibility with tests

// Mutex returns the cache mutex for backward compatibility
func (c *UniversalCache) Mutex() *sync.RWMutex {
	return &c.mu
}

// Strategy returns the cache strategy for backward compatibility
func (c *UniversalCache) Strategy() CacheStrategy {
	return c.config.Strategy
}

// serialize converts a value to bytes for backend storage
func (c *UniversalCache) serialize(value interface{}) ([]byte, error) {
	// Use JSON for serialization - simple and universal
	return json.Marshal(value)
}

// deserialize converts bytes from backend storage to a value
func (c *UniversalCache) deserialize(data []byte, value interface{}) error {
	// Use JSON for deserialization
	return json.Unmarshal(data, value)
}

// prefixKey adds a cache type prefix to the key for backend storage
func (c *UniversalCache) prefixKey(key string) string {
	return fmt.Sprintf("%s:%s", c.config.Type, key)
}

// updateLocalCache updates the local cache with a value from the backend
func (c *UniversalCache) updateLocalCache(key string, value interface{}, ttl time.Duration) error {
	size := c.estimateSize(value)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check memory limits
	if c.config.MaxMemoryBytes > 0 {
		for c.currentMemory+size > c.config.MaxMemoryBytes && c.lruList.Len() > 0 {
			c.evictOldest()
		}
	}

	// Check size limits
	if c.lruList.Len() >= c.config.MaxSize {
		c.evictOldest()
	}

	now := time.Now()
	item := &CacheItem{
		Key:          key,
		Value:        value,
		Size:         size,
		ExpiresAt:    now.Add(ttl),
		LastAccessed: now,
		AccessCount:  1,
		CacheType:    c.config.Type,
		Metadata:     make(map[string]interface{}),
	}

	item.element = c.lruList.PushFront(key)
	c.items[key] = item

	c.currentSize++
	c.currentMemory += size

	return nil
}
