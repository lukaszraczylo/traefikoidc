package traefikoidc

import (
	"sync"
	"time"
)

const (
	defaultBlacklistDuration = 24 * time.Hour
)

// CacheManager manages all caching components using the universal cache
type CacheManager struct {
	manager *UniversalCacheManager
	mu      sync.RWMutex
}

var (
	globalCacheManagerInstance *CacheManager
	cacheManagerInitOnce       sync.Once
)

// GetGlobalCacheManager returns a singleton CacheManager instance
// Deprecated: Use GetGlobalCacheManagerWithConfig instead
func GetGlobalCacheManager(wg *sync.WaitGroup) *CacheManager {
	return GetGlobalCacheManagerWithConfig(wg, nil)
}

// GetGlobalCacheManagerWithConfig returns a singleton CacheManager instance with optional Redis configuration
func GetGlobalCacheManagerWithConfig(wg *sync.WaitGroup, config *Config) *CacheManager {
	cacheManagerInitOnce.Do(func() {
		var redisConfig *RedisConfig
		var logger *Logger

		if config != nil {
			logger = NewLogger(config.LogLevel)

			// Initialize Redis config if not present
			if config.Redis == nil {
				config.Redis = &RedisConfig{}
			}

			// Apply environment variable fallbacks for fields not set in config
			// This allows env vars to be used as optional overrides
			config.Redis.ApplyEnvFallbacks()

			// Apply defaults after env fallbacks
			config.Redis.ApplyDefaults()

			redisConfig = config.Redis
		}

		globalCacheManagerInstance = &CacheManager{
			manager: GetUniversalCacheManagerWithConfig(logger, redisConfig),
		}
	})
	return globalCacheManagerInstance
}

// GetSharedTokenBlacklist returns the shared token blacklist cache
func (cm *CacheManager) GetSharedTokenBlacklist() CacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &CacheInterfaceWrapper{cache: cm.manager.GetBlacklistCache(), managed: true}
}

// GetSharedTokenCache returns the shared token cache
func (cm *CacheManager) GetSharedTokenCache() *TokenCache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &TokenCache{cache: cm.manager.GetTokenCache()}
}

// GetSharedMetadataCache returns the shared metadata cache
func (cm *CacheManager) GetSharedMetadataCache() *MetadataCache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &MetadataCache{
		cache:  cm.manager.GetMetadataCache(),
		logger: cm.manager.logger,
	}
}

// GetSharedJWKCache returns the shared JWK cache
func (cm *CacheManager) GetSharedJWKCache() JWKCacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &JWKCache{cache: cm.manager.GetJWKCache()}
}

// GetSharedIntrospectionCache returns the shared token introspection cache
// for caching OAuth 2.0 Token Introspection (RFC 7662) results
func (cm *CacheManager) GetSharedIntrospectionCache() CacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &CacheInterfaceWrapper{cache: cm.manager.GetIntrospectionCache(), managed: true}
}

// GetSharedTokenTypeCache returns the shared token type cache
// for caching token type detection results to improve performance
func (cm *CacheManager) GetSharedTokenTypeCache() CacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &CacheInterfaceWrapper{cache: cm.manager.GetTokenTypeCache(), managed: true}
}

// Close gracefully shuts down all cache components
func (cm *CacheManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.manager.Close()
}

// CleanupGlobalCacheManager cleans up the global cache manager
func CleanupGlobalCacheManager() error {
	if globalCacheManagerInstance != nil {
		return globalCacheManagerInstance.Close()
	}
	return nil
}

// CacheInterfaceWrapper wraps UniversalCache to implement CacheInterface
type CacheInterfaceWrapper struct {
	cache   *UniversalCache
	managed bool // If true, cache is managed globally and Close() is a no-op
}

// Set stores a value
func (c *CacheInterfaceWrapper) Set(key string, value interface{}, ttl time.Duration) {
	_ = c.cache.Set(key, value, ttl) // Safe to ignore: cache set failures are non-critical
}

// Get retrieves a value
func (c *CacheInterfaceWrapper) Get(key string) (interface{}, bool) {
	return c.cache.Get(key)
}

// Delete removes a key
func (c *CacheInterfaceWrapper) Delete(key string) {
	c.cache.Delete(key)
}

// SetMaxSize updates the max size
func (c *CacheInterfaceWrapper) SetMaxSize(size int) {
	c.cache.SetMaxSize(size)
}

// Cleanup triggers immediate cleanup of expired items
func (c *CacheInterfaceWrapper) Cleanup() {
	c.cache.Cleanup()
}

// Close shuts down the cache if it's not managed globally.
// For managed caches (from UniversalCacheManager), this is a no-op to prevent log flooding
// when multiple plugin instances are closed during Traefik configuration reloads.
func (c *CacheInterfaceWrapper) Close() {
	if c.managed {
		// Cache is managed globally by UniversalCacheManager, so we don't close it here.
		return
	}
	// Standalone cache - close it properly to stop cleanup goroutines
	if c.cache != nil {
		_ = c.cache.Close() // Safe to ignore: closing cache is best-effort during shutdown
	}
}

// Size returns the number of items
func (c *CacheInterfaceWrapper) Size() int {
	return c.cache.Size()
}

// Clear removes all items
func (c *CacheInterfaceWrapper) Clear() {
	c.cache.Clear()
}

// GetStats returns cache statistics
func (c *CacheInterfaceWrapper) GetStats() map[string]interface{} {
	return c.cache.GetMetrics()
}

// SetMaxMemory sets the maximum memory limit
func (c *CacheInterfaceWrapper) SetMaxMemory(bytes int64) {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	c.cache.config.MaxMemoryBytes = bytes
}
