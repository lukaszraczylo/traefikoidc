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
func GetGlobalCacheManager(wg *sync.WaitGroup) *CacheManager {
	cacheManagerInitOnce.Do(func() {
		globalCacheManagerInstance = &CacheManager{
			manager: GetUniversalCacheManager(nil),
		}
	})
	return globalCacheManagerInstance
}

// GetSharedTokenBlacklist returns the shared token blacklist cache
func (cm *CacheManager) GetSharedTokenBlacklist() CacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &CacheInterfaceWrapper{cache: cm.manager.GetBlacklistCache()}
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
	return &CacheInterfaceWrapper{cache: cm.manager.GetIntrospectionCache()}
}

// GetSharedTokenTypeCache returns the shared token type cache
// for caching token type detection results to improve performance
func (cm *CacheManager) GetSharedTokenTypeCache() CacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &CacheInterfaceWrapper{cache: cm.manager.GetTokenTypeCache()}
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
	cache *UniversalCache
}

// Set stores a value
func (c *CacheInterfaceWrapper) Set(key string, value interface{}, ttl time.Duration) {
	c.cache.Set(key, value, ttl)
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

// Close shuts down the cache
func (c *CacheInterfaceWrapper) Close() {
	// Close the underlying cache to stop goroutines
	if c.cache != nil {
		c.cache.Close()
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
