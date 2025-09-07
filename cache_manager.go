// Package traefikoidc provides OIDC authentication middleware for Traefik.
package traefikoidc

import (
	"sync"
	"time"
)

const (
	defaultBlacklistDuration = 24 * time.Hour
	defaultMaxBlacklistSize  = 10000
)

var (
	globalCacheManager *CacheManager
	cacheManagerOnce   sync.Once
	cacheManagerMutex  sync.RWMutex
)

// CacheManager manages all caching components for the OIDC middleware.
// It provides thread-safe access to token blacklist, token cache, metadata cache,
// and JWK cache. This centralizes cache management to ensure efficient memory
// usage and consistent cache behavior across the application.
type CacheManager struct {
	tokenBlacklist CacheInterface
	tokenCache     *TokenCache
	metadataCache  *MetadataCache
	jwkCache       JWKCacheInterface
	mu             sync.RWMutex
}

// GetGlobalCacheManager returns a singleton instance of CacheManager.
// It initializes all cache components on first call and reuses the same instance
// for subsequent calls. This ensures consistent cache state and efficient memory
// usage across the entire application lifecycle.
// Parameters:
//   - wg: WaitGroup for coordinating cache cleanup during shutdown.
//
// Returns:
//   - The global CacheManager instance.
func GetGlobalCacheManager(wg *sync.WaitGroup) *CacheManager {
	cacheManagerOnce.Do(func() {
		globalCacheManager = &CacheManager{
			tokenBlacklist: func() CacheInterface {
				config := DefaultUnifiedCacheConfig()
				config.MaxSize = defaultMaxBlacklistSize
				c := NewUnifiedCache(config)
				return NewCacheAdapter(c)
			}(),
			tokenCache:    NewTokenCache(),
			metadataCache: NewMetadataCache(wg),
			jwkCache:      &JWKCache{},
		}
	})
	return globalCacheManager
}

// GetSharedTokenBlacklist returns the shared token blacklist cache.
// This cache stores revoked or expired tokens to prevent replay attacks.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared token blacklist CacheInterface instance.
func (cm *CacheManager) GetSharedTokenBlacklist() CacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.tokenBlacklist
}

// GetSharedTokenCache returns the shared token cache for verified tokens.
// This cache stores claims from successfully verified tokens to avoid
// repeated verification of the same tokens.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared TokenCache instance.
func (cm *CacheManager) GetSharedTokenCache() *TokenCache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.tokenCache
}

// GetSharedMetadataCache returns the shared metadata cache.
// This cache stores OIDC provider metadata (endpoints, keys) to avoid
// repeated requests to the provider's .well-known configuration endpoint.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared MetadataCache instance.
func (cm *CacheManager) GetSharedMetadataCache() *MetadataCache {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.metadataCache
}

// GetSharedJWKCache returns the shared JWK (JSON Web Key) cache.
// This cache stores public keys from the provider's JWKS endpoint
// for token signature verification.
// Access is protected by read lock to ensure thread safety.
// Returns:
//   - The shared JWKCacheInterface instance.
func (cm *CacheManager) GetSharedJWKCache() JWKCacheInterface {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.jwkCache
}

// Close gracefully shuts down all cache components and releases resources.
// It closes all individual caches and cleans up their associated goroutines.
// This method should be called when the middleware is shutting down.
// Safe to call multiple times.
// Returns:
//   - An error if any cache fails to close properly, nil otherwise.
func (cm *CacheManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.tokenBlacklist != nil {
		cm.tokenBlacklist.Close()
		cm.tokenBlacklist = nil
	}
	if cm.tokenCache != nil {
		cm.tokenCache.Close()
		cm.tokenCache = nil
	}
	if cm.metadataCache != nil {
		cm.metadataCache.Close()
		cm.metadataCache = nil
	}
	if cm.jwkCache != nil {
		cm.jwkCache.Close()
		cm.jwkCache = nil
	}

	return nil
}

// CleanupGlobalCacheManager cleans up the global cache manager instance.
// It closes all cache components but does NOT reset the singleton for re-initialization
// to avoid race conditions with sync.Once. It's safe to call multiple times.
// Returns:
//   - An error if cache cleanup fails, nil otherwise.
func CleanupGlobalCacheManager() error {
	cacheManagerMutex.Lock()
	defer cacheManagerMutex.Unlock()

	if globalCacheManager != nil {
		err := globalCacheManager.Close()
		// Don't reset globalCacheManager to nil or cacheManagerOnce to avoid race conditions
		// The cache manager remains closed and the Close() method handles multiple calls
		return err
	}
	return nil
}
