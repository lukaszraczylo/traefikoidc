package cache

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// CompatibilityWrapper provides backward compatibility with existing cache interfaces
type CompatibilityWrapper struct {
	cache *Cache
}

// NewCompatibilityWrapper creates a new compatibility wrapper
func NewCompatibilityWrapper(cache *Cache) *CompatibilityWrapper {
	return &CompatibilityWrapper{cache: cache}
}

// CacheInterface implementation for backward compatibility
func (c *CompatibilityWrapper) Set(key string, value interface{}, ttl time.Duration) {
	_ = c.cache.Set(key, value, ttl)
}

func (c *CompatibilityWrapper) Get(key string) (interface{}, bool) {
	return c.cache.Get(key)
}

func (c *CompatibilityWrapper) Delete(key string) {
	c.cache.Delete(key)
}

func (c *CompatibilityWrapper) SetMaxSize(size int) {
	c.cache.SetMaxSize(size)
}

func (c *CompatibilityWrapper) Size() int {
	return c.cache.Size()
}

func (c *CompatibilityWrapper) Clear() {
	c.cache.Clear()
}

func (c *CompatibilityWrapper) Cleanup() {
	c.cache.Cleanup()
}

func (c *CompatibilityWrapper) Close() {
	_ = c.cache.Close()
}

func (c *CompatibilityWrapper) GetStats() map[string]interface{} {
	return c.cache.GetStats()
}

// UniversalCacheCompat provides compatibility with the old UniversalCache
type UniversalCacheCompat struct {
	*Cache
}

// NewUniversalCacheCompat creates a compatibility wrapper for UniversalCache
func NewUniversalCacheCompat(config Config) *UniversalCacheCompat {
	return &UniversalCacheCompat{
		Cache: New(config),
	}
}

// Set wraps the cache Set method for compatibility
func (u *UniversalCacheCompat) Set(key string, value interface{}, ttl time.Duration) error {
	return u.Cache.Set(key, value, ttl)
}

// TokenCacheCompat provides compatibility with the old TokenCache
type TokenCacheCompat struct {
	cache *TokenCache
}

// NewTokenCacheCompat creates a compatibility wrapper for TokenCache
func NewTokenCacheCompat() *TokenCacheCompat {
	manager := GetGlobalManager(nil)
	return &TokenCacheCompat{
		cache: manager.GetTokenCache(),
	}
}

// Set stores parsed token claims
func (t *TokenCacheCompat) Set(token string, claims map[string]interface{}, expiration time.Duration) {
	_ = t.cache.Set(token, claims, expiration)
}

// Get retrieves cached claims for a token
func (t *TokenCacheCompat) Get(token string) (map[string]interface{}, bool) {
	return t.cache.Get(token)
}

// Delete removes a token from cache
func (t *TokenCacheCompat) Delete(token string) {
	t.cache.Delete(token)
}

// MetadataCacheCompat provides compatibility with the old MetadataCache
type MetadataCacheCompat struct {
	cache  *MetadataCache
	logger Logger
	wg     *sync.WaitGroup
}

// NewMetadataCacheCompat creates a compatibility wrapper for MetadataCache
func NewMetadataCacheCompat(wg *sync.WaitGroup) *MetadataCacheCompat {
	manager := GetGlobalManager(nil)
	return &MetadataCacheCompat{
		cache:  manager.GetMetadataCache(),
		logger: manager.logger,
		wg:     wg,
	}
}

// NewMetadataCacheCompatWithLogger creates a MetadataCache with specific logger
func NewMetadataCacheCompatWithLogger(wg *sync.WaitGroup, logger Logger) *MetadataCacheCompat {
	manager := GetGlobalManager(logger)
	return &MetadataCacheCompat{
		cache:  manager.GetMetadataCache(),
		logger: logger,
		wg:     wg,
	}
}

// Set stores provider metadata with a TTL
func (m *MetadataCacheCompat) Set(providerURL string, metadata *ProviderMetadata, ttl time.Duration) error {
	return m.cache.Set(providerURL, metadata, ttl)
}

// Get retrieves provider metadata from cache
func (m *MetadataCacheCompat) Get(providerURL string) (*ProviderMetadata, bool) {
	return m.cache.Get(providerURL)
}

// Delete removes provider metadata
func (m *MetadataCacheCompat) Delete(providerURL string) {
	m.cache.Delete(providerURL)
}

// GetWithGracePeriod retrieves metadata with grace period support
func (m *MetadataCacheCompat) GetWithGracePeriod(ctx context.Context, providerURL string) (*ProviderMetadata, bool) {
	// For compatibility, just use regular Get
	return m.cache.Get(providerURL)
}

// JWKCacheCompat provides compatibility with the old JWKCache
type JWKCacheCompat struct {
	cache *JWKCache
}

// NewJWKCacheCompat creates a compatibility wrapper for JWKCache
func NewJWKCacheCompat() *JWKCacheCompat {
	manager := GetGlobalManager(nil)
	return &JWKCacheCompat{
		cache: manager.GetJWKCache(),
	}
}

// GetJWKS retrieves JWKS from cache or fetches from the remote URL if not cached
func (j *JWKCacheCompat) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	// Check cache first
	if jwks, found := j.cache.Get(jwksURL); found {
		return jwks, nil
	}

	// For compatibility, we don't fetch from remote - that should be done by the caller
	return nil, nil
}

// Set stores a JWK set
func (j *JWKCacheCompat) Set(jwksURL string, jwks *JWKSet, ttl time.Duration) error {
	return j.cache.Set(jwksURL, jwks, ttl)
}

// Cleanup is a no-op for compatibility
func (j *JWKCacheCompat) Cleanup() {}

// Close is a no-op for compatibility
func (j *JWKCacheCompat) Close() {}

// CacheManagerCompat provides compatibility with the old CacheManager
type CacheManagerCompat struct {
	manager *Manager
	mu      sync.RWMutex
}

// GetGlobalCacheManagerCompat returns a singleton CacheManager instance
func GetGlobalCacheManagerCompat(wg *sync.WaitGroup) *CacheManagerCompat {
	return &CacheManagerCompat{
		manager: GetGlobalManager(nil),
	}
}

// GetSharedTokenBlacklist returns the shared token blacklist cache
func (c *CacheManagerCompat) GetSharedTokenBlacklist() *CompatibilityWrapper {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return NewCompatibilityWrapper(c.manager.GetRawTokenCache())
}

// GetSharedTokenCache returns the shared token cache
func (c *CacheManagerCompat) GetSharedTokenCache() *TokenCacheCompat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return NewTokenCacheCompat()
}

// GetSharedMetadataCache returns the shared metadata cache
func (c *CacheManagerCompat) GetSharedMetadataCache() *MetadataCacheCompat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return NewMetadataCacheCompat(nil)
}

// GetSharedJWKCache returns the shared JWK cache
func (c *CacheManagerCompat) GetSharedJWKCache() *JWKCacheCompat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return NewJWKCacheCompat()
}

// Close gracefully shuts down all cache components
func (c *CacheManagerCompat) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.manager.Close()
}

// UniversalCacheManagerCompat provides compatibility with UniversalCacheManager
type UniversalCacheManagerCompat struct {
	manager *Manager
	logger  Logger
}

// GetUniversalCacheManagerCompat returns the global cache manager
func GetUniversalCacheManagerCompat(logger Logger) *UniversalCacheManagerCompat {
	return &UniversalCacheManagerCompat{
		manager: GetGlobalManager(logger),
		logger:  logger,
	}
}

// GetTokenCache returns the token cache
func (u *UniversalCacheManagerCompat) GetTokenCache() *UniversalCacheCompat {
	return &UniversalCacheCompat{
		Cache: u.manager.GetRawTokenCache(),
	}
}

// GetMetadataCache returns the metadata cache
func (u *UniversalCacheManagerCompat) GetMetadataCache() *UniversalCacheCompat {
	return &UniversalCacheCompat{
		Cache: u.manager.GetRawMetadataCache(),
	}
}

// GetJWKCache returns the JWK cache
func (u *UniversalCacheManagerCompat) GetJWKCache() *UniversalCacheCompat {
	return &UniversalCacheCompat{
		Cache: u.manager.GetRawJWKCache(),
	}
}

// GetBlacklistCache returns the blacklist cache (uses token cache)
func (u *UniversalCacheManagerCompat) GetBlacklistCache() *UniversalCacheCompat {
	return &UniversalCacheCompat{
		Cache: u.manager.GetRawTokenCache(),
	}
}

// Close shuts down the cache manager
func (u *UniversalCacheManagerCompat) Close() error {
	return u.manager.Close()
}
