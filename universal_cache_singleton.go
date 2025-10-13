package traefikoidc

import (
	"sync"
	"time"
)

// UniversalCacheManager manages all cache instances using the universal cache
type UniversalCacheManager struct {
	tokenCache         *UniversalCache
	blacklistCache     *UniversalCache
	metadataCache      *UniversalCache
	jwkCache           *UniversalCache
	sessionCache       *UniversalCache
	introspectionCache *UniversalCache // OAuth 2.0 Token Introspection cache (RFC 7662)
	tokenTypeCache     *UniversalCache // Cache for token type detection results
	mu                 sync.RWMutex
	logger             *Logger
}

var (
	universalCacheManager     *UniversalCacheManager
	universalCacheManagerOnce sync.Once
)

// GetUniversalCacheManager returns the singleton universal cache manager
func GetUniversalCacheManager(logger *Logger) *UniversalCacheManager {
	universalCacheManagerOnce.Do(func() {
		if logger == nil {
			logger = GetSingletonNoOpLogger()
		}

		universalCacheManager = &UniversalCacheManager{
			logger: logger,
		}

		// Initialize token cache - CRITICAL FIX: Reduced from 5000 to 1000
		universalCacheManager.tokenCache = NewUniversalCache(UniversalCacheConfig{
			Type:           CacheTypeToken,
			MaxSize:        1000,            // CRITICAL FIX: Reduced from 5000 to 1000 items
			MaxMemoryBytes: 5 * 1024 * 1024, // CRITICAL FIX: Added 5MB memory limit
			DefaultTTL:     1 * time.Hour,
			Logger:         logger,
		})

		// Initialize blacklist cache
		universalCacheManager.blacklistCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeToken,
			MaxSize:    1000,
			DefaultTTL: 24 * time.Hour,
			Logger:     logger,
		})

		// Initialize metadata cache with grace periods
		universalCacheManager.metadataCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeMetadata,
			MaxSize:    100,
			DefaultTTL: 1 * time.Hour,
			MetadataConfig: &MetadataCacheConfig{
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
			},
			Logger: logger,
		})

		// Initialize JWK cache
		universalCacheManager.jwkCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeJWK,
			MaxSize:    200,
			DefaultTTL: 1 * time.Hour,
			Logger:     logger,
		})

		// Initialize session cache - CRITICAL FIX: Reduced from 10000 to 2000
		universalCacheManager.sessionCache = NewUniversalCache(UniversalCacheConfig{
			Type:           CacheTypeSession,
			MaxSize:        2000,            // CRITICAL FIX: Reduced from 10000 to 2000 items
			MaxMemoryBytes: 5 * 1024 * 1024, // CRITICAL FIX: Added 5MB memory limit
			DefaultTTL:     30 * time.Minute,
			Logger:         logger,
		})

		// Initialize introspection cache for OAuth 2.0 Token Introspection (RFC 7662)
		universalCacheManager.introspectionCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeToken,  // Use token cache type for introspection results
			MaxSize:    1000,            // Cache up to 1000 introspection results
			DefaultTTL: 5 * time.Minute, // Short TTL for security (introspect frequently)
			Logger:     logger,
		})

		// Initialize token type cache for performance optimization
		universalCacheManager.tokenTypeCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeToken,  // Use token cache type for token type detection
			MaxSize:    2000,            // Cache up to 2000 token type detections
			DefaultTTL: 5 * time.Minute, // 5 minute TTL for token type detection
			Logger:     logger,
		})
	})

	return universalCacheManager
}

// GetTokenCache returns the token cache
func (m *UniversalCacheManager) GetTokenCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokenCache
}

// GetBlacklistCache returns the blacklist cache
func (m *UniversalCacheManager) GetBlacklistCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blacklistCache
}

// GetMetadataCache returns the metadata cache
func (m *UniversalCacheManager) GetMetadataCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metadataCache
}

// GetJWKCache returns the JWK cache
func (m *UniversalCacheManager) GetJWKCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.jwkCache
}

// GetSessionCache returns the session cache
func (m *UniversalCacheManager) GetSessionCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessionCache
}

// GetIntrospectionCache returns the token introspection cache
func (m *UniversalCacheManager) GetIntrospectionCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.introspectionCache
}

// GetTokenTypeCache returns the token type detection cache
func (m *UniversalCacheManager) GetTokenTypeCache() *UniversalCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokenTypeCache
}

// Close shuts down all caches
func (m *UniversalCacheManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cache := range []*UniversalCache{
		m.tokenCache, m.blacklistCache, m.metadataCache, m.jwkCache, m.sessionCache, m.introspectionCache, m.tokenTypeCache,
	} {
		if cache != nil {
			cache.Close()
		}
	}

	m.logger.Info("UniversalCacheManager: Closed all caches")
	return nil
}

// ResetUniversalCacheManagerForTesting resets the singleton for testing purposes only
// This should only be called in test code to ensure proper cleanup between tests
func ResetUniversalCacheManagerForTesting() {
	if universalCacheManager != nil {
		universalCacheManager.Close()
	}
	universalCacheManagerOnce = sync.Once{}
	universalCacheManager = nil
}
