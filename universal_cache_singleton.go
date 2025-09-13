package traefikoidc

import (
	"sync"
	"time"
)

// UniversalCacheManager manages all cache instances using the universal cache
type UniversalCacheManager struct {
	tokenCache     *UniversalCache
	blacklistCache *UniversalCache
	metadataCache  *UniversalCache
	jwkCache       *UniversalCache
	sessionCache   *UniversalCache
	mu             sync.RWMutex
	logger         *Logger
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

		// Initialize token cache
		universalCacheManager.tokenCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeToken,
			MaxSize:    5000,
			DefaultTTL: 1 * time.Hour,
			Logger:     logger,
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

		// Initialize session cache
		universalCacheManager.sessionCache = NewUniversalCache(UniversalCacheConfig{
			Type:       CacheTypeSession,
			MaxSize:    10000,
			DefaultTTL: 30 * time.Minute,
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

// Close shuts down all caches
func (m *UniversalCacheManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cache := range []*UniversalCache{
		m.tokenCache, m.blacklistCache, m.metadataCache, m.jwkCache, m.sessionCache,
	} {
		if cache != nil {
			cache.Close()
		}
	}

	m.logger.Info("UniversalCacheManager: Closed all caches")
	return nil
}
