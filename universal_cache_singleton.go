package traefikoidc

import (
	"context"
	"sync"
	"time"
)

// UniversalCacheManager manages all cache instances using the universal cache
// It runs a single consolidated cleanup goroutine for all caches, reducing
// goroutine count and CPU overhead compared to per-cache cleanup routines.
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

	// Consolidated cleanup management
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	cleanupStarted bool
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

		ctx, cancel := context.WithCancel(context.Background())

		universalCacheManager = &UniversalCacheManager{
			logger: logger,
			ctx:    ctx,
			cancel: cancel,
		}

		// Initialize all caches with SkipAutoCleanup=true to prevent 7 separate cleanup goroutines
		// Instead, we use a single consolidated cleanup routine managed by this manager

		// Initialize token cache - CRITICAL FIX: Reduced from 5000 to 1000
		universalCacheManager.tokenCache = NewUniversalCache(UniversalCacheConfig{
			Type:            CacheTypeToken,
			MaxSize:         1000,            // CRITICAL FIX: Reduced from 5000 to 1000 items
			MaxMemoryBytes:  5 * 1024 * 1024, // CRITICAL FIX: Added 5MB memory limit
			DefaultTTL:      1 * time.Hour,
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
		})

		// Initialize blacklist cache
		universalCacheManager.blacklistCache = NewUniversalCache(UniversalCacheConfig{
			Type:            CacheTypeToken,
			MaxSize:         1000,
			DefaultTTL:      24 * time.Hour,
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
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
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
		})

		// Initialize JWK cache
		universalCacheManager.jwkCache = NewUniversalCache(UniversalCacheConfig{
			Type:            CacheTypeJWK,
			MaxSize:         200,
			DefaultTTL:      1 * time.Hour,
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
		})

		// Initialize session cache - CRITICAL FIX: Reduced from 10000 to 2000
		universalCacheManager.sessionCache = NewUniversalCache(UniversalCacheConfig{
			Type:            CacheTypeSession,
			MaxSize:         2000,            // CRITICAL FIX: Reduced from 10000 to 2000 items
			MaxMemoryBytes:  5 * 1024 * 1024, // CRITICAL FIX: Added 5MB memory limit
			DefaultTTL:      30 * time.Minute,
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
		})

		// Initialize introspection cache for OAuth 2.0 Token Introspection (RFC 7662)
		universalCacheManager.introspectionCache = NewUniversalCache(UniversalCacheConfig{
			Type:            CacheTypeToken,  // Use token cache type for introspection results
			MaxSize:         1000,            // Cache up to 1000 introspection results
			DefaultTTL:      5 * time.Minute, // Short TTL for security (introspect frequently)
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
		})

		// Initialize token type cache for performance optimization
		universalCacheManager.tokenTypeCache = NewUniversalCache(UniversalCacheConfig{
			Type:            CacheTypeToken,  // Use token cache type for token type detection
			MaxSize:         2000,            // Cache up to 2000 token type detections
			DefaultTTL:      5 * time.Minute, // 5 minute TTL for token type detection
			Logger:          logger,
			SkipAutoCleanup: true, // Managed cleanup
		})

		// Start single consolidated cleanup goroutine for all caches
		// This replaces 7 individual cleanup goroutines with 1
		universalCacheManager.startConsolidatedCleanup()
	})

	return universalCacheManager
}

// startConsolidatedCleanup starts a single cleanup goroutine for all caches
// This reduces goroutine count from 7 to 1 and consolidates cleanup operations
func (m *UniversalCacheManager) startConsolidatedCleanup() {
	m.mu.Lock()
	if m.cleanupStarted {
		m.mu.Unlock()
		return
	}
	m.cleanupStarted = true
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		// Use 5-minute interval for consolidated cleanup
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.performConsolidatedCleanup()
			}
		}
	}()

	m.logger.Info("UniversalCacheManager: Started consolidated cleanup routine for all caches")
}

// performConsolidatedCleanup runs cleanup on all caches in sequence
// This is more efficient than parallel cleanup as it reduces lock contention
func (m *UniversalCacheManager) performConsolidatedCleanup() {
	m.mu.RLock()
	caches := []*UniversalCache{
		m.tokenCache,
		m.blacklistCache,
		m.metadataCache,
		m.jwkCache,
		m.sessionCache,
		m.introspectionCache,
		m.tokenTypeCache,
	}
	m.mu.RUnlock()

	totalCleaned := 0
	for _, cache := range caches {
		if cache != nil {
			// Each cache.Cleanup() is self-contained and handles its own locking
			cache.Cleanup()
		}
	}

	if totalCleaned > 0 {
		m.logger.Debugf("UniversalCacheManager: Consolidated cleanup completed for all caches")
	}
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

// Close shuts down all caches and the consolidated cleanup routine
func (m *UniversalCacheManager) Close() error {
	// Stop the consolidated cleanup routine first
	if m.cancel != nil {
		m.cancel()
	}

	// Wait for cleanup routine to finish
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cache := range []*UniversalCache{
		m.tokenCache, m.blacklistCache, m.metadataCache, m.jwkCache, m.sessionCache, m.introspectionCache, m.tokenTypeCache,
	} {
		if cache != nil {
			_ = cache.Close() // Safe to ignore: best effort cache cleanup
		}
	}

	m.cleanupStarted = false
	m.logger.Info("UniversalCacheManager: Closed all caches and cleanup routine")
	return nil
}

// ResetUniversalCacheManagerForTesting resets the singleton for testing purposes only
// This should only be called in test code to ensure proper cleanup between tests
func ResetUniversalCacheManagerForTesting() {
	if universalCacheManager != nil {
		_ = universalCacheManager.Close() // Safe to ignore: test cleanup best effort
	}
	universalCacheManagerOnce = sync.Once{}
	universalCacheManager = nil
}
