package traefikoidc

import (
	"sync"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/lukaszraczylo/traefikoidc/internal/cache/resilience"
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

		// Initialize with default in-memory backends
		initializeDefaultCaches(universalCacheManager, logger)
	})

	return universalCacheManager
}

// GetUniversalCacheManagerWithConfig returns the singleton universal cache manager with Redis configuration
func GetUniversalCacheManagerWithConfig(logger *Logger, redisConfig *RedisConfig) *UniversalCacheManager {
	universalCacheManagerOnce.Do(func() {
		if logger == nil {
			logger = GetSingletonNoOpLogger()
		}

		universalCacheManager = &UniversalCacheManager{
			logger: logger,
		}

		if redisConfig != nil && redisConfig.Enabled {
			logger.Infof("Initializing cache manager with Redis backend: %s", redisConfig.Address)
			initializeCachesWithRedis(universalCacheManager, logger, redisConfig)
		} else {
			logger.Info("Initializing cache manager with memory-only backend")
			initializeDefaultCaches(universalCacheManager, logger)
		}
	})

	return universalCacheManager
}

// initializeDefaultCaches initializes caches with memory-only backends
func initializeDefaultCaches(manager *UniversalCacheManager, logger *Logger) {
	// Initialize token cache - CRITICAL FIX: Reduced from 5000 to 1000
	manager.tokenCache = NewUniversalCache(UniversalCacheConfig{
		Type:           CacheTypeToken,
		MaxSize:        1000,            // CRITICAL FIX: Reduced from 5000 to 1000 items
		MaxMemoryBytes: 5 * 1024 * 1024, // CRITICAL FIX: Added 5MB memory limit
		DefaultTTL:     1 * time.Hour,
		Logger:         logger,
	})

	// Initialize blacklist cache
	manager.blacklistCache = NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeToken,
		MaxSize:    1000,
		DefaultTTL: 24 * time.Hour,
		Logger:     logger,
	})

	// Initialize metadata cache with grace periods
	manager.metadataCache = NewUniversalCache(UniversalCacheConfig{
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
	manager.jwkCache = NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeJWK,
		MaxSize:    200,
		DefaultTTL: 1 * time.Hour,
		Logger:     logger,
	})

	// Initialize session cache - CRITICAL FIX: Reduced from 10000 to 2000
	manager.sessionCache = NewUniversalCache(UniversalCacheConfig{
		Type:           CacheTypeSession,
		MaxSize:        2000,            // CRITICAL FIX: Reduced from 10000 to 2000 items
		MaxMemoryBytes: 5 * 1024 * 1024, // CRITICAL FIX: Added 5MB memory limit
		DefaultTTL:     30 * time.Minute,
		Logger:         logger,
	})

	// Initialize introspection cache for OAuth 2.0 Token Introspection (RFC 7662)
	manager.introspectionCache = NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeToken,  // Use token cache type for introspection results
		MaxSize:    1000,            // Cache up to 1000 introspection results
		DefaultTTL: 5 * time.Minute, // Short TTL for security (introspect frequently)
		Logger:     logger,
	})

	// Initialize token type cache for performance optimization
	manager.tokenTypeCache = NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeToken,  // Use token cache type for token type detection
		MaxSize:    2000,            // Cache up to 2000 token type detections
		DefaultTTL: 5 * time.Minute, // 5 minute TTL for token type detection
		Logger:     logger,
	})
}

// initializeCachesWithRedis initializes caches with Redis/Hybrid backends based on configuration
func initializeCachesWithRedis(manager *UniversalCacheManager, logger *Logger, redisConfig *RedisConfig) {
	// Apply defaults to Redis config
	redisConfig.ApplyDefaults()

	// Create Redis backend
	redisBackendConfig := &backends.Config{
		Type:          backends.BackendTypeRedis,
		RedisAddr:     redisConfig.Address,
		RedisPassword: redisConfig.Password,
		RedisDB:       redisConfig.DB,
		RedisPrefix:   redisConfig.KeyPrefix,
		PoolSize:      redisConfig.PoolSize,
		EnableMetrics: true,
	}

	var redisBackend backends.CacheBackend
	var err error

	// Create Redis backend with resilience features if enabled
	redisBackend, err = backends.NewRedisBackend(redisBackendConfig)
	if err != nil {
		logger.Errorf("Failed to create Redis backend: %v. Falling back to memory-only mode.", err)
		initializeDefaultCaches(manager, logger)
		return
	}

	// Wrap with circuit breaker if enabled
	if redisConfig.EnableCircuitBreaker {
		cbConfig := resilience.DefaultCircuitBreakerConfig()
		cbConfig.MaxFailures = redisConfig.CircuitBreakerThreshold
		cbConfig.Timeout = time.Duration(redisConfig.CircuitBreakerTimeout) * time.Second
		cbConfig.OnStateChange = func(from, to resilience.State) {
			logger.Infof("Circuit breaker state changed from %s to %s", from, to)
		}

		redisBackend = resilience.NewCircuitBreakerBackend(redisBackend, cbConfig)
		logger.Info("Redis backend wrapped with circuit breaker")
	}

	// Wrap with health checker if enabled
	if redisConfig.EnableHealthCheck {
		hcConfig := &resilience.HealthCheckConfig{
			CheckInterval:      time.Duration(redisConfig.HealthCheckInterval) * time.Second,
			Timeout:            5 * time.Second,
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
			OnStatusChange: func(from, to resilience.HealthStatus) {
				logger.Infof("Redis backend health status changed from %s to %s", from, to)
			},
		}

		redisBackend = resilience.NewHealthCheckBackend(redisBackend, hcConfig)
		logger.Info("Redis backend wrapped with health checker")
	}

	// Decide which backend to use based on cache mode
	var createBackend func(cacheType CacheType) backends.CacheBackend

	switch redisConfig.CacheMode {
	case "redis":
		// Redis-only mode
		createBackend = func(cacheType CacheType) backends.CacheBackend {
			return redisBackend
		}
		logger.Info("Using Redis-only cache backend")

	case "hybrid":
		// Hybrid mode is not currently supported due to interface incompatibilities
		// Fall back to Redis-only mode
		logger.Info("Hybrid mode not currently supported, using Redis-only mode")
		createBackend = func(cacheType CacheType) backends.CacheBackend {
			return redisBackend
		}

	default:
		// Memory-only mode (fallback)
		logger.Infof("Invalid cache mode: %s. Using memory-only mode.", redisConfig.CacheMode)
		initializeDefaultCaches(manager, logger)
		return
	}

	// Initialize token cache with backend
	manager.tokenCache = NewUniversalCacheWithBackend(
		UniversalCacheConfig{
			Type:           CacheTypeToken,
			MaxSize:        1000,
			MaxMemoryBytes: 5 * 1024 * 1024,
			DefaultTTL:     1 * time.Hour,
			Logger:         logger,
		},
		createBackend(CacheTypeToken),
	)

	// Initialize blacklist cache (CRITICAL - must be consistent across replicas)
	manager.blacklistCache = NewUniversalCacheWithBackend(
		UniversalCacheConfig{
			Type:       CacheTypeToken,
			MaxSize:    1000,
			DefaultTTL: 24 * time.Hour,
			Logger:     logger,
		},
		createBackend("blacklist"),
	)

	// Initialize metadata cache
	manager.metadataCache = NewUniversalCacheWithBackend(
		UniversalCacheConfig{
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
		},
		createBackend(CacheTypeMetadata),
	)

	// Initialize JWK cache
	manager.jwkCache = NewUniversalCacheWithBackend(
		UniversalCacheConfig{
			Type:       CacheTypeJWK,
			MaxSize:    200,
			DefaultTTL: 1 * time.Hour,
			Logger:     logger,
		},
		createBackend(CacheTypeJWK),
	)

	// Session cache stays memory-only (high volume, local state)
	manager.sessionCache = NewUniversalCache(UniversalCacheConfig{
		Type:           CacheTypeSession,
		MaxSize:        2000,
		MaxMemoryBytes: 5 * 1024 * 1024,
		DefaultTTL:     30 * time.Minute,
		Logger:         logger,
	})

	// Introspection cache uses backend for sharing results
	manager.introspectionCache = NewUniversalCacheWithBackend(
		UniversalCacheConfig{
			Type:       CacheTypeToken,
			MaxSize:    1000,
			DefaultTTL: 5 * time.Minute,
			Logger:     logger,
		},
		createBackend(CacheTypeToken),
	)

	// Token type cache stays memory-only (local optimization)
	manager.tokenTypeCache = NewUniversalCache(UniversalCacheConfig{
		Type:       CacheTypeToken,
		MaxSize:    2000,
		DefaultTTL: 5 * time.Minute,
		Logger:     logger,
	})

	logger.Infof("Cache manager initialized with %s backend configuration", redisConfig.CacheMode)
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
			_ = cache.Close() // Safe to ignore: best effort cache cleanup
		}
	}

	m.logger.Info("UniversalCacheManager: Closed all caches")
	return nil
}

// InitializeCacheManagerFromConfig initializes the cache manager with configuration
// This should be called early in the application startup with the loaded configuration
func InitializeCacheManagerFromConfig(config *Config) *UniversalCacheManager {
	logger := NewLogger(config.LogLevel)

	// Initialize Redis config if not present
	if config.Redis == nil {
		config.Redis = &RedisConfig{}
	}

	// Apply environment variable fallbacks for fields not set in config
	// This allows env vars to be used as optional overrides only when
	// the config field is not explicitly set through Traefik
	config.Redis.ApplyEnvFallbacks()

	// Apply defaults after env fallbacks
	config.Redis.ApplyDefaults()

	// Log cache backend selection
	if config.Redis != nil && config.Redis.Enabled {
		logger.Infof("Initializing cache backend with Redis: mode=%s, address=%s",
			config.Redis.CacheMode, config.Redis.Address)
	} else {
		logger.Info("Initializing cache backend with memory-only mode")
	}

	return GetUniversalCacheManagerWithConfig(logger, config.Redis)
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
