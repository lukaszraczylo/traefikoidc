package cache

import (
	"sync"
	"time"
)

// Manager manages multiple cache instances with singleton pattern
type Manager struct {
	logger        Logger
	tokenCache    *Cache
	metadataCache *Cache
	jwkCache      *Cache
	sessionCache  *Cache
	generalCache  *Cache
	typedToken    *TokenCache
	typedMetadata *MetadataCache
	typedJWK      *JWKCache
	typedSession  *SessionCache
	mu            sync.RWMutex
}

var (
	globalManager     *Manager
	globalManagerOnce sync.Once
)

// GetGlobalManager returns the singleton cache manager instance
func GetGlobalManager(logger Logger) *Manager {
	globalManagerOnce.Do(func() {
		globalManager = NewManager(logger)
	})
	return globalManager
}

// NewManager creates a new cache manager
func NewManager(logger Logger) *Manager {
	if logger == nil {
		logger = &noOpLogger{}
	}

	m := &Manager{
		logger: logger,
	}

	// Initialize core caches with appropriate configurations
	m.initializeCaches()

	return m
}

// initializeCaches creates all cache instances with appropriate configurations
func (m *Manager) initializeCaches() {
	// Token cache configuration
	tokenConfig := Config{
		Type:              TypeToken,
		MaxSize:           5000,
		MaxMemoryBytes:    32 * 1024 * 1024, // 32MB
		DefaultTTL:        1 * time.Hour,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
		Logger:            m.logger,
		TokenConfig: &TokenConfig{
			BlacklistTTL:        24 * time.Hour,
			RefreshTokenTTL:     7 * 24 * time.Hour,
			EnableTokenRotation: true,
		},
	}
	m.tokenCache = New(tokenConfig)
	m.typedToken = NewTokenCache(m.tokenCache)

	// Metadata cache configuration
	metadataConfig := Config{
		Type:              TypeMetadata,
		MaxSize:           100,
		MaxMemoryBytes:    10 * 1024 * 1024, // 10MB
		DefaultTTL:        24 * time.Hour,
		CleanupInterval:   30 * time.Minute,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
		Logger:            m.logger,
		MetadataConfig: &MetadataConfig{
			GracePeriod:                    5 * time.Minute,
			ExtendedGracePeriod:            15 * time.Minute,
			MaxGracePeriod:                 1 * time.Hour,
			SecurityCriticalMaxGracePeriod: 30 * time.Minute,
			SecurityCriticalFields:         []string{"issuer", "jwks_uri"},
		},
	}
	m.metadataCache = New(metadataConfig)
	m.typedMetadata = NewMetadataCache(m.metadataCache, *metadataConfig.MetadataConfig)

	// JWK cache configuration
	jwkConfig := Config{
		Type:              TypeJWK,
		MaxSize:           50,
		MaxMemoryBytes:    5 * 1024 * 1024, // 5MB
		DefaultTTL:        1 * time.Hour,
		CleanupInterval:   10 * time.Minute,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
		Logger:            m.logger,
		JWKConfig: &JWKConfig{
			RefreshInterval: 1 * time.Hour,
			MinRefreshTime:  5 * time.Minute,
			MaxKeyAge:       24 * time.Hour,
		},
	}
	m.jwkCache = New(jwkConfig)
	m.typedJWK = NewJWKCache(m.jwkCache)

	// Session cache configuration
	sessionConfig := Config{
		Type:              TypeSession,
		MaxSize:           10000,
		MaxMemoryBytes:    64 * 1024 * 1024, // 64MB
		DefaultTTL:        30 * time.Minute,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
		Logger:            m.logger,
	}
	m.sessionCache = New(sessionConfig)
	m.typedSession = NewSessionCache(m.sessionCache)

	// General cache configuration
	generalConfig := Config{
		Type:              TypeGeneral,
		MaxSize:           1000,
		MaxMemoryBytes:    16 * 1024 * 1024, // 16MB
		DefaultTTL:        10 * time.Minute,
		CleanupInterval:   5 * time.Minute,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
		EnableMetrics:     true,
		Logger:            m.logger,
	}
	m.generalCache = New(generalConfig)
}

// GetTokenCache returns the token cache instance
func (m *Manager) GetTokenCache() *TokenCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.typedToken
}

// GetMetadataCache returns the metadata cache instance
func (m *Manager) GetMetadataCache() *MetadataCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.typedMetadata
}

// GetJWKCache returns the JWK cache instance
func (m *Manager) GetJWKCache() *JWKCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.typedJWK
}

// GetSessionCache returns the session cache instance
func (m *Manager) GetSessionCache() *SessionCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.typedSession
}

// GetGeneralCache returns the general cache instance
func (m *Manager) GetGeneralCache() *Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generalCache
}

// GetRawTokenCache returns the raw token cache for compatibility
func (m *Manager) GetRawTokenCache() *Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokenCache
}

// GetRawMetadataCache returns the raw metadata cache for compatibility
func (m *Manager) GetRawMetadataCache() *Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metadataCache
}

// GetRawJWKCache returns the raw JWK cache for compatibility
func (m *Manager) GetRawJWKCache() *Cache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.jwkCache
}

// GetStats returns statistics for all caches
func (m *Manager) GetStats() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]map[string]interface{}{
		"token":    m.tokenCache.GetStats(),
		"metadata": m.metadataCache.GetStats(),
		"jwk":      m.jwkCache.GetStats(),
		"session":  m.sessionCache.GetStats(),
		"general":  m.generalCache.GetStats(),
	}
}

// ClearAll clears all cache instances
func (m *Manager) ClearAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokenCache.Clear()
	m.metadataCache.Clear()
	m.jwkCache.Clear()
	m.sessionCache.Clear()
	m.generalCache.Clear()
}

// Close gracefully shuts down all cache instances
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error

	if err := m.tokenCache.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := m.metadataCache.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := m.jwkCache.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := m.sessionCache.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := m.generalCache.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// CleanupAll runs cleanup on all cache instances
func (m *Manager) CleanupAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.tokenCache.Cleanup()
	m.metadataCache.Cleanup()
	m.jwkCache.Cleanup()
	m.sessionCache.Cleanup()
	m.generalCache.Cleanup()
}

// SetLogger updates the logger for all caches
func (m *Manager) SetLogger(logger Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger = logger
	if logger != nil {
		m.tokenCache.logger = logger
		m.metadataCache.logger = logger
		m.jwkCache.logger = logger
		m.sessionCache.logger = logger
		m.generalCache.logger = logger
	}
}
