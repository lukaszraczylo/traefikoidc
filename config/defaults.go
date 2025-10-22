// Package config provides default values and initialization for unified configuration
package config

import (
	"time"
)

// NewUnifiedConfig creates a new unified configuration with sensible defaults
func NewUnifiedConfig() *UnifiedConfig {
	return &UnifiedConfig{
		Provider:   DefaultProviderConfig(),
		Session:    DefaultSessionConfig(),
		Token:      DefaultTokenConfig(),
		Redis:      *DefaultRedisConfig(), // Using existing DefaultRedisConfig
		Security:   DefaultSecurityConfig(),
		Middleware: DefaultMiddlewareConfig(),
		Cache:      DefaultCacheConfig(),
		RateLimit:  DefaultRateLimitConfig(),
		Logging:    DefaultLoggingConfig(),
		Metrics:    DefaultMetricsConfig(),
		Health:     DefaultHealthConfig(),
		Transport:  DefaultTransportConfig(),
		Pool:       DefaultPoolConfig(),
		Circuit:    DefaultCircuitConfig(),
		Legacy:     make(map[string]interface{}),
	}
}

// DefaultProviderConfig returns default provider configuration
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		Scopes:           []string{"openid", "profile", "email"},
		OverrideScopes:   false,
		CustomClaims:     make(map[string]string),
		JWKCachePeriod:   24 * time.Hour,
		MetadataCacheTTL: 24 * time.Hour,
		Discovery:        true,
	}
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		Name:            "oidc_session",
		MaxAge:          86400, // 24 hours
		ChunkSize:       4000,  // Safe size for cookies
		MaxChunks:       5,
		Path:            "/",
		Secure:          true,
		HttpOnly:        true,
		SameSite:        "Lax",
		StorageType:     "cookie",
		CleanupInterval: 1 * time.Hour,
	}
}

// DefaultTokenConfig returns default token configuration
func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		AccessTokenTTL:     1 * time.Hour,
		RefreshTokenTTL:    24 * time.Hour,
		RefreshGracePeriod: 60 * time.Second,
		ValidationMode:     "jwt",
		CacheEnabled:       true,
		CacheTTL:           5 * time.Minute,
		CacheNegativeTTL:   30 * time.Second,
		ValidateSignature:  true,
		ValidateExpiry:     true,
		ValidateAudience:   true,
		ValidateIssuer:     true,
		RequiredClaims:     []string{"sub", "iat", "exp"},
		ClockSkew:          5 * time.Minute,
	}
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		ForceHTTPS:            true,
		EnablePKCE:            true,
		AllowedUsers:          []string{},
		AllowedUserDomains:    []string{},
		AllowedRolesAndGroups: []string{},
		ExcludedURLs: []string{
			"/favicon.ico",
			"/robots.txt",
			"/health",
			"/.well-known/",
			"/metrics",
			"/ping",
			"/static/",
			"/assets/",
			"/js/",
			"/css/",
			"/images/",
			"/fonts/",
		},
		Headers:          createDefaultSecurityConfig(),
		CSRFProtection:   true,
		CSRFTokenName:    "csrf_token",
		CSRFTokenTTL:     1 * time.Hour,
		MaxLoginAttempts: 5,
		LockoutDuration:  15 * time.Minute,
		RequireMFA:       false,
	}
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		Priority:        1000,
		SkipPaths:       []string{},
		RequirePaths:    []string{},
		PassthroughMode: false,
		MaxRequestSize:  10 * 1024 * 1024, // 10MB
		RequestTimeout:  30 * time.Second,
		IdleTimeout:     90 * time.Second,
		CustomHeaders:   make(map[string]string),
		RemoveHeaders:   []string{},
	}
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:         true,
		Type:            "memory",
		DefaultTTL:      5 * time.Minute,
		MaxEntries:      10000,
		MaxEntrySize:    1024 * 1024, // 1MB
		EvictionPolicy:  "lru",
		CleanupInterval: 10 * time.Minute,
		Namespace:       "traefikoidc",
		Compression:     false,
		Serialization:   "json",
	}
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:           false,
		RequestsPerSecond: 10,
		Burst:             20,
		StorageType:       "memory",
		WindowDuration:    1 * time.Minute,
		KeyType:           "ip",
		CustomKeyFunc:     "",
		WhitelistIPs:      []string{},
		WhitelistUsers:    []string{},
	}
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:           "info",
		Format:          "json",
		Output:          "stdout",
		FilePath:        "",
		FilterSensitive: true,
		MaskFields: []string{
			"password",
			"secret",
			"token",
			"key",
			"authorization",
			"cookie",
		},
		BufferSize:    8192,
		FlushInterval: 5 * time.Second,
		AuditEnabled:  false,
		AuditEvents: []string{
			"login",
			"logout",
			"token_refresh",
			"auth_failure",
		},
	}
}

// DefaultMetricsConfig returns default metrics configuration
func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Enabled:         false,
		Provider:        "prometheus",
		Endpoint:        "/metrics",
		Namespace:       "traefikoidc",
		Subsystem:       "middleware",
		CollectInterval: 10 * time.Second,
		Histograms:      true,
		Labels:          make(map[string]string),
	}
}

// DefaultHealthConfig returns default health check configuration
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		Enabled:       true,
		Path:          "/health",
		CheckInterval: 30 * time.Second,
		Timeout:       5 * time.Second,
		CheckProvider: true,
		CheckRedis:    true,
		CheckCache:    true,
		MaxLatency:    1 * time.Second,
		MinMemory:     100 * 1024 * 1024, // 100MB
	}
}

// DefaultTransportConfig returns default HTTP transport configuration
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       0, // No limit
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		TLSInsecureSkipVerify: false,
		TLSMinVersion:         "TLS1.2",
		TLSCipherSuites:       []string{},
		ProxyURL:              "",
		NoProxy:               []string{},
	}
}

// DefaultPoolConfig returns default connection pool configuration
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		Enabled:             true,
		Size:                10,
		MinSize:             2,
		MaxSize:             50,
		MaxAge:              30 * time.Minute,
		IdleTimeout:         5 * time.Minute,
		WaitTimeout:         5 * time.Second,
		HealthCheckInterval: 30 * time.Second,
		MaxRetries:          3,
	}
}

// DefaultCircuitConfig returns default circuit breaker configuration
func DefaultCircuitConfig() CircuitConfig {
	return CircuitConfig{
		Enabled:             true,
		MaxRequests:         100,
		Interval:            10 * time.Second,
		Timeout:             60 * time.Second,
		ConsecutiveFailures: 5,
		FailureRatio:        0.5,
		OnOpen:              "reject",
		OnHalfOpen:          "passthrough",
		MetricsEnabled:      true,
		LogStateChanges:     true,
	}
}

// MergeWithDefaults merges a partial configuration with defaults
func MergeWithDefaults(partial *UnifiedConfig) *UnifiedConfig {
	if partial == nil {
		return NewUnifiedConfig()
	}

	// Ensure Legacy field is initialized
	if partial.Legacy == nil {
		partial.Legacy = make(map[string]interface{})
	}

	// TODO: Implement deep merge logic with defaults
	// For now, just return the partial config
	return partial
}
