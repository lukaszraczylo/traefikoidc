// Package config provides unified configuration management for the OIDC middleware
package config

import (
	"time"
)

// UnifiedConfig is the master configuration structure consolidating all config aspects
// This replaces 45 duplicate config structs across the codebase
type UnifiedConfig struct {
	// Core Configuration
	Provider ProviderConfig `json:"provider" yaml:"provider"`
	Session  SessionConfig  `json:"session" yaml:"session"`
	Token    TokenConfig    `json:"token" yaml:"token"`
	Redis    RedisConfig    `json:"redis" yaml:"redis"`
	Security SecurityConfig `json:"security" yaml:"security"`

	// Middleware Configuration
	Middleware MiddlewareConfig `json:"middleware" yaml:"middleware"`
	Cache      CacheConfig      `json:"cache" yaml:"cache"`
	RateLimit  RateLimitConfig  `json:"rateLimit" yaml:"rateLimit"`

	// Operational Configuration
	Logging LoggingConfig `json:"logging" yaml:"logging"`
	Metrics MetricsConfig `json:"metrics" yaml:"metrics"`
	Health  HealthConfig  `json:"health" yaml:"health"`

	// Advanced Configuration
	Transport TransportConfig `json:"transport" yaml:"transport"`
	Pool      PoolConfig      `json:"pool" yaml:"pool"`
	Circuit   CircuitConfig   `json:"circuit" yaml:"circuit"`

	// Compatibility field for migration
	Legacy map[string]interface{} `json:"-" yaml:"-"`
}

// ProviderConfig contains OIDC provider settings
type ProviderConfig struct {
	IssuerURL             string            `json:"issuerURL" yaml:"issuerURL"`
	ClientID              string            `json:"clientID" yaml:"clientID"`
	ClientSecret          string            `json:"clientSecret" yaml:"clientSecret"`
	RedirectURL           string            `json:"redirectURL" yaml:"redirectURL"`
	LogoutURL             string            `json:"logoutURL" yaml:"logoutURL"`
	PostLogoutRedirectURI string            `json:"postLogoutRedirectURI" yaml:"postLogoutRedirectURI"`
	Scopes                []string          `json:"scopes" yaml:"scopes"`
	OverrideScopes        bool              `json:"overrideScopes" yaml:"overrideScopes"`
	CustomClaims          map[string]string `json:"customClaims" yaml:"customClaims"`
	JWKCachePeriod        time.Duration     `json:"jwkCachePeriod" yaml:"jwkCachePeriod"`
	MetadataCacheTTL      time.Duration     `json:"metadataCacheTTL" yaml:"metadataCacheTTL"`
	Discovery             bool              `json:"discovery" yaml:"discovery"`

	// Provider-specific endpoints
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty" yaml:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty" yaml:"tokenEndpoint,omitempty"`
	UserInfoEndpoint      string `json:"userInfoEndpoint,omitempty" yaml:"userInfoEndpoint,omitempty"`
	JWKSEndpoint          string `json:"jwksEndpoint,omitempty" yaml:"jwksEndpoint,omitempty"`
	IntrospectEndpoint    string `json:"introspectEndpoint,omitempty" yaml:"introspectEndpoint,omitempty"`
	RevocationEndpoint    string `json:"revocationEndpoint,omitempty" yaml:"revocationEndpoint,omitempty"`
}

// SessionConfig contains session management settings
type SessionConfig struct {
	Name          string `json:"name" yaml:"name"`
	MaxAge        int    `json:"maxAge" yaml:"maxAge"`
	Secret        string `json:"secret" yaml:"secret"`
	EncryptionKey string `json:"encryptionKey" yaml:"encryptionKey"`
	SigningKey    string `json:"signingKey" yaml:"signingKey"`
	ChunkSize     int    `json:"chunkSize" yaml:"chunkSize"`
	MaxChunks     int    `json:"maxChunks" yaml:"maxChunks"`

	// Cookie settings
	Domain   string `json:"domain" yaml:"domain"`
	Path     string `json:"path" yaml:"path"`
	Secure   bool   `json:"secure" yaml:"secure"`
	HttpOnly bool   `json:"httpOnly" yaml:"httpOnly"`
	SameSite string `json:"sameSite" yaml:"sameSite"`

	// Storage settings
	StorageType     string        `json:"storageType" yaml:"storageType"` // "memory", "redis", "cookie"
	CleanupInterval time.Duration `json:"cleanupInterval" yaml:"cleanupInterval"`
}

// TokenConfig contains token handling settings
type TokenConfig struct {
	AccessTokenTTL     time.Duration `json:"accessTokenTTL" yaml:"accessTokenTTL"`
	RefreshTokenTTL    time.Duration `json:"refreshTokenTTL" yaml:"refreshTokenTTL"`
	RefreshGracePeriod time.Duration `json:"refreshGracePeriod" yaml:"refreshGracePeriod"`
	ValidationMode     string        `json:"validationMode" yaml:"validationMode"` // "jwt", "introspect", "hybrid"
	IntrospectURL      string        `json:"introspectURL" yaml:"introspectURL"`

	// Token caching
	CacheEnabled     bool          `json:"cacheEnabled" yaml:"cacheEnabled"`
	CacheTTL         time.Duration `json:"cacheTTL" yaml:"cacheTTL"`
	CacheNegativeTTL time.Duration `json:"cacheNegativeTTL" yaml:"cacheNegativeTTL"`

	// Token validation
	ValidateSignature bool          `json:"validateSignature" yaml:"validateSignature"`
	ValidateExpiry    bool          `json:"validateExpiry" yaml:"validateExpiry"`
	ValidateAudience  bool          `json:"validateAudience" yaml:"validateAudience"`
	ValidateIssuer    bool          `json:"validateIssuer" yaml:"validateIssuer"`
	RequiredClaims    []string      `json:"requiredClaims" yaml:"requiredClaims"`
	ClockSkew         time.Duration `json:"clockSkew" yaml:"clockSkew"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	ForceHTTPS            bool                   `json:"forceHTTPS" yaml:"forceHTTPS"`
	EnablePKCE            bool                   `json:"enablePKCE" yaml:"enablePKCE"`
	AllowedUsers          []string               `json:"allowedUsers" yaml:"allowedUsers"`
	AllowedUserDomains    []string               `json:"allowedUserDomains" yaml:"allowedUserDomains"`
	AllowedRolesAndGroups []string               `json:"allowedRolesAndGroups" yaml:"allowedRolesAndGroups"`
	ExcludedURLs          []string               `json:"excludedURLs" yaml:"excludedURLs"`
	Headers               *SecurityHeadersConfig `json:"headers" yaml:"headers"`

	// CSRF protection
	CSRFProtection bool          `json:"csrfProtection" yaml:"csrfProtection"`
	CSRFTokenName  string        `json:"csrfTokenName" yaml:"csrfTokenName"`
	CSRFTokenTTL   time.Duration `json:"csrfTokenTTL" yaml:"csrfTokenTTL"`

	// Additional security
	MaxLoginAttempts int           `json:"maxLoginAttempts" yaml:"maxLoginAttempts"`
	LockoutDuration  time.Duration `json:"lockoutDuration" yaml:"lockoutDuration"`
	RequireMFA       bool          `json:"requireMFA" yaml:"requireMFA"`
}

// MiddlewareConfig contains middleware-specific settings
type MiddlewareConfig struct {
	Priority        int      `json:"priority" yaml:"priority"`
	SkipPaths       []string `json:"skipPaths" yaml:"skipPaths"`
	RequirePaths    []string `json:"requirePaths" yaml:"requirePaths"`
	PassthroughMode bool     `json:"passthroughMode" yaml:"passthroughMode"`

	// Request handling
	MaxRequestSize int64         `json:"maxRequestSize" yaml:"maxRequestSize"`
	RequestTimeout time.Duration `json:"requestTimeout" yaml:"requestTimeout"`
	IdleTimeout    time.Duration `json:"idleTimeout" yaml:"idleTimeout"`

	// Response handling
	CustomHeaders map[string]string `json:"customHeaders" yaml:"customHeaders"`
	RemoveHeaders []string          `json:"removeHeaders" yaml:"removeHeaders"`
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	Enabled        bool          `json:"enabled" yaml:"enabled"`
	Type           string        `json:"type" yaml:"type"` // "memory", "redis", "hybrid"
	DefaultTTL     time.Duration `json:"defaultTTL" yaml:"defaultTTL"`
	MaxEntries     int           `json:"maxEntries" yaml:"maxEntries"`
	MaxEntrySize   int64         `json:"maxEntrySize" yaml:"maxEntrySize"`
	EvictionPolicy string        `json:"evictionPolicy" yaml:"evictionPolicy"` // "lru", "lfu", "fifo"

	// Memory cache settings
	CleanupInterval time.Duration `json:"cleanupInterval" yaml:"cleanupInterval"`

	// Distributed cache settings
	Namespace     string `json:"namespace" yaml:"namespace"`
	Compression   bool   `json:"compression" yaml:"compression"`
	Serialization string `json:"serialization" yaml:"serialization"` // "json", "msgpack", "protobuf"
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool `json:"enabled" yaml:"enabled"`
	RequestsPerSecond int  `json:"requestsPerSecond" yaml:"requestsPerSecond"`
	Burst             int  `json:"burst" yaml:"burst"`

	// Rate limit storage
	StorageType    string        `json:"storageType" yaml:"storageType"` // "memory", "redis"
	WindowDuration time.Duration `json:"windowDuration" yaml:"windowDuration"`

	// Rate limit keys
	KeyType       string `json:"keyType" yaml:"keyType"` // "ip", "user", "token", "custom"
	CustomKeyFunc string `json:"customKeyFunc" yaml:"customKeyFunc"`

	// Whitelisting
	WhitelistIPs   []string `json:"whitelistIPs" yaml:"whitelistIPs"`
	WhitelistUsers []string `json:"whitelistUsers" yaml:"whitelistUsers"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level    string `json:"level" yaml:"level"`   // "debug", "info", "warn", "error"
	Format   string `json:"format" yaml:"format"` // "json", "text", "structured"
	Output   string `json:"output" yaml:"output"` // "stdout", "stderr", "file"
	FilePath string `json:"filePath" yaml:"filePath"`

	// Log filtering
	FilterSensitive bool     `json:"filterSensitive" yaml:"filterSensitive"`
	MaskFields      []string `json:"maskFields" yaml:"maskFields"`

	// Performance
	BufferSize    int           `json:"bufferSize" yaml:"bufferSize"`
	FlushInterval time.Duration `json:"flushInterval" yaml:"flushInterval"`

	// Audit logging
	AuditEnabled bool     `json:"auditEnabled" yaml:"auditEnabled"`
	AuditEvents  []string `json:"auditEvents" yaml:"auditEvents"`
}

// MetricsConfig contains metrics collection configuration
type MetricsConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Provider  string `json:"provider" yaml:"provider"` // "prometheus", "statsd", "otlp"
	Endpoint  string `json:"endpoint" yaml:"endpoint"`
	Namespace string `json:"namespace" yaml:"namespace"`
	Subsystem string `json:"subsystem" yaml:"subsystem"`

	// Collection settings
	CollectInterval time.Duration `json:"collectInterval" yaml:"collectInterval"`
	Histograms      bool          `json:"histograms" yaml:"histograms"`

	// Custom labels
	Labels map[string]string `json:"labels" yaml:"labels"`
}

// HealthConfig contains health check configuration
type HealthConfig struct {
	Enabled       bool          `json:"enabled" yaml:"enabled"`
	Path          string        `json:"path" yaml:"path"`
	CheckInterval time.Duration `json:"checkInterval" yaml:"checkInterval"`
	Timeout       time.Duration `json:"timeout" yaml:"timeout"`

	// Checks to perform
	CheckProvider bool `json:"checkProvider" yaml:"checkProvider"`
	CheckRedis    bool `json:"checkRedis" yaml:"checkRedis"`
	CheckCache    bool `json:"checkCache" yaml:"checkCache"`

	// Thresholds
	MaxLatency time.Duration `json:"maxLatency" yaml:"maxLatency"`
	MinMemory  int64         `json:"minMemory" yaml:"minMemory"`
}

// TransportConfig contains HTTP transport configuration
type TransportConfig struct {
	MaxIdleConns          int           `json:"maxIdleConns" yaml:"maxIdleConns"`
	MaxIdleConnsPerHost   int           `json:"maxIdleConnsPerHost" yaml:"maxIdleConnsPerHost"`
	MaxConnsPerHost       int           `json:"maxConnsPerHost" yaml:"maxConnsPerHost"`
	IdleConnTimeout       time.Duration `json:"idleConnTimeout" yaml:"idleConnTimeout"`
	TLSHandshakeTimeout   time.Duration `json:"tlsHandshakeTimeout" yaml:"tlsHandshakeTimeout"`
	ExpectContinueTimeout time.Duration `json:"expectContinueTimeout" yaml:"expectContinueTimeout"`
	ResponseHeaderTimeout time.Duration `json:"responseHeaderTimeout" yaml:"responseHeaderTimeout"`
	DisableKeepAlives     bool          `json:"disableKeepAlives" yaml:"disableKeepAlives"`
	DisableCompression    bool          `json:"disableCompression" yaml:"disableCompression"`

	// TLS configuration
	TLSInsecureSkipVerify bool     `json:"tlsInsecureSkipVerify" yaml:"tlsInsecureSkipVerify"`
	TLSMinVersion         string   `json:"tlsMinVersion" yaml:"tlsMinVersion"`
	TLSCipherSuites       []string `json:"tlsCipherSuites" yaml:"tlsCipherSuites"`

	// Proxy settings
	ProxyURL string   `json:"proxyURL" yaml:"proxyURL"`
	NoProxy  []string `json:"noProxy" yaml:"noProxy"`
}

// PoolConfig contains connection pool configuration
type PoolConfig struct {
	Enabled     bool          `json:"enabled" yaml:"enabled"`
	Size        int           `json:"size" yaml:"size"`
	MinSize     int           `json:"minSize" yaml:"minSize"`
	MaxSize     int           `json:"maxSize" yaml:"maxSize"`
	MaxAge      time.Duration `json:"maxAge" yaml:"maxAge"`
	IdleTimeout time.Duration `json:"idleTimeout" yaml:"idleTimeout"`
	WaitTimeout time.Duration `json:"waitTimeout" yaml:"waitTimeout"`

	// Health checking
	HealthCheckInterval time.Duration `json:"healthCheckInterval" yaml:"healthCheckInterval"`
	MaxRetries          int           `json:"maxRetries" yaml:"maxRetries"`
}

// CircuitConfig contains circuit breaker configuration
type CircuitConfig struct {
	Enabled             bool          `json:"enabled" yaml:"enabled"`
	MaxRequests         uint32        `json:"maxRequests" yaml:"maxRequests"`
	Interval            time.Duration `json:"interval" yaml:"interval"`
	Timeout             time.Duration `json:"timeout" yaml:"timeout"`
	ConsecutiveFailures uint32        `json:"consecutiveFailures" yaml:"consecutiveFailures"`
	FailureRatio        float64       `json:"failureRatio" yaml:"failureRatio"`

	// Circuit states
	OnOpen     string `json:"onOpen" yaml:"onOpen"` // "reject", "fallback", "passthrough"
	OnHalfOpen string `json:"onHalfOpen" yaml:"onHalfOpen"`

	// Monitoring
	MetricsEnabled  bool `json:"metricsEnabled" yaml:"metricsEnabled"`
	LogStateChanges bool `json:"logStateChanges" yaml:"logStateChanges"`
}
