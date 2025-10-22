// Package config provides validation for unified configuration
package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	if e.Value != nil {
		return fmt.Sprintf("config validation error: %s: %s (value: %v)", e.Field, e.Message, e.Value)
	}
	return fmt.Sprintf("config validation error: %s: %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

// Error implements the error interface
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}

	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// Validate performs comprehensive validation on the unified configuration
func (c *UnifiedConfig) Validate() error {
	var errors ValidationErrors

	// Validate Provider configuration
	if err := c.validateProvider(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Session configuration
	if err := c.validateSession(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Token configuration
	if err := c.validateToken(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Redis configuration (uses existing validation)
	if err := c.Redis.Validate(); err != nil {
		errors = append(errors, ValidationError{
			Field:   "Redis",
			Message: err.Error(),
		})
	}

	// Validate Security configuration
	if err := c.validateSecurity(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Middleware configuration
	if err := c.validateMiddleware(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Cache configuration
	if err := c.validateCache(); err != nil {
		errors = append(errors, err...)
	}

	// Validate RateLimit configuration
	if err := c.validateRateLimit(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Logging configuration
	if err := c.validateLogging(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Metrics configuration
	if err := c.validateMetrics(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Transport configuration
	if err := c.validateTransport(); err != nil {
		errors = append(errors, err...)
	}

	// Validate Circuit configuration
	if err := c.validateCircuit(); err != nil {
		errors = append(errors, err...)
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// validateProvider validates provider configuration
func (c *UnifiedConfig) validateProvider() ValidationErrors {
	var errors ValidationErrors

	// IssuerURL is required and must be a valid URL
	if c.Provider.IssuerURL == "" {
		errors = append(errors, ValidationError{
			Field:   "Provider.IssuerURL",
			Message: "issuer URL is required",
		})
	} else if _, err := url.Parse(c.Provider.IssuerURL); err != nil {
		errors = append(errors, ValidationError{
			Field:   "Provider.IssuerURL",
			Message: "invalid issuer URL",
			Value:   c.Provider.IssuerURL,
		})
	}

	// ClientID is required
	if c.Provider.ClientID == "" {
		errors = append(errors, ValidationError{
			Field:   "Provider.ClientID",
			Message: "client ID is required",
		})
	}

	// ClientSecret is required (except for public clients with PKCE)
	if c.Provider.ClientSecret == "" && !c.Security.EnablePKCE {
		errors = append(errors, ValidationError{
			Field:   "Provider.ClientSecret",
			Message: "client secret is required (or enable PKCE for public clients)",
		})
	}

	// RedirectURL must be valid if provided
	if c.Provider.RedirectURL != "" {
		if _, err := url.Parse(c.Provider.RedirectURL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "Provider.RedirectURL",
				Message: "invalid redirect URL",
				Value:   c.Provider.RedirectURL,
			})
		}
	}

	// Scopes must include 'openid' for OIDC
	hasOpenID := false
	for _, scope := range c.Provider.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID && !c.Provider.OverrideScopes {
		errors = append(errors, ValidationError{
			Field:   "Provider.Scopes",
			Message: "scopes must include 'openid' for OIDC",
			Value:   c.Provider.Scopes,
		})
	}

	// JWK cache period must be positive
	if c.Provider.JWKCachePeriod < 0 {
		errors = append(errors, ValidationError{
			Field:   "Provider.JWKCachePeriod",
			Message: "JWK cache period must be positive",
			Value:   c.Provider.JWKCachePeriod,
		})
	}

	return errors
}

// validateSession validates session configuration
func (c *UnifiedConfig) validateSession() ValidationErrors {
	var errors ValidationErrors

	// Session name must not be empty
	if c.Session.Name == "" {
		errors = append(errors, ValidationError{
			Field:   "Session.Name",
			Message: "session name is required",
		})
	}

	// Session secret or encryption key is required
	if c.Session.Secret == "" && c.Session.EncryptionKey == "" {
		errors = append(errors, ValidationError{
			Field:   "Session",
			Message: "either session secret or encryption key is required",
		})
	}

	// Encryption key must be at least 32 bytes for security
	if c.Session.EncryptionKey != "" && len(c.Session.EncryptionKey) < 32 {
		errors = append(errors, ValidationError{
			Field:   "Session.EncryptionKey",
			Message: "encryption key must be at least 32 characters for proper security",
			Value:   len(c.Session.EncryptionKey),
		})
	}

	// ChunkSize must be reasonable (between 1KB and 10KB)
	if c.Session.ChunkSize < 1000 || c.Session.ChunkSize > 10000 {
		errors = append(errors, ValidationError{
			Field:   "Session.ChunkSize",
			Message: "chunk size must be between 1000 and 10000 bytes",
			Value:   c.Session.ChunkSize,
		})
	}

	// MaxChunks must be reasonable (between 1 and 100)
	if c.Session.MaxChunks < 1 || c.Session.MaxChunks > 100 {
		errors = append(errors, ValidationError{
			Field:   "Session.MaxChunks",
			Message: "max chunks must be between 1 and 100",
			Value:   c.Session.MaxChunks,
		})
	}

	// SameSite must be valid
	validSameSite := map[string]bool{
		"":       true,
		"Lax":    true,
		"Strict": true,
		"None":   true,
	}
	if !validSameSite[c.Session.SameSite] {
		errors = append(errors, ValidationError{
			Field:   "Session.SameSite",
			Message: "invalid SameSite value (must be Lax, Strict, or None)",
			Value:   c.Session.SameSite,
		})
	}

	// StorageType must be valid
	validStorage := map[string]bool{
		"memory": true,
		"redis":  true,
		"cookie": true,
	}
	if !validStorage[c.Session.StorageType] {
		errors = append(errors, ValidationError{
			Field:   "Session.StorageType",
			Message: "invalid storage type (must be memory, redis, or cookie)",
			Value:   c.Session.StorageType,
		})
	}

	return errors
}

// validateToken validates token configuration
func (c *UnifiedConfig) validateToken() ValidationErrors {
	var errors ValidationErrors

	// Token TTLs must be positive
	if c.Token.AccessTokenTTL <= 0 {
		errors = append(errors, ValidationError{
			Field:   "Token.AccessTokenTTL",
			Message: "access token TTL must be positive",
			Value:   c.Token.AccessTokenTTL,
		})
	}

	if c.Token.RefreshTokenTTL <= 0 {
		errors = append(errors, ValidationError{
			Field:   "Token.RefreshTokenTTL",
			Message: "refresh token TTL must be positive",
			Value:   c.Token.RefreshTokenTTL,
		})
	}

	// Validation mode must be valid
	validModes := map[string]bool{
		"jwt":        true,
		"introspect": true,
		"hybrid":     true,
	}
	if !validModes[c.Token.ValidationMode] {
		errors = append(errors, ValidationError{
			Field:   "Token.ValidationMode",
			Message: "invalid validation mode (must be jwt, introspect, or hybrid)",
			Value:   c.Token.ValidationMode,
		})
	}

	// Introspect URL required for introspect or hybrid mode
	if (c.Token.ValidationMode == "introspect" || c.Token.ValidationMode == "hybrid") && c.Token.IntrospectURL == "" {
		errors = append(errors, ValidationError{
			Field:   "Token.IntrospectURL",
			Message: "introspect URL is required for introspect or hybrid validation mode",
		})
	}

	// Clock skew must be reasonable (0 to 10 minutes)
	if c.Token.ClockSkew < 0 || c.Token.ClockSkew > 10*time.Minute {
		errors = append(errors, ValidationError{
			Field:   "Token.ClockSkew",
			Message: "clock skew must be between 0 and 10 minutes",
			Value:   c.Token.ClockSkew,
		})
	}

	return errors
}

// validateSecurity validates security configuration
func (c *UnifiedConfig) validateSecurity() ValidationErrors {
	var errors ValidationErrors

	// Validate allowed user domains are valid domains
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$`)
	for _, domain := range c.Security.AllowedUserDomains {
		if !domainRegex.MatchString(domain) {
			errors = append(errors, ValidationError{
				Field:   "Security.AllowedUserDomains",
				Message: "invalid domain format",
				Value:   domain,
			})
		}
	}

	// Max login attempts must be reasonable
	if c.Security.MaxLoginAttempts < 0 || c.Security.MaxLoginAttempts > 100 {
		errors = append(errors, ValidationError{
			Field:   "Security.MaxLoginAttempts",
			Message: "max login attempts must be between 0 and 100",
			Value:   c.Security.MaxLoginAttempts,
		})
	}

	// Lockout duration must be reasonable
	if c.Security.LockoutDuration < 0 || c.Security.LockoutDuration > 24*time.Hour {
		errors = append(errors, ValidationError{
			Field:   "Security.LockoutDuration",
			Message: "lockout duration must be between 0 and 24 hours",
			Value:   c.Security.LockoutDuration,
		})
	}

	return errors
}

// validateMiddleware validates middleware configuration
func (c *UnifiedConfig) validateMiddleware() ValidationErrors {
	var errors ValidationErrors

	// Max request size must be reasonable (1KB to 100MB)
	if c.Middleware.MaxRequestSize < 1024 || c.Middleware.MaxRequestSize > 100*1024*1024 {
		errors = append(errors, ValidationError{
			Field:   "Middleware.MaxRequestSize",
			Message: "max request size must be between 1KB and 100MB",
			Value:   c.Middleware.MaxRequestSize,
		})
	}

	// Request timeout must be reasonable
	if c.Middleware.RequestTimeout < time.Second || c.Middleware.RequestTimeout > 5*time.Minute {
		errors = append(errors, ValidationError{
			Field:   "Middleware.RequestTimeout",
			Message: "request timeout must be between 1 second and 5 minutes",
			Value:   c.Middleware.RequestTimeout,
		})
	}

	return errors
}

// validateCache validates cache configuration
func (c *UnifiedConfig) validateCache() ValidationErrors {
	var errors ValidationErrors

	if !c.Cache.Enabled {
		return errors
	}

	// Cache type must be valid
	validTypes := map[string]bool{
		"memory": true,
		"redis":  true,
		"hybrid": true,
	}
	if !validTypes[c.Cache.Type] {
		errors = append(errors, ValidationError{
			Field:   "Cache.Type",
			Message: "invalid cache type (must be memory, redis, or hybrid)",
			Value:   c.Cache.Type,
		})
	}

	// Max entries must be reasonable
	if c.Cache.MaxEntries < 10 || c.Cache.MaxEntries > 1000000 {
		errors = append(errors, ValidationError{
			Field:   "Cache.MaxEntries",
			Message: "max entries must be between 10 and 1000000",
			Value:   c.Cache.MaxEntries,
		})
	}

	// Eviction policy must be valid
	validEviction := map[string]bool{
		"lru":  true,
		"lfu":  true,
		"fifo": true,
	}
	if !validEviction[c.Cache.EvictionPolicy] {
		errors = append(errors, ValidationError{
			Field:   "Cache.EvictionPolicy",
			Message: "invalid eviction policy (must be lru, lfu, or fifo)",
			Value:   c.Cache.EvictionPolicy,
		})
	}

	return errors
}

// validateRateLimit validates rate limiting configuration
func (c *UnifiedConfig) validateRateLimit() ValidationErrors {
	var errors ValidationErrors

	if !c.RateLimit.Enabled {
		return errors
	}

	// Requests per second must be reasonable
	if c.RateLimit.RequestsPerSecond < 1 || c.RateLimit.RequestsPerSecond > 10000 {
		errors = append(errors, ValidationError{
			Field:   "RateLimit.RequestsPerSecond",
			Message: "requests per second must be between 1 and 10000",
			Value:   c.RateLimit.RequestsPerSecond,
		})
	}

	// Burst must be at least as large as requests per second
	if c.RateLimit.Burst < c.RateLimit.RequestsPerSecond {
		errors = append(errors, ValidationError{
			Field:   "RateLimit.Burst",
			Message: "burst must be at least as large as requests per second",
			Value:   c.RateLimit.Burst,
		})
	}

	// Key type must be valid
	validKeyTypes := map[string]bool{
		"ip":     true,
		"user":   true,
		"token":  true,
		"custom": true,
	}
	if !validKeyTypes[c.RateLimit.KeyType] {
		errors = append(errors, ValidationError{
			Field:   "RateLimit.KeyType",
			Message: "invalid key type (must be ip, user, token, or custom)",
			Value:   c.RateLimit.KeyType,
		})
	}

	return errors
}

// validateLogging validates logging configuration
func (c *UnifiedConfig) validateLogging() ValidationErrors {
	var errors ValidationErrors

	// Log level must be valid
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLevels[c.Logging.Level] {
		errors = append(errors, ValidationError{
			Field:   "Logging.Level",
			Message: "invalid log level (must be debug, info, warn, or error)",
			Value:   c.Logging.Level,
		})
	}

	// Format must be valid
	validFormats := map[string]bool{
		"json":       true,
		"text":       true,
		"structured": true,
	}
	if !validFormats[c.Logging.Format] {
		errors = append(errors, ValidationError{
			Field:   "Logging.Format",
			Message: "invalid log format (must be json, text, or structured)",
			Value:   c.Logging.Format,
		})
	}

	// Output must be valid
	validOutputs := map[string]bool{
		"stdout": true,
		"stderr": true,
		"file":   true,
	}
	if !validOutputs[c.Logging.Output] {
		errors = append(errors, ValidationError{
			Field:   "Logging.Output",
			Message: "invalid log output (must be stdout, stderr, or file)",
			Value:   c.Logging.Output,
		})
	}

	// File path required if output is file
	if c.Logging.Output == "file" && c.Logging.FilePath == "" {
		errors = append(errors, ValidationError{
			Field:   "Logging.FilePath",
			Message: "file path is required when output is 'file'",
		})
	}

	return errors
}

// validateMetrics validates metrics configuration
func (c *UnifiedConfig) validateMetrics() ValidationErrors {
	var errors ValidationErrors

	if !c.Metrics.Enabled {
		return errors
	}

	// Provider must be valid
	validProviders := map[string]bool{
		"prometheus": true,
		"statsd":     true,
		"otlp":       true,
	}
	if !validProviders[c.Metrics.Provider] {
		errors = append(errors, ValidationError{
			Field:   "Metrics.Provider",
			Message: "invalid metrics provider (must be prometheus, statsd, or otlp)",
			Value:   c.Metrics.Provider,
		})
	}

	// Endpoint required for some providers
	if (c.Metrics.Provider == "statsd" || c.Metrics.Provider == "otlp") && c.Metrics.Endpoint == "" {
		errors = append(errors, ValidationError{
			Field:   "Metrics.Endpoint",
			Message: fmt.Sprintf("endpoint is required for %s provider", c.Metrics.Provider),
		})
	}

	return errors
}

// validateTransport validates transport configuration
func (c *UnifiedConfig) validateTransport() ValidationErrors {
	var errors ValidationErrors

	// Max connections must be reasonable
	if c.Transport.MaxIdleConns < 0 || c.Transport.MaxIdleConns > 10000 {
		errors = append(errors, ValidationError{
			Field:   "Transport.MaxIdleConns",
			Message: "max idle connections must be between 0 and 10000",
			Value:   c.Transport.MaxIdleConns,
		})
	}

	// TLS min version must be valid
	validTLSVersions := map[string]bool{
		"TLS1.0": true,
		"TLS1.1": true,
		"TLS1.2": true,
		"TLS1.3": true,
	}
	if c.Transport.TLSMinVersion != "" && !validTLSVersions[c.Transport.TLSMinVersion] {
		errors = append(errors, ValidationError{
			Field:   "Transport.TLSMinVersion",
			Message: "invalid TLS min version (must be TLS1.0, TLS1.1, TLS1.2, or TLS1.3)",
			Value:   c.Transport.TLSMinVersion,
		})
	}

	// Proxy URL must be valid if provided
	if c.Transport.ProxyURL != "" {
		if _, err := url.Parse(c.Transport.ProxyURL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "Transport.ProxyURL",
				Message: "invalid proxy URL",
				Value:   c.Transport.ProxyURL,
			})
		}
	}

	return errors
}

// validateCircuit validates circuit breaker configuration
func (c *UnifiedConfig) validateCircuit() ValidationErrors {
	var errors ValidationErrors

	if !c.Circuit.Enabled {
		return errors
	}

	// Consecutive failures must be reasonable
	if c.Circuit.ConsecutiveFailures < 1 || c.Circuit.ConsecutiveFailures > 100 {
		errors = append(errors, ValidationError{
			Field:   "Circuit.ConsecutiveFailures",
			Message: "consecutive failures must be between 1 and 100",
			Value:   c.Circuit.ConsecutiveFailures,
		})
	}

	// Failure ratio must be between 0 and 1
	if c.Circuit.FailureRatio < 0 || c.Circuit.FailureRatio > 1 {
		errors = append(errors, ValidationError{
			Field:   "Circuit.FailureRatio",
			Message: "failure ratio must be between 0 and 1",
			Value:   c.Circuit.FailureRatio,
		})
	}

	// OnOpen action must be valid
	validActions := map[string]bool{
		"reject":      true,
		"fallback":    true,
		"passthrough": true,
	}
	if !validActions[c.Circuit.OnOpen] {
		errors = append(errors, ValidationError{
			Field:   "Circuit.OnOpen",
			Message: "invalid OnOpen action (must be reject, fallback, or passthrough)",
			Value:   c.Circuit.OnOpen,
		})
	}

	return errors
}
