// Package config provides configuration management for the OIDC middleware
package config

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	minEncryptionKeyLength = 16
	ConstSessionTimeout    = 86400
)

//lint:ignore U1000 May be referenced for default exclusion patterns
var defaultExcludedURLs = map[string]struct{}{
	"/favicon.ico":  {},
	"/robots.txt":   {},
	"/health":       {},
	"/.well-known/": {},
	"/metrics":      {},
	"/ping":         {},
	"/api/":         {},
	"/static/":      {},
	"/assets/":      {},
	"/js/":          {},
	"/css/":         {},
	"/images/":      {},
	"/fonts/":       {},
}

// Settings manages configuration and initialization for the OIDC middleware
type Settings struct {
	logger Logger
}

// Logger interface for dependency injection
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

// Config represents the configuration for the OIDC middleware
type Config struct {
	ProviderURL               string         `json:"providerUrl"`
	ClientID                  string         `json:"clientId"`
	ClientSecret              string         `json:"clientSecret"`
	CallbackURL               string         `json:"callbackUrl"`
	LogoutURL                 string         `json:"logoutUrl"`
	PostLogoutRedirectURI     string         `json:"postLogoutRedirectUri"`
	SessionEncryptionKey      string         `json:"sessionEncryptionKey"`
	ForceHTTPS                bool           `json:"forceHttps"`
	LogLevel                  string         `json:"logLevel"`
	Scopes                    []string       `json:"scopes"`
	OverrideScopes            bool           `json:"overrideScopes"`
	AllowedUsers              []string       `json:"allowedUsers"`
	AllowedUserDomains        []string       `json:"allowedUserDomains"`
	AllowedRolesAndGroups     []string       `json:"allowedRolesAndGroups"`
	ExcludedURLs              []string       `json:"excludedUrls"`
	EnablePKCE                bool           `json:"enablePkce"`
	RateLimit                 int            `json:"rateLimit"`
	RefreshGracePeriodSeconds int            `json:"refreshGracePeriodSeconds"`
	Headers                   []HeaderConfig `json:"headers"`
	HTTPClient                *http.Client   `json:"-"`
	CookieDomain              string         `json:"cookieDomain"`
}

// HeaderConfig represents header template configuration
type HeaderConfig struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// NewSettings creates a new Settings instance
func NewSettings(logger Logger) *Settings {
	return &Settings{
		logger: logger,
	}
}

// CreateConfig creates a default configuration
func CreateConfig() *Config {
	return &Config{
		LogLevel:                  "INFO",
		ForceHTTPS:                true,
		EnablePKCE:                true,
		RateLimit:                 10,
		RefreshGracePeriodSeconds: 60,
	}
}

// InitializeTraefikOidc would initialize and configure a new TraefikOidc instance
// This functionality has been moved to the main New function in main.go
// This function is kept for compatibility but should not be used
func (s *Settings) InitializeTraefikOidc(ctx context.Context, next http.Handler, config *Config, name string) (interface{}, error) {
	return nil, fmt.Errorf("InitializeTraefikOidc is deprecated - use New function from main package instead")
}

//lint:ignore U1000 Kept for backward compatibility
func (s *Settings) setupHeaderTemplates(t interface{}, config *Config, logger Logger) error {
	logger.Debug("setupHeaderTemplates is deprecated")
	return nil
}

//lint:ignore U1000 May be needed for future background service management
func (s *Settings) startBackgroundServices(ctx context.Context, logger Logger) {
	startReplayCacheCleanup(ctx, logger)

	// Start memory monitoring for leak detection and performance insights
	memoryMonitor := GetGlobalMemoryMonitor()
	memoryMonitor.StartMonitoring(ctx, 60*time.Second) // Monitor every minute
	logger.Debug("Started global memory monitoring")
}

// Utility functions

//lint:ignore U1000 May be needed for future scope processing
func deduplicateScopes(scopes []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, scope := range scopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	return result
}

//lint:ignore U1000 May be needed for future scope merging operations
func mergeScopes(defaultScopes, userScopes []string) []string {
	result := make([]string, len(defaultScopes))
	copy(result, defaultScopes)
	return append(result, userScopes...)
}

//lint:ignore U1000 May be needed for future utility operations
func createStringMap(items []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range items {
		result[item] = struct{}{}
	}
	return result
}

//lint:ignore U1000 May be needed for future case-insensitive operations
func createCaseInsensitiveStringMap(items []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range items {
		result[strings.ToLower(item)] = struct{}{}
	}
	return result
}

//lint:ignore U1000 May be needed for future test environment detection
func isTestMode() bool {
	// This function should be implemented based on environment detection logic
	return false
}

// External dependencies that need to be provided
// TraefikOidc struct is defined in types.go

// These functions need to be provided by external packages
func NewLogger(level string) Logger                                          { return nil }
func CreateDefaultHTTPClient() *http.Client                                  { return nil }
func CreateTokenHTTPClient() *http.Client                                    { return nil }
func GetGlobalCacheManager(*sync.WaitGroup) CacheManager                     { return nil }
func NewSessionManager(string, bool, string, Logger) (SessionManager, error) { return nil, nil }
func NewErrorRecoveryManager(Logger) ErrorRecoveryManager                    { return nil }

//lint:ignore U1000 May be needed for future token claim extraction
func extractClaims(string) (map[string]interface{}, error) { return nil, nil }

//lint:ignore U1000 May be needed for future replay attack prevention
func startReplayCacheCleanup(context.Context, Logger) {}
func GetGlobalMemoryMonitor() MemoryMonitor           { return nil }

// Interfaces for external dependencies
type CacheManager interface {
	GetSharedTokenBlacklist() CacheInterface
	GetSharedTokenCache() *TokenCache
	GetSharedMetadataCache() *MetadataCache
	GetSharedJWKCache() JWKCacheInterface
	Close() error
}
type SessionManager interface{}
type ErrorRecoveryManager interface{}
type MemoryMonitor interface {
	StartMonitoring(ctx context.Context, interval time.Duration)
}
type CacheInterface interface {
	Set(key string, value interface{}, ttl time.Duration)
	Get(key string) (interface{}, bool)
	Delete(key string)
	SetMaxSize(size int)
	Cleanup()
	Close()
}
type TokenCache struct{}
type MetadataCache struct{}
type JWKCacheInterface interface{}
