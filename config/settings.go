// Package config provides configuration management for the OIDC middleware
package config

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	ProviderURL               string                 `json:"providerUrl"`
	ClientID                  string                 `json:"clientId"`
	ClientSecret              string                 `json:"clientSecret"`
	CallbackURL               string                 `json:"callbackUrl"`
	LogoutURL                 string                 `json:"logoutUrl"`
	PostLogoutRedirectURI     string                 `json:"postLogoutRedirectUri"`
	SessionEncryptionKey      string                 `json:"sessionEncryptionKey"`
	ForceHTTPS                bool                   `json:"forceHttps"`
	LogLevel                  string                 `json:"logLevel"`
	Scopes                    []string               `json:"scopes"`
	OverrideScopes            bool                   `json:"overrideScopes"`
	AllowedUsers              []string               `json:"allowedUsers"`
	AllowedUserDomains        []string               `json:"allowedUserDomains"`
	AllowedRolesAndGroups     []string               `json:"allowedRolesAndGroups"`
	ExcludedURLs              []string               `json:"excludedUrls"`
	EnablePKCE                bool                   `json:"enablePkce"`
	RateLimit                 int                    `json:"rateLimit"`
	RefreshGracePeriodSeconds int                    `json:"refreshGracePeriodSeconds"`
	Headers                   []HeaderConfig         `json:"headers"`
	HTTPClient                *http.Client           `json:"-"`
	CookieDomain              string                 `json:"cookieDomain"`
	SecurityHeaders           *SecurityHeadersConfig `json:"securityHeaders,omitempty"`
}

// HeaderConfig represents header template configuration
type HeaderConfig struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SecurityHeadersConfig configures security headers for the plugin
type SecurityHeadersConfig struct {
	// Enable security headers (default: true)
	Enabled bool `json:"enabled"`

	// Security profile: "default", "strict", "development", "api", or "custom"
	Profile string `json:"profile"`

	// Content Security Policy
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty"`

	// HSTS settings
	StrictTransportSecurity           bool `json:"strictTransportSecurity"`
	StrictTransportSecurityMaxAge     int  `json:"strictTransportSecurityMaxAge"` // seconds
	StrictTransportSecuritySubdomains bool `json:"strictTransportSecuritySubdomains"`
	StrictTransportSecurityPreload    bool `json:"strictTransportSecurityPreload"`

	// Frame options: "DENY", "SAMEORIGIN", or "ALLOW-FROM uri"
	FrameOptions string `json:"frameOptions,omitempty"`

	// Content type options (default: "nosniff")
	ContentTypeOptions string `json:"contentTypeOptions,omitempty"`

	// XSS protection (default: "1; mode=block")
	XSSProtection string `json:"xssProtection,omitempty"`

	// Referrer policy
	ReferrerPolicy string `json:"referrerPolicy,omitempty"`

	// Permissions policy
	PermissionsPolicy string `json:"permissionsPolicy,omitempty"`

	// Cross-origin settings
	CrossOriginEmbedderPolicy string `json:"crossOriginEmbedderPolicy,omitempty"`
	CrossOriginOpenerPolicy   string `json:"crossOriginOpenerPolicy,omitempty"`
	CrossOriginResourcePolicy string `json:"crossOriginResourcePolicy,omitempty"`

	// CORS settings
	CORSEnabled          bool     `json:"corsEnabled"`
	CORSAllowedOrigins   []string `json:"corsAllowedOrigins,omitempty"`
	CORSAllowedMethods   []string `json:"corsAllowedMethods,omitempty"`
	CORSAllowedHeaders   []string `json:"corsAllowedHeaders,omitempty"`
	CORSAllowCredentials bool     `json:"corsAllowCredentials"`
	CORSMaxAge           int      `json:"corsMaxAge"` // seconds

	// Custom headers (in addition to standard security headers)
	CustomHeaders map[string]string `json:"customHeaders,omitempty"`

	// Security features
	DisableServerHeader    bool `json:"disableServerHeader"`
	DisablePoweredByHeader bool `json:"disablePoweredByHeader"`
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
		Scopes:                    []string{"openid", "profile", "email"},
		Headers:                   []HeaderConfig{},
		SecurityHeaders:           createDefaultSecurityConfig(),
	}
}

// createDefaultSecurityConfig creates a default security headers configuration
func createDefaultSecurityConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		Enabled: true,
		Profile: "default",

		// Default security headers
		StrictTransportSecurity:           true,
		StrictTransportSecurityMaxAge:     31536000, // 1 year
		StrictTransportSecuritySubdomains: true,
		StrictTransportSecurityPreload:    true,

		FrameOptions:       "DENY",
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",
		ReferrerPolicy:     "strict-origin-when-cross-origin",

		// CORS disabled by default
		CORSEnabled:          false,
		CORSAllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		CORSAllowedHeaders:   []string{"Authorization", "Content-Type"},
		CORSAllowCredentials: false,
		CORSMaxAge:           86400, // 24 hours

		// Security features
		DisableServerHeader:    true,
		DisablePoweredByHeader: true,
	}
}

// ToInternalSecurityConfig converts plugin SecurityHeadersConfig to internal security config
func (c *SecurityHeadersConfig) ToInternalSecurityConfig() interface{} {
	if c == nil || !c.Enabled {
		return nil
	}

	// Create the internal security config structure
	config := map[string]interface{}{
		"DevelopmentMode": false,
	}

	// Apply profile-based defaults
	switch strings.ToLower(c.Profile) {
	case "strict":
		applyStrictProfile(config)
	case "development":
		applyDevelopmentProfile(config)
	case "api":
		applyAPIProfile(config)
	case "custom":
		// No defaults, use only what's explicitly configured
	default: // "default"
		applyDefaultProfile(config)
	}

	// Override with explicit configuration
	if c.ContentSecurityPolicy != "" {
		config["ContentSecurityPolicy"] = c.ContentSecurityPolicy
	}

	// HSTS configuration
	if c.StrictTransportSecurity {
		config["StrictTransportSecurityMaxAge"] = c.StrictTransportSecurityMaxAge
		config["StrictTransportSecuritySubdomains"] = c.StrictTransportSecuritySubdomains
		config["StrictTransportSecurityPreload"] = c.StrictTransportSecurityPreload
	}

	// Frame options
	if c.FrameOptions != "" {
		config["FrameOptions"] = c.FrameOptions
	}

	// Content type and XSS protection
	if c.ContentTypeOptions != "" {
		config["ContentTypeOptions"] = c.ContentTypeOptions
	}
	if c.XSSProtection != "" {
		config["XSSProtection"] = c.XSSProtection
	}

	// Referrer and permissions policies
	if c.ReferrerPolicy != "" {
		config["ReferrerPolicy"] = c.ReferrerPolicy
	}
	if c.PermissionsPolicy != "" {
		config["PermissionsPolicy"] = c.PermissionsPolicy
	}

	// Cross-origin policies
	if c.CrossOriginEmbedderPolicy != "" {
		config["CrossOriginEmbedderPolicy"] = c.CrossOriginEmbedderPolicy
	}
	if c.CrossOriginOpenerPolicy != "" {
		config["CrossOriginOpenerPolicy"] = c.CrossOriginOpenerPolicy
	}
	if c.CrossOriginResourcePolicy != "" {
		config["CrossOriginResourcePolicy"] = c.CrossOriginResourcePolicy
	}

	// CORS configuration
	config["CORSEnabled"] = c.CORSEnabled
	if len(c.CORSAllowedOrigins) > 0 {
		config["CORSAllowedOrigins"] = c.CORSAllowedOrigins
	}
	if len(c.CORSAllowedMethods) > 0 {
		config["CORSAllowedMethods"] = c.CORSAllowedMethods
	}
	if len(c.CORSAllowedHeaders) > 0 {
		config["CORSAllowedHeaders"] = c.CORSAllowedHeaders
	}
	config["CORSAllowCredentials"] = c.CORSAllowCredentials
	if c.CORSMaxAge > 0 {
		config["CORSMaxAge"] = c.CORSMaxAge
	}

	// Custom headers
	if len(c.CustomHeaders) > 0 {
		config["CustomHeaders"] = c.CustomHeaders
	}

	// Security features
	config["DisableServerHeader"] = c.DisableServerHeader
	config["DisablePoweredByHeader"] = c.DisablePoweredByHeader

	return config
}

// applyDefaultProfile applies default security settings
func applyDefaultProfile(config map[string]interface{}) {
	config["ContentSecurityPolicy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
	config["FrameOptions"] = "DENY"
	config["ContentTypeOptions"] = "nosniff"
	config["XSSProtection"] = "1; mode=block"
	config["ReferrerPolicy"] = "strict-origin-when-cross-origin"
	config["PermissionsPolicy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
	config["CrossOriginEmbedderPolicy"] = "require-corp"
	config["CrossOriginOpenerPolicy"] = "same-origin"
	config["CrossOriginResourcePolicy"] = "same-origin"
}

// applyStrictProfile applies strict security settings
func applyStrictProfile(config map[string]interface{}) {
	config["ContentSecurityPolicy"] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
	config["FrameOptions"] = "DENY"
	config["ContentTypeOptions"] = "nosniff"
	config["XSSProtection"] = "1; mode=block"
	config["ReferrerPolicy"] = "strict-origin-when-cross-origin"
	config["PermissionsPolicy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()"
	config["CrossOriginEmbedderPolicy"] = "require-corp"
	config["CrossOriginOpenerPolicy"] = "same-origin"
	config["CrossOriginResourcePolicy"] = "same-site"
}

// applyDevelopmentProfile applies development-friendly settings
func applyDevelopmentProfile(config map[string]interface{}) {
	config["ContentSecurityPolicy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' ws: wss:;"
	config["FrameOptions"] = "SAMEORIGIN"
	config["ContentTypeOptions"] = "nosniff"
	config["XSSProtection"] = "1; mode=block"
	config["ReferrerPolicy"] = "strict-origin-when-cross-origin"
	config["CrossOriginOpenerPolicy"] = "unsafe-none"
	config["CrossOriginResourcePolicy"] = "cross-origin"
	config["DevelopmentMode"] = true
}

// applyAPIProfile applies API-friendly settings
func applyAPIProfile(config map[string]interface{}) {
	config["ContentSecurityPolicy"] = "default-src 'none'; frame-ancestors 'none';"
	config["FrameOptions"] = "DENY"
	config["ContentTypeOptions"] = "nosniff"
	config["XSSProtection"] = "1; mode=block"
	config["ReferrerPolicy"] = "strict-origin-when-cross-origin"
	config["CrossOriginResourcePolicy"] = "cross-origin"
}

// GetSecurityHeadersApplier returns a function that applies security headers
func (c *Config) GetSecurityHeadersApplier() func(http.ResponseWriter, *http.Request) {
	if c.SecurityHeaders == nil || !c.SecurityHeaders.Enabled {
		return nil
	}

	// This would need to import the internal security package
	// For now, return a basic implementation
	return func(rw http.ResponseWriter, req *http.Request) {
		headers := rw.Header()

		// Apply basic security headers based on configuration
		if c.SecurityHeaders.FrameOptions != "" {
			headers.Set("X-Frame-Options", c.SecurityHeaders.FrameOptions)
		}
		if c.SecurityHeaders.ContentTypeOptions != "" {
			headers.Set("X-Content-Type-Options", c.SecurityHeaders.ContentTypeOptions)
		}
		if c.SecurityHeaders.XSSProtection != "" {
			headers.Set("X-XSS-Protection", c.SecurityHeaders.XSSProtection)
		}
		if c.SecurityHeaders.ReferrerPolicy != "" {
			headers.Set("Referrer-Policy", c.SecurityHeaders.ReferrerPolicy)
		}
		if c.SecurityHeaders.ContentSecurityPolicy != "" {
			headers.Set("Content-Security-Policy", c.SecurityHeaders.ContentSecurityPolicy)
		}

		// HSTS for HTTPS
		if (req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https") && c.SecurityHeaders.StrictTransportSecurity {
			hstsValue := fmt.Sprintf("max-age=%d", c.SecurityHeaders.StrictTransportSecurityMaxAge)
			if c.SecurityHeaders.StrictTransportSecuritySubdomains {
				hstsValue += "; includeSubDomains"
			}
			if c.SecurityHeaders.StrictTransportSecurityPreload {
				hstsValue += "; preload"
			}
			headers.Set("Strict-Transport-Security", hstsValue)
		}

		// CORS headers
		if c.SecurityHeaders.CORSEnabled {
			origin := req.Header.Get("Origin")
			if origin != "" && isOriginAllowed(origin, c.SecurityHeaders.CORSAllowedOrigins) {
				headers.Set("Access-Control-Allow-Origin", origin)
			}

			if len(c.SecurityHeaders.CORSAllowedMethods) > 0 {
				headers.Set("Access-Control-Allow-Methods", strings.Join(c.SecurityHeaders.CORSAllowedMethods, ", "))
			}
			if len(c.SecurityHeaders.CORSAllowedHeaders) > 0 {
				headers.Set("Access-Control-Allow-Headers", strings.Join(c.SecurityHeaders.CORSAllowedHeaders, ", "))
			}
			if c.SecurityHeaders.CORSAllowCredentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}
			if c.SecurityHeaders.CORSMaxAge > 0 {
				headers.Set("Access-Control-Max-Age", strconv.Itoa(c.SecurityHeaders.CORSMaxAge))
			}
		}

		// Custom headers
		for name, value := range c.SecurityHeaders.CustomHeaders {
			headers.Set(name, value)
		}

		// Remove server headers
		if c.SecurityHeaders.DisableServerHeader {
			headers.Del("Server")
		}
		if c.SecurityHeaders.DisablePoweredByHeader {
			headers.Del("X-Powered-By")
		}
	}
}

// isOriginAllowed checks if an origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if origin == allowed || allowed == "*" {
			return true
		}
		// Simple wildcard matching for subdomains
		if strings.Contains(allowed, "*") {
			if strings.HasPrefix(allowed, "https://*.") {
				domain := strings.TrimPrefix(allowed, "https://*.")
				if strings.HasSuffix(origin, "."+domain) || origin == "https://"+domain {
					return true
				}
			}
			if strings.HasPrefix(allowed, "http://*.") {
				domain := strings.TrimPrefix(allowed, "http://*.")
				if strings.HasSuffix(origin, "."+domain) || origin == "http://"+domain {
					return true
				}
			}
		}
	}
	return false
}
