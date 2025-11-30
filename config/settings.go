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

	// Dynamic Client Registration (RFC 7591) configuration
	DynamicClientRegistration *DynamicClientRegistrationConfig `json:"dynamicClientRegistration,omitempty"`
}

// DynamicClientRegistrationConfig configures OIDC Dynamic Client Registration (RFC 7591)
type DynamicClientRegistrationConfig struct {
	// Enabled enables automatic client registration with the OIDC provider
	Enabled bool `json:"enabled"`

	// InitialAccessToken is an optional bearer token for protected registration endpoints
	// Some providers require this token to authorize new client registrations
	InitialAccessToken string `json:"initialAccessToken,omitempty"`

	// RegistrationEndpoint overrides the endpoint discovered from provider metadata
	// If empty, uses the registration_endpoint from .well-known/openid-configuration
	RegistrationEndpoint string `json:"registrationEndpoint,omitempty"`

	// ClientMetadata contains the client metadata to register
	ClientMetadata *ClientRegistrationMetadata `json:"clientMetadata,omitempty"`

	// PersistCredentials determines whether to save registered credentials to a file
	// This allows reusing the same client_id/client_secret across restarts
	PersistCredentials bool `json:"persistCredentials"`

	// CredentialsFile is the path to store/load registered client credentials
	// Defaults to "/tmp/oidc-client-credentials.json" if not specified
	CredentialsFile string `json:"credentialsFile,omitempty"`
}

// ClientRegistrationMetadata contains client metadata for dynamic registration (RFC 7591)
type ClientRegistrationMetadata struct {
	// RedirectURIs is REQUIRED - array of redirect URIs for authorization
	RedirectURIs []string `json:"redirect_uris"`

	// ResponseTypes specifies OAuth 2.0 response types (default: ["code"])
	ResponseTypes []string `json:"response_types,omitempty"`

	// GrantTypes specifies OAuth 2.0 grant types (default: ["authorization_code"])
	GrantTypes []string `json:"grant_types,omitempty"`

	// ApplicationType is either "web" (default) or "native"
	ApplicationType string `json:"application_type,omitempty"`

	// Contacts is an array of email addresses for responsible parties
	Contacts []string `json:"contacts,omitempty"`

	// ClientName is a human-readable name for the client
	ClientName string `json:"client_name,omitempty"`

	// LogoURI is a URL pointing to a logo for the client
	LogoURI string `json:"logo_uri,omitempty"`

	// ClientURI is a URL of the home page of the client
	ClientURI string `json:"client_uri,omitempty"`

	// PolicyURI is a URL pointing to the client's privacy policy
	PolicyURI string `json:"policy_uri,omitempty"`

	// TOSURI is a URL pointing to the client's terms of service
	TOSURI string `json:"tos_uri,omitempty"`

	// JWKSURI is a URL for the client's JSON Web Key Set
	JWKSURI string `json:"jwks_uri,omitempty"`

	// SubjectType is "pairwise" or "public" (provider-specific)
	SubjectType string `json:"subject_type,omitempty"`

	// TokenEndpointAuthMethod specifies how the client authenticates at token endpoint
	// Values: "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// DefaultMaxAge is the default maximum authentication age in seconds
	DefaultMaxAge int `json:"default_max_age,omitempty"`

	// RequireAuthTime specifies whether auth_time claim is required in ID token
	RequireAuthTime bool `json:"require_auth_time,omitempty"`

	// DefaultACRValues specifies default ACR values
	DefaultACRValues []string `json:"default_acr_values,omitempty"`

	// Scope is a space-separated list of scopes (alternative to config.Scopes)
	Scope string `json:"scope,omitempty"`
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
