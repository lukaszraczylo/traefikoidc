// Package security provides security-related middleware and utilities
package security

import (
	"net/http"
	"strings"
	"time"
)

// SecurityHeadersConfig configures security headers
type SecurityHeadersConfig struct {
	// Content Security Policy
	ContentSecurityPolicy string

	// HSTS settings
	StrictTransportSecurity           string
	StrictTransportSecurityMaxAge     int // seconds
	StrictTransportSecuritySubdomains bool
	StrictTransportSecurityPreload    bool

	// Frame options
	FrameOptions string // DENY, SAMEORIGIN, or ALLOW-FROM uri

	// Content type options
	ContentTypeOptions string // nosniff

	// XSS protection
	XSSProtection string // 1; mode=block

	// Referrer policy
	ReferrerPolicy string

	// Permissions policy
	PermissionsPolicy string

	// Cross-origin settings
	CrossOriginEmbedderPolicy string
	CrossOriginOpenerPolicy   string
	CrossOriginResourcePolicy string

	// CORS settings
	CORSEnabled          bool
	CORSAllowedOrigins   []string
	CORSAllowedMethods   []string
	CORSAllowedHeaders   []string
	CORSAllowCredentials bool
	CORSMaxAge           int // seconds

	// Custom headers
	CustomHeaders map[string]string

	// Security features
	DisableServerHeader    bool
	DisablePoweredByHeader bool

	// Development mode (less strict for local development)
	DevelopmentMode bool
}

// DefaultSecurityConfig returns a secure default configuration
func DefaultSecurityConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",

		StrictTransportSecurityMaxAge:     31536000, // 1 year
		StrictTransportSecuritySubdomains: true,
		StrictTransportSecurityPreload:    true,

		FrameOptions:       "DENY",
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",
		ReferrerPolicy:     "strict-origin-when-cross-origin",

		PermissionsPolicy: "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()",

		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",

		CORSEnabled:        false,
		CORSAllowedMethods: []string{"GET", "POST", "OPTIONS"},
		CORSAllowedHeaders: []string{"Authorization", "Content-Type", "X-Requested-With"},
		CORSMaxAge:         86400, // 24 hours

		DisableServerHeader:    true,
		DisablePoweredByHeader: true,

		DevelopmentMode: false,
	}
}

// DevelopmentSecurityConfig returns a configuration suitable for development
func DevelopmentSecurityConfig() *SecurityHeadersConfig {
	config := DefaultSecurityConfig()

	// Relax CSP for development
	config.ContentSecurityPolicy = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' ws: wss:;"

	// Allow framing for development tools
	config.FrameOptions = "SAMEORIGIN"

	// Enable CORS for local development
	config.CORSEnabled = true
	config.CORSAllowedOrigins = []string{"http://localhost:*", "http://127.0.0.1:*"}
	config.CORSAllowCredentials = true

	// Relax cross-origin policies
	config.CrossOriginEmbedderPolicy = ""
	config.CrossOriginOpenerPolicy = "unsafe-none"
	config.CrossOriginResourcePolicy = "cross-origin"

	config.DevelopmentMode = true

	return config
}

// SecurityHeadersMiddleware applies security headers to HTTP responses
type SecurityHeadersMiddleware struct {
	config *SecurityHeadersConfig
}

// NewSecurityHeadersMiddleware creates a new security headers middleware
func NewSecurityHeadersMiddleware(config *SecurityHeadersConfig) *SecurityHeadersMiddleware {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	return &SecurityHeadersMiddleware{
		config: config,
	}
}

// Apply applies security headers to the response
func (m *SecurityHeadersMiddleware) Apply(rw http.ResponseWriter, req *http.Request) {
	headers := rw.Header()

	// Content Security Policy
	if m.config.ContentSecurityPolicy != "" {
		headers.Set("Content-Security-Policy", m.config.ContentSecurityPolicy)
	}

	// HSTS (only for HTTPS)
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		hstsValue := m.buildHSTSHeader()
		if hstsValue != "" {
			headers.Set("Strict-Transport-Security", hstsValue)
		}
	}

	// Frame options
	if m.config.FrameOptions != "" {
		headers.Set("X-Frame-Options", m.config.FrameOptions)
	}

	// Content type options
	if m.config.ContentTypeOptions != "" {
		headers.Set("X-Content-Type-Options", m.config.ContentTypeOptions)
	}

	// XSS protection
	if m.config.XSSProtection != "" {
		headers.Set("X-XSS-Protection", m.config.XSSProtection)
	}

	// Referrer policy
	if m.config.ReferrerPolicy != "" {
		headers.Set("Referrer-Policy", m.config.ReferrerPolicy)
	}

	// Permissions policy
	if m.config.PermissionsPolicy != "" {
		headers.Set("Permissions-Policy", m.config.PermissionsPolicy)
	}

	// Cross-origin policies
	if m.config.CrossOriginEmbedderPolicy != "" {
		headers.Set("Cross-Origin-Embedder-Policy", m.config.CrossOriginEmbedderPolicy)
	}

	if m.config.CrossOriginOpenerPolicy != "" {
		headers.Set("Cross-Origin-Opener-Policy", m.config.CrossOriginOpenerPolicy)
	}

	if m.config.CrossOriginResourcePolicy != "" {
		headers.Set("Cross-Origin-Resource-Policy", m.config.CrossOriginResourcePolicy)
	}

	// CORS headers
	if m.config.CORSEnabled {
		m.applyCORSHeaders(rw, req)
	}

	// Custom headers
	for name, value := range m.config.CustomHeaders {
		headers.Set(name, value)
	}

	// Remove server identification headers
	if m.config.DisableServerHeader {
		headers.Del("Server")
	}

	if m.config.DisablePoweredByHeader {
		headers.Del("X-Powered-By")
	}

	// Add security timestamp for debugging
	if m.config.DevelopmentMode {
		headers.Set("X-Security-Headers-Applied", time.Now().UTC().Format(time.RFC3339))
	}
}

// buildHSTSHeader constructs the HSTS header value
func (m *SecurityHeadersMiddleware) buildHSTSHeader() string {
	if m.config.StrictTransportSecurityMaxAge <= 0 {
		return ""
	}

	parts := []string{
		"max-age=" + string(rune(m.config.StrictTransportSecurityMaxAge)),
	}

	if m.config.StrictTransportSecuritySubdomains {
		parts = append(parts, "includeSubDomains")
	}

	if m.config.StrictTransportSecurityPreload {
		parts = append(parts, "preload")
	}

	return strings.Join(parts, "; ")
}

// applyCORSHeaders applies CORS headers based on the request
func (m *SecurityHeadersMiddleware) applyCORSHeaders(rw http.ResponseWriter, req *http.Request) {
	headers := rw.Header()
	origin := req.Header.Get("Origin")

	// Check if origin is allowed
	if origin != "" && m.isOriginAllowed(origin) {
		headers.Set("Access-Control-Allow-Origin", origin)
	} else if len(m.config.CORSAllowedOrigins) == 1 && m.config.CORSAllowedOrigins[0] == "*" {
		headers.Set("Access-Control-Allow-Origin", "*")
	}

	// Set other CORS headers
	if len(m.config.CORSAllowedMethods) > 0 {
		headers.Set("Access-Control-Allow-Methods", strings.Join(m.config.CORSAllowedMethods, ", "))
	}

	if len(m.config.CORSAllowedHeaders) > 0 {
		headers.Set("Access-Control-Allow-Headers", strings.Join(m.config.CORSAllowedHeaders, ", "))
	}

	if m.config.CORSAllowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}

	if m.config.CORSMaxAge > 0 {
		headers.Set("Access-Control-Max-Age", string(rune(m.config.CORSMaxAge)))
	}

	// Handle preflight requests
	if req.Method == "OPTIONS" {
		headers.Set("Access-Control-Allow-Methods", strings.Join(m.config.CORSAllowedMethods, ", "))
		headers.Set("Access-Control-Allow-Headers", strings.Join(m.config.CORSAllowedHeaders, ", "))
		rw.WriteHeader(http.StatusOK)
	}
}

// isOriginAllowed checks if the origin is in the allowed list
func (m *SecurityHeadersMiddleware) isOriginAllowed(origin string) bool {
	for _, allowed := range m.config.CORSAllowedOrigins {
		if m.matchOrigin(origin, allowed) {
			return true
		}
	}
	return false
}

// matchOrigin checks if an origin matches an allowed pattern
func (m *SecurityHeadersMiddleware) matchOrigin(origin, pattern string) bool {
	// Exact match
	if origin == pattern {
		return true
	}

	// Wildcard subdomain match (e.g., "https://*.example.com")
	if strings.Contains(pattern, "*") {
		// Simple wildcard matching for subdomains
		if strings.HasPrefix(pattern, "https://*.") {
			domain := strings.TrimPrefix(pattern, "https://*.")
			if strings.HasSuffix(origin, "."+domain) || origin == "https://"+domain {
				return true
			}
		}
		if strings.HasPrefix(pattern, "http://*.") {
			domain := strings.TrimPrefix(pattern, "http://*.")
			if strings.HasSuffix(origin, "."+domain) || origin == "http://"+domain {
				return true
			}
		}
	}

	// Port wildcard match (e.g., "http://localhost:*")
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, ":*")
		if strings.HasPrefix(origin, prefix+":") {
			return true
		}
	}

	return false
}

// Wrap wraps an HTTP handler with security headers
func (m *SecurityHeadersMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		m.Apply(rw, req)
		next.ServeHTTP(rw, req)
	})
}

// SecurityHeadersHandler is a convenience function that creates and applies security headers
func SecurityHeadersHandler(config *SecurityHeadersConfig) func(http.ResponseWriter, *http.Request) {
	middleware := NewSecurityHeadersMiddleware(config)
	return middleware.Apply
}

// Common security header presets

// StrictSecurityConfig returns a very strict security configuration
func StrictSecurityConfig() *SecurityHeadersConfig {
	config := DefaultSecurityConfig()

	// Very strict CSP
	config.ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

	// Stricter frame options
	config.FrameOptions = "DENY"

	// Disable CORS entirely
	config.CORSEnabled = false

	// Very strict cross-origin policies
	config.CrossOriginEmbedderPolicy = "require-corp"
	config.CrossOriginOpenerPolicy = "same-origin"
	config.CrossOriginResourcePolicy = "same-site"

	return config
}

// APISecurityConfig returns a configuration suitable for APIs
func APISecurityConfig() *SecurityHeadersConfig {
	config := DefaultSecurityConfig()

	// API-friendly CSP
	config.ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none';"

	// Enable CORS for APIs
	config.CORSEnabled = true
	config.CORSAllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
	config.CORSAllowedHeaders = []string{"Authorization", "Content-Type", "X-Requested-With", "X-API-Key"}

	// API-appropriate policies
	config.CrossOriginResourcePolicy = "cross-origin"

	return config
}

// ValidateConfig validates the security configuration
func (c *SecurityHeadersConfig) Validate() error {
	// Validate HSTS max age
	if c.StrictTransportSecurityMaxAge < 0 {
		c.StrictTransportSecurityMaxAge = 0
	}

	// Validate CORS max age
	if c.CORSMaxAge < 0 {
		c.CORSMaxAge = 0
	}

	// Validate frame options
	validFrameOptions := []string{"DENY", "SAMEORIGIN", ""}
	isValidFrameOption := false
	for _, valid := range validFrameOptions {
		if c.FrameOptions == valid || strings.HasPrefix(c.FrameOptions, "ALLOW-FROM ") {
			isValidFrameOption = true
			break
		}
	}
	if !isValidFrameOption {
		c.FrameOptions = "DENY"
	}

	return nil
}

// ApplyToResponseWriter is a helper function to quickly apply security headers
func ApplySecurityHeaders(rw http.ResponseWriter, req *http.Request, config *SecurityHeadersConfig) {
	middleware := NewSecurityHeadersMiddleware(config)
	middleware.Apply(rw, req)
}
