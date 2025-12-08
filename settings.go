package traefikoidc

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// TemplatedHeader represents a custom HTTP header with a templated value.
// The value can contain template expressions that will be evaluated for each
// authenticated request, such as {{.claims.email}} or {{.accessToken}}.
type TemplatedHeader struct {
	// Name is the HTTP header name to set (e.g., "X-Forwarded-Email")
	Name string `json:"name"`

	// Value is the template string for the header value
	// Example: "{{.claims.email}}", "Bearer {{.accessToken}}"
	Value string `json:"value"`
}

// Config holds the configuration for the OIDC middleware.
// It provides all necessary settings to configure OpenID Connect authentication
// with various providers like Auth0, Logto, or any standard OIDC provider.
type Config struct {
	HTTPClient        *http.Client `json:"-"`
	OIDCEndSessionURL string       `json:"oidcEndSessionURL"`
	CookieDomain      string       `json:"cookieDomain"`
	CookiePrefix      string       `json:"cookiePrefix"`  // Prefix for session cookie names (default: "_oidc_raczylo_")
	SessionMaxAge     int          `json:"sessionMaxAge"` // Maximum session age in seconds (default: 86400 = 24 hours)
	CallbackURL       string       `json:"callbackURL"`
	LogoutURL         string       `json:"logoutURL"`
	ClientID          string       `json:"clientID"`
	ClientSecret      string       `json:"clientSecret"`
	// Audience specifies the expected JWT audience claim value.
	// If not set, defaults to ClientID for backward compatibility.
	// For Auth0 API access tokens with custom audiences, set this to your API identifier.
	// For Azure AD with Application ID URI, set to "api://your-app-id".
	// Security: This value is validated against the JWT aud claim to prevent token confusion attacks.
	Audience                  string            `json:"audience,omitempty"`
	PostLogoutRedirectURI     string            `json:"postLogoutRedirectURI"`
	LogLevel                  string            `json:"logLevel"`
	SessionEncryptionKey      string            `json:"sessionEncryptionKey"`
	ProviderURL               string            `json:"providerURL"`
	RevocationURL             string            `json:"revocationURL"`
	ExcludedURLs              []string          `json:"excludedURLs"`
	AllowedUserDomains        []string          `json:"allowedUserDomains"`
	AllowedUsers              []string          `json:"allowedUsers"`
	Scopes                    []string          `json:"scopes"`
	Headers                   []TemplatedHeader `json:"headers"`
	AllowedRolesAndGroups     []string          `json:"allowedRolesAndGroups"`
	RateLimit                 int               `json:"rateLimit"`
	RefreshGracePeriodSeconds int               `json:"refreshGracePeriodSeconds"`
	ForceHTTPS                bool              `json:"forceHTTPS"`
	EnablePKCE                bool              `json:"enablePKCE"`
	OverrideScopes            bool              `json:"overrideScopes"`
	// StrictAudienceValidation enforces strict audience validation for access tokens.
	// When enabled, sessions are rejected if access token validation fails (prevents fallback to ID token).
	// This addresses Auth0 Scenario 2 security concerns where access tokens without proper
	// audience claims could be accepted based on ID token validation.
	// Default: false (backward compatible - allows ID token fallback)
	// Recommended: true for production environments requiring strict OAuth 2.0 compliance
	StrictAudienceValidation bool `json:"strictAudienceValidation,omitempty"`
	// AllowOpaqueTokens enables acceptance of non-JWT (opaque) access tokens.
	// When enabled, opaque tokens are validated via OAuth 2.0 Token Introspection (RFC 7662).
	// This supports Auth0 Scenario 3 and other providers that issue opaque access tokens.
	// Default: false (only JWT access tokens accepted)
	// Note: Requires introspection endpoint to be available from provider metadata
	AllowOpaqueTokens bool `json:"allowOpaqueTokens,omitempty"`
	// RequireTokenIntrospection forces token introspection for all opaque access tokens.
	// When enabled, opaque tokens are rejected if introspection endpoint is unavailable.
	// When disabled, opaque tokens fall back to ID token validation.
	// Default: false (allows fallback to ID token)
	// Recommended: true when AllowOpaqueTokens is enabled for maximum security
	RequireTokenIntrospection bool `json:"requireTokenIntrospection,omitempty"`
	// DisableReplayDetection disables JTI-based replay attack detection.
	// Enable this when running multiple Traefik replicas to prevent false positives.
	// Each replica maintains its own in-memory JTI cache, so the same valid token
	// hitting different replicas will trigger replay detection on subsequent requests.
	//
	// Security Note: When enabled, the plugin still validates token signatures,
	// expiration, and other claims. Only the JTI replay check is disabled.
	// Consider using a shared cache backend (Redis/Memcached) if replay detection
	// is required in multi-replica scenarios.
	//
	// Default: false (replay detection enabled)
	// Recommended: true for multi-replica deployments
	DisableReplayDetection bool                   `json:"disableReplayDetection,omitempty"`
	SecurityHeaders        *SecurityHeadersConfig `json:"securityHeaders,omitempty"`

	// Redis configures the Redis cache backend for distributed caching.
	// When enabled, provides cache sharing across multiple Traefik replicas.
	// Default: nil (disabled - uses in-memory caching)
	Redis *RedisConfig `json:"redis,omitempty"`

	// RoleClaimName specifies the JWT claim name to extract user roles from.
	// This allows compatibility with different OIDC providers that use different claim names.
	//
	// Examples:
	//   - Default (backward compatible): "roles"
	//   - Auth0 namespaced: "https://myapp.com/roles"
	//   - Keycloak realm roles: "realm_access.roles"
	//   - Custom claim: "user_roles"
	//
	// If not specified, defaults to "roles" for backward compatibility.
	// Supports both simple names and namespaced URIs per OIDC specification.
	//
	// Default: "roles"
	RoleClaimName string `json:"roleClaimName,omitempty"`

	// GroupClaimName specifies the JWT claim name to extract user groups from.
	// This allows compatibility with different OIDC providers that use different claim names.
	//
	// Examples:
	//   - Default (backward compatible): "groups"
	//   - Auth0 namespaced: "https://myapp.com/groups"
	//   - Azure AD groups: "groups"
	//   - Custom claim: "user_groups"
	//
	// If not specified, defaults to "groups" for backward compatibility.
	// Supports both simple names and namespaced URIs per OIDC specification.
	//
	// Default: "groups"
	GroupClaimName string `json:"groupClaimName,omitempty"`

	// UserIdentifierClaim specifies the JWT claim to use as the user identifier.
	// This allows authentication for users without email addresses (e.g., Azure AD service accounts).
	//
	// Examples:
	//   - Default (backward compatible): "email"
	//   - Azure AD without email: "sub", "oid", "upn", or "preferred_username"
	//   - Generic OIDC: "sub" (always present per OIDC spec)
	//
	// When set to a non-email claim:
	//   - AllowedUsers will match against this claim value instead of email
	//   - AllowedUserDomains validation is skipped (domains only apply to email)
	//   - The session will store this identifier as the user's identity
	//
	// Default: "email"
	UserIdentifierClaim string `json:"userIdentifierClaim,omitempty"`

	// DynamicClientRegistration enables OIDC Dynamic Client Registration (RFC 7591)
	// When enabled, the middleware will automatically register as a client with
	// the OIDC provider if ClientID/ClientSecret are not provided.
	DynamicClientRegistration *DynamicClientRegistrationConfig `json:"dynamicClientRegistration,omitempty"`

	// AllowPrivateIPAddresses disables the security check that blocks private/internal IP addresses.
	// By default, the plugin rejects URLs containing private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
	// to prevent SSRF attacks and ensure OIDC providers are publicly accessible.
	//
	// Enable this option ONLY when:
	//   - Your OIDC provider (e.g., Keycloak) runs on an internal network with private IPs
	//   - You have no DNS resolution available for internal services
	//   - Your entire stack runs in a Docker network or Kubernetes cluster with private addressing
	//
	// Security Warning: Enabling this option reduces SSRF protection. Only use in trusted
	// network environments where the OIDC provider is known and controlled.
	//
	// Default: false (private IPs are blocked for security)
	AllowPrivateIPAddresses bool `json:"allowPrivateIPAddresses,omitempty"`
}

// RedisConfig configures Redis cache backend settings for distributed caching.
// All fields support both JSON and YAML configuration for compatibility with Traefik's
// dynamic configuration (labels, YAML files, etc.)
type RedisConfig struct {
	// Enabled indicates if Redis caching should be used (default: false)
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Address is the Redis server address (e.g., "localhost:6379", "redis:6379")
	Address string `json:"address" yaml:"address"`

	// Password for Redis authentication (optional, leave empty for no auth)
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// DB is the Redis database number to use (default: 0)
	DB int `json:"db" yaml:"db"`

	// KeyPrefix is the prefix for all Redis keys (default: "traefikoidc:")
	KeyPrefix string `json:"keyPrefix" yaml:"keyPrefix"`

	// PoolSize is the maximum number of socket connections (default: 10)
	PoolSize int `json:"poolSize" yaml:"poolSize"`

	// ConnectTimeout is the timeout for establishing connections in seconds (default: 5)
	ConnectTimeout int `json:"connectTimeout" yaml:"connectTimeout"`

	// ReadTimeout is the timeout for read operations in seconds (default: 3)
	ReadTimeout int `json:"readTimeout" yaml:"readTimeout"`

	// WriteTimeout is the timeout for write operations in seconds (default: 3)
	WriteTimeout int `json:"writeTimeout" yaml:"writeTimeout"`

	// EnableTLS indicates if TLS should be used for Redis connections (default: false)
	EnableTLS bool `json:"enableTLS" yaml:"enableTLS"`

	// TLSSkipVerify skips TLS certificate verification (not recommended for production)
	TLSSkipVerify bool `json:"tlsSkipVerify" yaml:"tlsSkipVerify"`

	// CacheMode determines the caching strategy: "redis" (Redis only), "hybrid" (Memory+Redis), "memory" (Memory only)
	// Default: "redis" when enabled
	CacheMode string `json:"cacheMode" yaml:"cacheMode"`

	// HybridL1Size is the maximum number of items in L1 cache for hybrid mode (default: 500)
	HybridL1Size int `json:"hybridL1Size" yaml:"hybridL1Size"`

	// HybridL1MemoryMB is the maximum memory in MB for L1 cache in hybrid mode (default: 10)
	HybridL1MemoryMB int64 `json:"hybridL1MemoryMB" yaml:"hybridL1MemoryMB"`

	// EnableCircuitBreaker enables circuit breaker for Redis failures (default: true)
	EnableCircuitBreaker bool `json:"enableCircuitBreaker" yaml:"enableCircuitBreaker"`

	// CircuitBreakerThreshold is the number of failures before opening circuit (default: 5)
	CircuitBreakerThreshold int `json:"circuitBreakerThreshold" yaml:"circuitBreakerThreshold"`

	// CircuitBreakerTimeout is the timeout in seconds before attempting to close circuit (default: 60)
	CircuitBreakerTimeout int `json:"circuitBreakerTimeout" yaml:"circuitBreakerTimeout"`

	// EnableHealthCheck enables periodic health checks for Redis (default: true)
	EnableHealthCheck bool `json:"enableHealthCheck" yaml:"enableHealthCheck"`

	// HealthCheckInterval is the interval in seconds between health checks (default: 30)
	HealthCheckInterval int `json:"healthCheckInterval" yaml:"healthCheckInterval"`
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

const (
	// DefaultRateLimit defines the default rate limit for requests per second
	DefaultRateLimit = 100

	// MinRateLimit defines the minimum allowed rate limit to prevent DOS
	MinRateLimit = 10

	// DefaultLogLevel defines the default logging level
	DefaultLogLevel = "info"

	// MinSessionEncryptionKeyLength defines the minimum length for session encryption key
	MinSessionEncryptionKeyLength = 32
)

// CreateConfig creates a new Config with secure default values.
// Default values are set for optional fields:
//   - Scopes: ["openid", "profile", "email"]
//   - LogLevel: "info"
//   - LogoutURL: CallbackURL + "/logout"
//   - RateLimit: 100 requests per second
//   - PostLogoutRedirectURI: "/"
//   - ForceHTTPS: true (for security)
//   - EnablePKCE: false (PKCE is opt-in)
//   - Redis: nil (disabled by default, can be configured via Traefik config or env vars)
//
// CreateConfig initializes a new Config struct with default values for optional fields.
// It sets default scopes, log level, rate limit, enables ForceHTTPS, and sets the
// default refresh grace period. Required fields like ProviderURL, ClientID, ClientSecret,
// CallbackURL, and SessionEncryptionKey must be set explicitly after creation.
// Redis configuration can be provided through Traefik's dynamic configuration or
// as a fallback through environment variables.
//
// Returns:
//   - A pointer to a new Config struct with default settings applied.
func CreateConfig() *Config {
	c := &Config{
		Scopes:                    []string{"openid", "profile", "email"},
		LogLevel:                  DefaultLogLevel,
		RateLimit:                 DefaultRateLimit,
		ForceHTTPS:                true,  // Secure by default
		EnablePKCE:                false, // PKCE is opt-in
		OverrideScopes:            false, // Default to appending scopes, not overriding
		RefreshGracePeriodSeconds: 60,    // Default grace period of 60 seconds
		SecurityHeaders:           createDefaultSecurityConfig(),
		Redis:                     nil, // Redis is disabled by default, configure via Traefik or env vars
	}

	return c
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

// Validate checks the configuration settings for validity.
// It ensures that required fields (ProviderURL, CallbackURL, ClientID, ClientSecret, SessionEncryptionKey)
// are present and that URLs are well-formed (HTTPS where required). It also validates
// the session key length, log level, rate limit, and refresh grace period.
//
// Returns:
//   - nil if the configuration is valid.
//   - An error describing the first validation failure encountered.
func (c *Config) Validate() error {
	// Validate provider URL
	if c.ProviderURL == "" {
		return fmt.Errorf("providerURL is required")
	}
	if !isValidSecureURL(c.ProviderURL) {
		return fmt.Errorf("providerURL must be a valid HTTPS URL")
	}

	// Validate callback URL
	if c.CallbackURL == "" {
		return fmt.Errorf("callbackURL is required")
	}
	if !strings.HasPrefix(c.CallbackURL, "/") {
		return fmt.Errorf("callbackURL must start with /")
	}

	// Validate client credentials
	if c.ClientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("clientSecret is required")
	}

	// Validate session encryption key
	if c.SessionEncryptionKey == "" {
		return fmt.Errorf("sessionEncryptionKey is required")
	}
	if len(c.SessionEncryptionKey) < MinSessionEncryptionKeyLength {
		return fmt.Errorf("sessionEncryptionKey must be at least %d characters long", MinSessionEncryptionKeyLength)
	}

	// Validate log level
	if c.LogLevel != "" && !isValidLogLevel(c.LogLevel) {
		return fmt.Errorf("logLevel must be one of: debug, info, error")
	}

	// Validate excluded URLs
	for _, url := range c.ExcludedURLs {
		if !strings.HasPrefix(url, "/") {
			return fmt.Errorf("excluded URL must start with /: %s", url)
		}
		if strings.Contains(url, "..") {
			return fmt.Errorf("excluded URL must not contain path traversal: %s", url)
		}
		if strings.Contains(url, "*") {
			return fmt.Errorf("excluded URL must not contain wildcards: %s", url)
		}
	}

	// Validate revocation URL if set
	if c.RevocationURL != "" && !isValidSecureURL(c.RevocationURL) {
		return fmt.Errorf("revocationURL must be a valid HTTPS URL")
	}

	// Validate end session URL if set
	if c.OIDCEndSessionURL != "" && !isValidSecureURL(c.OIDCEndSessionURL) {
		return fmt.Errorf("oidcEndSessionURL must be a valid HTTPS URL")
	}

	// Validate post-logout redirect URI if set
	if c.PostLogoutRedirectURI != "" && c.PostLogoutRedirectURI != "/" {
		if !isValidSecureURL(c.PostLogoutRedirectURI) && !strings.HasPrefix(c.PostLogoutRedirectURI, "/") {
			return fmt.Errorf("postLogoutRedirectURI must be either a valid HTTPS URL or start with /")
		}
	}

	// Validate rate limit
	if c.RateLimit < MinRateLimit {
		return fmt.Errorf("rateLimit must be at least %d", MinRateLimit)
	}

	// Validate refresh grace period
	if c.RefreshGracePeriodSeconds < 0 {
		return fmt.Errorf("refreshGracePeriodSeconds cannot be negative")
	}

	// Validate audience if specified
	if c.Audience != "" {
		// Validate audience format - should be a valid identifier or URL
		if len(c.Audience) > 256 {
			return fmt.Errorf("audience must not exceed 256 characters")
		}

		// If audience looks like a URL, validate it's HTTPS
		if strings.HasPrefix(c.Audience, "http://") {
			return fmt.Errorf("audience URL must use HTTPS, not HTTP")
		}

		// Prevent wildcard audiences which could weaken security
		if strings.Contains(c.Audience, "*") {
			return fmt.Errorf("audience must not contain wildcards")
		}

		// Validate that audience doesn't contain obvious injection patterns
		if strings.ContainsAny(c.Audience, "\n\r\t\x00") {
			return fmt.Errorf("audience contains invalid characters")
		}
	}

	// Validate Redis configuration if provided
	if c.Redis != nil && c.Redis.Enabled {
		if err := c.Redis.Validate(); err != nil {
			return fmt.Errorf("redis configuration error: %w", err)
		}
	}

	// Validate headers configuration for template security
	for _, header := range c.Headers {
		if header.Name == "" {
			return fmt.Errorf("header name cannot be empty")
		}
		if header.Value == "" {
			return fmt.Errorf("header value template cannot be empty")
		}
		if !strings.Contains(header.Value, "{{") || !strings.Contains(header.Value, "}}") {
			return fmt.Errorf("header value '%s' does not appear to be a valid template (missing {{ }})", header.Value)
		}

		// Provide more helpful guidance for common template errors BEFORE security validation
		if strings.Contains(header.Value, "{{.claims") {
			return fmt.Errorf("header template '%s' appears to use lowercase 'claims' - use '{{.Claims...' instead (case sensitive)", header.Value)
		}
		if strings.Contains(header.Value, "{{.accessToken") {
			return fmt.Errorf("header template '%s' appears to use lowercase 'accessToken' - use '{{.AccessToken...' instead (case sensitive)", header.Value)
		}
		if strings.Contains(header.Value, "{{.idToken") {
			return fmt.Errorf("header template '%s' appears to use lowercase 'idToken' - use '{{.IdToken...' instead (case sensitive)", header.Value)
		}
		if strings.Contains(header.Value, "{{.refreshToken") {
			return fmt.Errorf("header template '%s' appears to use lowercase 'refreshToken' - use '{{.RefreshToken...' instead (case sensitive)", header.Value)
		}

		// Validate template syntax and security
		if err := validateTemplateSecure(header.Value); err != nil {
			return fmt.Errorf("header template '%s' failed security validation: %w", header.Value, err)
		}
	}

	return nil
}

// validateTemplateSecure validates template expressions for security vulnerabilities.
// It checks for dangerous template patterns that could lead to code execution or data leaks
// while allowing safe custom functions for field access and default values.
func validateTemplateSecure(templateStr string) error {
	// Allow our specific safe custom functions
	// These are added specifically to handle missing fields safely (issue #60)
	safeCustomFunctions := []string{
		"{{get ",     // Safe map access function
		"{{default ", // Safe default value function
	}

	// Check if template uses safe custom functions
	usesSafeFunctions := false
	for _, safeFn := range safeCustomFunctions {
		if strings.Contains(templateStr, safeFn) {
			usesSafeFunctions = true
			// These functions are explicitly allowed for safe field access
		}
	}

	// Check for dangerous template functions and patterns
	// Skip certain checks if using our safe functions
	dangerousPatterns := []string{
		"{{call",     // Function calls (except our safe ones)
		"{{range",    // Range over arbitrary data
		"{{define",   // Template definitions
		"{{template", // Template inclusions
		"{{block",    // Block definitions
		"{{/*",       // Comments that could hide malicious code
		"{{-",        // Trim whitespace (could be used to obfuscate)
		"-}}",        // Trim whitespace (could be used to obfuscate)
		"{{printf",   // Printf functions
		"{{print",    // Print functions (but not our safe ones)
		"{{println",  // Println functions
		"{{html",     // HTML functions
		"{{js",       // JavaScript functions
		"{{urlquery", // URL query functions
		"{{index",    // Index access to arbitrary data
		"{{slice",    // Slice operations
		"{{len",      // Length operations on arbitrary data
		"{{eq",       // Comparison operations
		"{{ne",       // Comparison operations
		"{{lt",       // Comparison operations
		"{{le",       // Comparison operations
		"{{gt",       // Comparison operations
		"{{ge",       // Comparison operations
		"{{and",      // Logical operations
		"{{or",       // Logical operations
		"{{not",      // Logical operations
	}

	// Allow 'with' for safe conditional access
	if !strings.Contains(templateStr, "{{with .Claims") {
		dangerousPatterns = append(dangerousPatterns, "{{with")
	}

	templateLower := strings.ToLower(templateStr)
	for _, pattern := range dangerousPatterns {
		// Skip check if it's one of our safe functions
		if usesSafeFunctions && (pattern == "{{call" || pattern == "{{print") {
			// Allow these if we're using safe functions
			continue
		}

		// Special handling for comparison operators to avoid false positives with "get" and "default"
		if pattern == "{{ge" && (strings.Contains(templateStr, "{{get ") || strings.Contains(templateStr, "{{default ")) {
			// Skip {{ge check if we're using the safe {{get or {{default functions
			continue
		}

		// Skip {{de checks if using {{default
		if pattern == "{{define" && strings.Contains(templateStr, "{{default ") {
			continue
		}

		if strings.Contains(templateLower, strings.ToLower(pattern)) {
			return fmt.Errorf("dangerous template pattern detected: %s", pattern)
		}
	}

	// Validate template variables against whitelist
	allowedPatterns := []string{
		"{{.AccessToken}}",
		"{{.IdToken}}",
		"{{.RefreshToken}}",
		"{{.Claims.",
		"{{get ",     // Safe custom function
		"{{default ", // Safe custom function
		"{{with ",    // Safe conditional (when used with Claims)
	}

	// Check if template contains only allowed patterns
	hasAllowedPattern := false
	for _, pattern := range allowedPatterns {
		if strings.Contains(templateStr, pattern) {
			hasAllowedPattern = true
			break
		}
	}

	if !hasAllowedPattern {
		return fmt.Errorf("template must use only allowed variables: AccessToken, IdToken, RefreshToken, Claims.*, or safe functions (get, default, with)")
	}

	// Validate claims access patterns
	if strings.Contains(templateStr, "{{.Claims.") {
		// Simple validation - ensure claims access is to known safe fields
		// This list includes standard OIDC claims and common provider-specific claims
		safeClaimsFields := map[string]bool{
			// Standard OIDC claims
			"email":              true,
			"name":               true,
			"given_name":         true,
			"family_name":        true,
			"preferred_username": true,
			"sub":                true,
			"iss":                true,
			"aud":                true,
			"exp":                true,
			"iat":                true,
			"groups":             true,
			"roles":              true,
			// Common custom claims
			"internal_role": true, // Custom roles field (issue #60)
			"role":          true, // Alternative role field
			"department":    true, // Organization info
			"organization":  true, // Organization info
			// Provider-specific claims
			"realm_access":    true, // Keycloak specific
			"resource_access": true, // Keycloak specific
			"oid":             true, // Azure AD object ID
			"tid":             true, // Azure AD tenant ID
			"upn":             true, // Azure AD User Principal Name
			"hd":              true, // Google hosted domain
			"picture":         true, // Profile picture
			// Additional standard claims
			"locale":         true, // User locale
			"zoneinfo":       true, // Timezone
			"phone_number":   true, // Contact info
			"email_verified": true, // Email verification status
			"updated_at":     true, // Last update time
		}

		// Extract field names from Claims access
		start := strings.Index(templateStr, "{{.Claims.")
		for start != -1 {
			end := strings.Index(templateStr[start:], "}}")
			if end == -1 {
				return fmt.Errorf("malformed Claims template syntax")
			}

			// Extract the content between "{{.Claims." and "}}"
			// start+10 skips "{{.Claims." and start+end is the position of "}}"
			claimsContent := templateStr[start+10 : start+end]

			// Get the field name (first part before any dots)
			fieldName := strings.Split(claimsContent, ".")[0]

			if !safeClaimsFields[fieldName] {
				return fmt.Errorf("access to Claims.%s is not allowed for security reasons", fieldName)
			}

			// Search for next occurrence
			nextStart := strings.Index(templateStr[start+end+2:], "{{.Claims.")
			if nextStart != -1 {
				start = start + end + 2 + nextStart
			} else {
				start = -1
			}
		}
	}

	// Prevent code injection through template syntax
	if strings.Contains(templateStr, "{{") && strings.Contains(templateStr, "}}") {
		// Count opening and closing braces
		openCount := strings.Count(templateStr, "{{")
		closeCount := strings.Count(templateStr, "}}")
		if openCount != closeCount {
			return fmt.Errorf("unbalanced template braces")
		}
	}

	return nil
}

// isValidSecureURL checks if a given string represents a valid, absolute HTTPS URL.
// It uses url.Parse and checks for a nil error, an "https" scheme, and a non-empty host.
//
// Parameters:
//   - s: The URL string to validate.
//
// Returns:
//   - true if the string is a valid HTTPS URL, false otherwise.
//
// isValidSecureURL validates that a URL string is well-formed and uses HTTPS.
// Returns true if the URL is valid and secure (HTTPS), false otherwise.
func isValidSecureURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// isValidLogLevel checks if the provided log level string is one of the supported values ("debug", "info", "error").
//
// Parameters:
//   - level: The log level string to validate.
//
// Returns:
//   - true if the log level is valid, false otherwise.
//
// isValidLogLevel checks if the provided log level is supported.
// Valid log levels are: debug, info, error.
func isValidLogLevel(level string) bool {
	return level == "debug" || level == "info" || level == "error"
}

// Logger provides structured logging capabilities with different severity levels.
// It supports error, info, and debug levels with appropriate output streams
// and formatting for each level.
type Logger struct {
	// logError handles error-level messages, writing to stderr
	logError *log.Logger
	// logInfo handles informational messages, writing to stdout
	logInfo *log.Logger
	// logDebug handles debug-level messages, writing to stdout when debug is enabled
	logDebug *log.Logger
}

// NewLogger creates and configures a new Logger instance based on the provided log level.
// It initializes loggers for ERROR (stderr), INFO (stdout), and DEBUG (stdout) levels,
// enabling output based on the specified level:
//   - "error": Only ERROR messages are output.
//   - "info": INFO and ERROR messages are output.
//   - "debug": DEBUG, INFO, and ERROR messages are output.
//
// If an invalid level is provided, it defaults to behavior similar to "error".
//
// Parameters:
//   - logLevel: The desired logging level ("debug", "info", or "error").
//
// Returns:
//   - A pointer to the configured Logger instance.
//
// NewLogger creates a new logger instance with the specified log level.
// If logLevel is empty, defaults to "info". Invalid log levels default to "info".
func NewLogger(logLevel string) *Logger {
	logError := log.New(io.Discard, "ERROR: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: TraefikOidcPlugin: ", log.Ldate|log.Ltime)

	logError.SetOutput(os.Stderr)

	if logLevel == "debug" || logLevel == "info" {
		logInfo.SetOutput(os.Stdout)
	}
	if logLevel == "debug" {
		logDebug.SetOutput(os.Stdout)
	}

	return &Logger{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
	}
}

// Info logs a message at the INFO level using Printf style formatting.
// Output is directed to stdout if the configured log level is "info" or "debug".
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
//
// Info logs an informational message if the logger's level allows it.
func (l *Logger) Info(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debug logs a message at the DEBUG level.
// Output is directed to stdout only if the configured log level is "debug".
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
//
// Debug logs a debug message if the logger's level allows it.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Error logs a message at the ERROR level using Printf style formatting.
// Output is always directed to stderr, regardless of the configured log level.
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
//
// Error logs an error message. Errors are always logged regardless of level.
func (l *Logger) Error(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// Infof logs a message at the INFO level using Printf style formatting.
// Equivalent to calling l.Info(format, args...).
// Output is directed to stdout if the configured log level is "info" or "debug".
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
//
// Infof logs a formatted informational message if the logger's level allows it.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debugf logs a formatted message at the DEBUG level.
// Equivalent to calling l.Debug(format, args...).
// Output is directed to stdout only if the configured log level is "debug".
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
//
// Debugf logs a formatted debug message if the logger's level allows it.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Errorf logs a message at the ERROR level using Printf style formatting.
// Equivalent to calling l.Error(format, args...).
// Output is always directed to stderr, regardless of the configured log level.
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
//
// Errorf logs a formatted error message. Errors are always logged regardless of level.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// newNoOpLogger creates a logger that discards all output.
// Deprecated: Use GetSingletonNoOpLogger() instead for better memory efficiency.
func newNoOpLogger() *Logger {
	return GetSingletonNoOpLogger()
}

// handleError logs an error message using the provided logger and sends an HTTP error
// response to the client with the specified message and status code.
//
// Parameters:
//   - w: The http.ResponseWriter to send the error response to.
//   - message: The error message string.
//   - code: The HTTP status code for the response.
//   - logger: The Logger instance to use for logging the error.
//
// handleError writes an HTTP error response with the specified status code and message.
// It logs the error and sets appropriate headers before writing the response.
//
//lint:ignore U1000 Kept for potential future error handling
func handleError(w http.ResponseWriter, message string, code int, logger *Logger) {
	logger.Error("%s", message)
	http.Error(w, message, code)
}

// GetSecurityHeadersApplier returns a function that applies security headers
func (c *Config) GetSecurityHeadersApplier() func(http.ResponseWriter, *http.Request) {
	if c.SecurityHeaders == nil || !c.SecurityHeaders.Enabled {
		return nil
	}

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
// Validate checks if the Redis configuration is valid
func (rc *RedisConfig) Validate() error {
	if !rc.Enabled {
		return nil
	}

	if rc.Address == "" {
		return fmt.Errorf("redis address is required when Redis is enabled")
	}

	// Validate cache mode
	if rc.CacheMode != "" {
		validModes := map[string]bool{
			"redis":  true,
			"hybrid": true,
			"memory": true,
		}
		if !validModes[rc.CacheMode] {
			return fmt.Errorf("invalid cache mode: %s (must be 'redis', 'hybrid', or 'memory')", rc.CacheMode)
		}
	}

	// Validate connection settings
	if rc.PoolSize < 0 {
		return fmt.Errorf("pool size cannot be negative")
	}
	if rc.ConnectTimeout < 0 {
		return fmt.Errorf("connect timeout cannot be negative")
	}
	if rc.ReadTimeout < 0 {
		return fmt.Errorf("read timeout cannot be negative")
	}
	if rc.WriteTimeout < 0 {
		return fmt.Errorf("write timeout cannot be negative")
	}

	// Validate hybrid mode settings
	if rc.CacheMode == "hybrid" {
		if rc.HybridL1Size < 0 {
			return fmt.Errorf("hybrid L1 size cannot be negative")
		}
		if rc.HybridL1MemoryMB < 0 {
			return fmt.Errorf("hybrid L1 memory cannot be negative")
		}
	}

	// Validate circuit breaker settings
	if rc.CircuitBreakerThreshold < 0 {
		return fmt.Errorf("circuit breaker threshold cannot be negative")
	}
	if rc.CircuitBreakerTimeout < 0 {
		return fmt.Errorf("circuit breaker timeout cannot be negative")
	}

	// Validate health check settings
	if rc.HealthCheckInterval < 0 {
		return fmt.Errorf("health check interval cannot be negative")
	}

	return nil
}

// ApplyDefaults sets default values for Redis configuration when fields are not explicitly set.
// This ensures reasonable defaults while allowing full customization through configuration.
func (rc *RedisConfig) ApplyDefaults() {
	// Only apply defaults if Redis is enabled
	if !rc.Enabled {
		return
	}

	// Connection defaults
	if rc.KeyPrefix == "" {
		rc.KeyPrefix = "traefikoidc:"
	}
	if rc.PoolSize == 0 {
		rc.PoolSize = 10
	}
	if rc.ConnectTimeout == 0 {
		rc.ConnectTimeout = 5
	}
	if rc.ReadTimeout == 0 {
		rc.ReadTimeout = 3
	}
	if rc.WriteTimeout == 0 {
		rc.WriteTimeout = 3
	}

	// Cache mode defaults
	if rc.CacheMode == "" {
		rc.CacheMode = "redis" // Default to redis-only mode for simplicity
	}

	// Hybrid mode specific defaults
	if rc.CacheMode == "hybrid" {
		if rc.HybridL1Size == 0 {
			rc.HybridL1Size = 500
		}
		if rc.HybridL1MemoryMB == 0 {
			rc.HybridL1MemoryMB = 10
		}
	}

	// Resilience features - these use a different pattern to detect if they were explicitly set
	// Since bool fields default to false, we need to be careful about defaults
	// For now, we'll enable by default only if not explicitly disabled via environment
	if rc.CircuitBreakerThreshold == 0 {
		rc.CircuitBreakerThreshold = 5
	}
	if rc.CircuitBreakerTimeout == 0 {
		rc.CircuitBreakerTimeout = 60
	}
	if rc.HealthCheckInterval == 0 {
		rc.HealthCheckInterval = 30
	}
}

// ApplyEnvFallbacks applies environment variable values as fallbacks for empty config fields.
// This allows environment variables to be used as optional overrides only when the
// corresponding config field is not set through Traefik's dynamic configuration.
// The plugin configuration takes precedence over environment variables.
func (rc *RedisConfig) ApplyEnvFallbacks() {
	// Only apply env fallbacks if Redis is not already configured
	if !rc.Enabled {
		// Check if Redis should be enabled from environment
		enabledStr := os.Getenv("REDIS_ENABLED")
		if enabledStr == "true" || enabledStr == "1" {
			rc.Enabled = true
		}
	}

	// Only apply other env vars if Redis is enabled
	if !rc.Enabled {
		return
	}

	// Apply environment variables only for empty fields
	if rc.Address == "" {
		if addr := os.Getenv("REDIS_ADDRESS"); addr != "" {
			rc.Address = addr
		}
	}

	if rc.Password == "" {
		rc.Password = os.Getenv("REDIS_PASSWORD")
	}

	if rc.KeyPrefix == "" {
		if prefix := os.Getenv("REDIS_KEY_PREFIX"); prefix != "" {
			rc.KeyPrefix = prefix
		}
	}

	if rc.CacheMode == "" {
		if mode := os.Getenv("REDIS_CACHE_MODE"); mode != "" {
			rc.CacheMode = mode
		}
	}

	// Apply numeric values only if not already set
	if rc.DB == 0 {
		if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
			if db, err := strconv.Atoi(dbStr); err == nil && db > 0 {
				rc.DB = db
			}
		}
	}

	if rc.PoolSize == 0 {
		if poolSizeStr := os.Getenv("REDIS_POOL_SIZE"); poolSizeStr != "" {
			if poolSize, err := strconv.Atoi(poolSizeStr); err == nil && poolSize > 0 {
				rc.PoolSize = poolSize
			}
		}
	}

	if rc.ConnectTimeout == 0 {
		if timeoutStr := os.Getenv("REDIS_CONNECT_TIMEOUT"); timeoutStr != "" {
			if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
				rc.ConnectTimeout = timeout
			}
		}
	}

	if rc.ReadTimeout == 0 {
		if timeoutStr := os.Getenv("REDIS_READ_TIMEOUT"); timeoutStr != "" {
			if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
				rc.ReadTimeout = timeout
			}
		}
	}

	if rc.WriteTimeout == 0 {
		if timeoutStr := os.Getenv("REDIS_WRITE_TIMEOUT"); timeoutStr != "" {
			if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
				rc.WriteTimeout = timeout
			}
		}
	}

	// Apply boolean values from env only if not already set in config
	if !rc.EnableTLS {
		if tlsStr := os.Getenv("REDIS_ENABLE_TLS"); tlsStr == "true" || tlsStr == "1" {
			rc.EnableTLS = true
		}
	}

	if !rc.TLSSkipVerify {
		if skipStr := os.Getenv("REDIS_TLS_SKIP_VERIFY"); skipStr == "true" || skipStr == "1" {
			rc.TLSSkipVerify = true
		}
	}

	// Hybrid mode settings
	if rc.HybridL1Size == 0 {
		if sizeStr := os.Getenv("REDIS_HYBRID_L1_SIZE"); sizeStr != "" {
			if size, err := strconv.Atoi(sizeStr); err == nil && size > 0 {
				rc.HybridL1Size = size
			}
		}
	}

	if rc.HybridL1MemoryMB == 0 {
		if memStr := os.Getenv("REDIS_HYBRID_L1_MEMORY_MB"); memStr != "" {
			if mem, err := strconv.ParseInt(memStr, 10, 64); err == nil && mem > 0 {
				rc.HybridL1MemoryMB = mem
			}
		}
	}
}

// LoadRedisConfigFromEnv loads Redis configuration from environment variables.
// Deprecated: Use RedisConfig.ApplyEnvFallbacks() on an existing config instead.
// This function is kept for backward compatibility but should not be used directly.
func LoadRedisConfigFromEnv() *RedisConfig {
	// Check if Redis is enabled
	enabledStr := os.Getenv("REDIS_ENABLED")
	if enabledStr == "" || enabledStr == "false" || enabledStr == "0" {
		return nil
	}

	config := &RedisConfig{
		Enabled: true,
	}

	// Parse numeric values
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		if db, err := strconv.Atoi(dbStr); err == nil {
			config.DB = db
		}
	}

	if poolSizeStr := os.Getenv("REDIS_POOL_SIZE"); poolSizeStr != "" {
		if poolSize, err := strconv.Atoi(poolSizeStr); err == nil {
			config.PoolSize = poolSize
		}
	}

	if connectTimeoutStr := os.Getenv("REDIS_CONNECT_TIMEOUT"); connectTimeoutStr != "" {
		if timeout, err := strconv.Atoi(connectTimeoutStr); err == nil {
			config.ConnectTimeout = timeout
		}
	}

	if readTimeoutStr := os.Getenv("REDIS_READ_TIMEOUT"); readTimeoutStr != "" {
		if timeout, err := strconv.Atoi(readTimeoutStr); err == nil {
			config.ReadTimeout = timeout
		}
	}

	if writeTimeoutStr := os.Getenv("REDIS_WRITE_TIMEOUT"); writeTimeoutStr != "" {
		if timeout, err := strconv.Atoi(writeTimeoutStr); err == nil {
			config.WriteTimeout = timeout
		}
	}

	// Parse boolean values
	if enableTLSStr := os.Getenv("REDIS_ENABLE_TLS"); enableTLSStr == "true" || enableTLSStr == "1" {
		config.EnableTLS = true
	}

	if skipVerifyStr := os.Getenv("REDIS_TLS_SKIP_VERIFY"); skipVerifyStr == "true" || skipVerifyStr == "1" {
		config.TLSSkipVerify = true
	}

	// Parse hybrid mode settings
	if l1SizeStr := os.Getenv("REDIS_HYBRID_L1_SIZE"); l1SizeStr != "" {
		if size, err := strconv.Atoi(l1SizeStr); err == nil {
			config.HybridL1Size = size
		}
	}

	if l1MemoryStr := os.Getenv("REDIS_HYBRID_L1_MEMORY_MB"); l1MemoryStr != "" {
		if memory, err := strconv.ParseInt(l1MemoryStr, 10, 64); err == nil {
			config.HybridL1MemoryMB = memory
		}
	}

	// Parse circuit breaker settings
	if enableCBStr := os.Getenv("REDIS_ENABLE_CIRCUIT_BREAKER"); enableCBStr == "false" || enableCBStr == "0" {
		config.EnableCircuitBreaker = false
	} else {
		config.EnableCircuitBreaker = true // Default to enabled
	}

	if cbThresholdStr := os.Getenv("REDIS_CIRCUIT_BREAKER_THRESHOLD"); cbThresholdStr != "" {
		if threshold, err := strconv.Atoi(cbThresholdStr); err == nil {
			config.CircuitBreakerThreshold = threshold
		}
	}

	if cbTimeoutStr := os.Getenv("REDIS_CIRCUIT_BREAKER_TIMEOUT"); cbTimeoutStr != "" {
		if timeout, err := strconv.Atoi(cbTimeoutStr); err == nil {
			config.CircuitBreakerTimeout = timeout
		}
	}

	// Parse health check settings
	if enableHCStr := os.Getenv("REDIS_ENABLE_HEALTH_CHECK"); enableHCStr == "false" || enableHCStr == "0" {
		config.EnableHealthCheck = false
	} else {
		config.EnableHealthCheck = true // Default to enabled
	}

	if hcIntervalStr := os.Getenv("REDIS_HEALTH_CHECK_INTERVAL"); hcIntervalStr != "" {
		if interval, err := strconv.Atoi(hcIntervalStr); err == nil {
			config.HealthCheckInterval = interval
		}
	}

	// Apply defaults after loading from env
	config.ApplyDefaults()

	return config
}

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
