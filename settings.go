package traefikoidc

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
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
	// ProviderURL is the base URL of the OIDC provider (required)
	// Example: https://accounts.google.com
	ProviderURL string `json:"providerURL"`

	// RevocationURL is the endpoint for revoking tokens (optional)
	// If not provided, it will be discovered from provider metadata
	RevocationURL string `json:"revocationURL"`

	// EnablePKCE enables Proof Key for Code Exchange (PKCE) for the authorization code flow (optional)
	// This enhances security but might not be supported by all OIDC providers
	// Default: false
	EnablePKCE bool `json:"enablePKCE"`

	// CallbackURL is the path where the OIDC provider will redirect after authentication (required)
	// Example: /oauth2/callback
	CallbackURL string `json:"callbackURL"`

	// LogoutURL is the path for handling logout requests (optional)
	// If not provided, it will be set to CallbackURL + "/logout"
	LogoutURL string `json:"logoutURL"`

	// ClientID is the OAuth 2.0 client identifier (required)
	ClientID string `json:"clientID"`

	// ClientSecret is the OAuth 2.0 client secret (required)
	ClientSecret string `json:"clientSecret"`

	// Scopes defines the OAuth 2.0 scopes to request (optional)
	// Defaults to ["openid", "profile", "email"] if not provided
	Scopes []string `json:"scopes"`

	// LogLevel sets the logging verbosity (optional)
	// Valid values: "debug", "info", "error"
	// Default: "info"
	LogLevel string `json:"logLevel"`

	// SessionEncryptionKey is used to encrypt session data (required)
	// Must be a secure random string
	SessionEncryptionKey string `json:"sessionEncryptionKey"`

	// ForceHTTPS forces the use of HTTPS for all URLs (optional)
	// Default: false
	ForceHTTPS bool `json:"forceHTTPS"`

	// RateLimit sets the maximum number of requests per second (optional)
	// Default: 100
	RateLimit int `json:"rateLimit"`

	// ExcludedURLs lists paths that bypass authentication (optional)
	// Cannot be used together with IncludedURLs
	// Example: ["/health", "/metrics"]
	ExcludedURLs []string `json:"excludedURLs"`

	// IncludedURLs lists paths that has authentication (optional)
	// Cannot be used together with ExcludedURLs
	// Example: ["/private", "/admin"]
	IncludedURLs []string `json:"includedURLs"`

	// AllowedUserDomains restricts access to specific email domains (optional)
	// Example: ["company.com", "subsidiary.com"]
	AllowedUserDomains []string `json:"allowedUserDomains"`

	// AllowedRolesAndGroups restricts access to users with specific roles or groups (optional)
	// Example: ["admin", "developer"]
	AllowedRolesAndGroups []string `json:"allowedRolesAndGroups"`

	// OIDCEndSessionURL is the provider's end session endpoint (optional)
	// If not provided, it will be discovered from provider metadata
	OIDCEndSessionURL string `json:"oidcEndSessionURL"`

	// PostLogoutRedirectURI is the URL to redirect to after logout (optional)
	// Default: "/"
	PostLogoutRedirectURI string `json:"postLogoutRedirectURI"`

	// HTTPClient allows customizing the HTTP client used for OIDC operations (optional)
	HTTPClient *http.Client

	// RefreshGracePeriodSeconds defines how many seconds before a token expires
	// the plugin should attempt to refresh it proactively (optional)
	// Default: 60
	RefreshGracePeriodSeconds int `json:"refreshGracePeriodSeconds"`
	// Headers defines custom HTTP headers to set with templated values (optional)
	// Values can reference tokens and claims using Go templates with the following variables:
	// - {{.AccessToken}} - The access token (ID token)
	// - {{.IdToken}} - Same as AccessToken (for consistency)
	// - {{.RefreshToken}} - The refresh token
	// - {{.Claims.email}} - Access token claims (use proper case for claim names)
	// Examples:
	//
	//	[{Name: "X-Forwarded-Email", Value: "{{.Claims.email}}"}]
	//	[{Name: "Authorization", Value: "Bearer {{.AccessToken}}"}]
	Headers []TemplatedHeader `json:"headers"`
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
//
// CreateConfig initializes a new Config struct with default values for optional fields.
// It sets default scopes, log level, rate limit, enables ForceHTTPS, and sets the
// default refresh grace period. Required fields like ProviderURL, ClientID, ClientSecret,
// CallbackURL, and SessionEncryptionKey must be set explicitly after creation.
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
		RefreshGracePeriodSeconds: 60,    // Default grace period of 60 seconds
	}

	return c
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

	// Validate only one of excludedURLs or includedURLs is set
	if len(c.ExcludedURLs) > 0 && len(c.IncludedURLs) > 0 {
		return fmt.Errorf("excludedURLs and includedURLs cannot be used together")
	}

	// Validate excluded and included URLs
	for _, url := range append(c.ExcludedURLs, c.IncludedURLs...) {
		if !strings.HasPrefix(url, "/") {
			return fmt.Errorf("excluded and included URL must start with /: %s", url)
		}
		if strings.Contains(url, "..") {
			return fmt.Errorf("excluded and included URL must not contain path traversal: %s", url)
		}
		if strings.Contains(url, "*") {
			return fmt.Errorf("excluded and included URL must not contain wildcards: %s", url)
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

	// Validate headers configuration
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

		// Provide more helpful guidance for common template errors
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
func (l *Logger) Info(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debug logs a message at the DEBUG level using Printf style formatting.
// Output is directed to stdout only if the configured log level is "debug".
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Error logs a message at the ERROR level using Printf style formatting.
// Output is always directed to stderr, regardless of the configured log level.
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
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
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debugf logs a message at the DEBUG level using Printf style formatting.
// Equivalent to calling l.Debug(format, args...).
// Output is directed to stdout only if the configured log level is "debug".
//
// Parameters:
//   - format: The format string (as in fmt.Printf).
//   - args: The arguments for the format string.
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
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// handleError logs an error message using the provided logger and sends an HTTP error
// response to the client with the specified message and status code.
//
// Parameters:
//   - w: The http.ResponseWriter to send the error response to.
//   - message: The error message string.
//   - code: The HTTP status code for the response.
//   - logger: The Logger instance to use for logging the error.
func handleError(w http.ResponseWriter, message string, code int, logger *Logger) {
	logger.Error(message)
	http.Error(w, message, code)
}
