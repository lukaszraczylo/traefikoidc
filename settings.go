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
	HTTPClient                *http.Client      `json:"-"`
	OIDCEndSessionURL         string            `json:"oidcEndSessionURL"`
	CookieDomain              string            `json:"cookieDomain"`
	CallbackURL               string            `json:"callbackURL"`
	LogoutURL                 string            `json:"logoutURL"`
	ClientID                  string            `json:"clientID"`
	ClientSecret              string            `json:"clientSecret"`
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
		OverrideScopes:            false, // Default to appending scopes, not overriding
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
func handleError(w http.ResponseWriter, message string, code int, logger *Logger) {
	logger.Error(message)
	http.Error(w, message, code)
}
