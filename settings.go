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

const (
	cookieName = "_raczylo_oidc"
)

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
	// Example: ["/health", "/metrics"]
	ExcludedURLs []string `json:"excludedURLs"`

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
}

// CreateConfig creates a new Config with sensible default values.
// Default values are set for optional fields:
//   - Scopes: ["openid", "profile", "email"]
//   - LogLevel: "info"
//   - LogoutURL: CallbackURL + "/logout"
//   - RateLimit: 100 requests per second
//   - PostLogoutRedirectURI: "/"
func CreateConfig() *Config {
	c := &Config{}

	if c.Scopes == nil {
		c.Scopes = []string{"openid", "profile", "email"}
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	if c.LogoutURL == "" {
		c.LogoutURL = c.CallbackURL + "/logout"
	}

	if c.RateLimit == 0 {
		c.RateLimit = 100
	}

	return c
}

// Validate performs validation checks on the Config.
// It ensures all required fields are set and have valid values.
// Returns an error if any validation check fails.
func (c *Config) Validate() error {
	if c.ProviderURL == "" {
		return fmt.Errorf("providerURL is required")
	}
	if !isValidURL(c.ProviderURL) {
		return fmt.Errorf("providerURL must be a valid URL")
	}
	if c.CallbackURL == "" {
		return fmt.Errorf("callbackURL is required")
	}
	if !strings.HasPrefix(c.CallbackURL, "/") {
		return fmt.Errorf("callbackURL must start with /")
	}
	if c.ClientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("clientSecret is required")
	}
	if c.SessionEncryptionKey == "" {
		return fmt.Errorf("sessionEncryptionKey is required")
	}
	if len(c.SessionEncryptionKey) < 32 {
		return fmt.Errorf("sessionEncryptionKey must be at least 32 characters long")
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("rateLimit must be non-negative")
	}
	if c.LogLevel != "" && !isValidLogLevel(c.LogLevel) {
		return fmt.Errorf("logLevel must be one of: debug, info, error")
	}
	return nil
}

// isValidURL checks if the provided string is a valid URL
func isValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// isValidLogLevel checks if the provided log level is valid
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

// NewLogger creates a new Logger with the specified log level.
// The log level determines which messages are output:
//   - "debug": Outputs all messages (debug, info, error)
//   - "info": Outputs info and error messages
//   - "error": Outputs only error messages
// Error messages are always written to stderr, while info and debug
// messages are written to stdout when enabled.
func NewLogger(logLevel string) *Logger {
	logError := log.New(io.Discard, "ERROR: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logInfo := log.New(io.Discard, "INFO: TraefikOidcPlugin: ", log.Ldate|log.Ltime)
	logDebug := log.New(io.Discard, "DEBUG: TraefikOidcPlugin: ", log.Ldate|log.Ltime)

	logError.SetOutput(os.Stderr)
	logInfo.SetOutput(os.Stdout)

	if logLevel == "debug" {
		logDebug.SetOutput(os.Stdout)
	}

	return &Logger{
		logError: logError,
		logInfo:  logInfo,
		logDebug: logDebug,
	}
}

// Info logs an informational message.
// These messages are intended for general operational information
// and are written to stdout.
func (l *Logger) Info(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debug logs a debug message.
// These messages are only output when debug level logging is enabled
// and are intended for detailed troubleshooting information.
func (l *Logger) Debug(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Error logs an error message.
// These messages indicate problems that need attention and are
// always written to stderr regardless of the log level.
func (l *Logger) Error(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// Infof logs an informational message using Printf formatting.
// These messages are intended for general operational information
// and are written to stdout.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logInfo.Printf(format, args...)
}

// Debugf logs a debug message using Printf formatting.
// These messages are only output when debug level logging is enabled
// and are intended for detailed troubleshooting information.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logDebug.Printf(format, args...)
}

// Errorf logs an error message using Printf formatting.
// These messages indicate problems that need attention and are
// always written to stderr regardless of the log level.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logError.Printf(format, args...)
}

// handleError writes an error message to both the HTTP response and the error log.
// It ensures consistent error handling across the middleware by logging the error
// and sending an appropriate HTTP response to the client.
func handleError(w http.ResponseWriter, message string, code int, logger *Logger) {
	logger.Error(message)
	http.Error(w, message, code)
}
