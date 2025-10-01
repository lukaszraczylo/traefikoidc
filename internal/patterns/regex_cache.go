// Package patterns provides cached compiled regex patterns for performance optimization
package patterns

import (
	"regexp"
	"sync"
)

// RegexCache manages compiled regex patterns with thread-safe access
type RegexCache struct {
	patterns map[string]*regexp.Regexp
	mu       sync.RWMutex
}

// NewRegexCache creates a new regex cache instance
func NewRegexCache() *RegexCache {
	return &RegexCache{
		patterns: make(map[string]*regexp.Regexp),
	}
}

// Get retrieves a compiled regex pattern, compiling and caching it if not present
func (c *RegexCache) Get(pattern string) (*regexp.Regexp, error) {
	// First try read lock for existing pattern
	c.mu.RLock()
	if regex, exists := c.patterns[pattern]; exists {
		c.mu.RUnlock()
		return regex, nil
	}
	c.mu.RUnlock()

	// Pattern not found, acquire write lock to compile and cache
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check in case another goroutine compiled it while we waited
	if regex, exists := c.patterns[pattern]; exists {
		return regex, nil
	}

	// Compile the pattern
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Cache the compiled pattern
	c.patterns[pattern] = regex
	return regex, nil
}

// MustGet is like Get but panics if the pattern cannot be compiled
func (c *RegexCache) MustGet(pattern string) *regexp.Regexp {
	regex, err := c.Get(pattern)
	if err != nil {
		panic("regex compilation failed for pattern '" + pattern + "': " + err.Error())
	}
	return regex
}

// Precompile compiles and caches multiple patterns at once
func (c *RegexCache) Precompile(patterns []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, pattern := range patterns {
		if _, exists := c.patterns[pattern]; !exists {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return err
			}
			c.patterns[pattern] = regex
		}
	}
	return nil
}

// Size returns the number of cached patterns
func (c *RegexCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.patterns)
}

// Clear removes all cached patterns
func (c *RegexCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.patterns = make(map[string]*regexp.Regexp)
}

// Global regex cache instance
var globalCache = NewRegexCache()

// Common regex patterns used throughout the OIDC implementation
const (
	// Email validation pattern (RFC 5322 compliant)
	EmailPattern = `^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`

	// Domain validation pattern
	DomainPattern = `^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`

	// URL validation pattern (http/https)
	URLPattern = `^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(/.*)?$`

	// JWT token pattern (three base64url parts separated by dots)
	JWTPattern = `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`

	// Bearer token pattern (Authorization header)
	BearerTokenPattern = `^Bearer\s+([A-Za-z0-9._~+/-]+=*)$`

	// Client ID pattern (alphanumeric with common separators)
	ClientIDPattern = `^[a-zA-Z0-9._-]+$`

	// Scope pattern (space-separated alphanumeric with underscores)
	ScopePattern = `^[a-zA-Z0-9_]+(\s+[a-zA-Z0-9_]+)*$`

	// Session ID pattern (hexadecimal)
	SessionIDPattern = `^[a-fA-F0-9]{32,128}$`

	// CSRF token pattern (base64url)
	CSRFTokenPattern = `^[A-Za-z0-9_-]+$`

	// Nonce pattern (base64url)
	NoncePattern = `^[A-Za-z0-9_-]+$`

	// Code verifier pattern for PKCE (base64url, 43-128 chars)
	CodeVerifierPattern = `^[A-Za-z0-9_-]{43,128}$`

	// Authorization code pattern (base64url)
	AuthCodePattern = `^[A-Za-z0-9._~+/-]+=*$`

	// Redirect URI validation (must be absolute HTTP/HTTPS URL)
	RedirectURIPattern = `^https?://[^\s/$.?#].[^\s]*$`

	// User-Agent pattern for bot detection
	BotUserAgentPattern = `(?i)(bot|crawler|spider|scraper|curl|wget|python|java|go-http)`

	// IP address pattern (IPv4)
	IPv4Pattern = `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`

	// Tenant ID pattern (UUID format for Azure, etc.)
	TenantIDPattern = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
)

// Precompiled common patterns for immediate use
var (
	EmailRegex        *regexp.Regexp
	DomainRegex       *regexp.Regexp
	URLRegex          *regexp.Regexp
	JWTRegex          *regexp.Regexp
	BearerTokenRegex  *regexp.Regexp
	ClientIDRegex     *regexp.Regexp
	ScopeRegex        *regexp.Regexp
	SessionIDRegex    *regexp.Regexp
	CSRFTokenRegex    *regexp.Regexp
	NonceRegex        *regexp.Regexp
	CodeVerifierRegex *regexp.Regexp
	AuthCodeRegex     *regexp.Regexp
	RedirectURIRegex  *regexp.Regexp
	BotUserAgentRegex *regexp.Regexp
	IPv4Regex         *regexp.Regexp
	TenantIDRegex     *regexp.Regexp
)

// Initialize precompiled patterns
func init() {
	commonPatterns := []string{
		EmailPattern,
		DomainPattern,
		URLPattern,
		JWTPattern,
		BearerTokenPattern,
		ClientIDPattern,
		ScopePattern,
		SessionIDPattern,
		CSRFTokenPattern,
		NoncePattern,
		CodeVerifierPattern,
		AuthCodePattern,
		RedirectURIPattern,
		BotUserAgentPattern,
		IPv4Pattern,
		TenantIDPattern,
	}

	if err := globalCache.Precompile(commonPatterns); err != nil {
		panic("Failed to precompile common regex patterns: " + err.Error())
	}

	// Assign precompiled patterns to global variables for easy access
	EmailRegex = globalCache.MustGet(EmailPattern)
	DomainRegex = globalCache.MustGet(DomainPattern)
	URLRegex = globalCache.MustGet(URLPattern)
	JWTRegex = globalCache.MustGet(JWTPattern)
	BearerTokenRegex = globalCache.MustGet(BearerTokenPattern)
	ClientIDRegex = globalCache.MustGet(ClientIDPattern)
	ScopeRegex = globalCache.MustGet(ScopePattern)
	SessionIDRegex = globalCache.MustGet(SessionIDPattern)
	CSRFTokenRegex = globalCache.MustGet(CSRFTokenPattern)
	NonceRegex = globalCache.MustGet(NoncePattern)
	CodeVerifierRegex = globalCache.MustGet(CodeVerifierPattern)
	AuthCodeRegex = globalCache.MustGet(AuthCodePattern)
	RedirectURIRegex = globalCache.MustGet(RedirectURIPattern)
	BotUserAgentRegex = globalCache.MustGet(BotUserAgentPattern)
	IPv4Regex = globalCache.MustGet(IPv4Pattern)
	TenantIDRegex = globalCache.MustGet(TenantIDPattern)
}

// Global helper functions for common validations

// ValidateEmail checks if an email address is valid
func ValidateEmail(email string) bool {
	return EmailRegex.MatchString(email)
}

// ValidateDomain checks if a domain name is valid
func ValidateDomain(domain string) bool {
	return DomainRegex.MatchString(domain)
}

// ValidateURL checks if a URL is valid (http/https)
func ValidateURL(url string) bool {
	return URLRegex.MatchString(url)
}

// ValidateJWT checks if a token has valid JWT format
func ValidateJWT(token string) bool {
	return JWTRegex.MatchString(token)
}

// ExtractBearerToken extracts the token from a Bearer authorization header
func ExtractBearerToken(authHeader string) (string, bool) {
	matches := BearerTokenRegex.FindStringSubmatch(authHeader)
	if len(matches) == 2 {
		return matches[1], true
	}
	return "", false
}

// ValidateClientID checks if a client ID has valid format
func ValidateClientID(clientID string) bool {
	return ClientIDRegex.MatchString(clientID)
}

// ValidateScopes checks if scopes string has valid format
func ValidateScopes(scopes string) bool {
	return ScopeRegex.MatchString(scopes)
}

// ValidateSessionID checks if a session ID has valid format
func ValidateSessionID(sessionID string) bool {
	return SessionIDRegex.MatchString(sessionID)
}

// ValidateCSRFToken checks if a CSRF token has valid format
func ValidateCSRFToken(token string) bool {
	return CSRFTokenRegex.MatchString(token)
}

// ValidateNonce checks if a nonce has valid format
func ValidateNonce(nonce string) bool {
	return NonceRegex.MatchString(nonce)
}

// ValidateCodeVerifier checks if a PKCE code verifier has valid format
func ValidateCodeVerifier(verifier string) bool {
	return CodeVerifierRegex.MatchString(verifier)
}

// ValidateAuthCode checks if an authorization code has valid format
func ValidateAuthCode(code string) bool {
	return AuthCodeRegex.MatchString(code)
}

// ValidateRedirectURI checks if a redirect URI is valid
func ValidateRedirectURI(uri string) bool {
	return RedirectURIRegex.MatchString(uri)
}

// IsBotUserAgent checks if a User-Agent suggests an automated client
func IsBotUserAgent(userAgent string) bool {
	return BotUserAgentRegex.MatchString(userAgent)
}

// ValidateIPv4 checks if an IP address is valid IPv4
func ValidateIPv4(ip string) bool {
	return IPv4Regex.MatchString(ip)
}

// ValidateTenantID checks if a tenant ID has valid UUID format
func ValidateTenantID(tenantID string) bool {
	return TenantIDRegex.MatchString(tenantID)
}

// GetGlobalCache returns the global regex cache instance
func GetGlobalCache() *RegexCache {
	return globalCache
}

// CompilePattern compiles a pattern using the global cache
func CompilePattern(pattern string) (*regexp.Regexp, error) {
	return globalCache.Get(pattern)
}

// MustCompilePattern compiles a pattern using the global cache, panicking on error
func MustCompilePattern(pattern string) *regexp.Regexp {
	return globalCache.MustGet(pattern)
}
