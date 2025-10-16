// Package auth provides authentication-related functionality for the OIDC middleware.
package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// ScopeFilter interface for filtering OAuth scopes based on provider capabilities
type ScopeFilter interface {
	FilterSupportedScopes(requestedScopes, supportedScopes []string, providerURL string) []string
}

// Handler provides core authentication functionality for OIDC flows
type Handler struct {
	logger          Logger
	enablePKCE      bool
	isGoogleProv    func() bool
	isAzureProv     func() bool
	clientID        string
	authURL         string
	issuerURL       string
	scopes          []string
	overrideScopes  bool
	scopeFilter     ScopeFilter // NEW
	scopesSupported []string    // NEW - from provider metadata
}

// Logger interface for dependency injection
type Logger interface {
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// NewAuthHandler creates a new Handler instance
func NewAuthHandler(logger Logger, enablePKCE bool, isGoogleProv, isAzureProv func() bool,
	clientID, authURL, issuerURL string, scopes []string, overrideScopes bool,
	scopeFilter ScopeFilter, scopesSupported []string) *Handler {
	return &Handler{
		logger:          logger,
		enablePKCE:      enablePKCE,
		isGoogleProv:    isGoogleProv,
		isAzureProv:     isAzureProv,
		clientID:        clientID,
		authURL:         authURL,
		issuerURL:       issuerURL,
		scopes:          scopes,
		overrideScopes:  overrideScopes,
		scopeFilter:     scopeFilter,     // NEW
		scopesSupported: scopesSupported, // NEW
	}
}

// InitiateAuthentication initiates the OIDC authentication flow.
// It generates CSRF tokens, nonce, PKCE parameters (if enabled), clears the session,
// stores authentication state, and redirects the user to the OIDC provider.
func (h *Handler) InitiateAuthentication(rw http.ResponseWriter, req *http.Request,
	session SessionData, redirectURL string,
	generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error)) {
	h.logger.Debugf("Initiating new OIDC authentication flow for request: %s", req.URL.RequestURI())

	const maxRedirects = 5
	redirectCount := session.GetRedirectCount()
	if redirectCount >= maxRedirects {
		h.logger.Errorf("Maximum redirect limit (%d) exceeded, possible redirect loop detected", maxRedirects)
		session.ResetRedirectCount()
		http.Error(rw, "Authentication failed: Too many redirects", http.StatusLoopDetected)
		return
	}

	session.IncrementRedirectCount()

	csrfToken := uuid.NewString()
	nonce, err := generateNonce()
	if err != nil {
		h.logger.Errorf("Failed to generate nonce: %v", err)
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Generate PKCE code verifier and challenge if PKCE is enabled
	var codeVerifier, codeChallenge string
	if h.enablePKCE {
		codeVerifier, err = generateCodeVerifier()
		if err != nil {
			h.logger.Errorf("Failed to generate code verifier: %v", err)
			http.Error(rw, "Failed to generate code verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge, err = deriveCodeChallenge()
		if err != nil {
			h.logger.Errorf("Failed to generate code challenge: %v", err)
			http.Error(rw, "Failed to generate code challenge", http.StatusInternalServerError)
			return
		}
		h.logger.Debugf("PKCE enabled, generated code challenge")
	}

	session.SetAuthenticated(false)
	session.SetEmail("")
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetIDToken("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	if h.enablePKCE {
		session.SetCodeVerifier(codeVerifier)
	}
	session.SetIncomingPath(req.URL.RequestURI())
	h.logger.Debugf("Storing incoming path: %s", req.URL.RequestURI())

	session.MarkDirty()

	if err := session.Save(req, rw); err != nil {
		h.logger.Errorf("Failed to save session before redirecting to provider: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	h.logger.Debugf("Session saved before redirect. CSRF: %s, Nonce: %s",
		csrfToken, nonce)

	authURL := h.BuildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)
	h.logger.Debugf("Redirecting user to OIDC provider: %s", authURL)

	http.Redirect(rw, req, authURL, http.StatusFound)
}

// BuildAuthURL constructs the OIDC provider authorization URL.
// It builds the URL with all necessary parameters including client_id, scopes,
// PKCE parameters, and provider-specific parameters for Google and Azure.
func (h *Handler) BuildAuthURL(redirectURL, state, nonce, codeChallenge string) string {
	params := url.Values{}
	params.Set("client_id", h.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)

	if h.enablePKCE && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	scopes := make([]string, len(h.scopes))
	copy(scopes, h.scopes)

	// Apply discovery-based scope filtering if available
	if h.scopeFilter != nil && len(h.scopesSupported) > 0 {
		scopes = h.scopeFilter.FilterSupportedScopes(scopes, h.scopesSupported, h.issuerURL)
		h.logger.Debugf("AuthHandler.BuildAuthURL: After discovery filtering: %v", scopes)
	}

	// Apply provider-specific modifications
	scopes, params = h.applyProviderSpecificConfig(scopes, params)

	// Final filtering pass to remove anything the provider doesn't support
	if h.scopeFilter != nil && len(h.scopesSupported) > 0 {
		scopes = h.scopeFilter.FilterSupportedScopes(scopes, h.scopesSupported, h.issuerURL)
		h.logger.Debugf("AuthHandler.BuildAuthURL: After final filtering: %v", scopes)
	}

	if len(scopes) > 0 {
		finalScopeString := strings.Join(scopes, " ")
		params.Set("scope", finalScopeString)
		h.logger.Debugf("AuthHandler.BuildAuthURL: Final scope string being sent to OIDC provider: %s", finalScopeString)
	}

	return h.buildURLWithParams(h.authURL, params)
}

// applyProviderSpecificConfig applies provider-specific scope and parameter modifications
func (h *Handler) applyProviderSpecificConfig(scopes []string, params url.Values) ([]string, url.Values) {
	switch {
	case h.isGoogleProv():
		return h.applyGoogleConfig(scopes, params)
	case h.isAzureProv():
		return h.applyAzureConfig(scopes, params)
	default:
		return h.applyStandardProviderConfig(scopes, params)
	}
}

// applyGoogleConfig applies Google-specific configuration
func (h *Handler) applyGoogleConfig(scopes []string, params url.Values) ([]string, url.Values) {
	// Google: Remove offline_access if present, add access_type=offline
	filteredScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != "offline_access" {
			filteredScopes = append(filteredScopes, scope)
		}
	}
	params.Set("access_type", "offline")
	h.logger.Debugf("Google OIDC provider detected, added access_type=offline")
	params.Set("prompt", "consent")
	h.logger.Debugf("Google OIDC provider detected, added prompt=consent to ensure refresh tokens")
	return filteredScopes, params
}

// applyAzureConfig applies Azure AD-specific configuration
func (h *Handler) applyAzureConfig(scopes []string, params url.Values) ([]string, url.Values) {
	params.Set("response_mode", "query")
	h.logger.Debugf("Azure AD provider detected, added response_mode=query")

	if h.shouldAddOfflineAccess(scopes) {
		scopes = append(scopes, "offline_access")
		h.logger.Debugf("Azure AD provider: Added offline_access scope (overrideScopes: %t, user scopes count: %d)",
			h.overrideScopes, len(h.scopes))
	} else {
		h.logger.Debugf("Azure AD provider: User is overriding scopes (count: %d), offline_access not automatically added.",
			len(h.scopes))
	}
	return scopes, params
}

// applyStandardProviderConfig applies configuration for standard OIDC providers
func (h *Handler) applyStandardProviderConfig(scopes []string, params url.Values) ([]string, url.Values) {
	if h.shouldAddOfflineAccess(scopes) {
		scopes = append(scopes, "offline_access")
		h.logger.Debugf("Standard provider: Added offline_access scope (overrideScopes: %t, user scopes count: %d)",
			h.overrideScopes, len(h.scopes))
	} else {
		h.logger.Debugf("Standard provider: User is overriding scopes (count: %d), offline_access not automatically added.",
			len(h.scopes))
	}
	return scopes, params
}

// shouldAddOfflineAccess determines if offline_access scope should be added
func (h *Handler) shouldAddOfflineAccess(scopes []string) bool {
	if h.overrideScopes && len(h.scopes) > 0 {
		return false
	}
	for _, scope := range scopes {
		if scope == "offline_access" {
			return false
		}
	}
	return true
}

// buildURLWithParams constructs a URL by combining a base URL with query parameters.
// It handles both relative and absolute URLs, validates URL security,
// and properly encodes query parameters.
func (h *Handler) buildURLWithParams(baseURL string, params url.Values) string {
	if baseURL != "" {
		if strings.HasPrefix(baseURL, "http://") || strings.HasPrefix(baseURL, "https://") {
			if err := h.validateURL(baseURL); err != nil {
				h.logger.Errorf("URL validation failed for %s: %v", baseURL, err)
				return ""
			}
		}
	}

	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		issuerURLParsed, err := url.Parse(h.issuerURL)
		if err != nil {
			h.logger.Errorf("Could not parse issuerURL: %s. Error: %v", h.issuerURL, err)
			return ""
		}

		baseURLParsed, err := url.Parse(baseURL)
		if err != nil {
			h.logger.Errorf("Could not parse baseURL: %s. Error: %v", baseURL, err)
			return ""
		}

		resolvedURL := issuerURLParsed.ResolveReference(baseURLParsed)

		if err := h.validateURL(resolvedURL.String()); err != nil {
			h.logger.Errorf("Resolved URL validation failed for %s: %v", resolvedURL.String(), err)
			return ""
		}

		resolvedURL.RawQuery = params.Encode()
		return resolvedURL.String()
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		h.logger.Errorf("Could not parse absolute baseURL: %s. Error: %v", baseURL, err)
		return ""
	}

	if err := h.validateParsedURL(u); err != nil {
		h.logger.Errorf("Parsed URL validation failed for %s: %v", baseURL, err)
		return ""
	}

	u.RawQuery = params.Encode()
	return u.String()
}

// validateURL performs security validation on URLs to prevent SSRF attacks.
// It checks for allowed schemes, validates hosts, and prevents access to private networks.
func (h *Handler) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("empty URL")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	return h.validateParsedURL(u)
}

// validateParsedURL validates a parsed URL structure for security.
// It checks schemes, hosts, and paths to prevent malicious URLs.
func (h *Handler) validateParsedURL(u *url.URL) error {
	allowedSchemes := map[string]bool{
		"https": true,
		"http":  true,
	}

	if !allowedSchemes[u.Scheme] {
		return fmt.Errorf("disallowed URL scheme: %s", u.Scheme)
	}

	if u.Scheme == "http" {
		h.logger.Debugf("Warning: Using HTTP scheme for URL: %s", u.String())
	}

	if u.Host == "" {
		return fmt.Errorf("missing host in URL")
	}

	if err := h.validateHost(u.Host); err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}

	if strings.Contains(u.Path, "..") {
		return fmt.Errorf("path traversal detected in URL path")
	}

	return nil
}

// validateHost validates a hostname for security and reachability.
// It prevents access to private networks and localhost addresses.
func (h *Handler) validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}

	// Strip port if present
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return fmt.Errorf("invalid host:port format: %w", err)
		}
	}

	// Check for localhost variations
	localhostVariations := []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
	}
	for _, localhost := range localhostVariations {
		if strings.EqualFold(host, localhost) {
			return fmt.Errorf("localhost access not allowed: %s", host)
		}
	}

	// Try to parse as IP address
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("loopback IP not allowed: %s", host)
		}
		if ip.IsPrivate() {
			return fmt.Errorf("private IP not allowed: %s", host)
		}
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("link-local IP not allowed: %s", host)
		}
		if ip.IsMulticast() {
			return fmt.Errorf("multicast IP not allowed: %s", host)
		}
	}

	return nil
}

// SessionData interface for dependency injection
type SessionData interface {
	GetRedirectCount() int
	ResetRedirectCount()
	IncrementRedirectCount()
	SetAuthenticated(bool)
	SetEmail(string)
	SetAccessToken(string)
	SetRefreshToken(string)
	SetIDToken(string)
	SetNonce(string)
	SetCodeVerifier(string)
	SetCSRF(string)
	SetIncomingPath(string)
	MarkDirty()
	Save(req *http.Request, rw http.ResponseWriter) error
}
