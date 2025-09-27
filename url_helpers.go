// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains URL-related helper methods for building, validating, and processing URLs
// used in the OIDC authentication flow.
package traefikoidc

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// =============================================================================
// URL Exclusion Methods
// =============================================================================

// determineExcludedURL checks if a URL path should bypass OIDC authentication.
// It compares the request path against configured excluded URL prefixes.
// Parameters:
//   - currentRequest: The request path to check.
//
// Returns:
//   - true if the URL should be excluded from authentication, false otherwise.
func (t *TraefikOidc) determineExcludedURL(currentRequest string) bool {
	for excludedURL := range t.excludedURLs {
		if strings.HasPrefix(currentRequest, excludedURL) {
			t.logger.Debugf("URL is excluded - got %s / excluded hit: %s", currentRequest, excludedURL)
			return true
		}
	}
	return false
}

// =============================================================================
// Request Analysis Methods
// =============================================================================

// determineScheme determines the URL scheme for building redirect URLs.
// It checks X-Forwarded-Proto header first, then TLS presence.
// Parameters:
//   - req: The HTTP request to analyze.
//
// Returns:
//   - The determined scheme: "https" or "http".
func (t *TraefikOidc) determineScheme(req *http.Request) string {
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// determineHost determines the host for building redirect URLs.
// It checks X-Forwarded-Host header first, then falls back to req.Host.
// Parameters:
//   - req: The HTTP request to analyze.
//
// Returns:
//   - The determined host string (e.g., "example.com:8080").
func (t *TraefikOidc) determineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}

// =============================================================================
// URL Building Methods
// =============================================================================

// buildAuthURL constructs the OIDC provider authorization URL.
// It builds the URL with all necessary parameters including client_id, scopes,
// PKCE parameters, and provider-specific parameters for Google and Azure.
// Parameters:
//   - redirectURL: The callback URL for after authentication.
//   - state: The CSRF token for state validation.
//   - nonce: The nonce for replay protection.
//   - codeChallenge: The PKCE code challenge (if PKCE is enabled).
//
// Returns:
//   - The fully constructed authorization URL string.
func (t *TraefikOidc) buildAuthURL(redirectURL, state, nonce, codeChallenge string) string {
	params := url.Values{}
	params.Set("client_id", t.clientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)

	if t.enablePKCE && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	scopes := make([]string, len(t.scopes))
	copy(scopes, t.scopes)

	if t.isGoogleProvider() {
		params.Set("access_type", "offline")
		t.logger.Debug("Google OIDC provider detected, added access_type=offline for refresh tokens")

		params.Set("prompt", "consent")
		t.logger.Debug("Google OIDC provider detected, added prompt=consent to ensure refresh tokens")
	} else if t.isAzureProvider() {
		params.Set("response_mode", "query")
		t.logger.Debug("Azure AD provider detected, added response_mode=query")

		hasOfflineAccess := false

		for _, scope := range scopes {
			if scope == "offline_access" {
				hasOfflineAccess = true
				break
			}
		}

		if !t.overrideScopes || (t.overrideScopes && len(t.scopes) == 0) {
			if !hasOfflineAccess {
				scopes = append(scopes, "offline_access")
				t.logger.Debugf("Azure AD provider: Added offline_access scope (overrideScopes: %t, user scopes count: %d)", t.overrideScopes, len(t.scopes))
			}
		} else {
			t.logger.Debugf("Azure AD provider: User is overriding scopes (count: %d), offline_access not automatically added.", len(t.scopes))
		}
	} else {
		if !t.overrideScopes || (t.overrideScopes && len(t.scopes) == 0) {
			hasOfflineAccess := false
			for _, scope := range scopes {
				if scope == "offline_access" {
					hasOfflineAccess = true
					break
				}
			}
			if !hasOfflineAccess {
				scopes = append(scopes, "offline_access")
				t.logger.Debugf("Standard provider: Added offline_access scope (overrideScopes: %t, user scopes count: %d)", t.overrideScopes, len(t.scopes))
			}
		} else {
			t.logger.Debugf("Standard provider: User is overriding scopes (count: %d), offline_access not automatically added.", len(t.scopes))
		}
	}

	if len(scopes) > 0 {
		finalScopeString := strings.Join(scopes, " ")
		params.Set("scope", finalScopeString)
		t.logger.Debugf("TraefikOidc.buildAuthURL: Final scope string being sent to OIDC provider: %s", finalScopeString)
	}

	return t.buildURLWithParams(t.authURL, params)
}

// buildURLWithParams constructs a URL by combining a base URL with query parameters.
// It handles both relative and absolute URLs, validates URL security,
// and properly encodes query parameters.
// Parameters:
//   - baseURL: The base URL to append parameters to.
//   - params: The query parameters to append.
//
// Returns:
//   - The fully constructed URL string with appended query parameters.
func (t *TraefikOidc) buildURLWithParams(baseURL string, params url.Values) string {
	if baseURL != "" {
		if strings.HasPrefix(baseURL, "http://") || strings.HasPrefix(baseURL, "https://") {
			if err := t.validateURL(baseURL); err != nil {
				t.logger.Errorf("URL validation failed for %s: %v", baseURL, err)
				return ""
			}
		}
	}

	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		issuerURLParsed, err := url.Parse(t.issuerURL)
		if err != nil {
			t.logger.Errorf("Could not parse issuerURL: %s. Error: %v", t.issuerURL, err)
			return ""
		}

		baseURLParsed, err := url.Parse(baseURL)
		if err != nil {
			t.logger.Errorf("Could not parse baseURL: %s. Error: %v", baseURL, err)
			return ""
		}

		resolvedURL := issuerURLParsed.ResolveReference(baseURLParsed)

		if err := t.validateURL(resolvedURL.String()); err != nil {
			t.logger.Errorf("Resolved URL validation failed for %s: %v", resolvedURL.String(), err)
			return ""
		}

		resolvedURL.RawQuery = params.Encode()
		return resolvedURL.String()
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		t.logger.Errorf("Could not parse absolute baseURL: %s. Error: %v", baseURL, err)
		return ""
	}

	if err := t.validateParsedURL(u); err != nil {
		t.logger.Errorf("Parsed URL validation failed for %s: %v", baseURL, err)
		return ""
	}

	u.RawQuery = params.Encode()
	return u.String()
}

// =============================================================================
// URL Validation Methods
// =============================================================================

// validateURL performs security validation on URLs to prevent SSRF attacks.
// It checks for allowed schemes, validates hosts, and prevents access to private networks.
// Parameters:
//   - urlStr: The URL string to validate.
//
// Returns:
//   - An error if the URL is invalid or poses security risks, nil if valid.
func (t *TraefikOidc) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("empty URL")
	}

	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	return t.validateParsedURL(u)
}

// validateParsedURL validates a parsed URL structure for security.
// It checks schemes, hosts, and paths to prevent malicious URLs.
// Parameters:
//   - u: The parsed URL to validate.
//
// Returns:
//   - An error if the URL is invalid or dangerous, nil if safe.
func (t *TraefikOidc) validateParsedURL(u *url.URL) error {
	allowedSchemes := map[string]bool{
		"https": true,
		"http":  true,
	}

	if !allowedSchemes[u.Scheme] {
		return fmt.Errorf("disallowed URL scheme: %s", u.Scheme)
	}

	if u.Scheme == "http" {
		t.logger.Debugf("Warning: Using HTTP scheme for URL: %s", u.String())
	}

	if u.Host == "" {
		return fmt.Errorf("missing host in URL")
	}

	if err := t.validateHost(u.Host); err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}

	if strings.Contains(u.Path, "..") {
		return fmt.Errorf("path traversal detected in URL path")
	}

	return nil
}

// validateHost validates a hostname or IP address for security.
// It prevents access to localhost, private networks, and known metadata endpoints.
// Parameters:
//   - host: The host string to validate (may include port).
//
// Returns:
//   - An error if the host is dangerous or not allowed, nil if safe.
func (t *TraefikOidc) validateHost(host string) error {
	hostname := host
	if strings.Contains(host, ":") {
		var err error
		hostname, _, err = net.SplitHostPort(host)
		if err != nil {
			return fmt.Errorf("invalid host format: %w", err)
		}
	}

	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("access to private/internal IP addresses is not allowed: %s", ip.String())
		}

		if ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("access to unspecified or multicast IP addresses is not allowed: %s", ip.String())
		}
	}

	dangerousHosts := map[string]bool{
		"localhost":                true,
		"127.0.0.1":                true,
		"::1":                      true,
		"0.0.0.0":                  true,
		"169.254.169.254":          true,
		"metadata.google.internal": true,
	}

	if dangerousHosts[strings.ToLower(hostname)] {
		return fmt.Errorf("access to dangerous hostname is not allowed: %s", hostname)
	}

	return nil
}
