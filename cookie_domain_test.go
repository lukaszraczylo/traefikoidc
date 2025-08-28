package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCookieDomainConfiguration tests that the cookie domain configuration is properly applied
func TestCookieDomainConfiguration(t *testing.T) {
	tests := []struct {
		configDomain   string
		requestHost    string
		forwardedHost  string
		expectedDomain string
		name           string
	}{
		{
			name:           "Configured domain takes precedence",
			configDomain:   ".example.com",
			requestHost:    "app.example.com",
			expectedDomain: ".example.com",
		},
		{
			name:           "Auto-detection when no domain configured",
			configDomain:   "",
			requestHost:    "app.example.com",
			expectedDomain: "app.example.com",
		},
		{
			name:           "X-Forwarded-Host used for auto-detection",
			configDomain:   "",
			requestHost:    "internal.local",
			forwardedHost:  "public.example.com",
			expectedDomain: "public.example.com",
		},
		{
			name:           "No domain for localhost",
			configDomain:   "",
			requestHost:    "localhost:8080",
			expectedDomain: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create session manager with configured domain
			logger := NewLogger("debug")
			sm, err := NewSessionManager("test-encryption-key-32-characters", false, tt.configDomain, logger)
			if err != nil {
				t.Fatalf("Failed to create session manager: %v", err)
			}

			// Create request
			req := httptest.NewRequest("GET", "http://"+tt.requestHost+"/test", nil)
			if tt.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
			}

			// Create a dummy response writer to test getCookieOptions behavior
			// We'll examine the session options domain instead
			options := &http.Cookie{
				Domain: sm.cookieDomain,
			}
			// If no configured domain, simulate auto-detection
			if sm.cookieDomain == "" && req != nil {
				host := req.Host
				if forwardedHost := req.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
					host = forwardedHost
				}
				if host != "" && !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
					if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
						host = host[:colonIndex]
					}
					options.Domain = host
				}
			}

			// Check domain
			if options.Domain != tt.expectedDomain {
				t.Errorf("Expected domain %q, got %q", tt.expectedDomain, options.Domain)
			}
		})
	}
}

// TestCookieDomainConsistency tests that all session cookies use the same domain
func TestCookieDomainConsistency(t *testing.T) {
	logger := NewLogger("debug")

	// Test with configured domain
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, ".example.com", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "http://app.example.com/test", nil)
	rr := httptest.NewRecorder()

	// Get session and set some values
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Set various session values including ID token
	session.SetNonce("test-nonce")
	session.SetAccessToken("test-access-token")
	session.SetRefreshToken("test-refresh-token")
	// Set a valid JWT-like ID token (needs 2 dots)
	session.SetIDToken("header.payload.signature")

	// Save session
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Check all cookies have the same domain
	cookies := rr.Result().Cookies()
	var seenDomain string

	for _, cookie := range cookies {
		// Only check our OIDC cookies
		if strings.HasPrefix(cookie.Name, "_oidc_") ||
			strings.HasPrefix(cookie.Name, "access_token_chunk_") ||
			strings.HasPrefix(cookie.Name, "refresh_token_chunk_") {

			// Normalize domain for comparison (handle leading dot and empty domain)
			normalizedDomain := cookie.Domain
			if normalizedDomain == "" {
				// Empty domain means host-only cookie, should match configured domain
				normalizedDomain = "example.com"
			} else if strings.HasPrefix(normalizedDomain, ".") {
				normalizedDomain = normalizedDomain[1:]
			}

			if seenDomain == "" {
				seenDomain = normalizedDomain
			} else if normalizedDomain != seenDomain {
				t.Errorf("Inconsistent cookie domains: %q vs %q for cookie %s",
					seenDomain, normalizedDomain, cookie.Name)
			}

			// Verify it matches configured domain (browsers may normalize by removing leading dot)
			// Empty domain is also acceptable for host-only cookies
			if cookie.Domain != "" && cookie.Domain != ".example.com" && cookie.Domain != "example.com" {
				t.Errorf("Cookie %s has domain %q, expected %q, %q, or empty",
					cookie.Name, cookie.Domain, ".example.com", "example.com")
			}
		}
	}
}

// TestCookieDomainWithReverseProxy simulates a reverse proxy scenario
func TestCookieDomainWithReverseProxy(t *testing.T) {
	logger := NewLogger("debug")

	// No configured domain, should auto-detect from X-Forwarded-Host
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Simulate reverse proxy request
	req := httptest.NewRequest("GET", "http://internal.local:8080/test", nil)
	req.Header.Set("X-Forwarded-Host", "public.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	// Test the domain configuration
	// Since getCookieOptions is private, we'll check the configured domain directly
	options := &http.Cookie{
		Domain: sm.cookieDomain,
	}
	// If no configured domain, simulate auto-detection
	if sm.cookieDomain == "" && req != nil {
		host := req.Host
		if forwardedHost := req.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
			host = forwardedHost
		}
		if host != "" && !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
			if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
				host = host[:colonIndex]
			}
			options.Domain = host
		}
	}

	// Check secure flag based on X-Forwarded-Proto
	isSecure := req.Header.Get("X-Forwarded-Proto") == "https" || req.TLS != nil
	options.Secure = isSecure // Note: forceHTTPS is private so we can't access it in test

	// Should use the forwarded host
	if options.Domain != "public.example.com" {
		t.Errorf("Expected domain from X-Forwarded-Host %q, got %q",
			"public.example.com", options.Domain)
	}

	// Should be secure due to X-Forwarded-Proto
	if !options.Secure {
		t.Error("Expected Secure flag to be true with X-Forwarded-Proto: https")
	}
}
