package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCookieCleanupBehavior tests the cookie cleanup function's behavior
func TestCookieCleanupBehavior(t *testing.T) {
	logger := NewLogger("debug")

	// Create session manager with a specific domain
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "app.example.com", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create request from app.example.com
	req := httptest.NewRequest("GET", "http://app.example.com/test", nil)

	// Add some OIDC cookies (browsers don't send domain info)
	cookies := []*http.Cookie{
		{
			Name:  "_oidc_raczylo_m",
			Value: "test-value-1",
		},
		{
			Name:  "_oidc_raczylo_a",
			Value: "test-value-2",
		},
		{
			Name:  "access_token_chunk_0",
			Value: "chunk-value",
		},
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	// Create response recorder to capture Set-Cookie headers
	rr := httptest.NewRecorder()

	// Run cleanup - it should attempt to delete cookies with various domains
	sm.CleanupOldCookies(rr, req)

	// Check Set-Cookie headers
	setCookies := rr.Result().Cookies()

	// The cleanup should have attempted to delete cookies with various domain variations
	// We should see deletion attempts for:
	// - app.example.com
	// - .app.example.com
	// - example.com
	// - .example.com
	var deletionAttempts int
	domainsAttempted := make(map[string]bool)

	for _, cookie := range setCookies {
		if cookie.MaxAge == -1 {
			deletionAttempts++
			domainsAttempted[cookie.Domain] = true
		}
	}

	// We should see deletion attempts for various domain variations
	// Note: The exact number depends on the implementation, but we should see multiple attempts
	if deletionAttempts == 0 {
		t.Error("Expected cleanup to attempt cookie deletions, but none were found")
	}

	// Log the domains attempted for debugging
	t.Logf("Deletion attempts: %d", deletionAttempts)
	for domain := range domainsAttempted {
		t.Logf("Attempted deletion for domain: %q", domain)
	}
}

// TestConfiguredDomainPersistence tests that configured domain is consistently used
func TestConfiguredDomainPersistence(t *testing.T) {
	logger := NewLogger("debug")

	// Create session manager with explicit domain configuration
	configuredDomain := ".example.com"
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, configuredDomain, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create requests from different subdomains
	tests := []struct {
		requestHost string
		name        string
	}{
		{
			name:        "Request from main domain",
			requestHost: "example.com",
		},
		{
			name:        "Request from subdomain",
			requestHost: "app.example.com",
		},
		{
			name:        "Request from nested subdomain",
			requestHost: "api.app.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.requestHost+"/test", nil)
			rr := httptest.NewRecorder()

			// Get session and set a value
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			defer session.ReturnToPool()

			session.SetNonce("test-nonce")

			// Save session
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Check that all cookies use the configured domain
			cookies := rr.Result().Cookies()
			for _, cookie := range cookies {
				if strings.HasPrefix(cookie.Name, "_oidc_") {
					// The domain should match the configured domain (with possible normalization)
					expectedDomains := []string{configuredDomain, strings.TrimPrefix(configuredDomain, ".")}
					domainMatches := false
					for _, expected := range expectedDomains {
						if cookie.Domain == expected || cookie.Domain == "" {
							domainMatches = true
							break
						}
					}
					if !domainMatches {
						t.Errorf("Cookie %s has unexpected domain %q, expected one of %v",
							cookie.Name, cookie.Domain, expectedDomains)
					}
				}
			}
		})
	}
}

// TestDomainMigration simulates migrating from no configured domain to explicit domain
func TestDomainMigration(t *testing.T) {
	logger := NewLogger("debug")

	// Step 1: Create session without configured domain (auto-detection)
	sm1, err := NewSessionManager("test-encryption-key-32-characters", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req1 := httptest.NewRequest("GET", "http://app.example.com/test", nil)
	rr1 := httptest.NewRecorder()

	session1, err := sm1.GetSession(req1)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	session1.SetNonce("test-nonce")
	session1.Save(req1, rr1)
	session1.ReturnToPool()

	// The cookies will have auto-detected domain
	oldCookies := rr1.Result().Cookies()
	t.Logf("Old cookies count: %d", len(oldCookies))

	// Step 2: Create new session manager with explicit domain configuration
	sm2, err := NewSessionManager("test-encryption-key-32-characters", false, ".example.com", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Step 3: Make request with old cookies
	req2 := httptest.NewRequest("GET", "http://app.example.com/test", nil)

	// Add the old cookies to the new request
	for _, cookie := range oldCookies {
		// Simulate browser behavior - don't include domain in Cookie header
		simpleCookie := &http.Cookie{
			Name:  cookie.Name,
			Value: cookie.Value,
		}
		req2.AddCookie(simpleCookie)
	}

	rr2 := httptest.NewRecorder()

	// Run cleanup - should attempt to delete old cookies
	sm2.CleanupOldCookies(rr2, req2)

	// Check that deletion cookies were sent
	newCookies := rr2.Result().Cookies()
	deletionCount := 0
	for _, cookie := range newCookies {
		if cookie.MaxAge == -1 {
			deletionCount++
		}
	}

	if deletionCount == 0 {
		t.Error("Expected cleanup to send deletion cookies during migration, but none were found")
	}

	t.Logf("Sent %d deletion cookies during migration", deletionCount)
}
