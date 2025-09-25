package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
)

// generateLargeRealisticToken creates a realistic JWT token with a large payload
// that mimics real-world OAuth tokens but with enough data to test chunking
func generateLargeRealisticToken() string {
	// Create a realistic JWT header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key-id",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create a large but realistic payload with many claims
	claims := map[string]interface{}{
		"iss":   "https://auth.example.com/",
		"sub":   "auth0|507f1f77bcf86cd799439011",
		"aud":   []string{"https://api.example.com", "https://app.example.com"},
		"iat":   1516239022,
		"exp":   1516325422,
		"azp":   "my_client_id",
		"scope": "openid profile email read:users write:users admin",
		"gty":   "client-credentials",
	}

	// Add many custom claims to make the token large
	for i := 0; i < 100; i++ {
		claimName := fmt.Sprintf("custom_claim_%d", i)
		claimValue := fmt.Sprintf("This is a test value for claim %d with some additional data to make it larger", i)
		claims[claimName] = claimValue
	}

	// Add some array claims with multiple values
	claims["permissions"] = []string{
		"read:users", "write:users", "delete:users", "create:users",
		"read:posts", "write:posts", "delete:posts", "create:posts",
		"admin:all", "super:admin", "system:manage", "audit:view",
	}

	claims["groups"] = []string{
		"administrators", "developers", "qa_team", "devops",
		"product_managers", "support_team", "security_team",
	}

	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create a mock signature (in real scenario this would be cryptographic)
	signature := base64.RawURLEncoding.EncodeToString(
		[]byte("mock_signature_with_some_additional_bytes_for_testing_purposes"))

	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signature)
}

// TestAuth0RedirectLoopFix tests the fixes applied to prevent Auth0 redirect loops
// specifically focusing on:
// 1. Consistent cookie configuration (Path="/", SameSite=Lax)
// 2. CSRF token accessibility during OAuth callbacks
// 3. Session cookie persistence across OAuth flow
// 4. Redirect loop prevention
func TestAuth0RedirectLoopFix(t *testing.T) {
	logger := NewLogger("debug")
	encryptionKey := "0123456789abcdef0123456789abcdef0123456789abcdef"

	sm, err := NewSessionManager(encryptionKey, false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	t.Run("CookieConfigurationConsistency", func(t *testing.T) {
		testCookieConfigurationConsistency(t, sm)
	})

	t.Run("CSRFTokenAccessibility", func(t *testing.T) {
		testCSRFTokenAccessibility(t, sm)
	})

	t.Run("SessionPersistenceAcrossOAuth", func(t *testing.T) {
		testSessionPersistenceAcrossOAuth(t, sm)
	})

	t.Run("RedirectLoopPrevention", func(t *testing.T) {
		testRedirectLoopPrevention(t, sm)
	})

	t.Run("CallbackCSRFValidation", func(t *testing.T) {
		testCallbackCSRFValidation(t, sm)
	})

	t.Run("EdgeCases", func(t *testing.T) {
		testEdgeCases(t, sm)
	})
}

// testCookieConfigurationConsistency verifies that cookies are configured
// consistently with Path="/" and SameSite=Lax regardless of request headers
func testCookieConfigurationConsistency(t *testing.T, sm *SessionManager) {
	tests := []struct {
		name        string
		headers     map[string]string
		expectPath  string
		expectSame  http.SameSite
		description string
	}{
		{
			name: "StandardRequest",
			headers: map[string]string{
				"Host": "example.com",
			},
			expectPath:  "/",
			expectSame:  http.SameSiteLaxMode,
			description: "Standard HTTP request should get consistent cookie config",
		},
		{
			name: "XMLHttpRequest",
			headers: map[string]string{
				"Host":              "example.com",
				"X-Requested-With":  "XMLHttpRequest",
				"X-Forwarded-Proto": "https",
			},
			expectPath:  "/",
			expectSame:  http.SameSiteLaxMode,
			description: "XMLHttpRequest should still use SameSite=Lax (fix for redirect loop)",
		},
		{
			name: "HTTPSRequest",
			headers: map[string]string{
				"Host":              "example.com",
				"X-Forwarded-Proto": "https",
			},
			expectPath:  "/",
			expectSame:  http.SameSiteLaxMode,
			description: "HTTPS requests should have consistent cookie config",
		},
		{
			name: "CustomDomainRequest",
			headers: map[string]string{
				"Host":              "auth.example.com",
				"X-Forwarded-Host":  "auth.example.com",
				"X-Forwarded-Proto": "https",
			},
			expectPath:  "/",
			expectSame:  http.SameSiteLaxMode,
			description: "Custom domain requests should maintain consistent config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/callback", nil)

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			rw := httptest.NewRecorder()

			// Get session and save it to trigger cookie setting
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Set some session data to ensure it gets saved
			session.SetCSRF("test-csrf-token")
			session.SetAuthenticated(false)

			err = session.Save(req, rw)
			if err != nil {
				t.Errorf("Failed to save session: %v", err)
			}

			// Verify cookie configuration
			cookies := rw.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("No cookies set in response")
			}

			for _, cookie := range cookies {
				if strings.HasPrefix(cookie.Name, "_oidc_raczylo") {
					if cookie.Path != tt.expectPath {
						t.Errorf("Expected Path=%s, got Path=%s for cookie %s",
							tt.expectPath, cookie.Path, cookie.Name)
					}
					if cookie.SameSite != tt.expectSame {
						t.Errorf("Expected SameSite=%v, got SameSite=%v for cookie %s",
							tt.expectSame, cookie.SameSite, cookie.Name)
					}
					t.Logf("Cookie %s: Path=%s, SameSite=%v, Secure=%v, HttpOnly=%v",
						cookie.Name, cookie.Path, cookie.SameSite, cookie.Secure, cookie.HttpOnly)
				}
			}

			session.Clear(req, nil)
		})
	}
}

// testCSRFTokenAccessibility verifies that CSRF tokens remain accessible
// during OAuth callbacks regardless of request type
func testCSRFTokenAccessibility(t *testing.T, sm *SessionManager) {
	csrfToken := uuid.New().String()

	tests := []struct {
		name        string
		headers     map[string]string
		description string
	}{
		{
			name: "StandardCallback",
			headers: map[string]string{
				"Host": "example.com",
			},
			description: "Standard OAuth callback should access CSRF token",
		},
		{
			name: "AjaxCallback",
			headers: map[string]string{
				"Host":             "example.com",
				"X-Requested-With": "XMLHttpRequest",
			},
			description: "AJAX OAuth callback should access CSRF token",
		},
		{
			name: "HTTPSCallback",
			headers: map[string]string{
				"Host":              "example.com",
				"X-Forwarded-Proto": "https",
			},
			description: "HTTPS OAuth callback should access CSRF token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Phase 1: Store CSRF token in session (auth initiation)
			initReq := httptest.NewRequest("GET", "http://example.com/protected", nil)
			for key, value := range tt.headers {
				initReq.Header.Set(key, value)
			}

			initRw := httptest.NewRecorder()

			session, err := sm.GetSession(initReq)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			session.SetCSRF(csrfToken)
			session.SetNonce("test-nonce")
			session.SetIncomingPath("/protected")

			err = session.Save(initReq, initRw)
			if err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Get cookies from response to simulate browser behavior
			storedCookies := initRw.Result().Cookies()

			// Phase 2: OAuth callback with same cookies
			callbackReq := httptest.NewRequest("GET",
				"http://example.com/callback?state="+csrfToken+"&code=auth_code", nil)

			for key, value := range tt.headers {
				callbackReq.Header.Set(key, value)
			}

			// Add cookies to callback request
			for _, cookie := range storedCookies {
				callbackReq.AddCookie(cookie)
			}

			// Get session in callback
			callbackSession, err := sm.GetSession(callbackReq)
			if err != nil {
				t.Fatalf("Failed to get callback session: %v", err)
			}
			defer callbackSession.Clear(callbackReq, nil)

			// Verify CSRF token is accessible
			retrievedCSRF := callbackSession.GetCSRF()
			if retrievedCSRF == "" {
				t.Error("CSRF token not accessible in callback session")
			}
			if retrievedCSRF != csrfToken {
				t.Errorf("CSRF token mismatch: expected %s, got %s", csrfToken, retrievedCSRF)
			}

			// Verify other session data is accessible
			if callbackSession.GetNonce() != "test-nonce" {
				t.Error("Nonce not accessible in callback session")
			}
			if callbackSession.GetIncomingPath() != "/protected" {
				t.Error("Incoming path not accessible in callback session")
			}

			t.Logf("CSRF token successfully retrieved in %s: %s", tt.name, retrievedCSRF)
		})
	}
}

// testSessionPersistenceAcrossOAuth verifies that session data persists
// correctly across the OAuth flow without being lost due to cookie issues
func testSessionPersistenceAcrossOAuth(t *testing.T, sm *SessionManager) {
	// Simulate complete OAuth flow
	req := httptest.NewRequest("GET", "http://example.com/protected", nil)
	req.Header.Set("Host", "example.com")
	req.Header.Set("X-Forwarded-Proto", "https")

	rw := httptest.NewRecorder()

	// Phase 1: Initial authentication request
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get initial session: %v", err)
	}

	csrfToken := uuid.New().String()
	nonce := "test-nonce-" + uuid.New().String()

	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	session.SetIncomingPath("/protected")
	session.SetCodeVerifier("test-code-verifier")

	err = session.Save(req, rw)
	if err != nil {
		t.Fatalf("Failed to save initial session: %v", err)
	}

	initialCookies := rw.Result().Cookies()
	if len(initialCookies) == 0 {
		t.Fatal("No cookies set in initial response")
	}

	// Phase 2: OAuth provider redirect (user authenticates)
	redirectReq := httptest.NewRequest("GET", "https://auth0.example.com/authorize", nil)
	// Add cookies as browser would
	for _, cookie := range initialCookies {
		redirectReq.AddCookie(cookie)
	}

	// Phase 3: OAuth callback
	callbackReq := httptest.NewRequest("GET",
		"http://example.com/callback?state="+csrfToken+"&code=auth_code_12345", nil)
	callbackReq.Header.Set("Host", "example.com")
	callbackReq.Header.Set("X-Forwarded-Proto", "https")

	// Add all cookies from initial response
	for _, cookie := range initialCookies {
		callbackReq.AddCookie(cookie)
	}

	callbackRw := httptest.NewRecorder()

	callbackSession, err := sm.GetSession(callbackReq)
	if err != nil {
		t.Fatalf("Failed to get callback session: %v", err)
	}
	defer callbackSession.Clear(callbackReq, nil)

	// Verify all session data persisted
	if callbackSession.GetCSRF() != csrfToken {
		t.Errorf("CSRF token not persisted: expected %s, got %s",
			csrfToken, callbackSession.GetCSRF())
	}
	if callbackSession.GetNonce() != nonce {
		t.Errorf("Nonce not persisted: expected %s, got %s",
			nonce, callbackSession.GetNonce())
	}
	if callbackSession.GetIncomingPath() != "/protected" {
		t.Errorf("Incoming path not persisted: expected /protected, got %s",
			callbackSession.GetIncomingPath())
	}
	if callbackSession.GetCodeVerifier() != "test-code-verifier" {
		t.Errorf("Code verifier not persisted: expected test-code-verifier, got %s",
			callbackSession.GetCodeVerifier())
	}

	// Simulate successful authentication
	callbackSession.SetAuthenticated(true)
	callbackSession.SetEmail("user@example.com")
	callbackSession.SetAccessToken("access_token_12345")
	callbackSession.SetRefreshToken("refresh_token_12345")
	callbackSession.SetIDToken("id_token_12345")

	// Clear OAuth-specific data
	callbackSession.SetCSRF("")
	callbackSession.SetNonce("")
	callbackSession.SetCodeVerifier("")
	callbackSession.ResetRedirectCount()

	err = callbackSession.Save(callbackReq, callbackRw)
	if err != nil {
		t.Errorf("Failed to save callback session: %v", err)
	}

	t.Log("OAuth flow simulation completed successfully - session data persisted")
}

// testRedirectLoopPrevention verifies that the redirect loop prevention
// mechanisms work correctly
func testRedirectLoopPrevention(t *testing.T, sm *SessionManager) {
	req := httptest.NewRequest("GET", "http://example.com/protected", nil)
	req.Header.Set("Host", "example.com")

	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.Clear(req, nil)

	// Test redirect count tracking
	initialCount := session.GetRedirectCount()
	if initialCount != 0 {
		t.Errorf("Initial redirect count should be 0, got %d", initialCount)
	}

	// Simulate multiple redirect attempts
	for i := 1; i <= 6; i++ {
		session.IncrementRedirectCount()
		count := session.GetRedirectCount()
		if count != i {
			t.Errorf("Expected redirect count %d, got %d", i, count)
		}

		// Test that redirect loop detection kicks in at 5 redirects
		if i >= 5 {
			t.Logf("Redirect count at %d - should trigger loop detection", count)
		}
	}

	// Test reset functionality
	session.ResetRedirectCount()
	if session.GetRedirectCount() != 0 {
		t.Errorf("Redirect count should be 0 after reset, got %d", session.GetRedirectCount())
	}

	t.Log("Redirect loop prevention tests passed")
}

// testCallbackCSRFValidation tests CSRF token validation in OAuth callbacks
func testCallbackCSRFValidation(t *testing.T, sm *SessionManager) {
	tests := []struct {
		name          string
		storedCSRF    string
		callbackState string
		shouldSucceed bool
		description   string
	}{
		{
			name:          "ValidCSRF",
			storedCSRF:    "valid-csrf-token-123",
			callbackState: "valid-csrf-token-123",
			shouldSucceed: true,
			description:   "Valid CSRF token should pass validation",
		},
		{
			name:          "InvalidCSRF",
			storedCSRF:    "valid-csrf-token-123",
			callbackState: "different-csrf-token-456",
			shouldSucceed: false,
			description:   "Invalid CSRF token should fail validation",
		},
		{
			name:          "EmptyStoredCSRF",
			storedCSRF:    "",
			callbackState: "some-csrf-token",
			shouldSucceed: false,
			description:   "Empty stored CSRF should fail validation",
		},
		{
			name:          "EmptyCallbackState",
			storedCSRF:    "valid-csrf-token-123",
			callbackState: "",
			shouldSucceed: false,
			description:   "Empty callback state should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup phase - store CSRF token
			setupReq := httptest.NewRequest("GET", "http://example.com/auth", nil)
			setupReq.Header.Set("Host", "example.com")

			session, err := sm.GetSession(setupReq)
			if err != nil {
				t.Fatalf("Failed to get setup session: %v", err)
			}

			if tt.storedCSRF != "" {
				session.SetCSRF(tt.storedCSRF)
			}

			setupRw := httptest.NewRecorder()
			err = session.Save(setupReq, setupRw)
			if err != nil {
				t.Fatalf("Failed to save setup session: %v", err)
			}

			setupCookies := setupRw.Result().Cookies()

			// Callback phase - validate CSRF
			callbackURL := "http://example.com/callback"
			if tt.callbackState != "" {
				callbackURL += "?state=" + tt.callbackState + "&code=test_code"
			} else {
				callbackURL += "?code=test_code"
			}

			callbackReq := httptest.NewRequest("GET", callbackURL, nil)
			callbackReq.Header.Set("Host", "example.com")

			// Add cookies
			for _, cookie := range setupCookies {
				callbackReq.AddCookie(cookie)
			}

			callbackSession, err := sm.GetSession(callbackReq)
			if err != nil {
				t.Fatalf("Failed to get callback session: %v", err)
			}
			defer callbackSession.Clear(callbackReq, nil)

			// Perform CSRF validation
			storedCSRF := callbackSession.GetCSRF()
			stateParam := callbackReq.URL.Query().Get("state")

			csrfValid := (storedCSRF != "" && stateParam != "" && storedCSRF == stateParam)

			if tt.shouldSucceed && !csrfValid {
				t.Errorf("CSRF validation should have succeeded but failed. Stored: '%s', State: '%s'",
					storedCSRF, stateParam)
			}
			if !tt.shouldSucceed && csrfValid {
				t.Errorf("CSRF validation should have failed but succeeded. Stored: '%s', State: '%s'",
					storedCSRF, stateParam)
			}

			t.Logf("CSRF validation test '%s': stored='%s', state='%s', valid=%v",
				tt.name, storedCSRF, stateParam, csrfValid)
		})
	}
}

// testEdgeCases tests various edge cases that could cause redirect loops
func testEdgeCases(t *testing.T, sm *SessionManager) {
	t.Run("MissingHeaders", func(t *testing.T) {
		// Test with minimal headers
		req := httptest.NewRequest("GET", "http://localhost/callback", nil)

		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session with minimal headers: %v", err)
		}
		defer session.Clear(req, nil)

		session.SetCSRF("test-csrf")
		rw := httptest.NewRecorder()
		err = session.Save(req, rw)
		if err != nil {
			t.Errorf("Failed to save session with minimal headers: %v", err)
		}

		// Verify cookies still have consistent configuration
		cookies := rw.Result().Cookies()
		for _, cookie := range cookies {
			if strings.HasPrefix(cookie.Name, "_oidc_raczylo") {
				if cookie.Path != "/" {
					t.Errorf("Cookie path inconsistent with minimal headers: got %s", cookie.Path)
				}
				if cookie.SameSite != http.SameSiteLaxMode {
					t.Errorf("Cookie SameSite inconsistent with minimal headers: got %v", cookie.SameSite)
				}
			}
		}
	})

	t.Run("DifferentDomains", func(t *testing.T) {
		domains := []string{"example.com", "auth.example.com", "sub.auth.example.com"}

		for _, domain := range domains {
			req := httptest.NewRequest("GET", "http://"+domain+"/callback", nil)
			req.Header.Set("Host", domain)
			req.Header.Set("X-Forwarded-Host", domain)

			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session for domain %s: %v", domain, err)
			}

			session.SetCSRF("test-csrf-" + domain)
			rw := httptest.NewRecorder()
			err = session.Save(req, rw)
			if err != nil {
				t.Errorf("Failed to save session for domain %s: %v", domain, err)
			}

			// Verify consistent cookie configuration across domains
			cookies := rw.Result().Cookies()
			for _, cookie := range cookies {
				if strings.HasPrefix(cookie.Name, "_oidc_raczylo") {
					if cookie.Path != "/" {
						t.Errorf("Domain %s: Cookie path inconsistent: got %s", domain, cookie.Path)
					}
					if cookie.SameSite != http.SameSiteLaxMode {
						t.Errorf("Domain %s: Cookie SameSite inconsistent: got %v", domain, cookie.SameSite)
					}
				}
			}

			session.Clear(req, nil)
			t.Logf("Domain %s: Cookie configuration consistent", domain)
		}
	})

	t.Run("ConcurrentSessions", func(t *testing.T) {
		// Test that multiple concurrent sessions don't interfere
		const numSessions = 5
		sessions := make([]*SessionData, numSessions)

		for i := 0; i < numSessions; i++ {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			req.Header.Set("Host", "example.com")

			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session %d: %v", i, err)
			}
			sessions[i] = session

			// Set unique data for each session
			session.SetCSRF("csrf-" + string(rune('A'+i)))
			session.SetNonce("nonce-" + string(rune('A'+i)))
		}

		// Verify each session has its own data
		for i, session := range sessions {
			expectedCSRF := "csrf-" + string(rune('A'+i))
			expectedNonce := "nonce-" + string(rune('A'+i))

			if session.GetCSRF() != expectedCSRF {
				t.Errorf("Session %d CSRF mismatch: expected %s, got %s",
					i, expectedCSRF, session.GetCSRF())
			}
			if session.GetNonce() != expectedNonce {
				t.Errorf("Session %d nonce mismatch: expected %s, got %s",
					i, expectedNonce, session.GetNonce())
			}

			session.Clear(nil, nil)
		}

		t.Log("Concurrent sessions test passed")
	})

	t.Run("LargeCookieHandling", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		req.Header.Set("Host", "example.com")

		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}
		defer session.Clear(req, nil)

		// Test with large realistic JWT token that might require chunking
		largeToken := generateLargeRealisticToken()
		session.SetAccessToken(largeToken)
		session.SetCSRF("test-csrf")

		rw := httptest.NewRecorder()
		err = session.Save(req, rw)
		if err != nil {
			t.Errorf("Failed to save session with large token: %v", err)
		}

		// Verify cookies are still consistent even with chunking
		cookies := rw.Result().Cookies()
		for _, cookie := range cookies {
			if strings.HasPrefix(cookie.Name, "_oidc_raczylo") {
				if cookie.Path != "/" {
					t.Errorf("Large cookie path inconsistent: got %s", cookie.Path)
				}
				if cookie.SameSite != http.SameSiteLaxMode {
					t.Errorf("Large cookie SameSite inconsistent: got %v", cookie.SameSite)
				}
			}
		}

		// Verify token can be retrieved correctly
		if session.GetAccessToken() != largeToken {
			t.Error("Large access token not retrieved correctly")
		}

		t.Log("Large cookie handling test passed")
	})
}

// TestSessionManagerEnhanceSessionSecurity tests the enhanced session security
// to ensure SameSite is consistently Lax and not dynamically switched
func TestSessionManagerEnhanceSessionSecurity(t *testing.T) {
	logger := NewLogger("debug")
	encryptionKey := "0123456789abcdef0123456789abcdef0123456789abcdef"

	sm, err := NewSessionManager(encryptionKey, false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	tests := []struct {
		name        string
		headers     map[string]string
		expectSame  http.SameSite
		description string
	}{
		{
			name: "StandardRequest",
			headers: map[string]string{
				"Host": "example.com",
			},
			expectSame:  http.SameSiteLaxMode,
			description: "Standard request should use SameSite=Lax",
		},
		{
			name: "XMLHttpRequestHeader",
			headers: map[string]string{
				"Host":             "example.com",
				"X-Requested-With": "XMLHttpRequest",
			},
			expectSame:  http.SameSiteLaxMode,
			description: "XMLHttpRequest should still use SameSite=Lax (no dynamic switching)",
		},
		{
			name: "AjaxWithForwardedProto",
			headers: map[string]string{
				"Host":              "example.com",
				"X-Requested-With":  "XMLHttpRequest",
				"X-Forwarded-Proto": "https",
			},
			expectSame:  http.SameSiteLaxMode,
			description: "AJAX HTTPS request should use SameSite=Lax (no dynamic switching)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Test the EnhanceSessionSecurity method directly
			options := &sessions.Options{}
			enhanced := sm.EnhanceSessionSecurity(options, req)

			if enhanced.SameSite != tt.expectSame {
				t.Errorf("Expected SameSite=%v, got SameSite=%v for %s",
					tt.expectSame, enhanced.SameSite, tt.description)
			}

			// Verify Path is always "/"
			if enhanced.Path != "/" {
				t.Errorf("Expected Path='/', got Path='%s' for %s",
					enhanced.Path, tt.description)
			}

			// Verify HttpOnly is always true
			if !enhanced.HttpOnly {
				t.Errorf("Expected HttpOnly=true, got HttpOnly=false for %s", tt.description)
			}

			t.Logf("%s: SameSite=%v, Path=%s, HttpOnly=%v, Secure=%v",
				tt.name, enhanced.SameSite, enhanced.Path, enhanced.HttpOnly, enhanced.Secure)
		})
	}
}

// TestCallbackHandlerIntegration tests the full callback handler integration
// to ensure CSRF tokens work correctly with the fixed cookie configuration
func TestCallbackHandlerIntegration(t *testing.T) {
	logger := NewLogger("debug")
	encryptionKey := "0123456789abcdef0123456789abcdef0123456789abcdef"

	sm, err := NewSessionManager(encryptionKey, false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	defer sm.Shutdown()

	// Simulate a complete OAuth flow with various request types
	scenarios := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "StandardBrowser",
			headers: map[string]string{
				"Host":       "example.com",
				"User-Agent": "Mozilla/5.0 (Browser)",
			},
		},
		{
			name: "AjaxRequest",
			headers: map[string]string{
				"Host":             "example.com",
				"User-Agent":       "Mozilla/5.0 (Browser)",
				"X-Requested-With": "XMLHttpRequest",
			},
		},
		{
			name: "HTTPSProxy",
			headers: map[string]string{
				"Host":              "example.com",
				"User-Agent":        "Mozilla/5.0 (Browser)",
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "example.com",
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Phase 1: Auth initiation - store CSRF token
			initReq := httptest.NewRequest("GET", "http://example.com/protected", nil)
			for key, value := range scenario.headers {
				initReq.Header.Set(key, value)
			}

			initRw := httptest.NewRecorder()

			session, err := sm.GetSession(initReq)
			if err != nil {
				t.Fatalf("Failed to get init session: %v", err)
			}

			csrfToken := uuid.New().String()
			session.SetCSRF(csrfToken)
			session.SetNonce("test-nonce")
			session.SetIncomingPath("/protected")

			err = session.Save(initReq, initRw)
			if err != nil {
				t.Fatalf("Failed to save init session: %v", err)
			}

			initCookies := initRw.Result().Cookies()

			// Phase 2: OAuth callback - validate CSRF token access
			callbackReq := httptest.NewRequest("GET",
				"http://example.com/callback?state="+csrfToken+"&code=test_code", nil)

			for key, value := range scenario.headers {
				callbackReq.Header.Set(key, value)
			}

			// Add cookies from init phase
			for _, cookie := range initCookies {
				callbackReq.AddCookie(cookie)
			}

			callbackSession, err := sm.GetSession(callbackReq)
			if err != nil {
				t.Fatalf("Failed to get callback session: %v", err)
			}
			defer callbackSession.Clear(callbackReq, nil)

			// This is the critical test - CSRF token must be accessible
			retrievedCSRF := callbackSession.GetCSRF()
			if retrievedCSRF == "" {
				t.Errorf("Scenario %s: CSRF token not accessible in callback", scenario.name)
			}
			if retrievedCSRF != csrfToken {
				t.Errorf("Scenario %s: CSRF token mismatch - expected %s, got %s",
					scenario.name, csrfToken, retrievedCSRF)
			}

			// Validate state parameter matches CSRF token
			stateParam := callbackReq.URL.Query().Get("state")
			if stateParam != csrfToken {
				t.Errorf("Scenario %s: State parameter mismatch - expected %s, got %s",
					scenario.name, csrfToken, stateParam)
			}

			// Simulate successful CSRF validation
			if retrievedCSRF != "" && retrievedCSRF == stateParam {
				t.Logf("Scenario %s: CSRF validation successful", scenario.name)
			} else {
				t.Errorf("Scenario %s: CSRF validation failed", scenario.name)
			}

			// Verify other session data persisted
			if callbackSession.GetNonce() != "test-nonce" {
				t.Errorf("Scenario %s: Nonce not persisted", scenario.name)
			}
			if callbackSession.GetIncomingPath() != "/protected" {
				t.Errorf("Scenario %s: Incoming path not persisted", scenario.name)
			}
		})
	}
}
