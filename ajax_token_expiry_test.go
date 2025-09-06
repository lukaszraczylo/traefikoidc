package traefikoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAjaxRequestsWith6HourExpiredTokens tests the fix for the production issue:
// After 6 hours of browser inactivity, AJAX requests should get 401 responses
// instead of redirects that lead to /unknown-session errors
func TestAjaxRequestsWith6HourExpiredTokens(t *testing.T) {
	t.Log("Testing AJAX requests with 6-hour expired tokens - verifying production fix")

	// Create test session manager
	sm, err := NewSessionManager("test_key_for_encryption_12345678", false, "", NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Set up middleware
	tOidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Request successful"))
		}),
		name:               "test-ajax-expiry",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		sessionManager:     sm,
		extractClaimsFunc:  extractClaims,
		logger:             NewLogger("debug"),
		redirURLPath:       "/oauth/callback",
		issuerURL:          "https://test-issuer.com",
		initComplete:       make(chan struct{}),
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		tokenHTTPClient:    &http.Client{Timeout: 10 * time.Second},
		tokenCache:         NewTokenCache(),
		tokenBlacklist:     NewCache(),
		refreshGracePeriod: 1 * time.Minute,
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc
	tOidc.tokenExchanger = tOidc

	// Close the initComplete channel to bypass the waiting
	close(tOidc.initComplete)

	// Test different AJAX request types
	testCases := []struct {
		name        string
		headers     map[string]string
		expectCode  int
		expectJSON  bool
		description string
	}{
		{
			name: "jQuery AJAX with expired tokens",
			headers: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
				"Accept":           "application/json",
			},
			expectCode:  http.StatusUnauthorized,
			expectJSON:  true,
			description: "Should return 401 for jQuery AJAX requests",
		},
		{
			name: "Fetch API with expired tokens",
			headers: map[string]string{
				"Sec-Fetch-Mode": "cors",
				"Accept":         "application/json",
			},
			expectCode:  http.StatusUnauthorized,
			expectJSON:  true,
			description: "Should return 401 for Fetch API requests",
		},
		{
			name: "JSON API request with expired tokens",
			headers: map[string]string{
				"Accept":       "application/json",
				"Content-Type": "application/json",
			},
			expectCode:  http.StatusUnauthorized,
			expectJSON:  true,
			description: "Should return 401 for JSON API requests",
		},
		{
			name: "Browser navigation with expired tokens",
			headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml",
			},
			expectCode:  http.StatusFound, // 302
			expectJSON:  false,
			description: "Should redirect for normal browser navigation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)

			// Create request
			req := httptest.NewRequest("GET", "/api/data", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "example.com")

			// Add test-specific headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			// Create session with 6+ hour old tokens
			session, err := tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Simulate authenticated session with expired tokens (6 hours old)
			session.SetAuthenticated(true)
			session.SetEmail("user@example.com")

			// Set refresh token with old timestamp (7 hours ago)
			session.SetRefreshToken("refresh_token_7_hours_old")
			// Manually set the issued_at to 7 hours ago
			session.refreshSession.Values["issued_at"] = time.Now().Add(-7 * time.Hour).Unix()

			// Don't set access/ID tokens (simulating they're expired/missing)

			// Save session
			rr := httptest.NewRecorder()
			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Apply cookies from session save to request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Make request
			rr = httptest.NewRecorder()
			tOidc.ServeHTTP(rr, req)

			// Verify response
			if rr.Code != tc.expectCode {
				t.Errorf("Expected status code %d, got %d", tc.expectCode, rr.Code)
				t.Logf("Response body: %s", rr.Body.String())
			}

			// Check if JSON response for AJAX requests
			if tc.expectJSON {
				var jsonResp map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &jsonResp); err != nil {
					t.Errorf("Expected JSON response for AJAX request, got: %s", rr.Body.String())
				} else {
					if errorMsg, ok := jsonResp["error"].(string); ok {
						t.Logf("JSON error response: %s", errorMsg)
						// The error message is "Unauthorized" from sendErrorResponse
						if errorMsg != "Unauthorized" && errorMsg != "Session expired" && errorMsg != "Authentication required" {
							t.Errorf("Unexpected error message: %s", errorMsg)
						}
					}
				}
			}

			// Check for problematic redirects
			if rr.Code == http.StatusFound || rr.Code == http.StatusTemporaryRedirect {
				location := rr.Header().Get("Location")
				if location == "" {
					t.Error("Redirect response missing Location header")
				} else {
					t.Logf("Redirect location: %s", location)
					// The fix should prevent /unknown-session redirects
					if tc.expectJSON {
						t.Error("AJAX request should not be redirected")
					}
				}
			}
		})
	}

	t.Log("✅ AJAX token expiry fix verified - no more /unknown-session errors for AJAX requests")
}

// TestRefreshTokenExpiryDetection tests the refresh token expiry detection logic
func TestRefreshTokenExpiryDetection(t *testing.T) {
	tOidc := &TraefikOidc{
		logger: NewLogger("debug"),
	}

	// Create test session manager
	sm, err := NewSessionManager("test_key_for_encryption_12345678", false, "", NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	req := httptest.NewRequest("GET", "/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	testCases := []struct {
		name            string
		setupSession    func()
		expectedExpired bool
	}{
		{
			name: "Fresh refresh token",
			setupSession: func() {
				session.SetRefreshToken("fresh_token")
				session.refreshSession.Values["issued_at"] = time.Now().Unix()
			},
			expectedExpired: false,
		},
		{
			name: "5 hour old refresh token",
			setupSession: func() {
				session.SetRefreshToken("5_hour_old_token")
				session.refreshSession.Values["issued_at"] = time.Now().Add(-5 * time.Hour).Unix()
			},
			expectedExpired: false,
		},
		{
			name: "6.5 hour old refresh token",
			setupSession: func() {
				session.SetRefreshToken("expired_token")
				session.refreshSession.Values["issued_at"] = time.Now().Add(-6*time.Hour - 30*time.Minute).Unix()
			},
			expectedExpired: true,
		},
		{
			name: "24 hour old refresh token",
			setupSession: func() {
				session.SetRefreshToken("very_old_token")
				session.refreshSession.Values["issued_at"] = time.Now().Add(-24 * time.Hour).Unix()
			},
			expectedExpired: true,
		},
		{
			name: "No timestamp available",
			setupSession: func() {
				session.SetRefreshToken("unknown_age_token")
				delete(session.refreshSession.Values, "issued_at")
			},
			expectedExpired: false, // Conservative: try refresh if we don't know age
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupSession()

			isExpired := tOidc.isRefreshTokenExpired(session)

			if isExpired != tc.expectedExpired {
				t.Errorf("Expected refresh token expired=%v, got %v", tc.expectedExpired, isExpired)
			}
		})
	}
}
