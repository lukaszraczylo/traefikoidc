package traefikoidc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

// TestTokenTypeDistinction tests that AccessToken and IdToken are correctly distinguished in templates
func TestTokenTypeDistinction(t *testing.T) {
	// Define test data where AccessToken and IdToken are deliberately different
	type templateData struct {
		AccessToken  string
		IdToken      string
		RefreshToken string
		Claims       map[string]interface{}
	}

	testData := templateData{
		AccessToken:  "test-access-token-abc123",
		IdToken:      "test-id-token-xyz789",
		RefreshToken: "test-refresh-token",
		Claims: map[string]interface{}{
			"sub":   "test-subject",
			"email": "user@example.com",
		},
	}

	// Test cases
	tests := []struct {
		name          string
		templateText  string
		expectedValue string
	}{
		{
			name:          "Access Token Only",
			templateText:  "Bearer {{.AccessToken}}",
			expectedValue: "Bearer test-access-token-abc123",
		},
		{
			name:          "ID Token Only",
			templateText:  "ID: {{.IdToken}}",
			expectedValue: "ID: test-id-token-xyz789",
		},
		{
			name:          "Both Tokens",
			templateText:  "Access: {{.AccessToken}} ID: {{.IdToken}}",
			expectedValue: "Access: test-access-token-abc123 ID: test-id-token-xyz789",
		},
		{
			name:          "Both Tokens in Authorization Format",
			templateText:  "Bearer {{.AccessToken}} and Bearer {{.IdToken}}",
			expectedValue: "Bearer test-access-token-abc123 and Bearer test-id-token-xyz789",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := template.New("test").Parse(tc.templateText)
			if err != nil {
				t.Fatalf("Failed to parse template: %v", err)
			}

			var buf bytes.Buffer
			err = tmpl.Execute(&buf, testData)
			if err != nil {
				t.Fatalf("Failed to execute template: %v", err)
			}

			result := buf.String()
			if result != tc.expectedValue {
				t.Errorf("Expected template output %q, got %q", tc.expectedValue, result)
			}
		})
	}
}

// TestTokenTypeIntegration tests the integration of ID and access tokens with the middleware
func TestTokenTypeIntegration(t *testing.T) {
	// Create a TestSuite to use its helper methods and fields
	ts := &TestSuite{t: t}
	ts.Setup()

	// Create different tokens for ID and access tokens
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":        "https://test-issuer.com",
		"aud":        "test-client-id",
		"exp":        float64(3000000000),
		"iat":        float64(1000000000),
		"nbf":        float64(1000000000),
		"sub":        "test-subject",
		"nonce":      "test-nonce",
		"jti":        generateRandomString(16),
		"token_type": "id_token",
		"email":      "user@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create test ID JWT: %v", err)
	}

	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":        "https://test-issuer.com",
		"aud":        "test-client-id",
		"exp":        float64(3000000000),
		"iat":        float64(1000000000),
		"nbf":        float64(1000000000),
		"sub":        "test-subject",
		"jti":        generateRandomString(16),
		"token_type": "access_token",
		"scope":      "openid profile email",
		"email":      "user@example.com", // Add email to access token so it's available in claims
	})
	if err != nil {
		t.Fatalf("Failed to create test access JWT: %v", err)
	}

	// Define test headers that use both token types
	headers := []TemplatedHeader{
		{Name: "X-ID-Token", Value: "{{.IdToken}}"},
		{Name: "X-Access-Token", Value: "{{.AccessToken}}"},
		{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
		{Name: "X-Email-From-Claims", Value: "{{.Claims.email}}"},
	}

	// Store intercepted headers for verification
	interceptedHeaders := make(map[string]string)

	// Create a test next handler that captures the headers
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture headers for verification
		for _, header := range headers {
			if value := r.Header.Get(header.Name); value != "" {
				interceptedHeaders[header.Name] = value
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create the TraefikOidc instance
	tOidc := &TraefikOidc{
		next:               nextHandler,
		name:               "test",
		redirURLPath:       "/callback",
		logoutURLPath:      "/callback/logout",
		issuerURL:          "https://test-issuer.com",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		jwkCache:           ts.mockJWKCache,
		jwksURL:            "https://test-jwks-url.com",
		tokenBlacklist:     NewCache(),
		tokenCache:         NewTokenCache(),
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		logger:             NewLogger("debug"),
		allowedUserDomains: map[string]struct{}{"example.com": {}},
		excludedURLs:       map[string]struct{}{"/favicon": {}},
		httpClient:         &http.Client{},
		initComplete:       make(chan struct{}),
		sessionManager:     ts.sessionManager,
		extractClaimsFunc:  extractClaims,
		headerTemplates:    make(map[string]*template.Template),
	}

	// Initialize and parse header templates
	for _, header := range headers {
		tmpl, err := template.New(header.Name).Parse(header.Value)
		if err != nil {
			t.Fatalf("Failed to parse header template for %s: %v", header.Name, err)
		}
		tOidc.headerTemplates[header.Name] = tmpl
	}

	// Close the initComplete channel to bypass the waiting
	close(tOidc.initComplete)

	// Create a test request
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	rr := httptest.NewRecorder()

	// Create a session
	session, err := tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Setup the session with authentication data
	session.SetAuthenticated(true)
	session.SetEmail("user@example.com")
	session.SetIDToken(idToken)         // Set the ID token
	session.SetAccessToken(accessToken) // Set the access token
	session.SetRefreshToken("test-refresh-token")

	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add session cookies to the request
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Reset the response recorder for the main test
	rr = httptest.NewRecorder()

	// Process the request
	tOidc.ServeHTTP(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, rr.Code)
	}

	// Verify headers were set correctly
	expectedHeaders := map[string]string{
		"X-ID-Token":          idToken,
		"X-Access-Token":      accessToken,
		"Authorization":       "Bearer " + accessToken,
		"X-Email-From-Claims": "user@example.com",
	}

	for name, expectedValue := range expectedHeaders {
		if value, exists := interceptedHeaders[name]; !exists {
			t.Errorf("Expected header %s was not set", name)
		} else if value != expectedValue {
			t.Errorf("Header %s expected value %q, got %q", name, expectedValue, value)
		}
	}
}

// TestSessionIDTokenAccessToken tests that the SessionData correctly stores and retrieves
// both ID tokens and access tokens separately
func TestSessionIDTokenAccessToken(t *testing.T) {
	// Create a logger for the session manager
	logger := NewLogger("debug")

	// Create a session manager
	sessionManager, err := NewSessionManager("test-session-encryption-key-at-least-32-bytes", false, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	// Get a session
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Set test tokens
	idToken := "test-id-token-123"
	accessToken := "test-access-token-456"
	refreshToken := "test-refresh-token-789"

	// Store tokens in session
	session.SetIDToken(idToken)
	session.SetAccessToken(accessToken)
	session.SetRefreshToken(refreshToken)

	// Save the session
	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Get cookies from response
	cookies := rr.Result().Cookies()

	// Create a new request with those cookies
	req2 := httptest.NewRequest("GET", "/test", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	// Get the session again
	session2, err := sessionManager.GetSession(req2)
	if err != nil {
		t.Fatalf("Failed to get session from request with cookies: %v", err)
	}

	// Verify that the tokens were correctly stored and retrieved
	retrievedIDToken := session2.GetIDToken()
	retrievedAccessToken := session2.GetAccessToken()
	retrievedRefreshToken := session2.GetRefreshToken()

	if retrievedIDToken != idToken {
		t.Errorf("ID token mismatch: expected %q, got %q", idToken, retrievedIDToken)
	}

	if retrievedAccessToken != accessToken {
		t.Errorf("Access token mismatch: expected %q, got %q", accessToken, retrievedAccessToken)
	}

	if retrievedRefreshToken != refreshToken {
		t.Errorf("Refresh token mismatch: expected %q, got %q", refreshToken, retrievedRefreshToken)
	}

	// Verify that the tokens are distinct
	if retrievedIDToken == retrievedAccessToken {
		t.Errorf("ID token and Access token should be different, but both are %q", retrievedIDToken)
	}
}
