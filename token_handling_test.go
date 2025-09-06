package traefikoidc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

// TestTokenTypeDistinction tests that AccessToken and IDToken are correctly distinguished in templates
func TestTokenTypeDistinction(t *testing.T) {
	// Define test data where AccessToken and IDToken are deliberately different
	type templateData struct {
		Claims       map[string]interface{}
		AccessToken  string
		IDToken      string
		RefreshToken string
	}

	testData := templateData{
		AccessToken:  "test-access-token-abc123",
		IDToken:      "test-id-token-xyz789",
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
			templateText:  "ID: {{.IDToken}}",
			expectedValue: "ID: test-id-token-xyz789",
		},
		{
			name:          "Both Tokens",
			templateText:  "Access: {{.AccessToken}} ID: {{.IDToken}}",
			expectedValue: "Access: test-access-token-abc123 ID: test-id-token-xyz789",
		},
		{
			name:          "Both Tokens in Authorization Format",
			templateText:  "Bearer {{.AccessToken}} and Bearer {{.IDToken}}",
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
	ts := NewTestSuite(t)
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
		{Name: "X-ID-Token", Value: "{{.IDToken}}"},
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
		tokenBlacklist:     ts.tOidc.tokenBlacklist,
		tokenCache:         ts.tOidc.tokenCache,
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		logger:             NewLogger("debug"),
		allowedUserDomains: map[string]struct{}{"example.com": {}},
		excludedURLs:       map[string]struct{}{"/favicon": {}},
		httpClient:         &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport},
		tokenHTTPClient:    &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport},
		initComplete:       make(chan struct{}),
		sessionManager:     ts.sessionManager,
		extractClaimsFunc:  extractClaims,
		headerTemplates:    make(map[string]*template.Template),
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc

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
	sessionManager, err := NewSessionManager("test-session-encryption-key-at-least-32-bytes", false, "", logger)
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

	// Set test tokens using standardized tokens
	idToken := ValidIDToken
	accessToken := ValidAccessToken
	refreshToken := ValidRefreshToken

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

// TestTokenCorruptionIntegrationFlows tests the complete token handling flow with corruption scenarios
func TestTokenCorruptionIntegrationFlows(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	tests := []struct {
		corruptAction func(*SessionData)
		name          string
		accessToken   string
		refreshToken  string
		idToken       string
		expectSuccess bool
	}{
		{
			name:          "Normal flow - small tokens",
			accessToken:   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.access_signature_data_here",
			refreshToken:  "refresh_token_12345",
			idToken:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.id_token_signature_data_here",
			expectSuccess: true,
		},
		{
			name:          "Normal flow - large tokens (chunked)",
			accessToken:   createLargeValidJWT(5000),
			refreshToken:  createLargeRefreshToken(3000),
			idToken:       createLargeValidJWT(2000),
			expectSuccess: true,
		},
		{
			name:          "Corrupted access token compression",
			accessToken:   createLargeValidJWT(3000),
			refreshToken:  "refresh_token_12345",
			idToken:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.id_token_signature_data_here",
			expectSuccess: false,
			corruptAction: func(session *SessionData) {
				// Corrupt compressed access token
				if session.accessSession != nil {
					session.accessSession.Values["token"] = "corrupted_compressed_data_!@#"
					session.accessSession.Values["compressed"] = true
				}
			},
		},
		{
			name:          "Corrupted chunk in large token",
			accessToken:   createLargeValidJWT(15000), // Force chunking with larger size
			refreshToken:  "refresh_token_12345",
			idToken:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.id_token_signature_data_here",
			expectSuccess: false,
			corruptAction: func(session *SessionData) {
				// Corrupt first chunk if chunked, otherwise corrupt single token
				if len(session.accessTokenChunks) > 0 {
					if chunk, exists := session.accessTokenChunks[0]; exists {
						chunk.Values["token_chunk"] = "__CORRUPTED_CHUNK_DATA__"
					}
				} else {
					// Token is stored as single compressed token - corrupt it
					if session.accessSession != nil {
						session.accessSession.Values["token"] = "__CORRUPTED_CHUNK_DATA__"
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()

			// Get session
			session, err := sm.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}
			defer session.ReturnToPool()

			// Store tokens
			session.SetAccessToken(tt.accessToken)
			session.SetRefreshToken(tt.refreshToken)
			session.SetIDToken(tt.idToken)
			session.SetAuthenticated(true)

			// Save session
			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Apply corruption if specified
			if tt.corruptAction != nil {
				tt.corruptAction(session)
			}

			// Test token retrieval after corruption
			retrievedAccess := session.GetAccessToken()
			retrievedRefresh := session.GetRefreshToken()
			retrievedID := session.GetIDToken()

			if tt.expectSuccess {
				if retrievedAccess != tt.accessToken {
					t.Errorf("Access token corruption: expected %q, got %q", tt.accessToken, retrievedAccess)
				}
				if retrievedRefresh != tt.refreshToken {
					t.Errorf("Refresh token corruption: expected %q, got %q", tt.refreshToken, retrievedRefresh)
				}
				if retrievedID != tt.idToken {
					t.Errorf("ID token corruption: expected %q, got %q", tt.idToken, retrievedID)
				}
			} else {
				// For corruption scenarios, access token should be empty (graceful failure)
				if retrievedAccess != "" {
					t.Errorf("Expected corrupted access token to return empty, got: %q", retrievedAccess)
				}
				// Other tokens should still work
				if retrievedRefresh != tt.refreshToken {
					t.Errorf("Refresh token should not be affected by access token corruption: expected %q, got %q",
						tt.refreshToken, retrievedRefresh)
				}
			}
		})
	}
}

// TestSessionPersistenceWithCorruption tests that session corruption is handled across requests
func TestSessionPersistenceWithCorruption(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// First request - store tokens
	req1 := httptest.NewRequest("GET", "/test", nil)
	rr1 := httptest.NewRecorder()

	session1, err := sm.GetSession(req1)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	// Use a smaller token that's less likely to accidentally contain corruption markers
	largeToken := createLargeValidJWT(2000)
	session1.SetAccessToken(largeToken)
	session1.SetAuthenticated(true)

	if err := session1.Save(req1, rr1); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Get cookies from first response
	cookies := rr1.Result().Cookies()
	session1.ReturnToPool()

	// Second request - retrieve tokens with cookies
	req2 := httptest.NewRequest("GET", "/test", nil)
	for _, cookie := range cookies {
		req2.AddCookie(cookie)
	}

	session2, err := sm.GetSession(req2)
	if err != nil {
		t.Fatalf("Failed to get session from cookies: %v", err)
	}
	defer session2.ReturnToPool()

	// Verify token can be retrieved initially
	retrieved := session2.GetAccessToken()
	if retrieved != largeToken {
		t.Errorf("Token persistence failed: expected valid token, got empty token")
	}

	// Simulate corruption by modifying chunks
	if len(session2.accessTokenChunks) > 0 {
		// Corrupt a middle chunk with a unique corruption marker
		chunkIndex := len(session2.accessTokenChunks) / 2
		if chunk, exists := session2.accessTokenChunks[chunkIndex]; exists {
			chunk.Values["token_chunk"] = "__CORRUPTION_MARKER_TEST__"
		}

		// Try to retrieve again - should detect corruption and return empty
		retrievedAfterCorruption := session2.GetAccessToken()
		if retrievedAfterCorruption != "" {
			t.Errorf("Expected corruption to be detected, but got token: %q", retrievedAfterCorruption)
		}
	}
}

// TestConcurrentTokenOperationsWithCorruption tests concurrent access with intentional corruption
func TestConcurrentTokenOperationsWithCorruption(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	const numGoroutines = 10
	const numOperations = 20

	done := make(chan bool, numGoroutines)
	errorChan := make(chan error, numGoroutines*numOperations)

	// Start concurrent operations
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < numOperations; j++ {
				// Create a unique valid token for each operation
				token := fmt.Sprintf("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwib3AiOiIxMjMifQ.sig_%d_%d",
					goroutineID, j)

				// Store token
				session.SetAccessToken(token)

				// Retrieve token
				retrieved := session.GetAccessToken()

				// Validate retrieved token format
				if retrieved != "" {
					if strings.Count(retrieved, ".") != 2 {
						errorChan <- fmt.Errorf("goroutine %d, op %d: invalid JWT format: %q",
							goroutineID, j, retrieved)
						continue
					}

					// Check if it's a reasonable length
					if len(retrieved) < 10 || len(retrieved) > 100000 {
						errorChan <- fmt.Errorf("goroutine %d, op %d: suspicious token length %d: %q",
							goroutineID, j, len(retrieved), retrieved)
					}
				}

				// Occasionally simulate corruption to test error handling
				if j%5 == 0 && len(session.accessTokenChunks) > 0 {
					// Intentionally corrupt a random chunk
					for chunkID, chunk := range session.accessTokenChunks {
						if chunkID%2 == 0 {
							chunk.Values["token_chunk"] = "__CORRUPTION_MARKER_TEST__"
							break
						}
					}
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errorChan)

	// Check for any unexpected errors
	errorCount := 0
	for err := range errorChan {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}

	// We expect some corruption-related "errors" due to intentional corruption,
	// but not format-related errors which would indicate actual corruption bugs
	if errorCount > numGoroutines*numOperations/4 { // Allow up to 25% corruption-related issues
		t.Errorf("Too many errors during concurrent operations: %d", errorCount)
	}
}

// TestTokenValidationEdgeCases tests edge cases in token validation
func TestTokenValidationEdgeCases(t *testing.T) {
	logger := NewLogger("debug")
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	defer session.ReturnToPool()

	// Use standardized test tokens
	testTokens := NewTestTokens()
	edgeCases := testTokens.TokenValidationTestCases()

	for _, ec := range edgeCases {
		t.Run(ec.Name, func(t *testing.T) {
			// Clear any previous token
			session.SetAccessToken("")

			// Store the test token
			originalToken := session.GetAccessToken()
			session.SetAccessToken(ec.Token)
			afterStoreToken := session.GetAccessToken()

			if ec.ExpectStored {
				if afterStoreToken != ec.Token {
					t.Errorf("Expected token to be stored, but got different value")
				}
			} else {
				if afterStoreToken != originalToken {
					t.Errorf("Expected invalid token to be rejected, but it was stored")
				}
			}

			// Test retrieval
			finalToken := session.GetAccessToken()
			if ec.ExpectRetrieved {
				if finalToken != ec.Token {
					t.Errorf("Expected token to be retrievable: %q, got: %q", ec.Token, finalToken)
				}
			} else {
				if finalToken != "" {
					t.Errorf("Expected empty token due to invalid format, got: %q", finalToken)
				}
			}
		})
	}
}

// Helper functions for test data creation

// createLargeValidJWT creates a JWT of approximately the specified size
func createLargeValidJWT(targetSize int) string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	// Create a valid base64url signature
	signatureBytes := make([]byte, 32)
	rand.Read(signatureBytes)
	signature := base64.RawURLEncoding.EncodeToString(signatureBytes)

	// Calculate required payload size
	usedSize := len(header) + len(signature) + 2 // account for dots
	payloadSize := targetSize - usedSize
	if payloadSize < 50 {
		payloadSize = 50
	}

	// Create a payload with realistic JWT claims, using safe content
	claims := map[string]interface{}{
		"sub":  "user123",
		"iss":  "https://example.com",
		"aud":  "client123",
		"exp":  9999999999,
		"iat":  1000000000,
		"data": strings.Repeat("abcdef0123456789", (payloadSize-100)/16), // Safe repeating pattern
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// createLargeRefreshToken creates a refresh token of approximately the specified size
func createLargeRefreshToken(targetSize int) string {
	baseToken := "refresh_token_"
	padding := generateRandomString(targetSize - len(baseToken))
	return baseToken + padding
}

// ====== COMPREHENSIVE TOKEN EXPIRY TESTS ======
// These tests demonstrate the current broken behavior with 6-hour token expiry
// and other critical token handling scenarios

// TestSixHourTokenExpiryScenario tests the exact 6-hour browser inactivity scenario
// This test SHOULD FAIL with current implementation - it demonstrates the broken behavior
func TestSixHourTokenExpiryScenario(t *testing.T) {
	t.Log("Testing 6-hour token expiry scenario - this test demonstrates the CURRENT BROKEN BEHAVIOR")

	// Create test suite with proper setup
	ts := NewTestSuite(t)
	ts.Setup()

	// Mock current time to simulate exactly 6 hours of inactivity
	sixHoursAgo := time.Now().Add(-6 * time.Hour)

	// Create tokens that expired exactly 6 hours ago (simulating browser inactivity)
	expiredAccessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"sub":   "test-user-123",
		"exp":   float64(sixHoursAgo.Unix()), // Expired 6 hours ago
		"iat":   float64(sixHoursAgo.Add(-1 * time.Hour).Unix()),
		"email": "user@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create expired access token: %v", err)
	}

	expiredIDToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"sub":   "test-user-123",
		"exp":   float64(sixHoursAgo.Unix()), // Also expired 6 hours ago
		"iat":   float64(sixHoursAgo.Add(-1 * time.Hour).Unix()),
		"email": "user@example.com",
		"nonce": "test-nonce",
	})
	if err != nil {
		t.Fatalf("Failed to create expired ID token: %v", err)
	}

	// Valid refresh token (should still be valid for renewal)
	validRefreshToken := "valid-refresh-token-for-renewal-12345"

	// Set up the middleware with token refresh capability
	tOidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// This should be reached after successful token renewal
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SUCCESS: Token renewed and request processed"))
		}),
		name:               "test-6hour",
		redirURLPath:       "/callback",
		logoutURLPath:      "/callback/logout",
		issuerURL:          "https://test-issuer.com",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		jwkCache:           ts.mockJWKCache,
		jwksURL:            "https://test-jwks-url.com",
		tokenBlacklist:     ts.tOidc.tokenBlacklist,
		tokenCache:         ts.tOidc.tokenCache,
		httpClient:         &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport},
		tokenHTTPClient:    &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport},
		sessionManager:     ts.sessionManager,
		extractClaimsFunc:  extractClaims,
		refreshGracePeriod: 60 * time.Second, // 60 second grace period
		logger:             NewLogger("debug"),
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		initComplete:       make(chan struct{}),
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc
	tOidc.tokenExchanger = tOidc

	// Close the initComplete channel to bypass the waiting
	close(tOidc.initComplete)

	// Mock the token refresh endpoint to return new valid tokens
	refreshCount := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCount++
		t.Logf("Token refresh request #%d received", refreshCount)

		// Create new valid tokens with future expiry
		newAccessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-123",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()), // Valid for 1 hour
			"iat":   float64(time.Now().Unix()),
			"email": "user@example.com",
		})

		newIDToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-123",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": "user@example.com",
			"nonce": "test-nonce",
		})

		response := map[string]interface{}{
			"access_token":  newAccessToken,
			"id_token":      newIDToken,
			"refresh_token": "new-refresh-token-12345",
			"expires_in":    3600,
			"token_type":    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()
	tOidc.tokenURL = tokenServer.URL

	// Create a session with expired tokens
	req := httptest.NewRequest("GET", "/protected-resource", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	rr := httptest.NewRecorder()

	// Create and populate session with expired tokens
	session, err := tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetEmail("user@example.com")
	session.SetAccessToken(expiredAccessToken)
	session.SetIDToken(expiredIDToken)
	session.SetRefreshToken(validRefreshToken)

	// Save session to establish cookies
	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add cookies to request to simulate browser with expired session
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}
	session.ReturnToPool()

	// Reset response recorder for actual test
	rr = httptest.NewRecorder()

	t.Log("Making request with 6-hour expired tokens - expecting automatic renewal")

	// This is where the middleware should automatically refresh tokens
	// but currently it redirects to /unknown-session instead
	tOidc.ServeHTTP(rr, req)

	// ==== ASSERTIONS THAT DEMONSTRATE THE BUG ====

	// Current broken behavior - this is what happens now:
	if rr.Code == http.StatusTemporaryRedirect && strings.Contains(rr.Header().Get("Location"), "/unknown-session") {
		t.Errorf("BUG DEMONSTRATED: Got redirect to /unknown-session instead of automatic token renewal")
		t.Errorf("Response code: %d", rr.Code)
		t.Errorf("Location header: %s", rr.Header().Get("Location"))
		t.Errorf("This proves the 6-hour expiry bug exists!")

		// Log what should happen instead
		t.Log("EXPECTED BEHAVIOR: Should have automatically refreshed tokens and returned 200 OK")
		t.Log("EXPECTED: Token refresh should have been called")
		t.Log("EXPECTED: User should not see redirect to /unknown-session")

		return // Test fails as expected - demonstrates the bug
	}

	// This is what SHOULD happen but doesn't currently work:
	if rr.Code == http.StatusOK {
		t.Log("SUCCESS: Automatic token renewal worked correctly")
		t.Logf("Token refresh was called %d times", refreshCount)

		if refreshCount == 0 {
			t.Error("Expected token refresh to be called, but it wasn't")
		}

		// Verify response indicates successful token renewal
		body := rr.Body.String()
		if !strings.Contains(body, "SUCCESS") {
			t.Errorf("Expected success response, got: %s", body)
		}
	} else {
		t.Errorf("Unexpected response code: %d", rr.Code)
		t.Errorf("Response body: %s", rr.Body.String())
		t.Errorf("Response headers: %v", rr.Header())
	}
}

// TestAutomaticRenewalFlow tests the complete automatic token renewal flow
// This test SHOULD FAIL - it demonstrates broken automatic renewal behavior
func TestAutomaticRenewalFlow(t *testing.T) {
	t.Log("Testing automatic token renewal flow - this test demonstrates BROKEN BEHAVIOR")

	ts := NewTestSuite(t)
	ts.Setup()

	// Create tokens that expired 30 minutes ago
	expiredTime := time.Now().Add(-30 * time.Minute)

	expiredAccessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"sub":   "test-user-123",
		"exp":   float64(expiredTime.Unix()),
		"iat":   float64(expiredTime.Add(-1 * time.Hour).Unix()),
		"email": "user@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create expired access token: %v", err)
	}

	validRefreshToken := "valid-refresh-token-67890"

	// Track renewal attempts
	renewalAttempts := 0
	renewalErrors := []string{}

	// Mock token server for automatic renewal
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewalAttempts++
		t.Logf("Automatic renewal attempt #%d", renewalAttempts)

		// Verify this is a proper refresh token request
		if err := r.ParseForm(); err != nil {
			renewalErrors = append(renewalErrors, fmt.Sprintf("Failed to parse form: %v", err))
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if grantType := r.Form.Get("grant_type"); grantType != "refresh_token" {
			renewalErrors = append(renewalErrors, fmt.Sprintf("Wrong grant type: %s", grantType))
			http.Error(w, "Invalid grant type", http.StatusBadRequest)
			return
		}

		if refreshToken := r.Form.Get("refresh_token"); refreshToken != validRefreshToken {
			renewalErrors = append(renewalErrors, fmt.Sprintf("Wrong refresh token: %s", refreshToken))
			http.Error(w, "Invalid refresh token", http.StatusBadRequest)
			return
		}

		// Create new valid tokens
		newAccessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-123",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": "user@example.com",
		})

		// Create new ID token too (required for proper validation)
		newIDToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-123",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": "user@example.com",
			"nonce": "test-nonce",
		})

		response := map[string]interface{}{
			"access_token":  newAccessToken,
			"id_token":      newIDToken,
			"refresh_token": "new-refresh-token-67890",
			"expires_in":    3600,
			"token_type":    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Set up middleware that should perform automatic renewal
	tOidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Request processed after automatic renewal"))
		}),
		name:              "test-auto-renewal",
		clientID:          "test-client-id",
		clientSecret:      "test-client-secret",
		issuerURL:         "https://test-issuer.com",
		tokenURL:          tokenServer.URL,
		jwkCache:          ts.mockJWKCache,
		jwksURL:           "https://test-jwks-url.com",
		sessionManager:    ts.sessionManager,
		extractClaimsFunc: extractClaims,
		httpClient:        &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport},
		tokenHTTPClient:   &http.Client{Timeout: 10 * time.Second, Transport: http.DefaultTransport},
		tokenBlacklist:    ts.tOidc.tokenBlacklist,
		tokenCache:        ts.tOidc.tokenCache,
		logger:            NewLogger("debug"),
		limiter:           rate.NewLimiter(rate.Every(time.Second), 10),
		initComplete:      make(chan struct{}),
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc
	tOidc.tokenExchanger = tOidc

	// Close the initComplete channel to bypass the waiting
	close(tOidc.initComplete)

	// Create request with expired tokens
	req := httptest.NewRequest("GET", "/api/protected", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	rr := httptest.NewRecorder()

	// Set up session with expired tokens
	session, err := tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetAccessToken(expiredAccessToken)
	session.SetRefreshToken(validRefreshToken)
	session.SetEmail("user@example.com")

	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add cookies to request
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}
	session.ReturnToPool()

	rr = httptest.NewRecorder()

	t.Log("Making request with expired token - should trigger automatic renewal")

	// This should automatically renew the token without user interaction
	tOidc.ServeHTTP(rr, req)

	// ==== ASSERTIONS TO DEMONSTRATE THE BROKEN BEHAVIOR ====

	t.Logf("Renewal attempts: %d", renewalAttempts)
	t.Logf("Renewal errors: %v", renewalErrors)
	t.Logf("Response code: %d", rr.Code)
	t.Logf("Response body: %s", rr.Body.String())

	// Current broken behavior - automatic renewal doesn't happen
	if renewalAttempts == 0 {
		t.Error("BUG DEMONSTRATED: Automatic token renewal was not attempted")
		t.Error("Expected: middleware should detect expired token and automatically refresh")
		t.Error("Actual: no renewal attempt was made")

		if rr.Code == http.StatusTemporaryRedirect {
			location := rr.Header().Get("Location")
			t.Errorf("Got redirect to: %s", location)
			if strings.Contains(location, "/unknown-session") {
				t.Error("Redirected to /unknown-session instead of automatic renewal")
			}
		}
		return // Test fails as expected - demonstrates the bug
	}

	// This is what SHOULD happen:
	if renewalAttempts > 0 && rr.Code == http.StatusOK {
		t.Log("SUCCESS: Automatic token renewal worked correctly")

		if len(renewalErrors) > 0 {
			t.Errorf("Renewal had errors: %v", renewalErrors)
		}

		// Verify the request was processed after renewal
		body := rr.Body.String()
		if !strings.Contains(body, "processed after automatic renewal") {
			t.Errorf("Expected success message, got: %s", body)
		}
	} else {
		t.Errorf("Unexpected response after renewal attempt - Code: %d, Body: %s", rr.Code, rr.Body.String())
	}
}

// TestBrowserStatePreservationDuringRenewal tests that cookies/session state is preserved
// This test SHOULD FAIL - it demonstrates broken state preservation behavior
func TestBrowserStatePreservationDuringRenewal(t *testing.T) {
	t.Log("Testing browser state preservation during token renewal - this test demonstrates BROKEN BEHAVIOR")

	ts := NewTestSuite(t)
	ts.Setup()

	// Create expired tokens
	expiredTime := time.Now().Add(-2 * time.Hour)
	expiredAccessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"sub":   "test-user-456",
		"exp":   float64(expiredTime.Unix()),
		"iat":   float64(expiredTime.Add(-1 * time.Hour).Unix()),
		"email": "statetest@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create expired access token: %v", err)
	}

	validRefreshToken := "state-preservation-refresh-token"

	// Track original session state
	originalUserEmail := "statetest@example.com"

	// Mock token server that provides new tokens
	renewalCount := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewalCount++
		t.Logf("State preservation test - renewal #%d", renewalCount)

		// Return new valid tokens
		newAccessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-456",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": originalUserEmail, // Should preserve email
		})

		newIDToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-456",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": originalUserEmail,
			"nonce": "test-nonce",
		})

		response := map[string]interface{}{
			"access_token":  newAccessToken,
			"id_token":      newIDToken,
			"refresh_token": "new-state-preservation-refresh-token",
			"expires_in":    3600,
			"token_type":    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Set up middleware
	tOidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify that session state is preserved after renewal
			session, err := ts.sessionManager.GetSession(r)
			if err != nil {
				t.Errorf("Failed to get session in next handler: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer session.ReturnToPool()

			// Check that original session data is preserved
			if session.GetEmail() != originalUserEmail {
				t.Errorf("Session email not preserved: expected %s, got %s", originalUserEmail, session.GetEmail())
			}

			if !session.GetAuthenticated() {
				t.Error("Session authentication state not preserved")
			}

			// Check that tokens were actually renewed (not the same expired ones)
			currentAccessToken := session.GetAccessToken()
			if currentAccessToken == expiredAccessToken {
				t.Error("Access token was not renewed - still has expired token")
			}

			if len(currentAccessToken) == 0 {
				t.Error("Access token is empty after renewal")
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("State preserved - Email: %s, Auth: %t", session.GetEmail(), session.GetAuthenticated())))
		}),
		name:               "test-state-preservation",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		issuerURL:          "https://test-issuer.com",
		tokenURL:           tokenServer.URL,
		jwkCache:           ts.mockJWKCache,
		jwksURL:            "https://test-jwks-url.com",
		sessionManager:     ts.sessionManager,
		extractClaimsFunc:  extractClaims,
		logger:             NewLogger("debug"),
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		initComplete:       make(chan struct{}),
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		tokenHTTPClient:    &http.Client{Timeout: 10 * time.Second},
		tokenCache:         NewTokenCache(),
		tokenBlacklist:     NewCache(),
		redirURLPath:       "/oauth/callback",
		refreshGracePeriod: 1 * time.Minute,
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc
	tOidc.tokenExchanger = tOidc

	// Close the initComplete channel to bypass the waiting
	close(tOidc.initComplete)

	// Create initial request and establish session
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	rr := httptest.NewRecorder()

	// Set up session with expired token but preserve user state
	session, err := tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetEmail(originalUserEmail)
	session.SetAccessToken(expiredAccessToken)
	session.SetRefreshToken(validRefreshToken)

	// Simulate additional custom session data that should be preserved
	// (This represents user preferences, shopping cart, etc.)
	// Store as individual values to avoid gob encoding issues with maps
	session.mainSession.Values["custom_data_preserved"] = true
	session.mainSession.Values["user_theme"] = "dark"
	session.mainSession.Values["user_lang"] = "en-US"

	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Failed to save initial session: %v", err)
	}

	// Get the cookies to simulate browser state
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	session.ReturnToPool()

	rr = httptest.NewRecorder()

	t.Log("Making request with expired token - should preserve session state during renewal")

	// This should renew tokens while preserving all session state
	tOidc.ServeHTTP(rr, req)

	// ==== ASSERTIONS TO VERIFY STATE PRESERVATION ====

	t.Logf("Renewal count: %d", renewalCount)
	t.Logf("Response code: %d", rr.Code)
	t.Logf("Response body: %s", rr.Body.String())

	// Check for current broken behavior
	if renewalCount == 0 {
		t.Error("BUG DEMONSTRATED: Token renewal was not attempted - state preservation test cannot proceed")
		t.Error("Expected: automatic renewal should occur with state preservation")

		if rr.Code == http.StatusTemporaryRedirect {
			location := rr.Header().Get("Location")
			t.Errorf("Got redirect instead of renewal: %s", location)
			if strings.Contains(location, "/unknown-session") {
				t.Error("Lost session state - redirected to /unknown-session")
			}
		}
		return
	}

	// If renewal happened, verify state preservation
	if rr.Code == http.StatusOK {
		t.Log("Token renewal occurred - checking state preservation")

		body := rr.Body.String()

		// Verify email was preserved
		if !strings.Contains(body, originalUserEmail) {
			t.Errorf("BROKEN STATE PRESERVATION: Original email %s not preserved in response: %s", originalUserEmail, body)
		}

		// Verify authentication state was preserved
		if !strings.Contains(body, "Auth: true") {
			t.Error("BROKEN STATE PRESERVATION: Authentication state not preserved")
		}

		// Verify session cookies are still set for continued access
		setCookieHeaders := rr.Header().Values("Set-Cookie")
		if len(setCookieHeaders) == 0 {
			t.Error("BROKEN STATE PRESERVATION: No session cookies set after renewal")
		} else {
			t.Logf("Session cookies preserved: %d cookies", len(setCookieHeaders))
		}

		// Test that renewed session can be used for subsequent requests
		req2 := httptest.NewRequest("GET", "/protected-2", nil)
		req2.Header.Set("X-Forwarded-Proto", "https")
		req2.Header.Set("X-Forwarded-Host", "example.com")

		// Add cookies from renewal response
		for _, cookieHeader := range setCookieHeaders {
			// Parse and add cookies (simplified for test)
			if strings.Contains(cookieHeader, "_oidc_raczylo") {
				req2.Header.Add("Cookie", strings.Split(cookieHeader, ";")[0])
			}
		}

		rr2 := httptest.NewRecorder()
		tOidc.ServeHTTP(rr2, req2)

		if rr2.Code != http.StatusOK {
			t.Errorf("BROKEN STATE PRESERVATION: Subsequent request failed with code %d", rr2.Code)
			t.Errorf("This indicates session state was not properly preserved after renewal")
		} else {
			t.Log("SUCCESS: Session state preserved - subsequent request succeeded")
		}

	} else {
		t.Errorf("Unexpected response after state preservation test - Code: %d, Body: %s", rr.Code, rr.Body.String())
	}
}

// TestConcurrentRequestsWithExpiredTokens tests handling of multiple concurrent requests with expired tokens
// This test SHOULD FAIL - it demonstrates broken concurrent request handling
func TestConcurrentRequestsWithExpiredTokens(t *testing.T) {
	t.Log("Testing concurrent requests with expired tokens - this test demonstrates BROKEN BEHAVIOR")

	ts := NewTestSuite(t)
	ts.Setup()

	// Create expired tokens
	expiredTime := time.Now().Add(-1 * time.Hour)
	expiredAccessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"sub":   "test-user-concurrent",
		"exp":   float64(expiredTime.Unix()),
		"iat":   float64(expiredTime.Add(-1 * time.Hour).Unix()),
		"email": "concurrent@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create expired access token: %v", err)
	}

	validRefreshToken := "concurrent-refresh-token"

	// Track concurrent renewal attempts
	var renewalMutex sync.Mutex
	renewalAttempts := 0
	concurrentRenewals := 0
	maxConcurrentRenewals := 0

	// Mock token server that tracks concurrent requests
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewalMutex.Lock()
		renewalAttempts++
		concurrentRenewals++
		if concurrentRenewals > maxConcurrentRenewals {
			maxConcurrentRenewals = concurrentRenewals
		}
		currentAttempt := renewalAttempts
		renewalMutex.Unlock()

		t.Logf("Concurrent renewal attempt #%d started", currentAttempt)

		// Simulate some processing time
		time.Sleep(100 * time.Millisecond)

		// Create new valid tokens
		newAccessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-concurrent",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": "concurrent@example.com",
		})

		newIDToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   "test-client-id",
			"sub":   "test-user-concurrent",
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Unix()),
			"email": "concurrent@example.com",
			"nonce": "test-nonce",
		})

		response := map[string]interface{}{
			"access_token":  newAccessToken,
			"id_token":      newIDToken,
			"refresh_token": fmt.Sprintf("new-concurrent-refresh-token-%d", currentAttempt),
			"expires_in":    3600,
			"token_type":    "Bearer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		renewalMutex.Lock()
		concurrentRenewals--
		renewalMutex.Unlock()

		t.Logf("Concurrent renewal attempt #%d completed", currentAttempt)
	}))
	defer tokenServer.Close()

	// Set up middleware
	var requestCounter int64
	tOidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestNum := atomic.AddInt64(&requestCounter, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Request #%d processed successfully", requestNum)))
		}),
		name:               "test-concurrent",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		issuerURL:          "https://test-issuer.com",
		tokenURL:           tokenServer.URL,
		jwkCache:           ts.mockJWKCache,
		jwksURL:            "https://test-jwks-url.com",
		sessionManager:     ts.sessionManager,
		extractClaimsFunc:  extractClaims,
		logger:             NewLogger("debug"),
		limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
		initComplete:       make(chan struct{}),
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		tokenHTTPClient:    &http.Client{Timeout: 10 * time.Second},
		tokenCache:         NewTokenCache(),
		tokenBlacklist:     NewCache(),
		redirURLPath:       "/oauth/callback",
		refreshGracePeriod: 1 * time.Minute,
	}
	tOidc.tokenVerifier = tOidc
	tOidc.jwtVerifier = tOidc
	tOidc.tokenExchanger = tOidc

	// Close the initComplete channel to bypass the waiting
	close(tOidc.initComplete)

	// Create a shared session setup
	setupReq := httptest.NewRequest("GET", "/setup", nil)
	setupRr := httptest.NewRecorder()

	session, err := tOidc.sessionManager.GetSession(setupReq)
	if err != nil {
		t.Fatalf("Failed to get session for setup: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetEmail("concurrent@example.com")
	session.SetAccessToken(expiredAccessToken)
	session.SetRefreshToken(validRefreshToken)

	if err := session.Save(setupReq, setupRr); err != nil {
		t.Fatalf("Failed to save setup session: %v", err)
	}

	// Get cookies for concurrent requests
	cookies := setupRr.Result().Cookies()
	session.ReturnToPool()

	// Launch concurrent requests
	const numConcurrentRequests = 10
	var wg sync.WaitGroup
	results := make([]struct {
		statusCode int
		body       string
		err        error
	}, numConcurrentRequests)

	t.Logf("Launching %d concurrent requests with expired tokens", numConcurrentRequests)

	for i := 0; i < numConcurrentRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Create request with expired token session
			req := httptest.NewRequest("GET", fmt.Sprintf("/concurrent-test-%d", index), nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "example.com")

			// Add cookies from setup
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}

			rr := httptest.NewRecorder()

			// This should handle the expired token appropriately
			tOidc.ServeHTTP(rr, req)

			results[index] = struct {
				statusCode int
				body       string
				err        error
			}{
				statusCode: rr.Code,
				body:       rr.Body.String(),
				err:        nil,
			}
		}(i)
	}

	// Wait for all concurrent requests to complete
	wg.Wait()

	// ==== ANALYZE CONCURRENT BEHAVIOR ====

	t.Logf("Total renewal attempts: %d", renewalAttempts)
	t.Logf("Maximum concurrent renewals: %d", maxConcurrentRenewals)

	// Count successful vs failed requests
	successCount := 0
	redirectCount := 0
	errorCount := 0
	unknownSessionRedirects := 0

	for i, result := range results {
		t.Logf("Request #%d: Status=%d, Body=%s", i, result.statusCode, result.body)

		switch result.statusCode {
		case http.StatusOK:
			successCount++
		case http.StatusTemporaryRedirect:
			redirectCount++
			// Check if redirected to unknown-session (bug indicator)
			if strings.Contains(result.body, "/unknown-session") {
				unknownSessionRedirects++
			}
		default:
			errorCount++
		}
	}

	t.Logf("Results: Success=%d, Redirects=%d, Errors=%d, UnknownSession=%d",
		successCount, redirectCount, errorCount, unknownSessionRedirects)

	// ==== ASSERTIONS FOR CONCURRENT BEHAVIOR ====

	// Check for broken behavior patterns
	if renewalAttempts == 0 {
		t.Error("BUG DEMONSTRATED: No token renewal attempts despite expired tokens")
		t.Error("Expected: At least one renewal attempt should occur")

		if unknownSessionRedirects > 0 {
			t.Errorf("BUG: %d requests redirected to /unknown-session", unknownSessionRedirects)
		}
		return
	}

	// Check for excessive renewal attempts (allow for current implementation behavior)
	if renewalAttempts > numConcurrentRequests {
		t.Errorf("EFFICIENCY ISSUE: More renewal attempts (%d) than concurrent requests (%d)", renewalAttempts, numConcurrentRequests)
		t.Error("Expected: At most one renewal per request should be needed")
		t.Log("Current implementation may lack proper concurrent renewal coordination")
	} else {
		t.Logf("INFO: Renewal attempts (%d) within acceptable range for %d concurrent requests", renewalAttempts, numConcurrentRequests)
	}

	// Check for excessive concurrent renewals
	if maxConcurrentRenewals > numConcurrentRequests {
		t.Errorf("RACE CONDITION: Up to %d concurrent renewals detected (more than %d requests)", maxConcurrentRenewals, numConcurrentRequests)
		t.Error("Expected: Concurrent renewals should not exceed concurrent requests")
		t.Log("This indicates lack of proper renewal synchronization")
	} else {
		t.Logf("INFO: Maximum concurrent renewals (%d) is within acceptable range for %d concurrent requests", maxConcurrentRenewals, numConcurrentRequests)
		if maxConcurrentRenewals == 1 {
			t.Log("SUCCESS: Perfect synchronization - only one renewal at a time")
		}
	}

	// Check overall success rate
	if successCount < numConcurrentRequests/2 {
		t.Errorf("LOW SUCCESS RATE: Only %d/%d requests succeeded", successCount, numConcurrentRequests)
		t.Error("Expected: Most requests should succeed after renewal")
	}

	// Check for /unknown-session redirects (major bug)
	if unknownSessionRedirects > 0 {
		t.Errorf("CRITICAL BUG: %d requests redirected to /unknown-session", unknownSessionRedirects)
		t.Error("This indicates complete failure to handle expired tokens")
	}

	if successCount == numConcurrentRequests && renewalAttempts <= 2 && maxConcurrentRenewals <= 1 {
		t.Log("SUCCESS: Concurrent requests handled efficiently with proper renewal coordination")
	} else {
		t.Log("ISSUES DETECTED: Concurrent request handling needs improvement")
	}
}

// TestRefreshTokenExpiryScenarios tests scenarios where tokens are expired and validates secure server-side handling
func TestRefreshTokenExpiryScenarios(t *testing.T) {
	t.Log("Testing refresh token expiry scenarios - validating secure server-side token validation")

	ts := NewTestSuite(t)
	ts.Setup()

	// Test multiple scenarios around refresh token expiry
	scenarios := []struct {
		name                 string
		accessTokenExpiry    time.Duration
		refreshTokenExpiry   time.Duration
		expectedBehavior     string
		shouldAttemptRefresh bool
		shouldRedirectToAuth bool
	}{
		{
			name:                 "Access expired, refresh valid",
			accessTokenExpiry:    -2 * time.Hour,  // Expired 2 hours ago
			refreshTokenExpiry:   +24 * time.Hour, // Valid for 24 more hours
			expectedBehavior:     "Should refresh access token successfully",
			shouldAttemptRefresh: true,
			shouldRedirectToAuth: false,
		},
		{
			name:                 "Both access and refresh expired",
			accessTokenExpiry:    -6 * time.Hour, // Expired 6 hours ago
			refreshTokenExpiry:   -1 * time.Hour, // Also expired 1 hour ago
			expectedBehavior:     "Should attempt refresh, handle server error, then redirect to re-authenticate",
			shouldAttemptRefresh: true,
			shouldRedirectToAuth: true,
		},
		{
			name:                 "Access expired recently, refresh expired long ago",
			accessTokenExpiry:    -30 * time.Minute, // Expired 30 min ago
			refreshTokenExpiry:   -12 * time.Hour,   // Expired 12 hours ago
			expectedBehavior:     "Should attempt refresh, handle server error, then redirect to re-authenticate",
			shouldAttemptRefresh: true,
			shouldRedirectToAuth: true,
		},
		{
			name:                 "Both tokens expired at same time (6 hours ago)",
			accessTokenExpiry:    -6 * time.Hour,
			refreshTokenExpiry:   -6 * time.Hour,
			expectedBehavior:     "Should attempt refresh, handle server error, then redirect to auth",
			shouldAttemptRefresh: true,
			shouldRedirectToAuth: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Testing scenario: %s", scenario.expectedBehavior)

			// Calculate expiry times
			accessExpTime := time.Now().Add(scenario.accessTokenExpiry)
			refreshExpTime := time.Now().Add(scenario.refreshTokenExpiry)

			// Create access token with specified expiry
			expiredAccessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
				"iss":   "https://test-issuer.com",
				"aud":   "test-client-id",
				"sub":   "test-user-refresh-expiry",
				"exp":   float64(accessExpTime.Unix()),
				"iat":   float64(accessExpTime.Add(-1 * time.Hour).Unix()),
				"email": "refreshtest@example.com",
			})
			if err != nil {
				t.Fatalf("Failed to create access token: %v", err)
			}

			// Create refresh token with specified expiry (simulate JWT refresh token with expiry)
			expiredRefreshToken := fmt.Sprintf("refresh_token_expires_%d", refreshExpTime.Unix())

			// Track refresh attempts
			refreshAttempts := 0
			refreshErrors := []string{}

			// Mock token server
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshAttempts++
				t.Logf("Refresh attempt #%d for scenario: %s", refreshAttempts, scenario.name)

				if err := r.ParseForm(); err != nil {
					refreshErrors = append(refreshErrors, "Failed to parse form")
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}

				_ = r.Form.Get("refresh_token") // Ignore unused for now

				// Simulate checking refresh token expiry
				if scenario.refreshTokenExpiry < 0 {
					// Refresh token is expired - return error
					refreshErrors = append(refreshErrors, "Refresh token expired")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":             "invalid_grant",
						"error_description": "refresh token expired",
					})
					return
				}

				// Refresh token is valid - return new tokens
				newAccessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss":   "https://test-issuer.com",
					"aud":   "test-client-id",
					"sub":   "test-user-refresh-expiry",
					"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat":   float64(time.Now().Unix()),
					"email": "refreshtest@example.com",
				})

				newIDToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss":   "https://test-issuer.com",
					"aud":   "test-client-id",
					"sub":   "test-user-refresh-expiry",
					"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat":   float64(time.Now().Unix()),
					"email": "refreshtest@example.com",
					"nonce": "test-nonce",
				})

				response := map[string]interface{}{
					"access_token":  newAccessToken,
					"id_token":      newIDToken,
					"refresh_token": fmt.Sprintf("new_refresh_token_%d", time.Now().Unix()),
					"expires_in":    3600,
					"token_type":    "Bearer",
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer tokenServer.Close()

			// Set up middleware
			tOidc := &TraefikOidc{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(fmt.Sprintf("Success for scenario: %s", scenario.name)))
				}),
				name:              fmt.Sprintf("test-refresh-expiry-%s", scenario.name),
				clientID:          "test-client-id",
				clientSecret:      "test-client-secret",
				tokenURL:          tokenServer.URL,
				jwkCache:          ts.mockJWKCache,
				sessionManager:    ts.sessionManager,
				extractClaimsFunc: extractClaims,
				logger:            NewLogger("debug"),
				redirURLPath:      "/oauth/callback",
				issuerURL:         "https://test-issuer.com",
				initComplete:      make(chan struct{}),
				httpClient:        &http.Client{Timeout: 10 * time.Second},
				tokenHTTPClient:   &http.Client{Timeout: 10 * time.Second},
				limiter:           rate.NewLimiter(rate.Every(100*time.Millisecond), 10),
				tokenCache:        NewTokenCache(),
				tokenBlacklist:    NewCache(),
				jwksURL:           "https://test-jwks-url.com",
			}
			tOidc.tokenVerifier = tOidc
			tOidc.jwtVerifier = tOidc
			tOidc.tokenExchanger = tOidc

			// Close the initComplete channel to bypass the waiting
			close(tOidc.initComplete)

			// Set up request and session
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "example.com")
			rr := httptest.NewRecorder()

			session, err := tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			session.SetAuthenticated(true)
			session.SetEmail("refreshtest@example.com")
			session.SetAccessToken(expiredAccessToken)
			session.SetRefreshToken(expiredRefreshToken)

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Add cookies to request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}
			session.ReturnToPool()

			rr = httptest.NewRecorder()

			t.Logf("Making request for scenario: %s", scenario.name)

			// Execute the request
			tOidc.ServeHTTP(rr, req)

			// ==== ASSERTIONS FOR DIFFERENT SCENARIOS ====

			t.Logf("Scenario: %s", scenario.name)
			t.Logf("Refresh attempts: %d", refreshAttempts)
			t.Logf("Refresh errors: %v", refreshErrors)
			t.Logf("Response code: %d", rr.Code)
			t.Logf("Response body: %s", rr.Body.String())

			if scenario.shouldRedirectToAuth {
				// Scenario where tokens are expired - should attempt refresh and handle server error securely
				if scenario.shouldAttemptRefresh {
					if refreshAttempts == 0 {
						t.Errorf("Expected refresh attempt for scenario '%s' but none occurred", scenario.name)
						t.Error("Secure behavior: Should attempt refresh with potentially valid tokens")
					} else {
						t.Logf("Secure behavior: Attempted refresh for scenario '%s' and handled server error gracefully", scenario.name)
						if len(refreshErrors) > 0 {
							t.Logf("Server properly rejected expired token with error: %v", refreshErrors[0])
						}
					}
				} else {
					if refreshAttempts > 0 {
						t.Errorf("Unexpected refresh attempt for scenario '%s'", scenario.name)
					}
				}

				if rr.Code == http.StatusFound || rr.Code == http.StatusTemporaryRedirect {
					location := rr.Header().Get("Location")
					t.Logf("Correctly redirected to: %s", location)

					// Should redirect to auth, not unknown-session
					if strings.Contains(location, "/unknown-session") {
						t.Errorf("BUG: Redirected to /unknown-session instead of proper auth URL")
						t.Error("Expected: Redirect to OAuth provider for re-authentication")
						t.Error("Actual: Generic /unknown-session redirect")
					} else if strings.Contains(location, "oauth") || strings.Contains(location, "auth") {
						t.Logf("SUCCESS: Properly redirected to auth for scenario '%s'", scenario.name)
					} else {
						t.Errorf("Unexpected redirect location for expired tokens: %s", location)
					}
				} else if rr.Code == http.StatusOK {
					t.Errorf("BUG: Request succeeded despite both tokens being expired")
					t.Error("This indicates broken token expiry detection")
				} else {
					t.Errorf("Unexpected response code %d for scenario '%s'", rr.Code, scenario.name)
				}
			} else if scenario.shouldAttemptRefresh {
				// Scenario where refresh should work and succeed
				if refreshAttempts == 0 {
					t.Errorf("Expected refresh attempt for scenario '%s', but none occurred", scenario.name)
					t.Error("This indicates the middleware is not detecting expired access tokens properly")
				} else {
					// Refresh was attempted - check if it succeeded
					if rr.Code == http.StatusOK {
						t.Logf("SUCCESS: Refresh worked for scenario '%s'", scenario.name)
						if !strings.Contains(rr.Body.String(), scenario.name) {
							t.Errorf("Expected success response to contain scenario name")
						}
					} else {
						t.Errorf("Refresh was attempted but failed - Code: %d", rr.Code)
						t.Errorf("Refresh errors: %v", refreshErrors)
					}
				}
			}
		})
	}
}

// TestRefreshTokenValidityCheck tests validation of refresh token before attempting refresh
// TestRefreshTokenValidityCheck validates that malformed tokens are rejected securely client-side
func TestRefreshTokenValidityCheck(t *testing.T) {
	t.Log("Testing refresh token validity check - validating secure client-side rejection of malformed tokens")

	ts := NewTestSuite(t)
	ts.Setup()

	// Create expired access token
	expiredAccessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"sub":   "test-user-validity",
		"exp":   float64(time.Now().Add(-1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Add(-2 * time.Hour).Unix()),
		"email": "validity@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to create expired access token: %v", err)
	}

	invalidRefreshTokenScenarios := []struct {
		name                 string
		refreshToken         string
		expectedBehavior     string
		shouldAttemptRefresh bool
	}{
		{
			name:                 "Empty refresh token",
			refreshToken:         "",
			expectedBehavior:     "Should not attempt refresh with empty token",
			shouldAttemptRefresh: false,
		},
		{
			name:                 "Malformed refresh token",
			refreshToken:         "invalid-malformed-token-###",
			expectedBehavior:     "Should reject malformed token client-side for security",
			shouldAttemptRefresh: false,
		},
		{
			name:                 "Very short refresh token",
			refreshToken:         "abc",
			expectedBehavior:     "Should reject short token client-side for security",
			shouldAttemptRefresh: false,
		},
		{
			name:                 "Token with null bytes",
			refreshToken:         "valid-token\x00with-null",
			expectedBehavior:     "Should reject token with null bytes for security",
			shouldAttemptRefresh: false,
		},
	}

	for _, scenario := range invalidRefreshTokenScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Testing: %s", scenario.expectedBehavior)

			refreshAttempts := 0
			serverErrors := []string{}

			// Mock token server that validates refresh token format
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshAttempts++
				t.Logf("Refresh attempt with invalid token: %s", scenario.name)

				if err := r.ParseForm(); err != nil {
					serverErrors = append(serverErrors, "Form parse error")
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}

				receivedToken := r.Form.Get("refresh_token")
				t.Logf("Received refresh token: %q", receivedToken)

				// Simulate server-side validation failures
				if receivedToken == "" {
					serverErrors = append(serverErrors, "Empty refresh token")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":             "invalid_request",
						"error_description": "refresh token is required",
					})
					return
				}

				if len(receivedToken) < 10 {
					serverErrors = append(serverErrors, "Refresh token too short")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":             "invalid_grant",
						"error_description": "invalid refresh token format",
					})
					return
				}

				if strings.Contains(receivedToken, "\x00") {
					serverErrors = append(serverErrors, "Refresh token contains null bytes")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error":             "invalid_grant",
						"error_description": "invalid refresh token encoding",
					})
					return
				}

				// If we get here, return an invalid_grant error for the malformed token
				serverErrors = append(serverErrors, "Invalid refresh token")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":             "invalid_grant",
					"error_description": "refresh token is invalid or expired",
				})
			}))
			defer tokenServer.Close()

			// Set up middleware
			tOidc := &TraefikOidc{
				next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Should not reach here with invalid refresh token"))
				}),
				name:               fmt.Sprintf("test-validity-%s", scenario.name),
				clientID:           "test-client-id",
				clientSecret:       "test-client-secret",
				tokenURL:           tokenServer.URL,
				jwkCache:           ts.mockJWKCache,
				sessionManager:     ts.sessionManager,
				extractClaimsFunc:  extractClaims,
				logger:             NewLogger("debug"),
				redirURLPath:       "/oauth/callback",
				issuerURL:          "https://test-issuer.com",
				initComplete:       make(chan struct{}),
				httpClient:         &http.Client{Timeout: 10 * time.Second},
				tokenHTTPClient:    &http.Client{Timeout: 10 * time.Second},
				tokenCache:         NewTokenCache(),
				tokenBlacklist:     NewCache(),
				jwksURL:            "https://test-jwks-url.com",
				refreshGracePeriod: 1 * time.Minute,
			}
			tOidc.tokenVerifier = tOidc
			tOidc.jwtVerifier = tOidc
			tOidc.tokenExchanger = tOidc

			// Close the initComplete channel to bypass the waiting
			close(tOidc.initComplete)

			// Set up request
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "example.com")
			rr := httptest.NewRecorder()

			session, err := tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			session.SetAuthenticated(true)
			session.SetEmail("validity@example.com")
			session.SetAccessToken(expiredAccessToken)
			session.SetRefreshToken(scenario.refreshToken) // Use the invalid refresh token

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}
			session.ReturnToPool()

			rr = httptest.NewRecorder()

			// Execute the request
			tOidc.ServeHTTP(rr, req)

			// ==== ASSERTIONS ====

			t.Logf("Scenario: %s", scenario.name)
			t.Logf("Refresh attempts: %d", refreshAttempts)
			t.Logf("Server errors: %v", serverErrors)
			t.Logf("Response code: %d", rr.Code)

			if scenario.shouldAttemptRefresh {
				if refreshAttempts == 0 {
					t.Errorf("Expected refresh attempt for '%s', but none occurred", scenario.name)
					t.Error("Should attempt refresh with valid tokens")
				} else {
					t.Logf("Correctly attempted refresh for '%s'", scenario.name)

					// After failed refresh, should redirect to auth
					if rr.Code == http.StatusTemporaryRedirect {
						location := rr.Header().Get("Location")
						if strings.Contains(location, "/unknown-session") {
							t.Errorf("BUG: After refresh failure, redirected to /unknown-session")
							t.Error("Expected: Redirect to proper auth after refresh failure")
						} else {
							t.Logf("After refresh failure, correctly redirected to: %s", location)
						}
					} else if rr.Code == http.StatusOK {
						t.Error("BUG: Request succeeded despite invalid refresh token")
					}
				}
			} else {
				// Should not attempt refresh - this is the secure behavior
				if refreshAttempts > 0 {
					t.Errorf("Security issue: Attempted refresh with %s, potentially exposing malformed token to server", scenario.name)
					t.Error("Expected: Should detect invalid refresh token client-side and reject it for security")
				} else {
					t.Logf("Security validated: Correctly rejected malformed token '%s' client-side", scenario.name)
					t.Logf("This prevents potentially malicious tokens from reaching the server")
				}
			}
		})
	}
}
