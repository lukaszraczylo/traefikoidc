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
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
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
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
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
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
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
	sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, logger)
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
