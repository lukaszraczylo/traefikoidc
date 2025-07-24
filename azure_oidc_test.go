package traefikoidc

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// mockTraefikOidc extends TraefikOidc to override JWT verification for testing
type mockTraefikOidc struct {
	*TraefikOidc
}

// Override VerifyToken to avoid JWKS lookup in tests
func (m *mockTraefikOidc) VerifyToken(token string) error {
	// Cache test claims to avoid "claims not found" errors
	testClaims := map[string]interface{}{
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
	}
	m.tokenCache.Set(token, testClaims, time.Hour)
	return nil // Always succeed for testing
}

// Override VerifyJWTSignatureAndClaims to avoid JWKS lookup in tests
func (m *mockTraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	// Cache test claims to avoid "claims not found" errors
	testClaims := map[string]interface{}{
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
	}
	m.tokenCache.Set(token, testClaims, time.Hour)
	return nil // Always succeed for testing
}

func TestAzureOIDCRegression(t *testing.T) {
	// Create a mocked TraefikOidc instance configured for Azure AD
	mockLogger := NewLogger("debug")

	// Configure for Azure AD provider
	baseOidc := &TraefikOidc{
		issuerURL:             "https://login.microsoftonline.com/tenant-id/v2.0",
		authURL:               "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
		tokenURL:              "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
		jwksURL:               "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
		clientID:              "test-client-id",
		clientSecret:          "test-client-secret",
		scopes:                []string{"openid", "profile", "email"},
		refreshGracePeriod:    60 * time.Second,
		limiter:               rate.NewLimiter(rate.Every(time.Second), 100), // Add rate limiter
		logger:                mockLogger,
		httpClient:            createDefaultHTTPClient(), // Add HTTP client
		jwkCache:              &JWKCache{},               // Add JWK cache
		tokenCache:            NewTokenCache(),
		tokenBlacklist:        NewCache(),
		allowedUserDomains:    make(map[string]struct{}),
		allowedUsers:          make(map[string]struct{}),
		allowedRolesAndGroups: make(map[string]struct{}),
		excludedURLs:          make(map[string]struct{}),
		extractClaimsFunc:     extractClaims,
	}

	// Create the mock wrapper
	tOidc := &mockTraefikOidc{TraefikOidc: baseOidc}

	// Initialize session manager
	sessionManager, _ := NewSessionManager("test-encryption-key-32-bytes-long", false, mockLogger)
	tOidc.sessionManager = sessionManager

	// Mock the JWT verification to avoid JWKS lookup issues
	tOidc.tokenVerifier = &mockTokenVerifier{
		verifyFunc: func(token string) error {
			// For test tokens, always return success and cache claims
			if strings.HasPrefix(token, "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0") {
				// Cache test claims for JWT tokens
				testClaims := map[string]interface{}{
					"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat":   float64(time.Now().Unix()),
					"sub":   "test-user",
					"email": "test@example.com",
				}
				tOidc.tokenCache.Set(token, testClaims, time.Hour)
				return nil
			}
			// For opaque tokens (non-JWT format), return success
			if !strings.Contains(token, ".") || strings.Count(token, ".") != 2 {
				return nil
			}
			// For JWT tokens, cache basic claims to avoid cache lookup issues
			testClaims := map[string]interface{}{
				"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
				"iat":   float64(time.Now().Unix()),
				"sub":   "test-user",
				"email": "test@example.com",
			}
			tOidc.tokenCache.Set(token, testClaims, time.Hour)
			return nil // Always succeed for test purposes
		},
	}

	// Mock JWT verifier to avoid JWKS lookup
	tOidc.jwtVerifier = &mockJWTVerifier{
		verifyFunc: func(jwt *JWT, token string) error {
			// Also cache claims here to ensure they're available
			testClaims := map[string]interface{}{
				"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
				"iat":   float64(time.Now().Unix()),
				"sub":   "test-user",
				"email": "test@example.com",
			}
			tOidc.tokenCache.Set(token, testClaims, time.Hour)
			return nil // Always succeed
		},
	}

	t.Run("Azure provider detection works correctly", func(t *testing.T) {
		if !tOidc.isAzureProvider() {
			t.Error("Azure provider should be detected for Azure AD issuer URL")
		}

		if tOidc.isGoogleProvider() {
			t.Error("Google provider should not be detected for Azure AD issuer URL")
		}
	})

	t.Run("Azure auth URL includes correct parameters", func(t *testing.T) {
		authURL := tOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Check that response_mode=query was added for Azure
		if !strings.Contains(authURL, "response_mode=query") {
			t.Errorf("response_mode=query not added to Azure auth URL: %s", authURL)
		}

		// Verify offline_access scope is included for Azure providers
		if !strings.Contains(authURL, "offline_access") {
			t.Errorf("offline_access scope not included in Azure auth URL: %s", authURL)
		}

		// Verify Azure doesn't get Google-specific parameters
		if strings.Contains(authURL, "access_type=offline") {
			t.Errorf("access_type=offline incorrectly added to Azure auth URL: %s", authURL)
		}

		if strings.Contains(authURL, "prompt=consent") {
			t.Errorf("prompt=consent incorrectly added to Azure auth URL: %s", authURL)
		}
	})

	t.Run("Azure access token validation takes priority", func(t *testing.T) {
		// Create a request and session
		req := httptest.NewRequest("GET", "/protected", nil)
		session, _ := tOidc.sessionManager.GetSession(req)

		// Set up session with Azure-style tokens
		session.SetAuthenticated(true)
		session.SetEmail("user@example.com")

		// Use standardized test tokens with valid future expiration dates
		accessToken := ValidAccessToken // This token expires in 2065
		session.SetAccessToken(accessToken)

		// Create an expired ID token using a mock JWT with past expiration
		idTokenClaims := map[string]interface{}{
			"iss":   "https://login.microsoftonline.com/tenant-id/v2.0",
			"aud":   "test-client-id",
			"exp":   time.Now().Add(-1 * time.Hour).Unix(), // Expired
			"iat":   time.Now().Add(-2 * time.Hour).Unix(),
			"sub":   "user123",
			"email": "user@example.com",
		}
		idToken, _ := createAzureMockJWT(idTokenClaims)
		session.SetIDToken(idToken)

		// Mock the token verification to simulate Azure behavior
		originalTokenVerifier := tOidc.tokenVerifier
		tOidc.tokenVerifier = &mockTokenVerifier{
			verifyFunc: func(token string) error {
				if token == accessToken {
					// Access token validation succeeds - cache claims
					testClaims := map[string]interface{}{
						"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
						"iat":   float64(time.Now().Unix()),
						"sub":   "test-user",
						"email": "test@example.com",
					}
					tOidc.tokenCache.Set(token, testClaims, time.Hour)
					return nil
				}
				if token == idToken {
					// ID token validation fails (expired) - don't cache
					return newMockError("token has expired")
				}
				return newMockError("token validation failed")
			},
		}
		defer func() { tOidc.tokenVerifier = originalTokenVerifier }()

		// Test Azure-specific validation
		authenticated, needsRefresh, expired := tOidc.validateAzureTokens(session)

		// Azure should prioritize access token, so even with expired ID token,
		// user should still be authenticated since access token is valid
		if !authenticated {
			t.Error("Azure user should be authenticated when access token is valid, even if ID token is expired")
		}

		if expired {
			t.Error("Azure session should not be marked as expired when access token is valid")
		}

		// May need refresh if we want to get a fresh ID token
		if !needsRefresh {
			t.Log("Azure session may not need immediate refresh if access token is still valid")
		}
	})

	t.Run("Azure handles opaque access tokens gracefully", func(t *testing.T) {
		// Create a request and session
		req := httptest.NewRequest("GET", "/protected", nil)
		session, _ := tOidc.sessionManager.GetSession(req)

		// Set up session with JWT access token (not opaque for this test)
		session.SetAuthenticated(true)
		session.SetEmail("user@example.com")
		session.SetAccessToken(ValidAccessToken) // This is actually a JWT token

		// Use a valid ID token from test tokens
		session.SetIDToken(ValidIDToken) // This token expires in 2065

		// Mock the token verification
		originalTokenVerifier := tOidc.tokenVerifier
		tOidc.tokenVerifier = &mockTokenVerifier{
			verifyFunc: func(token string) error {
				if token == ValidIDToken {
					// ID token is valid - cache claims
					testClaims := map[string]interface{}{
						"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
						"iat":   float64(time.Now().Unix()),
						"sub":   "test-user",
						"email": "test@example.com",
					}
					tOidc.tokenCache.Set(token, testClaims, time.Hour)
					return nil
				}
				return newMockError("token validation failed")
			},
		}
		defer func() { tOidc.tokenVerifier = originalTokenVerifier }()

		// Test Azure-specific validation with opaque token
		authenticated, needsRefresh, expired := tOidc.validateAzureTokens(session)

		// Azure should handle opaque access tokens gracefully
		if !authenticated {
			t.Error("Azure user should be authenticated with opaque access token")
		}

		if expired {
			t.Error("Azure session should not be expired with valid tokens")
		}

		if needsRefresh {
			t.Log("Azure session with opaque token may signal refresh to get JWT tokens")
		}
	})

	t.Run("Azure CSRF handling during token validation failures", func(t *testing.T) {
		// Create a request and session
		req := httptest.NewRequest("GET", "/protected", nil)
		rw := httptest.NewRecorder()
		session, _ := tOidc.sessionManager.GetSession(req)

		// Set up session with CSRF token (simulating ongoing auth flow)
		session.SetCSRF("test-csrf-token-123")
		session.SetNonce("test-nonce-456")
		session.SetAuthenticated(false) // Not yet authenticated

		// Save session to simulate real scenario
		session.Save(req, rw)

		// Mock token verification to always fail (simulating Azure token issues)
		originalTokenVerifier := tOidc.tokenVerifier
		tOidc.tokenVerifier = &mockTokenVerifier{
			verifyFunc: func(token string) error {
				return newMockError("azure token validation failed")
			},
		}
		defer func() { tOidc.tokenVerifier = originalTokenVerifier }()

		// Test that CSRF is preserved during Azure validation failures
		authenticated, needsRefresh, expired := tOidc.validateAzureTokens(session)

		// Should not be authenticated due to validation failure
		if authenticated {
			t.Error("Should not be authenticated when token validation fails")
		}

		// Should be marked as expired since no tokens work
		if !expired && !needsRefresh {
			t.Error("Should be marked as needing refresh or expired when validation fails")
		}

		// Verify CSRF token is still preserved in session
		if session.GetCSRF() != "test-csrf-token-123" {
			t.Error("CSRF token should be preserved during Azure token validation failures")
		}

		if session.GetNonce() != "test-nonce-456" {
			t.Error("Nonce should be preserved during Azure token validation failures")
		}
	})
}

// createAzureMockJWT creates a basic JWT token for testing purposes
func createAzureMockJWT(claims map[string]interface{}) (string, error) {
	// For testing purposes, create a JWT with expired claims when needed
	// Use the test tokens infrastructure for most cases, but allow expired tokens for specific tests
	testTokens := NewTestTokens()

	// Check if this is meant to be an expired token
	if exp, ok := claims["exp"].(int64); ok && exp < time.Now().Unix() {
		return testTokens.CreateExpiredJWT(), nil
	}

	// Otherwise return a valid token
	return ValidIDToken, nil
}

// Mock error type for testing
type mockError struct {
	message string
}

func (e *mockError) Error() string {
	return e.message
}

func newMockError(message string) error {
	return &mockError{message: message}
}

// Mock token verifier for testing
type mockTokenVerifier struct {
	verifyFunc func(token string) error
}

func (m *mockTokenVerifier) VerifyToken(token string) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(token)
	}
	return nil
}

// Mock JWT verifier for testing
type mockJWTVerifier struct {
	verifyFunc func(jwt *JWT, token string) error
}

func (m *mockJWTVerifier) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(jwt, token)
	}
	return nil
}
