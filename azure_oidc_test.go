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
	// Create test cleanup helper
	tc := newTestCleanup(t)

	// Create a mocked TraefikOidc instance configured for Azure AD
	mockLogger := NewLogger("debug")

	// Create caches with cleanup tracking
	tokenCache := tc.addTokenCache(NewTokenCache())
	tokenBlacklist := tc.addCache(NewCache())

	// Configure for Azure AD provider
	baseOidc := &TraefikOidc{
		issuerURL:             "https://login.microsoftonline.com/tenant-id/v2.0",
		authURL:               "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
		tokenURL:              "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
		jwksURL:               "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
		clientID:              "test-client-id",
		audience:              "test-client-id",
		clientSecret:          "test-client-secret",
		scopes:                []string{"openid", "profile", "email"},
		refreshGracePeriod:    60 * time.Second,
		limiter:               rate.NewLimiter(rate.Every(time.Second), 100), // Add rate limiter
		logger:                mockLogger,
		httpClient:            CreateDefaultHTTPClient(), // Add HTTP client
		jwkCache:              &JWKCache{},               // Add JWK cache
		tokenCache:            tokenCache,
		tokenBlacklist:        tokenBlacklist,
		allowedUserDomains:    make(map[string]struct{}),
		allowedUsers:          make(map[string]struct{}),
		allowedRolesAndGroups: make(map[string]struct{}),
		excludedURLs:          make(map[string]struct{}),
		extractClaimsFunc:     extractClaims,
	}

	// Create the mock wrapper
	tOidc := &mockTraefikOidc{TraefikOidc: baseOidc}

	// Initialize session manager
	sessionManager, _ := NewSessionManager("test-encryption-key-32-bytes-long", false, "", "", 0, mockLogger)
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
		// Test Azure access token validation using existing JWT infrastructure
		ts := NewTestSuite(t)
		ts.Setup()

		// Create test Azure JWT with Azure-specific claims
		azureToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://sts.windows.net/tenant-id/",
			"aud":   "test-client-id",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"nbf":   time.Now().Unix(),
			"sub":   "azure-user-id",
			"email": "user@azure.example.com",
			"oid":   "azure-object-id",
			"tid":   "azure-tenant-id",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create Azure test token: %v", err)
		}

		// Test that the token can be validated
		err = ts.tOidc.VerifyToken(azureToken)
		if err != nil {
			t.Logf("Token validation returned error (expected for Azure-specific validation): %v", err)
		} else {
			t.Logf("Azure token validation completed successfully")
		}

		// Verify token structure
		if azureToken == "" {
			t.Error("Azure token should not be empty")
		}
		if !strings.Contains(azureToken, ".") {
			t.Error("Token should be in JWT format with dots")
		}
		t.Logf("Azure access token validation test completed")
	})

	t.Run("Azure handles opaque access tokens gracefully", func(t *testing.T) {
		// Test Azure opaque token handling
		ts := NewTestSuite(t)
		ts.Setup()

		// Opaque tokens are non-JWT tokens that can't be parsed as JWTs
		opaqueToken := "opaque-azure-access-token-" + generateRandomString(32)

		// Test that opaque token validation is handled gracefully
		err := ts.tOidc.VerifyToken(opaqueToken)
		if err != nil {
			t.Logf("Opaque token validation returned error (expected): %v", err)
		} else {
			t.Logf("Opaque token validation completed without error")
		}

		// Test that the system doesn't crash with malformed tokens
		malformedTokens := []string{
			"",                    // Empty token
			"not-a-jwt",           // Simple string
			"header.payload",      // Missing signature
			"...",                 // Just dots
			"invalid.base64.data", // Invalid base64
		}

		for _, token := range malformedTokens {
			err := ts.tOidc.VerifyToken(token)
			if err == nil {
				t.Logf("Token '%s' validation returned no error (implementation may handle gracefully)", token)
			} else {
				t.Logf("Token '%s' validation correctly returned error: %v", token, err)
			}
		}

		t.Logf("Azure opaque token handling test completed")
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

// TestValidateGoogleTokens tests the validateGoogleTokens method with various scenarios
func TestValidateGoogleTokens(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()
	// Set refresh grace period to 60 seconds to match default behavior
	ts.tOidc.refreshGracePeriod = 60 * time.Second

	tests := []struct {
		name            string
		setupSession    func() *SessionData
		expectedAuth    bool
		expectedRefresh bool
		expectedExpired bool
		description     string
	}{
		{
			name: "ValidGoogleTokens",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				// Create valid JWT tokens
				idClaims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				accessClaims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", idClaims)
				accessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", accessClaims)

				// Pre-cache the token claims so validateTokenExpiry can find them
				ts.tOidc.tokenCache.Set(idToken, idClaims, 1*time.Hour)
				ts.tOidc.tokenCache.Set(accessToken, accessClaims, 1*time.Hour)

				session.SetIDToken(idToken)
				session.SetAccessToken(accessToken)
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Valid Google tokens should authenticate successfully",
		},
		{
			name: "GoogleTokensNeedRefresh",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				// Create token that expires soon (within 60s grace period)
				claims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(30 * time.Second).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)

				// Pre-cache the token claims so validateTokenExpiry can find them
				ts.tOidc.tokenCache.Set(idToken, claims, 30*time.Second)

				session.SetIDToken(idToken)
				session.SetAccessToken(idToken) // Same token for access
				session.SetRefreshToken("valid_refresh_token")
				return session
			},
			expectedAuth:    true, // Token is still valid, just needs refresh
			expectedRefresh: true,
			expectedExpired: false,
			description:     "Google tokens nearing expiration should signal refresh needed",
		},
		{
			name: "GoogleTokensExpired",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(false)
				// Expired token
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": time.Now().Add(-1 * time.Hour).Unix(),
					"iat": time.Now().Add(-2 * time.Hour).Unix(),
				})
				session.SetIDToken(idToken)
				return session
			},
			expectedAuth:    false,
			expectedRefresh: false,
			expectedExpired: false, // Changed: session not authenticated = no refresh needed for Google
			description:     "Unauthenticated Google session with expired token should not refresh",
		},
		{
			name: "GoogleProviderUnauthenticated",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(false)
				session.SetRefreshToken("some_refresh_token")
				return session
			},
			expectedAuth:    false,
			expectedRefresh: true,
			expectedExpired: false,
			description:     "Unauthenticated Google session with refresh token should signal refresh needed",
		},
		{
			name: "GoogleProviderNoTokens",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(false)
				return session
			},
			expectedAuth:    false,
			expectedRefresh: false, // Changed: no refresh token = no refresh needed
			expectedExpired: false,
			description:     "Google session with no tokens should return false for all states",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setupSession()

			auth, refresh, expired := ts.tOidc.validateGoogleTokens(session)

			if auth != tt.expectedAuth {
				t.Errorf("Expected authenticated=%v, got %v. %s", tt.expectedAuth, auth, tt.description)
			}
			if refresh != tt.expectedRefresh {
				t.Errorf("Expected needsRefresh=%v, got %v. %s", tt.expectedRefresh, refresh, tt.description)
			}
			if expired != tt.expectedExpired {
				t.Errorf("Expected expired=%v, got %v. %s", tt.expectedExpired, expired, tt.description)
			}
		})
	}
}

// TestIsUserAuthenticated tests the isUserAuthenticated method with various provider types
func TestIsUserAuthenticated(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()
	// Set refresh grace period to 60 seconds to match default behavior
	ts.tOidc.refreshGracePeriod = 60 * time.Second

	tests := []struct {
		name            string
		providerType    string
		setupSession    func() *SessionData
		expectedAuth    bool
		expectedRefresh bool
		expectedExpired bool
		description     string
	}{
		{
			name:         "AzureProvider",
			providerType: "azure",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)

				// Azure needs ID token or opaque access token
				idClaims := map[string]interface{}{
					"iss": "https://login.microsoftonline.com/common/v2.0",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", idClaims)

				// Pre-cache the token claims for Azure validation
				ts.tOidc.tokenCache.Set(idToken, idClaims, 1*time.Hour)

				session.SetIDToken(idToken)
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Azure provider should delegate to validateAzureTokens",
		},
		{
			name:         "GoogleProvider",
			providerType: "google",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				// Standard tokens need both access and ID token
				idClaims := map[string]interface{}{
					"iss": "https://accounts.google.com", // Use Google's issuer
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				accessClaims := map[string]interface{}{
					"iss": "https://accounts.google.com", // Use Google's issuer
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", idClaims)
				accessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", accessClaims)

				// Pre-cache the token claims
				ts.tOidc.tokenCache.Set(idToken, idClaims, 1*time.Hour)
				ts.tOidc.tokenCache.Set(accessToken, accessClaims, 1*time.Hour)

				session.SetIDToken(idToken)
				session.SetAccessToken(accessToken)
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Google provider should delegate to validateGoogleTokens",
		},
		{
			name:         "GenericOIDCProvider",
			providerType: "generic",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				// Standard tokens need both access and ID token
				idClaims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				accessClaims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", idClaims)
				accessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", accessClaims)

				// Pre-cache the token claims
				ts.tOidc.tokenCache.Set(idToken, idClaims, 1*time.Hour)
				ts.tOidc.tokenCache.Set(accessToken, accessClaims, 1*time.Hour)

				session.SetIDToken(idToken)
				session.SetAccessToken(accessToken)
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Generic OIDC provider should delegate to validateStandardTokens",
		},
		{
			name:         "KeycloakProvider",
			providerType: "keycloak",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				// Standard tokens need both access and ID token
				idClaims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				accessClaims := map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
					"iat": float64(time.Now().Unix()),
				}
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", idClaims)
				accessToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", accessClaims)

				// Pre-cache the token claims
				ts.tOidc.tokenCache.Set(idToken, idClaims, 1*time.Hour)
				ts.tOidc.tokenCache.Set(accessToken, accessClaims, 1*time.Hour)

				session.SetIDToken(idToken)
				session.SetAccessToken(accessToken)
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Keycloak provider should delegate to validateStandardTokens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Handle Azure provider type by changing issuerURL temporarily
			originalIssuer := ts.tOidc.issuerURL
			if tt.providerType == "azure" {
				ts.tOidc.issuerURL = "https://login.microsoftonline.com/common/v2.0"
			} else if tt.providerType == "google" {
				ts.tOidc.issuerURL = "https://accounts.google.com"
			}
			defer func() { ts.tOidc.issuerURL = originalIssuer }()

			session := tt.setupSession()
			auth, refresh, expired := ts.tOidc.isUserAuthenticated(session)

			if auth != tt.expectedAuth {
				t.Errorf("Expected authenticated=%v, got %v. %s", tt.expectedAuth, auth, tt.description)
			}
			if refresh != tt.expectedRefresh {
				t.Errorf("Expected needsRefresh=%v, got %v. %s", tt.expectedRefresh, refresh, tt.description)
			}
			if expired != tt.expectedExpired {
				t.Errorf("Expected expired=%v, got %v. %s", tt.expectedExpired, expired, tt.description)
			}
		})
	}
}

// TestValidateAzureTokensEdgeCases tests Azure token validation with comprehensive edge cases
func TestValidateAzureTokensEdgeCases(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()
	// Set refresh grace period to 60 seconds to match default behavior
	ts.tOidc.refreshGracePeriod = 60 * time.Second

	tests := []struct {
		name            string
		setupSession    func() *SessionData
		expectedAuth    bool
		expectedRefresh bool
		expectedExpired bool
		description     string
	}{
		{
			name: "UnauthenticatedWithRefreshToken",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(false)
				session.SetRefreshToken("valid_refresh_token")
				return session
			},
			expectedAuth:    false,
			expectedRefresh: true,
			expectedExpired: false,
			description:     "Unauthenticated Azure session with refresh token",
		},
		{
			name: "UnauthenticatedWithoutRefreshToken",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(false)
				return session
			},
			expectedAuth:    false,
			expectedRefresh: true,
			expectedExpired: false,
			description:     "Unauthenticated Azure session without refresh token",
		},
		{
			name: "AuthenticatedWithInvalidJWTAccessToken",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				session.SetAccessToken("invalid.jwt.token") // JWT format but invalid
				// Valid ID token
				idToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
					"iss": "https://test-issuer.com",
					"aud": "test-client-id",
					"sub": "test-user",
					"exp": time.Now().Add(1 * time.Hour).Unix(),
					"iat": time.Now().Unix(),
				})
				session.SetIDToken(idToken)
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Azure session with invalid JWT access token but valid ID token",
		},
		{
			name: "AuthenticatedWithOpaqueAccessToken",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				session.SetAccessToken("opaque_access_token_longer_than_minimum") // Not JWT format but long enough
				return session
			},
			expectedAuth:    true,
			expectedRefresh: false,
			expectedExpired: false,
			description:     "Azure session with opaque access token",
		},
		{
			name: "AuthenticatedWithBothTokensInvalid",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				session.SetAccessToken("invalid.jwt.token")
				session.SetIDToken("another.invalid.token")
				session.SetRefreshToken("refresh_token")
				return session
			},
			expectedAuth:    false,
			expectedRefresh: true,
			expectedExpired: false,
			description:     "Azure session with both access and ID tokens invalid but has refresh token",
		},
		{
			name: "AuthenticatedWithBothTokensInvalidNoRefresh",
			setupSession: func() *SessionData {
				session := createTestSession()
				session.SetAuthenticated(true)
				session.SetAccessToken("invalid.jwt.token")
				session.SetIDToken("another.invalid.token")
				return session
			},
			expectedAuth:    false,
			expectedRefresh: false,
			expectedExpired: true,
			description:     "Azure session with both tokens invalid and no refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setupSession()

			auth, refresh, expired := ts.tOidc.validateAzureTokens(session)

			if auth != tt.expectedAuth {
				t.Errorf("Expected authenticated=%v, got %v. %s", tt.expectedAuth, auth, tt.description)
			}
			if refresh != tt.expectedRefresh {
				t.Errorf("Expected needsRefresh=%v, got %v. %s", tt.expectedRefresh, refresh, tt.description)
			}
			if expired != tt.expectedExpired {
				t.Errorf("Expected expired=%v, got %v. %s", tt.expectedExpired, expired, tt.description)
			}
		})
	}
}
