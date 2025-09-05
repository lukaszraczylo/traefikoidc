package traefikoidc

import (
	"strings"
	"testing"
	"time"
)

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

// TestStartMetadataRefresh tests the metadata refresh functionality
func TestStartMetadataRefresh(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	tests := []struct {
		name        string
		providerURL string
		description string
	}{
		{
			name:        "SuccessfulMetadataRefresh",
			providerURL: "https://test-issuer.com",
			description: "Should start metadata refresh successfully",
		},
		{
			name:        "MetadataRefreshWithEmptyURL",
			providerURL: "",
			description: "Should handle empty provider URL gracefully",
		},
		{
			name:        "MetadataRefreshWithInvalidURL",
			providerURL: "invalid-url",
			description: "Should handle invalid provider URL gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start metadata refresh (this should not panic or error immediately)
			ts.tOidc.startMetadataRefresh(tt.providerURL)

			// Give some time for goroutine to start
			time.Sleep(100 * time.Millisecond)

			// The function should return successfully
			// We can't easily test the periodic behavior without making tests very slow,
			// but we test that it starts without issues
		})
	}
}

// TestStartMetadataRefreshContextCancellation tests context cancellation handling
func TestStartMetadataRefreshContextCancellation(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Mock the context cancellation by closing the plugin
	ts.tOidc.startMetadataRefresh("https://test-issuer.com")

	// Give some time for goroutine to start
	time.Sleep(100 * time.Millisecond)

	// Close the plugin to test cleanup
	ts.tOidc.Close()

	// Give some time for cleanup
	time.Sleep(100 * time.Millisecond)

	// Test passes if no goroutines are leaked (checked by other tests)
}

// MockReadCloser implements io.ReadCloser for testing HTTP responses
type MockReadCloser struct {
	*strings.Reader
}

func (m *MockReadCloser) Close() error {
	return nil
}
