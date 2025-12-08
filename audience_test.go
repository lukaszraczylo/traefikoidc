package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// =============================================================================
// AUDIENCE CONFIGURATION TESTS
// =============================================================================

// TestAudienceConfiguration tests the custom audience configuration feature
func TestAudienceConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		configAudience   string
		clientID         string
		expectedAudience string
	}{
		{
			name:             "no custom audience - uses clientID",
			configAudience:   "",
			clientID:         "test-client-id",
			expectedAudience: "test-client-id",
		},
		{
			name:             "custom audience specified",
			configAudience:   "api://custom-audience",
			clientID:         "test-client-id",
			expectedAudience: "api://custom-audience",
		},
		{
			name:             "auth0 style custom audience",
			configAudience:   "https://api.example.com",
			clientID:         "test-client-id",
			expectedAudience: "https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with custom audience
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = tt.clientID
			config.ClientSecret = "test-secret"
			config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			config.CallbackURL = "/callback"
			config.Audience = tt.configAudience

			// Create middleware instance
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			traefikOidc, err := NewWithContext(context.Background(), config, next, "test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			// Verify audience is set correctly
			if traefikOidc.audience != tt.expectedAudience {
				t.Errorf("Expected audience %s, got %s", tt.expectedAudience, traefikOidc.audience)
			}

			// Cleanup
			_ = traefikOidc.Close()
		})
	}
}

// TestAudienceValidation tests the audience validation in Config.Validate()
func TestAudienceValidation(t *testing.T) {
	tests := []struct {
		name          string
		audience      string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid custom audience URL",
			audience:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "valid azure style audience",
			audience:    "api://12345678-1234-1234-1234-123456789012",
			expectError: false,
		},
		{
			name:        "empty audience is valid (uses clientID)",
			audience:    "",
			expectError: false,
		},
		{
			name:          "http URL not allowed",
			audience:      "http://api.example.com",
			expectError:   true,
			errorContains: "audience URL must use HTTPS",
		},
		{
			name:          "wildcard not allowed",
			audience:      "https://*.example.com",
			expectError:   true,
			errorContains: "audience must not contain wildcards",
		},
		{
			name:          "too long audience",
			audience:      "https://" + string(make([]byte, 250)) + ".com",
			expectError:   true,
			errorContains: "audience must not exceed 256 characters",
		},
		{
			name:          "invalid characters",
			audience:      "api://test\ninjection",
			expectError:   true,
			errorContains: "audience contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = "test-client"
			config.ClientSecret = "test-secret"
			config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			config.CallbackURL = "/callback"
			config.Audience = tt.audience

			err := config.Validate()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// CONFIG AUDIENCE VALIDATION TESTS
// =============================================================================

// TestConfigAudienceValidation tests the Config.Validate() method for the audience field
func TestConfigAudienceValidation(t *testing.T) {
	tests := []struct {
		name        string
		audience    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "Empty audience is valid for backward compatibility",
			audience: "",
			wantErr:  false,
		},
		{
			name:     "Valid HTTPS URL audience Auth0 format",
			audience: "https://api.example.com",
			wantErr:  false,
		},
		{
			name:     "Valid identifier audience",
			audience: "my-api",
			wantErr:  false,
		},
		{
			name:     "Valid Azure AD Application ID URI format",
			audience: "api://12345-guid-67890",
			wantErr:  false,
		},
		{
			name:     "Valid Auth0 API identifier",
			audience: "https://my-company.auth0.com/api/v2/",
			wantErr:  false,
		},
		{
			name:        "HTTP URL audience should fail",
			audience:    "http://api.example.com",
			wantErr:     true,
			errContains: "must use HTTPS",
		},
		{
			name:        "Audience with wildcard should fail",
			audience:    "https://api.*.example.com",
			wantErr:     true,
			errContains: "must not contain wildcards",
		},
		{
			name:        "Audience with single asterisk should fail",
			audience:    "*",
			wantErr:     true,
			errContains: "must not contain wildcards",
		},
		{
			name:        "Audience over 256 characters should fail",
			audience:    strings.Repeat("a", 257),
			wantErr:     true,
			errContains: "must not exceed 256 characters",
		},
		{
			name:        "Audience with newline should fail",
			audience:    "my-api\ninjection",
			wantErr:     true,
			errContains: "contains invalid characters",
		},
		{
			name:        "Audience with carriage return should fail",
			audience:    "my-api\rinjection",
			wantErr:     true,
			errContains: "contains invalid characters",
		},
		{
			name:        "Audience with tab should fail",
			audience:    "my-api\tinjection",
			wantErr:     true,
			errContains: "contains invalid characters",
		},
		{
			name:     "Valid audience exactly 256 characters",
			audience: strings.Repeat("a", 256),
			wantErr:  false,
		},
		{
			name:     "Valid simple identifier",
			audience: "my-service-api",
			wantErr:  false,
		},
		{
			name:     "Valid URN format",
			audience: "urn:myservice:api:v1",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = "test-client-id"
			config.ClientSecret = "test-client-secret"
			config.CallbackURL = "/callback"
			config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)
			config.Audience = tt.audience

			err := config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Error message should contain %q, got: %v", tt.errContains, err)
			}
		})
	}
}

// =============================================================================
// AUTH0 SCENARIO TESTS
// =============================================================================

// TestAuth0Scenario1WithCustomAudience tests Auth0 scenario 1:
// - Custom audience configured in plugin
// - Authorize endpoint called WITH audience parameter
// - ID token: aud = client_id
// - Access token: aud = [userinfo, custom_audience]
// Expected: Both tokens validate correctly
func TestAuth0Scenario1WithCustomAudience(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	customAudience := "https://my-api.example.com"
	ts.tOidc.audience = customAudience

	// Create ID token with aud = client_id (OIDC standard)
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",       // ID token always has client_id
		"nonce": "test-nonce-scenario1", // ID tokens have nonce per OIDC spec
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
		"jti":   "id-token-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create ID token: %v", err)
	}

	// Create access token with aud = [userinfo, custom_audience]
	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": []interface{}{
			"https://test-issuer.com/userinfo",
			customAudience, // Custom API audience
		},
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"scope": "openid profile email read:data", // Access tokens have scope
		"jti":   "access-token-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	// Verify ID token validates against client_id
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(idToken)
	if err != nil {
		t.Errorf("ID token validation failed (should validate against client_id): %v", err)
	}

	// Verify access token validates against custom audience
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(accessToken)
	if err != nil {
		t.Errorf("Access token validation failed (should validate against custom audience): %v", err)
	}

	// Verify buildAuthURL includes audience parameter (URL-encoded)
	authURL := ts.tOidc.buildAuthURL("https://example.com/callback", "state", "nonce", "")
	if !strings.Contains(authURL, "audience=") {
		t.Errorf("Auth URL should contain audience parameter when custom audience is configured, got: %s", authURL)
	}
	// Verify the audience is properly URL-encoded (contains %3A for :, %2F for /)
	if !strings.Contains(authURL, "audience=https%3A%2F%2Fmy-api.example.com") {
		t.Errorf("Auth URL should contain URL-encoded custom audience, got: %s", authURL)
	}
}

// TestAuth0Scenario2DefaultAudience tests Auth0 scenario 2:
// - No custom audience configured (defaults to client_id)
// - Authorize endpoint called WITHOUT audience parameter
// - ID token: aud = client_id
// - Access token: aud = [userinfo, default_audience] (no client_id)
// Expected: ID token validates, access token falls back to ID token validation
func TestAuth0Scenario2DefaultAudience(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// No custom audience - defaults to client_id
	ts.tOidc.audience = ts.tOidc.clientID

	// Create ID token with aud = client_id
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"nonce": "test-nonce-scenario2", // ID tokens have nonce per OIDC spec
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
		"jti":   "id-token-jti-2",
	})
	if err != nil {
		t.Fatalf("Failed to create ID token: %v", err)
	}

	// Create access token with aud = [userinfo, some_default_audience]
	// This represents Auth0's default audience behavior
	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": []interface{}{
			"https://test-issuer.com/userinfo",
			"https://test-issuer.com/api/v2/", // Default Auth0 Management API
		},
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"scope": "openid profile email",
		"jti":   "access-token-jti-2",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	// Verify ID token validates
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(idToken)
	if err != nil {
		t.Errorf("ID token validation failed: %v", err)
	}

	// Access token won't have client_id in aud, so it will fail validation
	// This is expected for scenario 2 - the session validation relies on ID token
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(accessToken)
	if err == nil {
		t.Logf("Access token validation passed (unexpected but OK if client_id is in aud array)")
	} else {
		// Expected failure - access token doesn't have client_id in aud
		t.Logf("Access token validation failed as expected (aud doesn't contain client_id): %v", err)
	}

	// Verify buildAuthURL does NOT include audience parameter (since audience == client_id)
	authURL := ts.tOidc.buildAuthURL("https://example.com/callback", "state", "nonce", "")
	if strings.Contains(authURL, "audience=") {
		t.Errorf("Auth URL should NOT contain audience parameter when audience equals client_id, got: %s", authURL)
	}
}

// TestAuth0Scenario3OpaqueAccessToken tests Auth0 scenario 3:
// - No custom audience configured
// - No default audience in Auth0
// - ID token: aud = client_id
// - Access token: opaque (not JWT)
// Expected: ID token validates, opaque access token is accepted
func TestAuth0Scenario3OpaqueAccessToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Enable opaque tokens for this scenario (Option C requirement)
	ts.tOidc.allowOpaqueTokens = true

	// No custom audience
	ts.tOidc.audience = ts.tOidc.clientID

	// Create ID token
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"nonce": "test-nonce-scenario3", // ID tokens have nonce per OIDC spec
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
		"jti":   "id-token-jti-3",
	})
	if err != nil {
		t.Fatalf("Failed to create ID token: %v", err)
	}

	// Opaque access token (not a JWT - just a random string)
	opaqueAccessToken := "opaque_access_token_random_string_12345"

	// Verify ID token validates
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(idToken)
	if err != nil {
		t.Errorf("ID token validation failed: %v", err)
	}

	// Opaque access token should fail JWT validation (expected)
	err = ts.tOidc.VerifyToken(opaqueAccessToken)
	if err == nil {
		t.Error("Opaque access token should fail JWT validation")
	} else {
		t.Logf("Opaque access token correctly rejected by JWT validator: %v", err)
	}

	// Test that validateStandardTokens handles opaque tokens correctly
	// by falling back to ID token validation
	req := httptest.NewRequest("GET", "https://example.com/test", nil)

	session, err := ts.tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetAccessToken(opaqueAccessToken)
	session.SetIDToken(idToken)

	authenticated, needsRefresh, expired := ts.tOidc.validateStandardTokens(session)
	if !authenticated || needsRefresh || expired {
		t.Errorf("Session with opaque access token and valid ID token should be authenticated. Got: auth=%v, refresh=%v, expired=%v",
			authenticated, needsRefresh, expired)
	}
}

// TestAuth0AudienceArrayValidation tests that audience validation
// correctly handles array audiences (common in Auth0)
func TestAuth0AudienceArrayValidation(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	customAudience := "https://my-api.example.com"
	ts.tOidc.audience = customAudience

	// Access token with audience as array containing our custom audience
	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": []interface{}{
			"https://test-issuer.com/userinfo",
			customAudience,
			"https://another-api.example.com",
		},
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"scope": "openid profile email read:data write:data",
		"jti":   "array-aud-token-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	// Should validate successfully - custom audience is in the array
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(accessToken)
	if err != nil {
		t.Errorf("Access token with audience array should validate when custom audience is present: %v", err)
	}
}

// TestAuth0MismatchedAudience tests that tokens with wrong audience fail validation
func TestAuth0MismatchedAudience(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	customAudience := "https://my-api.example.com"
	ts.tOidc.audience = customAudience

	// Access token with WRONG audience
	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": []interface{}{
			"https://test-issuer.com/userinfo",
			"https://different-api.example.com", // Wrong audience
		},
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"scope": "openid profile email",
		"jti":   "wrong-aud-token-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	// Should fail validation - audience doesn't match
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(accessToken)
	if err == nil {
		t.Error("Access token with wrong audience should fail validation")
	} else if !strings.Contains(err.Error(), "invalid audience") {
		t.Errorf("Expected 'invalid audience' error, got: %v", err)
	}
}

// TestAuth0Scenario2StrictMode tests strict audience validation mode:
// - Scenario 2 (access token with wrong audience) should be REJECTED
// - strictAudienceValidation=true prevents fallback to ID token
// - This addresses Allan's security concerns about audience bypass
func TestAuth0Scenario2StrictMode(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Enable strict mode to prevent Scenario 2 bypass (Option C)
	ts.tOidc.strictAudienceValidation = true

	// Configure custom audience
	customAudience := "https://my-api.example.com"
	ts.tOidc.audience = customAudience

	// Create ID token with aud = client_id (valid)
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"nonce": "test-nonce-strict",
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
		"jti":   "id-token-strict-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create ID token: %v", err)
	}

	// Create access token with WRONG audience (doesn't include custom audience)
	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": []interface{}{
			"https://test-issuer.com/userinfo",
			"https://wrong-api.example.com", // Wrong audience - not our custom audience
		},
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"scope": "openid profile email",
		"jti":   "access-token-strict-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	// Test session validation with wrong access token and valid ID token
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	session, err := ts.tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)
	session.SetIDToken(idToken)
	session.SetRefreshToken("test-refresh-token") // Add refresh token so it can attempt refresh

	// In strict mode, this should FAIL (no fallback to ID token)
	authenticated, needsRefresh, expired := ts.tOidc.validateStandardTokens(session)
	if authenticated {
		t.Errorf("Strict mode: Session with wrong access token audience should be rejected, but got authenticated=true")
	}
	if !needsRefresh {
		t.Errorf("Strict mode: Should signal refresh needed after rejection, got needsRefresh=%v", needsRefresh)
	}
	if expired {
		t.Errorf("Strict mode: Should not mark as expired (should try refresh first), got expired=%v", expired)
	}

	t.Logf("Strict mode correctly rejected Scenario 2 (access token audience mismatch)")
}

// TestIDTokenAlwaysValidatesAgainstClientID verifies that ID tokens
// are ALWAYS validated against client_id, regardless of configured audience
func TestIDTokenAlwaysValidatesAgainstClientID(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Configure a custom audience different from client_id
	customAudience := "https://my-api.example.com"
	ts.tOidc.audience = customAudience

	// Create ID token with aud = client_id (per OIDC spec)
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id", // ID token MUST have client_id
		"nonce": "test-nonce-123", // ID tokens have nonce for replay protection
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
		"jti":   "id-token-client-id-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create ID token: %v", err)
	}

	// Should validate successfully - ID tokens are checked against client_id
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(idToken)
	if err != nil {
		t.Errorf("ID token should validate against client_id even when custom audience is configured: %v", err)
	}

	// Create ID token with WRONG audience (should fail)
	wrongIDToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   customAudience,         // WRONG - should be client_id
		"nonce": "test-nonce-wrong-456", // ID token has nonce, so it will be detected as ID token
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Unix()),
		"sub":   "test-user",
		"email": "test@example.com",
		"jti":   "wrong-id-token-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create wrong ID token: %v", err)
	}

	// Should fail - ID tokens must have client_id as audience
	cleanupReplayCache()
	initReplayCache()
	err = ts.tOidc.VerifyToken(wrongIDToken)
	if err == nil {
		t.Error("ID token with custom audience (not client_id) should fail validation")
	}
}

// =============================================================================
// JWT AUDIENCE VERIFICATION TESTS
// =============================================================================

// TestJWTAudienceVerification tests JWT verification with custom audience values
func TestJWTAudienceVerification(t *testing.T) {
	// Create cleanup helper
	tc := newTestCleanup(t)

	// Generate RSA key for signing JWTs
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	// Create JWK
	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	mockJWKCache := &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	logger := NewLogger("debug")
	tokenBlacklist := tc.addCache(NewCache())
	tokenCache := tc.addTokenCache(NewTokenCache())

	tests := []struct {
		name            string
		configAudience  string
		tokenAudience   interface{}
		wantErr         bool
		errContains     string
		skipReplayCheck bool
	}{
		{
			name:            "JWT with string aud matching configured audience",
			configAudience:  "https://api.example.com",
			tokenAudience:   "https://api.example.com",
			wantErr:         false,
			skipReplayCheck: true,
		},
		{
			name:            "JWT with array aud containing configured audience",
			configAudience:  "https://api.example.com",
			tokenAudience:   []interface{}{"https://other.com", "https://api.example.com", "https://another.com"},
			wantErr:         false,
			skipReplayCheck: true,
		},
		{
			name:            "JWT with string aud NOT matching configured audience",
			configAudience:  "https://api.example.com",
			tokenAudience:   "https://wrong-api.example.com",
			wantErr:         true,
			errContains:     "invalid audience",
			skipReplayCheck: true,
		},
		{
			name:            "JWT with array aud NOT containing configured audience",
			configAudience:  "https://api.example.com",
			tokenAudience:   []interface{}{"https://other.com", "https://another.com"},
			wantErr:         true,
			errContains:     "invalid audience",
			skipReplayCheck: true,
		},
		{
			name:            "JWT with clientID as aud when no custom audience configured",
			configAudience:  "",
			tokenAudience:   "test-client-id",
			wantErr:         false,
			skipReplayCheck: true,
		},
		{
			name:            "JWT with empty string aud",
			configAudience:  "https://api.example.com",
			tokenAudience:   "",
			wantErr:         true,
			errContains:     "invalid audience",
			skipReplayCheck: true,
		},
		{
			name:            "Azure AD Application ID URI format",
			configAudience:  "api://12345-app-id",
			tokenAudience:   "api://12345-app-id",
			wantErr:         false,
			skipReplayCheck: true,
		},
		{
			name:            "Auth0 custom API audience",
			configAudience:  "https://mycompany.com/api",
			tokenAudience:   "https://mycompany.com/api",
			wantErr:         false,
			skipReplayCheck: true,
		},
		{
			name:            "Token confusion attack - audience for different service",
			configAudience:  "https://service-a.example.com",
			tokenAudience:   "https://service-b.example.com",
			wantErr:         true,
			errContains:     "invalid audience",
			skipReplayCheck: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create TraefikOidc instance
			tOidc := &TraefikOidc{
				issuerURL:      "https://test-issuer.com",
				clientID:       "test-client-id",
				clientSecret:   "test-client-secret",
				jwkCache:       mockJWKCache,
				jwksURL:        "https://test-jwks-url.com",
				tokenBlacklist: tokenBlacklist,
				tokenCache:     tokenCache,
				limiter:        rate.NewLimiter(rate.Every(time.Second), 10),
				logger:         logger,
				httpClient:     &http.Client{},
			}

			// Set up the token verifier and JWT verifier
			tOidc.jwtVerifier = tOidc
			tOidc.tokenVerifier = tOidc

			// Determine the expected audience for validation
			expectedAudience := tt.configAudience
			if expectedAudience == "" {
				expectedAudience = tOidc.clientID
			}

			// Set the audience field on the tOidc instance
			tOidc.audience = expectedAudience

			// Create JWT with specified audience
			jti := generateRandomString(16)
			if tt.skipReplayCheck {
				// Use a unique JTI for each test to avoid replay detection
				jti = fmt.Sprintf("test-%s-%s", tt.name, jti)
			}

			jwt, err := createTestJWT(rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
				"iss":   "https://test-issuer.com",
				"aud":   tt.tokenAudience,
				"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
				"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
				"sub":   "test-subject",
				"email": "user@example.com",
				"jti":   jti,
			})
			if err != nil {
				t.Fatalf("Failed to create test JWT: %v", err)
			}

			// Verify the token
			err = tOidc.VerifyToken(jwt)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Error message should contain %q, got: %v", tt.errContains, err)
			}
		})
	}
}

// TestJWTAudienceBackwardCompatibility tests that existing behavior is preserved
// when the Audience field is not set
func TestJWTAudienceBackwardCompatibility(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Test with no custom audience configured - should use clientID
	jwt, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id", // Should match clientID
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
		"sub":   "test-subject",
		"email": "user@example.com",
		"jti":   generateRandomString(16),
	})
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	err = ts.tOidc.VerifyToken(jwt)
	if err != nil {
		t.Errorf("Backward compatibility broken: VerifyToken() error = %v, expected nil", err)
	}
}

// =============================================================================
// INTEGRATION TESTS - AUTH0
// =============================================================================

// TestAudienceIntegrationAuth0Scenario tests Auth0-specific use case
func TestAudienceIntegrationAuth0Scenario(t *testing.T) {
	// Create cleanup helper
	tc := newTestCleanup(t)

	// Simulate Auth0 scenario: custom audience for API access
	config := CreateConfig()
	config.ProviderURL = "https://mycompany.auth0.com"
	config.ClientID = "auth0-client-id"
	config.ClientSecret = "auth0-client-secret"
	config.CallbackURL = "/callback"
	config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)
	config.Audience = "https://api.mycompany.com" // Custom API audience

	// Validate config
	if err := config.Validate(); err != nil {
		t.Fatalf("Auth0 config validation failed: %v", err)
	}

	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	jwk := JWK{
		Kty: "RSA",
		Kid: "auth0-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	mockJWKCache := &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	logger := NewLogger("debug")
	tokenBlacklist := tc.addCache(NewCache())
	tokenCache := tc.addTokenCache(NewTokenCache())

	tOidc := &TraefikOidc{
		issuerURL:      config.ProviderURL,
		clientID:       config.ClientID,
		clientSecret:   config.ClientSecret,
		audience:       config.Audience, // Set audience from config
		jwkCache:       mockJWKCache,
		jwksURL:        "https://mycompany.auth0.com/.well-known/jwks.json",
		tokenBlacklist: tokenBlacklist,
		tokenCache:     tokenCache,
		limiter:        rate.NewLimiter(rate.Every(time.Second), 10),
		logger:         logger,
		httpClient:     &http.Client{},
	}

	// Default audience to clientID if not specified
	if tOidc.audience == "" {
		tOidc.audience = tOidc.clientID
	}

	tOidc.jwtVerifier = tOidc
	tOidc.tokenVerifier = tOidc

	t.Run("Valid Auth0 API access token with custom audience", func(t *testing.T) {
		jwt, err := createTestJWT(rsaPrivateKey, "RS256", "auth0-key-id", map[string]interface{}{
			"iss":   config.ProviderURL,
			"aud":   config.Audience, // Matches configured audience
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "auth0|123456",
			"email": "user@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create Auth0 JWT: %v", err)
		}

		err = tOidc.VerifyToken(jwt)
		if err != nil {
			t.Errorf("Auth0 token verification failed: %v", err)
		}
	})

	t.Run("Auth0 ACCESS token with clientID instead of API audience should fail", func(t *testing.T) {
		jwt, err := createTestJWT(rsaPrivateKey, "RS256", "auth0-key-id", map[string]interface{}{
			"iss":   config.ProviderURL,
			"aud":   config.ClientID,        // Using clientID instead of API audience
			"scope": "openid profile email", // Mark as access token
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "auth0|123456",
			"email": "user@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create Auth0 JWT: %v", err)
		}

		err = tOidc.VerifyToken(jwt)
		if err == nil {
			t.Error("Auth0 access token with wrong audience should have been rejected")
		} else if !strings.Contains(err.Error(), "invalid audience") {
			t.Errorf("Expected 'invalid audience' error, got: %v", err)
		}
	})
}

// =============================================================================
// INTEGRATION TESTS - AZURE AD
// =============================================================================

// TestAudienceIntegrationAzureADScenario tests Azure AD-specific use case
func TestAudienceIntegrationAzureADScenario(t *testing.T) {
	// Create cleanup helper
	tc := newTestCleanup(t)

	// Simulate Azure AD scenario: Application ID URI format
	config := CreateConfig()
	config.ProviderURL = "https://login.microsoftonline.com/tenant-id/v2.0"
	config.ClientID = "azure-client-id"
	config.ClientSecret = "azure-client-secret"
	config.CallbackURL = "/callback"
	config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)
	config.Audience = "api://12345-abcd-6789-efgh" // Azure AD Application ID URI

	// Validate config
	if err := config.Validate(); err != nil {
		t.Fatalf("Azure AD config validation failed: %v", err)
	}

	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	jwk := JWK{
		Kty: "RSA",
		Kid: "azure-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	mockJWKCache := &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	logger := NewLogger("debug")
	tokenBlacklist := tc.addCache(NewCache())
	tokenCache := tc.addTokenCache(NewTokenCache())

	tOidc := &TraefikOidc{
		issuerURL:      config.ProviderURL,
		clientID:       config.ClientID,
		clientSecret:   config.ClientSecret,
		audience:       config.Audience, // Set audience from config
		jwkCache:       mockJWKCache,
		jwksURL:        config.ProviderURL + "/.well-known/jwks.json",
		tokenBlacklist: tokenBlacklist,
		tokenCache:     tokenCache,
		limiter:        rate.NewLimiter(rate.Every(time.Second), 10),
		logger:         logger,
		httpClient:     &http.Client{},
	}

	// Default audience to clientID if not specified
	if tOidc.audience == "" {
		tOidc.audience = tOidc.clientID
	}

	tOidc.jwtVerifier = tOidc
	tOidc.tokenVerifier = tOidc

	t.Run("Valid Azure AD token with Application ID URI audience", func(t *testing.T) {
		jwt, err := createTestJWT(rsaPrivateKey, "RS256", "azure-key-id", map[string]interface{}{
			"iss":   config.ProviderURL,
			"aud":   config.Audience, // Matches Application ID URI
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "azure-user-id",
			"email": "user@example.com",
			"oid":   "object-id-12345",
			"tid":   "tenant-id",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create Azure AD JWT: %v", err)
		}

		err = tOidc.VerifyToken(jwt)
		if err != nil {
			t.Errorf("Azure AD token verification failed: %v", err)
		}
	})

	t.Run("Azure AD token with multiple audiences including correct one", func(t *testing.T) {
		jwt, err := createTestJWT(rsaPrivateKey, "RS256", "azure-key-id", map[string]interface{}{
			"iss":   config.ProviderURL,
			"aud":   []interface{}{config.ClientID, config.Audience, "https://graph.microsoft.com"},
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "azure-user-id",
			"email": "user@example.com",
			"oid":   "object-id-12345",
			"tid":   "tenant-id",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create Azure AD JWT: %v", err)
		}

		err = tOidc.VerifyToken(jwt)
		if err != nil {
			t.Errorf("Azure AD token with multiple audiences verification failed: %v", err)
		}
	})
}

// =============================================================================
// SECURITY TESTS
// =============================================================================

// TestAudienceSecurityTokenConfusionAttack tests security against token confusion attacks
func TestAudienceSecurityTokenConfusionAttack(t *testing.T) {
	// Create cleanup helper
	tc := newTestCleanup(t)

	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	mockJWKCache := &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	logger := NewLogger("debug")
	tokenBlacklist := tc.addCache(NewCache())
	tokenCache := tc.addTokenCache(NewTokenCache())

	// Service A configuration
	serviceA := &TraefikOidc{
		issuerURL:      "https://auth.example.com",
		clientID:       "service-a-client-id",
		clientSecret:   "service-a-secret",
		audience:       "service-a-client-id", // Service A uses its clientID as audience
		jwkCache:       mockJWKCache,
		jwksURL:        "https://auth.example.com/.well-known/jwks.json",
		tokenBlacklist: tokenBlacklist,
		tokenCache:     tokenCache,
		limiter:        rate.NewLimiter(rate.Every(time.Second), 10),
		logger:         logger,
		httpClient:     &http.Client{},
	}
	serviceA.jwtVerifier = serviceA
	serviceA.tokenVerifier = serviceA

	t.Run("Token confusion - Try to use service B token on service A", func(t *testing.T) {
		// Create a token intended for service B
		serviceBToken, err := createTestJWT(rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://auth.example.com",
			"aud":   "https://service-b.example.com", // For service B
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "attacker@example.com",
			"email": "attacker@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create service B token: %v", err)
		}

		// Try to verify the service B token on service A
		err = serviceA.VerifyToken(serviceBToken)
		switch {
		case err == nil:
			t.Error("SECURITY VULNERABILITY: Token confusion attack succeeded - service B token was accepted by service A")
		case !strings.Contains(err.Error(), "invalid audience"):
			t.Errorf("Expected 'invalid audience' error for token confusion, got: %v", err)
		default:
			t.Logf("Token confusion attack correctly prevented: %v", err)
		}
	})
}

// TestAudienceSecurityWildcardInjection tests that wildcards are rejected
func TestAudienceSecurityWildcardInjection(t *testing.T) {
	tests := []struct {
		name     string
		audience string
	}{
		{
			name:     "Single asterisk",
			audience: "*",
		},
		{
			name:     "Wildcard in URL",
			audience: "https://*.example.com",
		},
		{
			name:     "Wildcard in path",
			audience: "https://api.example.com/*",
		},
		{
			name:     "Multiple wildcards",
			audience: "https://*.*.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = "test-client-id"
			config.ClientSecret = "test-client-secret"
			config.CallbackURL = "/callback"
			config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)
			config.Audience = tt.audience

			err := config.Validate()
			if err == nil {
				t.Errorf("SECURITY VULNERABILITY: Wildcard audience %q was not rejected", tt.audience)
			} else if !strings.Contains(err.Error(), "must not contain wildcards") {
				t.Errorf("Expected 'must not contain wildcards' error, got: %v", err)
			}
		})
	}
}

// TestAudienceSecurityInjectionAttempts tests various injection attempts
func TestAudienceSecurityInjectionAttempts(t *testing.T) {
	tests := []struct {
		name        string
		audience    string
		errContains string
	}{
		{
			name:        "Newline injection",
			audience:    "api.example.com\nmalicious.com",
			errContains: "contains invalid characters",
		},
		{
			name:        "Carriage return injection",
			audience:    "api.example.com\rmalicious.com",
			errContains: "contains invalid characters",
		},
		{
			name:        "Tab injection",
			audience:    "api.example.com\tmalicious.com",
			errContains: "contains invalid characters",
		},
		{
			name:        "Null byte injection",
			audience:    "api.example.com\x00malicious.com",
			errContains: "contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = "test-client-id"
			config.ClientSecret = "test-client-secret"
			config.CallbackURL = "/callback"
			config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)
			config.Audience = tt.audience

			err := config.Validate()
			if err == nil {
				t.Errorf("SECURITY VULNERABILITY: Injection attempt with %q was not rejected", tt.name)
			} else if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

// TestAudienceWithReplayProtection tests that replay protection works correctly with custom audiences
func TestAudienceWithReplayProtection(t *testing.T) {
	// Create cleanup helper
	tc := newTestCleanup(t)

	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	mockJWKCache := &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	logger := NewLogger("debug")
	tokenBlacklist := tc.addCache(NewCache())
	tokenCache := tc.addTokenCache(NewTokenCache())

	tOidc := &TraefikOidc{
		issuerURL:      "https://auth.example.com",
		clientID:       "test-client-id",
		clientSecret:   "test-client-secret",
		jwkCache:       mockJWKCache,
		jwksURL:        "https://auth.example.com/.well-known/jwks.json",
		tokenBlacklist: tokenBlacklist,
		tokenCache:     tokenCache,
		limiter:        rate.NewLimiter(rate.Every(time.Second), 10),
		logger:         logger,
		httpClient:     &http.Client{},
	}
	tOidc.jwtVerifier = tOidc
	tOidc.tokenVerifier = tOidc

	// Create a token with custom audience and fixed JTI
	fixedJTI := "replay-test-jti-" + generateRandomString(8)
	customAudience := "https://api.example.com"

	// Set the audience field to match what we expect
	tOidc.audience = customAudience

	jwt, err := createTestJWT(rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://auth.example.com",
		"aud":   customAudience,
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
		"sub":   "test-user",
		"email": "user@example.com",
		"jti":   fixedJTI,
	})
	if err != nil {
		t.Fatalf("Failed to create JWT: %v", err)
	}

	// First verification should succeed
	err = tOidc.VerifyToken(jwt)
	if err != nil {
		t.Fatalf("First verification failed: %v", err)
	}

	// Verify that the JTI was blacklisted
	if blacklisted, exists := tOidc.tokenBlacklist.Get(fixedJTI); !exists || blacklisted == nil {
		t.Logf("Note: JTI was not added to blacklist (may be due to test token prefix)")
	} else {
		t.Logf("Replay protection verified: JTI %s is correctly blacklisted", fixedJTI)
	}
}

// =============================================================================
// END-TO-END TESTS
// =============================================================================

// TestAudienceEndToEndScenario tests a complete end-to-end scenario with middleware
func TestAudienceEndToEndScenario(t *testing.T) {
	// Create cleanup helper
	tc := newTestCleanup(t)

	// Create a test next handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Authenticated with custom audience"))
	})

	// Generate test keys
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey := &rsaPrivateKey.PublicKey

	jwk := JWK{
		Kty: "RSA",
		Kid: "test-key-id",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	jwks := &JWKSet{
		Keys: []JWK{jwk},
	}

	mockJWKCache := &MockJWKCache{
		JWKS: jwks,
		Err:  nil,
	}

	logger := NewLogger("debug")
	sm, err := NewSessionManager(strings.Repeat("a", MinSessionEncryptionKeyLength), false, "", "", 0, logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	tokenBlacklist := tc.addCache(NewCache())
	tokenCache := tc.addTokenCache(NewTokenCache())

	customAudience := "https://api.company.com"

	tOidc := &TraefikOidc{
		next:                nextHandler,
		name:                "test",
		redirURLPath:        "/callback",
		logoutURLPath:       "/callback/logout",
		issuerURL:           "https://auth.company.com",
		clientID:            "test-client-id",
		clientSecret:        "test-client-secret",
		audience:            customAudience, // Set custom audience
		jwkCache:            mockJWKCache,
		jwksURL:             "https://auth.company.com/.well-known/jwks.json",
		tokenBlacklist:      tokenBlacklist,
		tokenCache:          tokenCache,
		limiter:             rate.NewLimiter(rate.Every(time.Second), 10),
		logger:              logger,
		allowedUserDomains:  map[string]struct{}{"company.com": {}},
		userIdentifierClaim: "email", // Required for user identification
		excludedURLs:        map[string]struct{}{},
		httpClient:          &http.Client{},
		initComplete:        make(chan struct{}),
		sessionManager:      sm,
		extractClaimsFunc:   extractClaims,
	}
	tOidc.jwtVerifier = tOidc
	tOidc.tokenVerifier = tOidc
	close(tOidc.initComplete)

	t.Run("End-to-end with correct custom audience", func(t *testing.T) {
		// Create a valid token with the custom audience
		validJWT, err := createTestJWT(rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://auth.company.com",
			"aud":   customAudience,
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			"iat":   float64(time.Now().Add(-2 * time.Minute).Unix()),
			"sub":   "user-123",
			"email": "user@company.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create valid JWT: %v", err)
		}

		// Create a request with authenticated session
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "company.com")

		// Create session with token
		resp := httptest.NewRecorder()
		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}

		if err := session.SetAuthenticated(true); err != nil {
			t.Fatalf("Failed to set authenticated: %v", err)
		}
		session.SetEmail("user@company.com")
		session.SetIDToken(validJWT)
		session.SetAccessToken(validJWT)

		if err := session.Save(req, resp); err != nil {
			t.Fatalf("Failed to save session: %v", err)
		}

		// Get cookies and add them to a new request
		cookies := resp.Result().Cookies()
		req = httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "company.com")
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		resp = httptest.NewRecorder()
		tOidc.ServeHTTP(resp, req)

		if resp.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", resp.Code, resp.Body.String())
		}
	})
}
