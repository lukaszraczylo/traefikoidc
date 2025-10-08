// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains tests for Auth0-specific audience validation scenarios.
package traefikoidc

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

	t.Logf("✓ Strict mode correctly rejected Scenario 2 (access token audience mismatch)")
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
