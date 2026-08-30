package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestStandardExpiredAccessTokenWithValidIDToken_RequestsRefresh guards the
// auth-gate decision when the JWT access token has EXPIRED but the session's
// ID token is still valid. Previously the gate fell back to ID-token expiry
// (validateTokenExpiryRS(rs, rs.idToken)) and returned authenticated with
// needsRefresh=false, so the expired access token was forwarded to the
// upstream resource as-is and no refresh ran until the longer-lived ID
// token itself neared expiry — contradicting the middleware's documented
// rule that refresh follows ACCESS-token expiry (middleware.go:232-235).
// Now a validly-signed-but-expired access token requests a refresh.
func TestStandardExpiredAccessTokenWithValidIDToken_RequestsRefresh(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cleanupReplayCache()
	initReplayCache()
	defer cleanupReplayCache()

	now := time.Now()

	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   float64(now.Add(-time.Hour).Unix()), // EXPIRED
		"iat":   float64(now.Add(-2 * time.Hour).Unix()),
		"nbf":   float64(now.Add(-2 * time.Hour).Unix()),
		"sub":   "test-user",
		"scope": "openid profile email",
		"jti":   "r131-expired-access",
	})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   float64(now.Add(time.Hour).Unix()), // still valid
		"iat":   float64(now.Add(-2 * time.Minute).Unix()),
		"nbf":   float64(now.Add(-2 * time.Minute).Unix()),
		"sub":   "test-user",
		"nonce": "test-nonce",
	})
	if err != nil {
		t.Fatalf("create id token: %v", err)
	}

	session, err := ts.tOidc.sessionManager.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)
	session.SetIDToken(idToken)
	session.SetRefreshToken("refresh-token-123")

	rs := (&requestState{}).captureSession(session)
	authenticated, needsRefresh, reauth := ts.tOidc.validateStandardTokensRS(rs)

	if !authenticated {
		t.Fatalf("session is still authenticated via the valid ID token (auth=%v refresh=%v reauth=%v)", authenticated, needsRefresh, reauth)
	}
	if !needsRefresh {
		t.Fatalf("expired access token with valid ID token must request refresh, got auth=%v refresh=%v reauth=%v", authenticated, needsRefresh, reauth)
	}
}

// Control: a still-valid access token (with a valid ID token) requires no
// refresh — the fix must not cause spurious refreshes.
func TestStandardValidAccessTokenWithValidIDToken_NoRefresh(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cleanupReplayCache()
	initReplayCache()
	defer cleanupReplayCache()

	now := time.Now()

	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   float64(now.Add(time.Hour).Unix()), // still valid
		"iat":   float64(now.Add(-2 * time.Minute).Unix()),
		"nbf":   float64(now.Add(-2 * time.Minute).Unix()),
		"sub":   "test-user",
		"scope": "openid profile email",
		"jti":   "r131-valid-access",
	})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss":   "https://test-issuer.com",
		"aud":   "test-client-id",
		"exp":   float64(now.Add(time.Hour).Unix()),
		"iat":   float64(now.Add(-2 * time.Minute).Unix()),
		"nbf":   float64(now.Add(-2 * time.Minute).Unix()),
		"sub":   "test-user",
		"nonce": "test-nonce",
	})
	if err != nil {
		t.Fatalf("create id token: %v", err)
	}

	session, err := ts.tOidc.sessionManager.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)
	session.SetIDToken(idToken)
	session.SetRefreshToken("refresh-token-123")

	rs := (&requestState{}).captureSession(session)
	authenticated, needsRefresh, _ := ts.tOidc.validateStandardTokensRS(rs)

	if !authenticated {
		t.Fatalf("valid session must authenticate")
	}
	if needsRefresh {
		t.Fatalf("still-valid access token must not request refresh")
	}
}
