package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestReviewFailClosed_ExpiredJWTNoIDToken verifies the fail-closed contract:
// a JWT access token that fails verification (expired) with no ID token and
// no refresh token must NOT authenticate. Previously this path returned
// (authenticated=true) — fail-open, trusting an invalid access token.
func TestReviewFailClosed_ExpiredJWTNoIDToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	// Validly-signed but already-expired access token.
	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
		"iat": float64(time.Now().Add(-2 * time.Hour).Unix()),
		"sub": "test-user",
		"jti": "expired-access-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	session, err := ts.tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)
	// No ID token, no refresh token: nothing left to corroborate the access token.

	rs := (&requestState{}).captureSession(session)
	authenticated, needsRefresh, expired := ts.tOidc.validateStandardTokensRS(rs)
	if authenticated {
		t.Errorf("Expired JWT access token with no ID token must NOT authenticate. Got auth=%v refresh=%v expired=%v",
			authenticated, needsRefresh, expired)
	}
	if !expired {
		t.Errorf("Expired JWT access token with no ID token should force re-authentication (expired=true). Got expired=%v", expired)
	}
	if needsRefresh {
		t.Errorf("No refresh token present, needsRefresh must be false. Got %v", needsRefresh)
	}
}

// TestReviewFailClosed_ExpiredJWTWithRefreshRequestsRefresh verifies that an
// expired JWT access token with no ID token but an available refresh token is
// not authenticated but signals a refresh rather than failing open.
func TestReviewFailClosed_ExpiredJWTWithRefreshRequestsRefresh(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
		"iat": float64(time.Now().Add(-2 * time.Hour).Unix()),
		"sub": "test-user",
		"jti": "expired-access-with-refresh-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	session, err := ts.tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)
	session.SetRefreshToken("refresh-token")

	rs := (&requestState{}).captureSession(session)
	authenticated, needsRefresh, expired := ts.tOidc.validateStandardTokensRS(rs)
	if authenticated {
		t.Errorf("Expired access token must not authenticate even with refresh available. Got auth=%v", authenticated)
	}
	if !needsRefresh {
		t.Errorf("Expired access token with refresh token available should request refresh. Got needsRefresh=%v", needsRefresh)
	}
	if expired {
		t.Errorf("With refresh available, should prefer refresh over forced expiry. Got expired=%v", expired)
	}
}

// TestReview_ValidJWTAccessTokenNoIDToken_StillAuthenticates guards against
// over-correction: a still-valid JWT access token with no ID token must
// continue to authenticate (used by access-token-only providers like GitHub).
func TestReview_ValidJWTAccessTokenNoIDToken_StillAuthenticates(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
		"iat": float64(time.Now().Add(-2 * time.Minute).Unix()),
		"sub": "test-user",
		"jti": "valid-access-jti",
	})
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	session, err := ts.tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}
	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)

	rs := (&requestState{}).captureSession(session)
	authenticated, needsRefresh, expired := ts.tOidc.validateStandardTokensRS(rs)
	if !authenticated {
		t.Errorf("Valid JWT access token with no ID token should authenticate. Got auth=%v refresh=%v expired=%v",
			authenticated, needsRefresh, expired)
	}
}
