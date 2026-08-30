package traefikoidc

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestLenientAudienceRequiresUnexpiredAccessToken verifies that on the
// default (lenient) audience-validation path, an access token with a valid
// signature but wrong audience is still required to be unexpired before it is
// accepted as authenticated. Previously jwt.Verify short-circuits at the aud
// check before the exp check, so an expired wrong-audience access token (with
// no ID token to corroborate it) was accepted without expiry ever being
// checked, and its claims were trusted for RBAC.
func TestLenientAudienceRequiresUnexpiredAccessToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()
	ts.tOidc.audience = "https://my-api.example.com"
	ts.tOidc.strictAudienceValidation = false // default lenient

	cleanupReplayCache()
	initReplayCache()
	defer cleanupReplayCache()

	t.Run("expired wrong-audience token rejected", func(t *testing.T) {
		accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   []interface{}{"https://other-api.example.com"}, // wrong audience
			"exp":   float64(time.Now().Add(-1 * time.Hour).Unix()), // EXPIRED
			"iat":   float64(time.Now().Add(-2 * time.Hour).Unix()),
			"sub":   "test-user",
			"scope": "openid profile email",
			"jti":   "r66-lenient-expired",
		})
		if err != nil {
			t.Fatalf("failed to create access token: %v", err)
		}

		session, err := ts.tOidc.sessionManager.GetSession(httptest.NewRequest("GET", "/", nil))
		if err != nil {
			t.Fatal(err)
		}
		session.SetAuthenticated(true)
		session.SetAccessToken(accessToken)
		session.SetIDToken("")
		session.SetRefreshToken("") // no refresh: must force re-auth, not accept

		rs := (&requestState{}).captureSession(session)
		authenticated, _, expired := ts.tOidc.validateStandardTokensRS(rs)
		if authenticated {
			t.Fatal("expired wrong-audience access token was accepted as authenticated (expiry not checked on lenient path)")
		}
		if !expired {
			t.Log("note: force-re-auth path chosen (expired flag not set)")
		}
	})

	t.Run("unexpired wrong-audience token still accepted (lenient preserved)", func(t *testing.T) {
		accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://test-issuer.com",
			"aud":   []interface{}{"https://other-api.example.com"}, // wrong audience
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),  // still valid
			"iat":   float64(time.Now().Unix()),
			"sub":   "test-user",
			"scope": "openid profile email",
			"jti":   "r66-lenient-valid",
		})
		if err != nil {
			t.Fatalf("failed to create access token: %v", err)
		}

		session, err := ts.tOidc.sessionManager.GetSession(httptest.NewRequest("GET", "/", nil))
		if err != nil {
			t.Fatal(err)
		}
		session.SetAuthenticated(true)
		session.SetAccessToken(accessToken)
		session.SetIDToken("")
		session.SetRefreshToken("")

		rs := (&requestState{}).captureSession(session)
		authenticated, _, _ := ts.tOidc.validateStandardTokensRS(rs)
		if !authenticated {
			t.Fatal("unexpired wrong-audience access token should still be accepted under lenient audience validation")
		}
	})
}
