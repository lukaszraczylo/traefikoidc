package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRefreshToken_EmptyAccessTokenKeepsPrevious is a regression for the
// refresh path storing an empty access token: validateStandardTokensRS treats
// a stored empty access token (with a refresh token present) as "needs
// refresh", so persisting it made every subsequent request re-trigger a
// refresh (an infinite refresh loop). The fix keeps the previous tokens and
// reports the refresh as failed instead.
func TestRefreshToken_EmptyAccessTokenKeepsPrevious(t *testing.T) {
	testLogger := newNoOpLogger()

	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		testLogger,
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	oidc := &TraefikOidc{
		logger:        testLogger,
		tokenVerifier: &EnhancedMockTokenVerifier{Err: nil},
		extractClaimsFunc: func(token string) (map[string]interface{}, error) {
			return map[string]interface{}{"sub": "user-1"}, nil
		},
		userIdentifierClaim: "sub",
		tokenExchanger: &EnhancedMockTokenExchanger{
			RefreshTokenFunc: func(rt string) (*TokenResponse, error) {
				// Provider returns a valid id_token but an empty access token.
				return &TokenResponse{IDToken: "valid-idtoken", AccessToken: ""}, nil
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	defer session.returnToPoolSafely()
	session.SetRefreshToken("refresh-token")
	session.SetAccessToken("old-access-token-value-abcdefghij")

	// OLD behavior: refresh "succeeds" and returns true while persisting an
	// empty access token, so the next request validates as needs-refresh
	// again (refresh loop). NEW: returns false and keeps previous tokens.
	if ok := oidc.refreshToken(rw, req, session); ok {
		t.Fatalf("expected refresh to be reported as failed on an empty access token")
	}
	if got := session.GetAccessToken(); got != "old-access-token-value-abcdefghij" {
		t.Fatalf("expected previous access token preserved, got %q", got)
	}
}

// TestCallback_EmptyAccessTokenRejected is a regression: handleCallback
// accepted a code-exchange response with a valid id_token but no access
// token, authenticating the user with an empty Bearer credential and
// persisting an empty access token. Per OIDC Core 3.1.3.3 the exchange
// must return an access token; the fix rejects the response.
func TestCallback_EmptyAccessTokenRejected(t *testing.T) {
	testLogger := newNoOpLogger()

	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		testLogger,
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	csrfToken := "valid-csrf-token"
	nonce := "test-nonce-12345"

	oidc := &TraefikOidc{
		logger:         testLogger,
		sessionManager: sessionManager,
		enablePKCE:     false,
		allowedUsers:   nil,
		tokenExchanger: &EnhancedMockTokenExchanger{
			ExchangeResponse: &TokenResponse{
				AccessToken:  "",
				RefreshToken: "refresh-token",
				IDToken:      "some-id-token",
				ExpiresIn:    3600,
			},
		},
		tokenVerifier: &EnhancedMockTokenVerifier{Err: nil}, // id_token "valid"
		extractClaimsFunc: func(token string) (map[string]interface{}, error) {
			return map[string]interface{}{"sub": "123", "email": "test@example.com", "nonce": nonce}, nil
		},
		userIdentifierClaim: "email",
	}

	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	session.SetIncomingPath("/original/protected/path")
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, c := range rw.Result().Cookies() {
		req2.AddCookie(c)
	}
	rw2 := httptest.NewRecorder()
	oidc.handleCallback(rw2, req2, "https://example.com/callback")

	// OLD: authenticated and redirected (302) with an empty access token.
	// NEW: rejects the incomplete response.
	if rw2.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on missing access token, got %d", rw2.Code)
	}
}
