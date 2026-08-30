package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestR161_NonceFailureReturns400 guards the callback nonce-failure status
// (auth_flow.go). Nonce validity is a client-side authorization-request
// integrity check, the same class as the state/CSRF checks which
// correctly return 400. Previously the three nonce branches returned 500
// (client fault surfaced as an upstream outage), misleading
// intermediaries. This test drives the nonce-missing-in-session branch.
// Fail-on-old: returns 500.
func TestR161_NonceFailureReturns400(t *testing.T) {
	logger := NewLogger("error")
	sm, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		logger,
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	oidc := &TraefikOidc{
		logger:              logger,
		sessionManager:      sm,
		enablePKCE:          false,
		userIdentifierClaim: "email",
		authURL:             "https://auth.example.com/authorize",
	}

	// Token exchange returns an id_token whose nonce does NOT match the
	// session (here the session nonce is left empty, exercising the
	// nonce-missing-in-session branch).
	oidc.tokenExchanger = &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token-value",
			RefreshToken: "refresh-token-value",
			IDToken:      "header.payload.signature",
			ExpiresIn:    3600,
		},
	}
	oidc.tokenVerifier = &EnhancedMockTokenVerifier{Err: nil}
	oidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"sub":   "1234567890",
			"email": "test@example.com",
			"nonce": "some-nonce",
		}, nil
	}

	// First request to establish the session (CSRF set, nonce left empty).
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()
	session, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetCSRF(csrfToken)
	// note: no SetNonce — session nonce remains empty
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	// Real callback request with the established cookies.
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, c := range rw.Result().Cookies() {
		req2.AddCookie(c)
	}
	rw2 := httptest.NewRecorder()
	oidc.handleCallback(rw2, req2, "https://example.com/callback")

	if rw2.Code != http.StatusBadRequest {
		t.Fatalf("nonce failure must return 400 (client-side integrity), got %d", rw2.Code)
	}
}
