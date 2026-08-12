package traefikoidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAuthCallback_ExchangeFailureInvalidatesState guards the fix that
// persists the one-time auth-state cleanup when the authorization-code
// exchange fails. The browser's session cookie must no longer hold a valid
// CSRF/nonce/code_verifier so a partially-failed flow cannot be continued
// or the (possibly unconsumed) code replayed against a stale state.
func TestAuthCallback_ExchangeFailureInvalidatesState(t *testing.T) {
	testLogger := newNoOpLogger()

	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		testLogger,
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	oidc := &TraefikOidc{
		sessionManager: sessionManager,
		logger:         testLogger,
		enablePKCE:     true,
		tokenExchanger: &EnhancedMockTokenExchanger{ExchangeErr: errors.New("token exchange failed")},
	}

	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetCSRF(csrfToken)
	session.SetNonce("test-nonce")
	session.SetCodeVerifier("test-code-verifier")
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	// Drive the callback with the session cookies from the first save.
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, c := range rw.Result().Cookies() {
		req2.AddCookie(c)
	}
	rw2 := httptest.NewRecorder()
	oidc.handleCallback(rw2, req2, "https://example.com/callback")

	if rw2.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on exchange failure, got %d", rw2.Code)
	}

	// Reload the session from the *callback response* cookies. The
	// one-time auth state must have been cleared and persisted.
	req3 := httptest.NewRequest(http.MethodGet, "/callback", nil)
	if n := len(rw2.Result().Cookies()); n == 0 {
		t.Fatal("expected session cookies in the callback response")
	}
	for _, c := range rw2.Result().Cookies() {
		req3.AddCookie(c)
	}
	session3, err := sessionManager.GetSession(req3)
	if err != nil {
		t.Fatalf("GetSession after callback: %v", err)
	}
	defer session3.returnToPoolSafely()

	if got := session3.GetCSRF(); got != "" {
		t.Errorf("expected CSRF cleared after failed exchange, got %q", got)
	}
	if got := session3.GetNonce(); got != "" {
		t.Errorf("expected nonce cleared after failed exchange, got %q", got)
	}
	if got := session3.GetCodeVerifier(); got != "" {
		t.Errorf("expected code_verifier cleared after failed exchange, got %q", got)
	}
}
