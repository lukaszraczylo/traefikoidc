package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleCallback_RateLimitedResponseHasNoRetryAfter pins FIX-32: the
// callback's 429 for ErrRateLimitExceeded advertises Retry-After, but by
// then clearOneTimeAuthState has already cleared csrf/nonce/code_verifier
// and the authorization code has already been exchanged (redeemed at the
// IdP). A client that honors Retry-After and retries the same callback URL
// is guaranteed to hit the "CSRF token missing in session" 400 branch, not
// a successful retry.
func TestHandleCallback_RateLimitedResponseHasNoRetryAfter(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	oidc := &TraefikOidc{
		sessionManager: sessionManager,
		logger:         newNoOpLogger(),
		enablePKCE:     false,
		tokenExchanger: &EnhancedMockTokenExchanger{
			ExchangeResponse: &TokenResponse{AccessToken: "valid-access-token", IDToken: "some-id-token"},
		},
		tokenVerifier: &EnhancedMockTokenVerifier{Err: ErrRateLimitExceeded},
	}

	csrf := "csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rw := httptest.NewRecorder()
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetCSRF(csrf)
	session.SetNonce("nonce")
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrf, nil)
	for _, c := range rw.Result().Cookies() {
		req2.AddCookie(c)
	}
	rw2 := httptest.NewRecorder()
	oidc.handleCallback(rw2, req2, "https://myapp.example.com/callback")

	if rw2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for a rate-limited verify, got %d: %s", rw2.Code, rw2.Body.String())
	}
	if got := rw2.Header().Get("Retry-After"); got != "" {
		t.Fatalf("Retry-After = %q, want none: the one-time auth state is already destroyed by the time this response is sent, so a retry can only fail", got)
	}
}
