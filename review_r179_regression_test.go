package traefikoidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestR179_CallbackRateLimitReturns429 regresses auth_flow.go/how the
// shared rate limiter is surfaced during the OIDC callback. When the
// global token-origin limiter is exhausted, verifyTokenWithOpts returns
// ErrRateLimitExceeded; handleCallback must answer 429 + Retry-After (a
// rate limit), not a generic 500. Fail-on-old: 500 with no Retry-After.
func TestR179_CallbackRateLimitReturns429(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		time.Hour,
		NewLogger("error"),
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	oidc := &TraefikOidc{
		logger:              NewLogger("error"),
		enablePKCE:          false,
		userIdentifierClaim: "email",
		authURL:             "https://auth.example.com/authorize",
		sessionManager:      sessionManager,
		tokenVerifier:       nil, // set to self below so verify hits the limiter
	}
	oidc.tokenVerifier = oidc
	// Exhausted limiter: burst 0, so every Allow() is false.
	oidc.limiter = rate.NewLimiter(rate.Every(time.Hour), 0)

	// Exchange succeeds (valid access + id token); the rate limit fires
	// at verifyToken.
	ts := NewTestSuite(t)
	ts.Setup()
	idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "test-subject",
	})
	if err != nil {
		t.Fatalf("createTestJWT: %v", err)
	}
	oidc.tokenExchanger = &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{AccessToken: "at", IDToken: idToken},
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
	if err = session.Save(req, rw); err != nil {
		t.Fatalf("Save session: %v", err)
	}
	session.returnToPoolSafely()

	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	oidc.handleCallback(rw2, req2, "https://example.com/callback")

	if rw2.Code != http.StatusTooManyRequests {
		t.Fatalf("handleCallback under rate limit: got status %d, want 429", rw2.Code)
	}
	if got := rw2.Header().Get("Retry-After"); got == "" {
		t.Fatal("handleCallback under rate limit must send Retry-After")
	}
}

// TestR179_ReplayEntryCoversClockSkewWindow regresses the replay-window gap:
// a JWT accepted in the post-exp clock-skew window (exp + ClockSkewToleranceFuture)
// had its replay entry expire at nominal exp, so within (exp, exp+skew] the same
// token was re-accepted as fresh. The replay entry must now cover exp + skew.
// Fail-on-old: second verification of an in-skew expired token succeeds (no replay
// entry was recorded because until(exp) <= 0).
func TestR179_ReplayEntryCoversClockSkewWindow(t *testing.T) {
	initReplayCache()
	ts := NewTestSuite(t)
	ts.Setup()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": time.Now().Add(-time.Minute).Unix(), // within ClockSkewToleranceFuture (2m)
		"sub": "test-subject",
		"jti": generateRandomString(16),
	})
	if err != nil {
		t.Fatalf("createTestJWT: %v", err)
	}

	j, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}

	if err := j.Verify("https://test-issuer.com", "test-client-id"); err != nil {
		t.Fatalf("first verification of an in-skew expired token must succeed: %v", err)
	}
	if err := j.Verify("https://test-issuer.com", "test-client-id"); err == nil {
		t.Fatal("second verification must be rejected as replay (entry must cover exp + clock skew)")
	}
}

// TestR179_PanicRecoverySetsNoStore regresses middleware.go: a handler
// panic recovered by ServeHTTP must answer a 500 with Cache-Control:
// no-store (consistent with every other auth-failure response), so an
// intermediary cannot cache a bug-induced 500.
func TestR179_PanicRecoverySetsNoStore(t *testing.T) {
	oidc := &TraefikOidc{
		logger: NewLogger("error"),
		securityHeadersApplier: func(_ http.ResponseWriter, _ *http.Request) {
			panic("boom")
		},
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("panicked handler: got status %d, want 500", rw.Code)
	}
	if got := rw.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("recovered 500 must set Cache-Control: no-store, got %q", got)
	}
}

var _ = context.Background
