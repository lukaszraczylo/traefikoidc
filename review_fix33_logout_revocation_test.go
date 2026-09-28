package traefikoidc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newFix33LogoutSession builds a session cookie set carrying an access and
// refresh token, for a fresh request presenting them to handleLogout.
func newFix33LogoutSession(t *testing.T, sm *SessionManager) *http.Request {
	t.Helper()
	base := httptest.NewRequest(http.MethodGet, "/protected", nil)
	baseRec := httptest.NewRecorder()
	session, err := sm.GetSession(base)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	// Opaque access/refresh tokens must clear the chunk manager's minimum
	// length / content checks to survive the cookie round trip.
	session.SetAccessToken("test-access-token-0123456789abcdefghijklmnopqrstuvwxyz")
	session.SetRefreshToken("test-refresh-token-0123456789abcdefghijklmnopqrstuvwxyz")
	if err := session.Save(base, baseRec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	for _, c := range baseRec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// TestHandleLogout_LogsProviderRevocationFailure pins FIX-33: handleLogout
// makes two synchronous provider revocation calls (access token, refresh
// token) and must not silently discard a genuine failure. At head both
// calls are `_ = t.RevokeTokenWithProvider(...)`. A non-2xx HTTP response
// is already logged inside RevokeTokenWithProvider itself, so this uses a
// network-level failure (connection refused) instead — that error path
// (token_manager.go "failed to send token revocation request") is only
// ever returned, never logged, so the discard at the call site is the
// only place it could be surfaced.
func TestHandleLogout_LogsProviderRevocationFailure(t *testing.T) {
	// Start and immediately close a server to obtain a URL nothing is
	// listening on (connection refused), deterministically forcing the
	// network-error path rather than a slow/flaky unroutable address.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadRevocationURL := srv.URL
	srv.Close()

	sm := createTestSessionManager(t)
	req := newFix33LogoutSession(t, sm)
	rw := httptest.NewRecorder()

	logger := NewLogger("error")
	var logBuf bytes.Buffer
	logger.logError.SetOutput(&logBuf)

	oidc := &TraefikOidc{
		logger:         logger,
		sessionManager: sm,
		tokenCache:     NewTokenCache(),
		httpClient:     http.DefaultClient,
		revocationURL:  deadRevocationURL,
	}
	oidc.handleLogout(rw, req)

	if rw.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect even though revocation failed, got %d", rw.Code)
	}
	logOutput := logBuf.String()
	if !strings.Contains(strings.ToLower(logOutput), "revocation") {
		t.Fatalf("expected an error-level log line naming the failed provider revocation, got: %q", logOutput)
	}
}

// TestHandleLogout_NoRevocationLogWhenEndpointNotConfigured guards the
// other half of FIX-33's contract: when the provider has no revocation
// endpoint at all (the common case), handleLogout must stay silent rather
// than logging an error on every logout.
func TestHandleLogout_NoRevocationLogWhenEndpointNotConfigured(t *testing.T) {
	sm := createTestSessionManager(t)
	req := newFix33LogoutSession(t, sm)
	rw := httptest.NewRecorder()

	logger := NewLogger("error")
	var logBuf bytes.Buffer
	logger.logError.SetOutput(&logBuf)

	oidc := &TraefikOidc{
		logger:         logger,
		sessionManager: sm,
		tokenCache:     NewTokenCache(),
		httpClient:     http.DefaultClient,
		// revocationURL left unset: RevokeTokenWithProvider returns
		// ErrRevocationEndpointNotConfigured, which must not be logged.
	}
	oidc.handleLogout(rw, req)

	if rw.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rw.Code)
	}
	if logOutput := logBuf.String(); strings.Contains(strings.ToLower(logOutput), "revocation") {
		t.Fatalf("logout must not log an error for the expected 'endpoint not configured' case, got: %q", logOutput)
	}
}

// TestHandleLogout_RevocationCallIsBounded pins the timeout half of
// FIX-33: each RevokeTokenWithProvider call must be bounded by a short
// context timeout, not context.Background() with no deadline of its own.
// At head a revocation endpoint that never responds hangs the logout
// redirect indefinitely (bounded here only by the test's own generous
// wait, not by any timeout in the code under test).
func TestHandleLogout_RevocationCallIsBounded(t *testing.T) {
	blockUntilClosed := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockUntilClosed // never responds within the test's patience
	}))
	defer func() {
		close(blockUntilClosed)
		srv.Close()
	}()

	sm := createTestSessionManager(t)
	req := newFix33LogoutSession(t, sm)
	rw := httptest.NewRecorder()

	oidc := &TraefikOidc{
		logger:         NewLogger("error"),
		sessionManager: sm,
		tokenCache:     NewTokenCache(),
		httpClient:     srv.Client(),
		revocationURL:  srv.URL,
	}

	done := make(chan struct{})
	go func() {
		oidc.handleLogout(rw, req)
		close(done)
	}()

	// Generous relative to any sane short revocation timeout, but far
	// short of "forever" so the unbounded head behavior fails decisively
	// instead of hanging the test suite.
	select {
	case <-done:
		if rw.Code != http.StatusFound {
			t.Fatalf("expected 302 redirect, got %d", rw.Code)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("handleLogout did not return within a bounded time; RevokeTokenWithProvider is not timeout-bounded")
	}
}
