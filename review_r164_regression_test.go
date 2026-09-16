package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestR164_DcrPendingDoesNotReseedSession guards the ordering of the
// dynamic-client-registration guard inside defaultInitiateAuthentication
// (auth_flow.go). When DCR is enabled but has not produced a client_id
// yet, the flow answers 503 without redirecting; previously that guard
// ran AFTER prepareSessionForAuthentication + session.Save, so the
// pending-DCR 503 still re-seeded and persisted the session —
// discarding any existing session state for no reason (and contradicting
// the documented intent that an aborted login flow must not clear a
// valid existing session). The fix runs the guard before the mutation,
// so the 503 leaves the session untouched.
// Fail-on-old: a pending-DCR 503 re-seeds the session (CSRF changes and
// a Set-Cookie is emitted).
func TestR164_DcrPendingDoesNotReseedSession(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		GetSingletonNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	ts.tOidc.sessionManager = sessionManager
	ts.tOidc.issuerURL = "https://auth.example.com"
	ts.tOidc.clientID = "" // DCR pending: no client_id yet
	ts.tOidc.scopes = []string{"openid", "email"}
	ts.tOidc.dcrConfig = &DynamicClientRegistrationConfig{Enabled: true}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/protected", nil)
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	defer session.returnToPoolSafely()

	// Pre-existing session state that must survive a pending-DCR 503.
	session.SetCSRF("should-survive")
	session.SetAccessToken("some-existing-token")

	rw := httptest.NewRecorder()
	ts.tOidc.defaultInitiateAuthentication(rw, req, session, "https://example.com/callback")

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("pending DCR should answer 503, got %d", rw.Code)
	}
	if got := session.GetCSRF(); got != "should-survive" {
		t.Fatalf("pending DCR must not re-seed the session CSRF: want %q, got %q", "should-survive", got)
	}
	// No session cookies should be written when we 503 before redirecting.
	if n := len(rw.Header().Values("Set-Cookie")); n != 0 {
		t.Fatalf("pending DCR must not persist a re-seeded session (got %d Set-Cookie)", n)
	}
}
