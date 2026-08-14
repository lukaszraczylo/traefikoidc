package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInitiateAuth_EmptyAuthorizeURLFailsClosed verifies that when the
// provider authorize URL cannot be built (empty-ish issuer), the login flow
// fails closed with a 500 instead of emitting an empty-Location redirect
// (which makes the browser reload the current page, re-entering the flow
// and bumping the redirect count until the hard 508). It also proves the
// authorize URL is built BEFORE the session is mutated, so a build failure
// must not wipe an existing (valid) session (R142).
func TestInitiateAuth_EmptyAuthorizeURLFailsClosed(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	// Empty issuer + empty authURL: buildURLWithParams resolves the empty
	// base against the empty issuer to "" -> validateURL("") fails ->
	// buildAuthURL returns "".
	oidc := &TraefikOidc{
		sessionManager: sessionManager,
		logger:         newNoOpLogger(),
		issuerURL:      "",
		authURL:        "",
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	sess, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	sess.SetUserIdentifier("preserve-me")
	sess.MarkDirty()
	defer sess.returnToPoolSafely()

	rw := httptest.NewRecorder()
	oidc.defaultInitiateAuthentication(rw, req, sess, "https://provider.example.com/callback")

	if rw.Code == http.StatusFound || rw.Code == http.StatusSeeOther || rw.Code == http.StatusMovedPermanently {
		t.Fatalf("empty authorize URL must not produce a redirect (loop), got %d loc=%q", rw.Code, rw.Header().Get("Location"))
	}
	if loc := rw.Header().Get("Location"); loc == "" && rw.Code == http.StatusOK {
		t.Fatal("flow unexpectedly completed with an empty location")
	}
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for unbuildable authorize URL, got %d", rw.Code)
	}
	// The existing session must survive a failed login-flow start.
	if got := sess.GetUserIdentifier(); got != "preserve-me" {
		t.Fatalf("session must be preserved when authorize-URL build fails, userIdentifier=%q", got)
	}
}
