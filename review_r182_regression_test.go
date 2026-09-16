package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// R182: OIDC callback must be HTTP GET only (RFC 6749 §3.1.2)
// ---------------------------------------------------------------------------
// The callback branch dispatched handleCallback on any method matched by
// path. handleCallback reads code/state/error only from the query string
// (form_post is not supported), so a HEAD or other non-GET probe reached
// the full exchange logic and consumed one-time state, or failed
// confusingly ("No authorization code received in callback"). The branch
// now rejects non-GET with 405 + no-store.
// Fail-on-old: POST to the callback reached handleCallback and returned
// 400 ("CSRF token missing" on a fresh session) instead of 405.
func TestR182_CallbackRejectsNonGetMethod(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		redirURLPath:                 "/callback",
		issuerURL:                    "https://provider.example.com",
	}
	close(oidc.initComplete)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/callback", nil)
	req.Header.Set("Accept", "text/html")

	oidc.ServeHTTP(rw, req)

	if rw.Code != http.StatusMethodNotAllowed {
		t.Fatalf("callback with method POST: got status %d, want 405", rw.Code)
	}
	if cc := rw.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("callback 405 must be no-store; got %q", cc)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Errorf("405 must not emit a redirect Location; got %q", loc)
	}
}

// A legitimate GET that reaches the callback still proceeds (does not hit
// the method gate). With no session CSRF it returns 400 for the missing
// CSRF rather than 405.
func TestR182_GetCallbackNotRejectedByMethodGate(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		redirURLPath:                 "/callback",
		issuerURL:                    "https://provider.example.com",
	}
	close(oidc.initComplete)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?state=x&code=y", nil)
	req.Header.Set("Accept", "text/html")

	oidc.ServeHTTP(rw, req)

	if rw.Code == http.StatusMethodNotAllowed {
		t.Fatalf("GET callback must not be rejected by the method gate; got 405")
	}
}
