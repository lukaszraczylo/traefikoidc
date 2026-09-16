package traefikoidc

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// R98 regression (Logout): a session whose ID token lacks an `iat` claim
// must still be invalidated by backchannel/front-channel logout.
// Previously sessionCreatedAtForInvalidation fell back to time.Now() at
// check time, so the invalidation timestamp (set at logout) always
// preceded the "created-at" and the session survived logout silently.
// Now the fallback uses the session's own created_at.
func TestSessionCreatedAtForInvalidationFallsBackToSessionCreatedAt(t *testing.T) {
	sm := createTestSessionManager(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	defer s.returnToPoolSafely()
	// Session created 1h ago; logout will be invalidated at (about) now.
	s.mainSession.Values["created_at"] = time.Now().Add(-time.Hour).Unix()

	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		sessionInvalidationCache: mockCache,
	}
	if err := oidc.invalidateSession("", "user@example.com"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}

	// An ID token carrying sub/sid but NO iat claim (triggers the fallback).
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user@example.com","sid":"session123"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	idToken := header + "." + payload + "." + sig

	sid, sub, _ := oidc.extractSessionInfo(idToken)
	createdAt := oidc.sessionCreatedAtForInvalidation(idToken, s)

	// The fallback must use the session's real created-at (1h ago), not
	// time.Now(): otherwise invalidation would never apply to this session.
	if time.Since(createdAt) < 30*time.Minute {
		t.Fatalf("session created-at must fall back to the session's real value (1h ago), got recent time %v", createdAt)
	}
	if !oidc.isSessionInvalidated(sid, sub, createdAt) {
		t.Fatalf("session with missing iat must be invalidated by logout; fallback now lets it survive")
	}
}
