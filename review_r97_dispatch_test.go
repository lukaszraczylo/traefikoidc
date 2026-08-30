package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// R97 regression (Dispatch): when a session cookie has expired past
// sessionMaxAge, GetSession returns (nil, "session expired") and the
// retry also returns nil, so the middleware must obtain a fresh clean
// session and re-initiate authentication instead of answering an
// unrecoverable HTTP 500. The fix introduces SessionManager.newSession to
// hand out exactly such a session with correct pool/active-session
// accounting. Old code has no newSession (build fail on old); new code
// returns a usable, correctly-accounted clean session whose sub-sessions
// are non-nil so the auth flow can write CSRF/nonce and Save.
func TestSessionManagerNewSessionReturnsCleanReusableSession(t *testing.T) {
	sm := createTestSessionManager(t)

	before := atomic.LoadInt64(&sm.activeSessions)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s := sm.newSession(req)
	if s == nil {
		t.Fatalf("newSession returned nil; middleware would 500 on expired session")
	}
	defer s.returnToPoolSafely()

	if !s.inUse.Load() {
		t.Fatalf("newSession session not marked in-use")
	}
	if s.dirty {
		t.Fatalf("newSession session should start clean (not dirty)")
	}
	if !s.useCombinedStorage {
		t.Fatalf("newSession session should default to combined storage")
	}
	if s.GetUserIdentifier() != "" {
		t.Fatalf("newSession session must not carry a stale user identifier")
	}
	if s.mainSession == nil || s.accessSession == nil || s.refreshSession == nil || s.idTokenSession == nil {
		t.Fatalf("newSession session must have non-nil sub-sessions for the auth flow to write into")
	}
	if after := atomic.LoadInt64(&sm.activeSessions); after != before+1 {
		t.Fatalf("newSession must increment activeSessions: before=%d after=%d", before, after)
	}
}
