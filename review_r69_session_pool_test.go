package traefikoidc

import (
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestSession_TimeoutNoDoublePool regresses a double return of the same
// SessionData to the session pool on the session-timeout path: GetSession
// called sessionData.Clear(r,nil) (whose defer returnToPoolSafely pooled
// the object) and then handleError pooled it AGAIN. The identical pointer
// therefore entered the pool twice, so two concurrent GetSession calls
// could hand out one shared object (data race / cross-request session
// bleed), and activeSessions was double-decremented (could go negative).
func TestSession_TimeoutNoDoublePool(t *testing.T) {
	sm := createTestSessionManager(t)

	// Build an authenticated session whose creation time exceeds the max
	// age (default 24h) and persist it so a later load sees it expired.
	req0 := httptest.NewRequest("GET", "/", nil)
	s, err := sm.GetSession(req0)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	s.SetUserIdentifier("user@example.com")
	if err := s.SetAuthenticated(true); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	s.mainSession.Values["created_at"] = time.Now().Add(-48 * time.Hour).Unix()
	rec := httptest.NewRecorder()
	if err := s.Save(req0, rec); err != nil {
		t.Fatalf("save session: %v", err)
	}

	mid := atomic.LoadInt64(&sm.activeSessions)

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if _, err := sm.GetSession(req); err == nil {
		t.Fatalf("expected session-timeout error for an expired session")
	}

	after := atomic.LoadInt64(&sm.activeSessions)
	if after < mid {
		t.Fatalf("activeSessions double-decremented (double pool return): mid=%d after=%d", mid, after)
	}
}
