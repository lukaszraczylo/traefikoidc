package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSession_ReturnToPool_ExactlyOnce is a regression for ReturnToPool's
// inverted, non-atomic inUse guard. The old code returned the session only
// when it was NOT in use — so immediately after GetSession (inUse=true)
// ReturnToPool did nothing (leaked the object and left activeSessions
// inflated). The fix mirrors returnToPoolSafely: an atomic
// compare-and-swap returns the session exactly once. Observable contract:
// returning one in-use session decrements activeSessions by exactly 1.
func TestSession_ReturnToPool_ExactlyOnce(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	sm := oidc.sessionManager

	sd, err := sm.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	before := atomic.LoadInt64(&sm.activeSessions)

	sd.ReturnToPool()

	got := before - atomic.LoadInt64(&sm.activeSessions)
	if got != 1 {
		t.Fatalf("ReturnToPool returned the session %d times, want exactly 1 (leak or double-return)", got)
	}
}

// TestSession_ReauthAfterClear_BalancesPool guards the IdP-initiated-logout
// re-auth fix: processAuthorizedRequest(RS) called session.Clear (which
// returns the object to the shared pool) and then reused that same object
// to write the re-auth challenge — a use-after-return raced with a
// concurrent GetSession. The fix re-acquires an owned session from the
// pool instead. This deterministic test locks in that the fixed
// reacquire-then-return pattern leaves activeSessions exactly balanced
// (no leak, no double decrement).
func TestSession_ReauthAfterClear_BalancesPool(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	sm := oidc.sessionManager
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	start := atomic.LoadInt64(&sm.activeSessions)
	sd, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	// Handler branch: Clear returns sd to the pool, then we re-acquire an
	// owned session for the re-auth challenge and return it.
	if err := sd.Clear(req, rw); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	ns, gerr := sm.GetSession(req)
	if gerr != nil {
		t.Fatalf("re-acquire GetSession: %v", gerr)
	}
	ns.returnToPoolSafely()

	if end := atomic.LoadInt64(&sm.activeSessions); end != start {
		t.Fatalf("activeSessions changed by %d across clear+reacquire (start=%d end=%d)", end-start, start, end)
	}
}
