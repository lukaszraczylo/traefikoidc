package traefikoidc

// TestServeHTTP_InvalidatedSessionReacquireDoesNotStealConcurrentSession is a
// regression for the wiring gap at session.go:1825 (re-review finding, a
// follow-up to FIX-10). The only existing pin for FIX-10's behavioral
// change, fix10_session_pool_aba_test.go, calls returnToPoolIfOwner
// directly and never drives ServeHTTP, where the actual fix lives:
//
//	sessionGen := session.ownerGeneration()
//	defer session.returnToPoolIfOwner(sessionGen)   // middleware.go:700-701
//
// Reverting those two lines back to a plain `defer session.returnToPoolSafely()`
// compiles and leaves the whole root test suite green, because no test
// exercises ServeHTTP's own Clear-and-reacquire branch under a concurrent
// claim on the freed object.
//
// This drives a REAL ServeHTTP call through that branch
// (processAuthorizedRequestRS's backchannel/front-channel-logout
// invalidation check, middleware.go:901-926): session.Clear() releases the
// original session object back to the pool, then the SAME goroutine
// reacquires a fresh one for the re-auth challenge and returns. ServeHTTP's
// own outer deferred pool-return only fires afterward, when the function
// itself returns.
//
// To land a concurrent claim on the freed object inside that window
// deterministically -- rather than depend on scheduler luck, or on
// sync.Pool's unspecified reuse timing lining up under a real race -- it
// uses sessionClearReleaseHook (session.go) to pause the invalidated
// request's goroutine the instant Clear() frees its session, steals that
// exact object with a direct, sequential GetSession call (it is the only
// object in the pool at that point, so this reacquire is not itself part of
// any race), marks it as a different user's live session, then lets the
// invalidated request run to completion -- including its outer ServeHTTP
// defer.
//
// If that defer is returnToPoolSafely (the reverted wiring), it
// unconditionally releases and Reset()s whichever session currently owns
// the object -- the stolen one -- even though the captured generation no
// longer names its owner. With the correct wiring
// (returnToPoolIfOwner(sessionGen)), the generation mismatch makes the
// stale call a no-op.
import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServeHTTP_InvalidatedSessionReacquireDoesNotStealConcurrentSession(t *testing.T) {
	sessionManager := createTestSessionManager(t)

	invalidationCache := NewCache()
	defer invalidationCache.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	idTokenA, err := createTestJWT(key, "RS256", "test-key-id", map[string]interface{}{"sub": "userA"})
	if err != nil {
		t.Fatalf("craft id token: %v", err)
	}
	accessTokenA, err := createTestJWT(key, "RS256", "test-key-id", map[string]interface{}{"sub": "userA"})
	if err != nil {
		t.Fatalf("craft access token: %v", err)
	}

	tokenCache := NewTokenCache()
	defer tokenCache.Close()
	// verifyToken is mocked to accept any token unconditionally (signature
	// verification is orthogonal to the pool-ownership bug this test pins);
	// the real gate that determines "authenticated, no refresh needed" is
	// validateTokenExpiryRS reading a cached, unexpired claim set for the
	// access token.
	tokenCache.Set(accessTokenA, map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())}, time.Hour)

	oidc := newTestOIDC(t, func(o *TraefikOidc) {
		o.sessionManager = sessionManager
		o.enableBackchannelLogout = true
		o.sessionInvalidationCache = invalidationCache
		o.tokenVerifier = &EnhancedMockTokenVerifier{Err: nil}
		o.tokenCache = tokenCache
	})

	// Build the invalidated user's authenticated session request.
	reqA := httptest.NewRequest(http.MethodGet, "/protected", nil)
	sessionA, err := sessionManager.GetSession(reqA)
	if err != nil {
		t.Fatalf("GetSession (request A): %v", err)
	}
	sessionA.SetUserIdentifier("userA")
	if err := sessionA.SetAuthenticated(true); err != nil {
		t.Fatalf("authenticate session A: %v", err)
	}
	sessionA.SetIDToken(idTokenA)
	sessionA.SetAccessToken(accessTokenA)
	// Push the session's created_at comfortably into the past so the
	// invalidation timestamp (set below, at "now") unambiguously lands
	// at-or-after it, regardless of any second-boundary timing.
	sessionA.mainSession.Values["created_at"] = time.Now().Add(-time.Hour).Unix()
	recA := httptest.NewRecorder()
	if err := sessionA.Save(reqA, recA); err != nil {
		t.Fatalf("save session A: %v", err)
	}
	for _, c := range recA.Result().Cookies() {
		reqA.AddCookie(c)
	}

	if err := oidc.invalidateSession("", "userA"); err != nil {
		t.Fatalf("invalidateSession: %v", err)
	}

	// Pause request A's goroutine the instant its Clear() frees the
	// original session object, capturing that exact pointer.
	released := make(chan *SessionData, 1)
	proceedA := make(chan struct{})
	sessionClearReleaseHook = func(sd *SessionData) {
		released <- sd
		<-proceedA
	}
	defer func() { sessionClearReleaseHook = nil }()

	rwA := httptest.NewRecorder()
	doneA := make(chan struct{})
	go func() {
		oidc.ServeHTTP(rwA, reqA)
		close(doneA)
	}()

	var freed *SessionData
	select {
	case freed = <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request A's Clear() to release its session")
	}

	// Steal the freed object with a direct, sequential GetSession call:
	// request A is parked inside the hook, so nothing else touches the
	// pool while this runs.
	reqB := httptest.NewRequest(http.MethodGet, "/other", nil)
	var stolen *SessionData
	for attempt := 0; attempt < 200; attempt++ {
		cand, gerr := sessionManager.GetSession(reqB)
		if gerr != nil {
			t.Fatalf("GetSession (request B, attempt %d): %v", attempt, gerr)
		}
		if cand == freed {
			stolen = cand
			break
		}
		cand.ReturnToPool()
	}
	if stolen == nil {
		close(proceedA)
		<-doneA
		t.Fatal("test environment assumption failed: the freed session object was not handed back to a direct GetSession call within 200 attempts")
	}
	stolen.SetUserIdentifier("userB")
	stolenGen := stolen.ownerGeneration()

	// Let request A finish: its own reacquire-and-redirect, then its outer
	// ServeHTTP defer.
	close(proceedA)
	select {
	case <-doneA:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ServeHTTP (request A) to return")
	}

	if stolen.ownerGeneration() != stolenGen || !stolen.inUse.Load() {
		t.Fatalf("request A's deferred pool-return corrupted a concurrently-claimed session (generation now %d, want %d; inUse=%v)",
			stolen.ownerGeneration(), stolenGen, stolen.inUse.Load())
	}
	if got := stolen.GetUserIdentifier(); got != "userB" {
		t.Fatalf("request A's deferred pool-return wiped the concurrent owner's session data: got identifier %q, want \"userB\"", got)
	}

	stolen.ReturnToPool()
}
