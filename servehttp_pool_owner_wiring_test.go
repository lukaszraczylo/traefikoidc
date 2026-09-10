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
// reacquires a fresh one (ns) for the re-auth challenge and returns.
// ServeHTTP's own outer deferred pool-return only fires afterward, when the
// function itself returns.
//
// The concurrent claim on the freed object needs two things to be
// deterministic: (1) the SessionData pointer itself, and (2) a guarantee
// that request A's own reacquire (ns := GetSession(req), which runs before
// ServeHTTP returns) does not ALSO end up mutating it -- if it did, its
// legitimate GetSession/re-auth bookkeeping would silently corrupt whatever
// the "concurrent owner" set, invalidating the test for the wrong reason.
//
// (1) comes for free: sessionClearReleaseHook (session.go) is called
// synchronously on request A's own goroutine right after Clear() frees the
// session, with that exact pointer as its argument.
//
// (2) has two layers, one for the SessionData pointer and one for the
// gorilla session underneath it:
//
//   - Pointer identity: racing a second real GetSession call against
//     request A's own reacquire -- even from the very same goroutine
//     immediately after the Put -- was tried first, and a standalone
//     same-goroutine Put-then-Get repeated in a tight loop (no other
//     goroutines, GOMAXPROCS(1), GC disabled) still missed the just-freed
//     object roughly a quarter of the time; sync.Pool's exact per-P reuse
//     behavior is an unspecified implementation detail this test must not
//     depend on. Instead, the hook swaps the SessionManager's pool for a
//     fresh, empty one (same New func) the instant it captures the freed
//     pointer, so every GetSession/newSession call from then on --
//     specifically request A's reacquire -- allocates a brand-new
//     SessionData instead of colliding with the stolen one.
//
//   - gorilla session cache: even with a distinct SessionData pointer,
//     ns's GetSession(req) call reads the SAME *http.Request (reqA) the
//     stolen object was originally loaded from. gorilla/sessions caches a
//     decoded *sessions.Session on the request's context keyed by cookie
//     name, so calling store.Get(reqA, ...) again -- exactly what ns's
//     acquisition does -- hands back the SAME underlying mainSession the
//     stolen SessionData already points to, even though the two are
//     different SessionData structs. Writing through ns.mainSession
//     (CSRF/nonce/etc. for the re-auth challenge) would then silently
//     mutate the stolen object's session VALUES too, regardless of the
//     pool-ownership bug this test targets. So this test does not use
//     mainSession-backed state (e.g. SetUserIdentifier) to detect
//     corruption -- only the ownership fields that live on the SessionData
//     struct itself (sessionOwner/inUse, read via ownerGeneration and
//     inUse.Load), which ns's aliased mainSession cannot touch.
//
// The hook marks the stolen pointer's ownership fields for a simulated
// concurrent owner and blocks until told to let request A finish --
// including its outer ServeHTTP defer.
//
// If that defer is returnToPoolSafely (the reverted wiring), it
// unconditionally releases and Reset()s whichever session currently owns
// the object -- the stolen one -- flipping inUse back to false even though
// the captured generation no longer names its owner. With the correct
// wiring (returnToPoolIfOwner(sessionGen)), the generation mismatch makes
// the stale call a no-op and inUse stays true.
import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync"
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

	// The hook runs synchronously on request A's own goroutine, right after
	// Clear() frees the original session object. It claims that EXACT
	// object's ownership fields for a simulated concurrent owner, then
	// swaps in a fresh empty pool so request A's own upcoming reacquire
	// allocates a different object instead of colliding with this one (see
	// the long comment above), and blocks until the main goroutine says
	// request A may continue.
	released := make(chan struct{})
	proceedA := make(chan struct{})
	var stolen *SessionData
	var stolenGen uint64
	sessionClearReleaseHook = func(freed *SessionData) {
		stolenGen = freed.generation.Add(1)
		freed.sessionOwner.Store(stolenGen)
		freed.inUse.Store(true)
		stolen = freed

		sessionManager.sessionPool = sync.Pool{New: sessionManager.sessionPool.New}

		close(released)
		<-proceedA
	}
	defer func() { sessionClearReleaseHook = nil }()

	rwA := httptest.NewRecorder()
	doneA := make(chan struct{})
	go func() {
		oidc.ServeHTTP(rwA, reqA)
		close(doneA)
	}()

	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request A's Clear() to release its session")
	}

	// Let request A finish: its own reacquire-and-redirect (against the
	// now-swapped, empty pool), then its outer ServeHTTP defer.
	close(proceedA)
	select {
	case <-doneA:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ServeHTTP (request A) to return")
	}

	// Safe to read stolen's state without synchronization now: request A's
	// goroutine (the only other writer) has fully returned. inUse is the
	// discriminator: releaseToPool (reached whenever a release succeeds,
	// correctly or not) always flips it false, but never touches
	// generation, so a wrongly-succeeded release still reports a matching
	// ownerGeneration -- inUse alone tells the two apart here.
	if !stolen.inUse.Load() {
		t.Fatalf("request A's deferred pool-return released a concurrently-claimed session (generation %d): inUse=false, want true",
			stolen.ownerGeneration())
	}
	if stolen.ownerGeneration() != stolenGen {
		t.Fatalf("concurrently-claimed session's generation changed unexpectedly: got %d, want %d", stolen.ownerGeneration(), stolenGen)
	}

	stolen.ReturnToPool()
}
