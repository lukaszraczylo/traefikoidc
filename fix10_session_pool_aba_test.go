package traefikoidc

// Regression test for FIX-10 (review-2026-09-10 finding at session.go:1784,
// middleware.go:566/789/883): a request-scoped deferred pool-return has no
// way to tell a stale holder from the current owner (ABA on the pool-return
// CAS). ServeHTTP acquires a session and defers its return; deep in the call
// chain, session.Clear() returns the SAME object to the pool and the
// handler re-acquires it under a fresh GetSession/newSession call. If a
// concurrent request pops that pooled object before the ORIGINAL deferred
// return fires, the stale return's CompareAndSwap(true, false) still
// succeeds against the new owner, incorrectly releasing (and Reset()ting) a
// session another request is actively using.
//
// Adapted from the throwaway repro at
// .claude/review-2026-09-10/repro/zz_g1_aba_test.go (TestG1StaleDeferABA),
// renamed to describe the behavior it pins and rewritten against the
// generation-gated return the fix introduces (ownerGeneration /
// returnToPoolIfOwner) instead of the raw returnToPoolSafely the bug lived
// in -- a caller must adopt the new API for the fix to apply, so the test
// exercises the same call the fixed middleware.go ServeHTTP now makes.
//
// The ABA reuse step (does the pool hand the SAME object back to a second
// GetSession after Clear) is itself an unspecified sync.Pool implementation
// detail, not part of the contract this fix establishes. Rather than depend
// on that timing (flaky: it did not reproduce on every run), this test
// drives the two field mutations GetSession/newSession make on every real
// handout -- inUse.Store(true) then generation.Add(1) -- directly on the
// SAME object Clear() just returned, deterministically recreating "a new
// owner acquired this exact object" regardless of pool internals.

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSessionPoolReturn_StaleGenerationDoesNotReleaseNewOwner reproduces the
// ABA sequence: request A acquires session O and captures its ownership
// generation (mirrors ServeHTTP's defer registration at middleware.go:566).
// O is cleared and returned to the pool (mirrors session.Clear at
// middleware.go:774/868); a new owner then claims the SAME object the way
// GetSession/newSession do (mirrors the re-acquire at
// middleware.go:781/875) and starts using it. A's stale deferred return
// then fires (mirrors ServeHTTP's defer running at function exit) and must
// be a no-op against the new owner's live ownership.
func TestSessionPoolReturn_StaleGenerationDoesNotReleaseNewOwner(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	r1 := httptest.NewRequest("GET", "https://app.example.com/", nil)
	o, err := sm.GetSession(r1)
	if err != nil {
		t.Fatalf("GetSession (request A): %v", err)
	}
	// ServeHTTP captures the generation right after acquiring, then defers
	// a generation-gated return instead of an unconditional one.
	staleGen := o.ownerGeneration()

	if err := o.Clear(r1, httptest.NewRecorder()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if o.inUse.Load() {
		t.Fatalf("Clear must return the object to the pool (inUse still true)")
	}

	// A new owner claims the exact same object: this is the only state
	// GetSession/newSession mutate on a handout (session.go:1076-1077,
	// 1106-1107), reproduced directly so the test does not depend on
	// sync.Pool's unspecified reuse timing.
	o.inUse.Store(true)
	o.generation.Add(1)
	o.SetUserIdentifier("bob")

	if staleGen == o.ownerGeneration() {
		t.Fatalf("test setup bug: new owner's generation (%d) must differ from the captured stale generation (%d)", o.ownerGeneration(), staleGen)
	}

	// A's stale deferred return fires at ServeHTTP exit, after the new
	// owner has already claimed and started using the same object.
	o.returnToPoolIfOwner(staleGen)

	if !o.inUse.Load() {
		t.Fatalf("stale deferred return (captured generation %d) released a session owned by another holder (current generation %d)", staleGen, o.ownerGeneration())
	}
	if o.GetUserIdentifier() != "bob" {
		t.Fatalf("stale deferred return corrupted the new owner's session data: got user %q, want \"bob\"", o.GetUserIdentifier())
	}

	o.returnToPoolSafely()
}

// TestSessionPoolReturn_CurrentGenerationStillReturns is the control: a
// non-stale generation-gated return (the common case -- no Clear+reacquire
// happened) must still return the object to the pool, so the fix does not
// leak sessions on the ordinary path.
func TestSessionPoolReturn_CurrentGenerationStillReturns(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	s, err := sm.GetSession(r)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	gen := s.ownerGeneration()

	s.returnToPoolIfOwner(gen)

	if s.inUse.Load() {
		t.Fatalf("returnToPoolIfOwner with the current generation must return the object to the pool (inUse still true)")
	}
}
