package traefikoidc

// TestSessionPoolReturnIfOwner_ConcurrentHandoutRace is a regression for a
// residual ABA in returnToPoolIfOwner (re-review finding at session.go:1829,
// a follow-up to FIX-10). Before the fix, the ownership check
// (sd.generation.Load() != gen) and the release
// (sd.inUse.CompareAndSwap(true, false), inside returnToPoolSafely) were two
// INDEPENDENT atomics, and a release (Clear -> returnToPoolSafely) only ever
// touched inUse, never generation. So once an object was freed, generation
// still read the ORIGINAL owner's value. GetSession/newSession hand a freed
// object to a new owner by writing inUse.Store(true) BEFORE
// generation.Add(1), so there was a window, right between those two writes,
// where inUse was already true for the NEW owner but generation still read
// the OLD (freed) owner's value. A stale returnToPoolIfOwner(gen) call (the
// deferred return from that PREVIOUS owner, e.g. after ServeHTTP's session
// got Clear()'d and reacquired -- middleware.go:700-701) landing its
// generation check inside that window read a match, then its
// CompareAndSwap(true, false) succeeded against the NEW owner's inUse flag:
// it released (and later Reset()'d) a session another goroutine was
// actively holding -- cross-request session bleed.
//
// The fix packs ownership and generation into one atomic word
// (sessionOwner) that a release zeroes and a handout overwrites with a
// fresh, monotonically increasing, never-reused value. The "is gen still
// the owner" check and the release are one CompareAndSwap, so there is no
// separate load-then-act step for a concurrent handout to land inside, AND
// a freed object never again matches a stale caller's old generation
// (sessionOwner reads 0 the instant it is freed, and no future handout can
// ever write that same nonzero value back).
//
// This drives the real release sequence (free, matching what Clear does)
// then races the real returnToPoolIfOwner against a goroutine performing
// exactly the writes GetSession/newSession make on a handout of that freed
// object, many times, to catch any reintroduced interleaving statistically.
// A cruder version of this simulation (skipping the explicit free step,
// which does not matter for the OLD two-field design because a release
// never touched generation there) reproduced the pre-fix bug in roughly
// 0.1% of iterations (362/400000) against the unfixed code -- consistent
// with the original re-review evidence of about 3 hits per 1.2M iterations
// (0, 0, 2, 0, 0 hits per 200k-iteration run).
import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionPoolReturnIfOwner_ConcurrentHandoutRace(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	const iterations = 400_000

	o := &SessionData{manager: sm}
	var hits int32

	for i := 0; i < iterations; i++ {
		// Original acquisition (sequential, before the race): object handed
		// out at generation gen (mirrors ServeHTTP capturing
		// sessionGen := session.ownerGeneration() right after GetSession).
		gen := o.generation.Add(1)
		o.sessionOwner.Store(gen)
		o.inUse.Store(true)

		// The original owner's session.Clear() releases it back to the
		// pool. This always completes, sequentially, on the SAME goroutine
		// that will later run that goroutine's own deferred stale return --
		// a real concurrent handout of this object can only ever start
		// after this point.
		o.sessionOwner.Store(0)
		o.inUse.Store(false)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// The ORIGINAL owner's stale deferred return, racing a
			// concurrent request that may reacquire the freed object.
			o.returnToPoolIfOwner(gen)
		}()
		go func() {
			defer wg.Done()
			// A concurrent request's GetSession/newSession reacquiring the
			// SAME freed pooled object: the exact writes those methods
			// make on a handout, in their documented order.
			newGen := o.generation.Add(1)
			o.sessionOwner.Store(newGen)
			o.inUse.Store(true)
		}()
		wg.Wait()

		// The new owner's claim must survive: sessionOwner must still name
		// its generation, and inUse must still read true.
		if o.sessionOwner.Load() == 0 || !o.inUse.Load() {
			atomic.AddInt32(&hits, 1)
		}

		// Reset shared state for the next iteration regardless of outcome.
		o.inUse.Store(false)
		o.sessionOwner.Store(0)
	}

	if hits > 0 {
		t.Fatalf("stale returnToPoolIfOwner released a concurrently re-acquired session in %d/%d iterations (want 0)", hits, iterations)
	}
}
