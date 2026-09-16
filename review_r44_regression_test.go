package traefikoidc

import (
	"sync"
	"testing"

	"github.com/gorilla/sessions"
)

// TestSessionDataRedirectCountConcurrency is a regression test for the redirect
// counter data race. GetRedirectCount / IncrementRedirectCount /
// ResetRedirectCount previously read and wrote sd.mainSession.Values without
// acquiring sd.sessionMutex, while other session methods (SetAuthenticated,
// SetIDToken, Save) write the same map under that lock. A SessionData can be
// returned to the object pool (Clear -> returnToPoolSafely) and reused by
// another goroutine while the original caller still mutates it, so concurrent
// lock-free map writes could occur. Run under -race: this failed on the old
// code (concurrent map writes), passes now.
func TestSessionDataRedirectCountConcurrency(t *testing.T) {
	sd := &SessionData{
		sessionMutex: sync.RWMutex{},
		mainSession:  &sessions.Session{Values: make(map[interface{}]interface{})},
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				sd.IncrementRedirectCount()
				sd.ResetRedirectCount()
				_ = sd.GetRedirectCount()
			}
		}()
	}
	wg.Wait()
}
