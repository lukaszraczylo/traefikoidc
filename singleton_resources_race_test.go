package traefikoidc

import (
	"sync"
	"testing"
)

// TestConcurrentGetResourceManagerVsReset stresses GetResourceManager against
// resetResourceManagerForTesting under -race. GetResourceManager returns the
// process-global via an unprotected read unless the caller holds
// resourceManagerMutex (regression: a live background task reading the
// singleton while a shuffled test resets it was a data race). Run with -race;
// this fails (race) before the mutex fix and passes after.
func TestConcurrentGetResourceManagerVsReset(t *testing.T) {
	var wg sync.WaitGroup

	// Readers constantly re-fetch the global, as a background task would.
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if rm := GetResourceManager(); rm == nil {
					t.Log("GetResourceManager returned nil")
				}
			}
		}()
	}

	// Resetter repeatedly pins/unpins the singleton with the test helper,
	// mirroring resetResourceManagerForTesting's writes in a shuffled suite.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			resetResourceManagerForTesting()
		}
	}()

	wg.Wait()
}
