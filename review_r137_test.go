package traefikoidc

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestClientCredentials_NoDataRaceWithDCRWrite verifies that request-path
// readers of the client credential fields (clientID/clientSecret/audience)
// snapshot them under metadataMu.RLock rather than reading them lock-free.
//
// DCR (performDynamicClientRegistration, main.go) rewrites these fields under
// metadataMu.Lock at runtime (when a first registration failed and the 2h
// metadata refresh retries), so a lock-free read is a data race (R137).
//
// Requires -race to discriminate: on the OLD code buildAuthURL read
// t.clientID t.audience directly (race -> flagged); on the NEW code it
// snapshots via clientCredentials (clean).
func TestClientCredentials_NoDataRaceWithDCRWrite(t *testing.T) {
	// This test only discriminates under -race; without it there is nothing
	// to observe, so keep it focused and fast for non-race runs.
	ts := NewTestSuite(t)
	ts.Setup()
	oidc := ts.tOidc

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutine mutating the credential fields under metadataMu.Lock,
	// mirroring what performDynamicClientRegistration does at runtime.
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			oidc.metadataMu.Lock()
			oidc.clientID = fmt.Sprintf("rw-%d", i%3)
			oidc.clientSecret = fmt.Sprintf("sec-%d", i%3)
			oidc.audience = fmt.Sprintf("aud-%d", i%3)
			oidc.metadataMu.Unlock()
			i++
		}
	}()

	// Reader goroutines exercising request-path reader functions that touch
	// the credential fields.
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// buildAuthURL reads t.clientID + t.audience (via snapshot now).
				_ = oidc.buildAuthURL("https://app.example.com/callback", "state", "nonce", "")
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
