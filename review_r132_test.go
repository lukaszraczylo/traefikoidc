package traefikoidc

// R132 regression: saveCombined must read token/main-session fields under
// sessionMutex.RLock so a concurrent Set* (which writes under the write
// side) cannot tear the combined payload. Previously only the extra-map
// walk took the Read side; the token field reads (getAccessTokenUnsafe &
// friends) were unlocked, a latent data race on the refresh-rotation
// path (a concurrently-rotated refresh token could be read half-consistently
// and re-encoded into the cookie, clobbering the fresh one). Run with -race.

import (
	"sync"
	"testing"

	"net/http/httptest"

	"github.com/gorilla/sessions"
)

func TestSaveCombined_NoDataRaceWithConcurrentSet(t *testing.T) {
	sm := createTestSessionManager(t)
	req := httptest.NewRequest("GET", "/", nil)
	sd, err := sm.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	sd.useCombinedStorage = true

	options := &sessions.Options{Path: "/", MaxAge: 86400, HttpOnly: true, Secure: true}

	// Seed the refresh/access tokens so the concurrent save has something
	// to read; SetAccessToken requires >=20-char tokens.
	sd.SetAccessToken("aaaaaaaaaaaaaaaaaaaaaaaaaaaa") // must be >= 20 chars
	sd.refreshSession.Values["token"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// One reader goroutine calls saveCombined (payload build reads under
	// RLock after R132) while many writers call SetAccessToken (writes
	// under Lock). Before R132 the companion payload reads were unlocked,
	// so -race flagged the torn read here.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rw := httptest.NewRecorder()
		for j := 0; j < 500; j++ {
			_ = sd.saveCombined(req, rw, options) // ignore cookie-write errors; testing the read race
		}
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				sd.SetAccessToken("tok-%d-%d-abcdefghijklmnopqrstuvwxyz")
			}
		}(i)
	}
	wg.Wait()
}
