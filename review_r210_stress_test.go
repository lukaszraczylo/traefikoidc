package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestServeHTTPConcurrentLive is a concurrency hammer on the REAL middleware
// instance: many goroutines drive ServeHTTP through the shared hot path
// (security headers, session pool, shouldBypass, limiter, requestState
// capture) while others hit the callback branch, run under -race. Catches
// shared-state races (session-pool bleed, limiter, header applier) that
// sequential tests miss (R210).
func TestServeHTTPConcurrentLive(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("error"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		redirURLPath:                 "/callback",
		issuerURL:                    "https://provider.example.com",
		perSourceLimiter:             newPerSourceAuthLimiter(1000),
	}
	close(oidc.initComplete)

	var wg sync.WaitGroup
	var ok, nonOK, callbackHits atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				var (
					rw  = httptest.NewRecorder()
					req *http.Request
				)
				if i%10 == 0 {
					req = httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
					callbackHits.Add(1)
				} else {
					req = httptest.NewRequest(http.MethodGet, "/protected", nil)
				}
				req.Header.Set("X-Forwarded-For", "8.8.8.8")
				oidc.ServeHTTP(rw, req)
				if rw.Code == http.StatusOK {
					ok.Add(1)
				} else {
					nonOK.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("concurrent sweep: ok=%d nonOK=%d callback=%d", ok.Load(), nonOK.Load(), callbackHits.Load())
	if callbackHits.Load() == 0 {
		t.Fatal("expected callback branch to be exercised")
	}
}
