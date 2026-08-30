package traefikoidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestConcurrentServeHTTP_SharedInstance drives the full request path
// (bootstraps, auth-bypass evaluation, session lookup, redirect) across many
// goroutines against ONE shared plugin instance. Traefik runs the middleware
// concurrently for every request on a router, so this is the production
// concurrency shape. Holds under -race only if the request path touches
// shared mutable state via atomics/locks, never plain field writes.
func TestConcurrentServeHTTP_SharedInstance(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("debug"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		issuerURL:                    "https://provider.example.com",
		redirURLPath:                 "/callback",
		logoutURLPath:                "/logout",
		clientID:                     "test-client",
		audience:                     "test-client",
		authURL:                      "https://provider.example.com/auth",
		firstRequestStarted:          0, // let exactly one goroutine win the bootstrap CAS
		metadataRefreshStartedAtomic: 0,
	}
	close(oidc.initComplete)

	const goroutines = 40
	const perGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				req := httptest.NewRequest("GET", fmt.Sprintf("/api/g%d/", g), nil)
				w := httptest.NewRecorder()
				oidc.ServeHTTP(w, req)
				// Unauthenticated request must bounce to the IdP (3xx), not
				// forward to the backend (200) or error.
				if w.Code < 300 || w.Code >= 400 {
					t.Errorf("expected auth redirect (3xx), got %d", w.Code)
				}
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentServeHTTP_ExcludedBypass drives the auth-bypass path
// concurrently (shouldBypassAuth read-path) on a shared instance.
func TestConcurrentServeHTTP_ExcludedBypass(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	oidc := &TraefikOidc{
		next:                         next,
		logger:                       NewLogger("debug"),
		initComplete:                 make(chan struct{}),
		sessionManager:               createTestSessionManager(t),
		firstRequestStarted:          1,
		metadataRefreshStartedAtomic: 1,
		authURL:                      "https://provider.example.com/auth",
	}
	close(oidc.initComplete)

	const goroutines = 40
	const perGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				w := httptest.NewRecorder()
				oidc.ServeHTTP(w, req)
			}
		}()
	}
	wg.Wait()
}
