package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestServeHTTP_Bearer_AllowedUsersGate guards the bearer (M2M) path against
// bypassing the allowedUsers / allowedUserDomains gate. Every cookie-path
// entry point enforces isAllowedUser; the bearer path reaches
// forwardAuthorized with no earlier check, so a valid bearer whose subject
// is absent from the allowlist must be rejected with 403 rather than be
// forwarded (which would make the restriction a no-op on the bearer path).
func TestServeHTTP_Bearer_AllowedUsersGate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sub  string
		want int
	}{
		{name: "subject allowed", sub: "service-account-1", want: http.StatusOK},
		{name: "subject not allowed", sub: "other-sa", want: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			oidc := makeBearerOIDC(t, next)
			oidc.allowedUsers = map[string]struct{}{"service-account-1": {}}
			claims := defaultBearerClaims()
			claims["sub"] = tc.sub
			token := makeBearerJWT(t, defaultBearerHeader(), claims)
			seedVerified(t, oidc, token, claims)

			req := httptest.NewRequest("GET", "/api/work", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rw := httptest.NewRecorder()
			oidc.ServeHTTP(rw, req)
			if rw.Code != tc.want {
				t.Fatalf("status=%d, want %d", rw.Code, tc.want)
			}
		})
	}
}

// TestSessionPool_ReturnToPool_ExactlyOnce is a regression for the check-
// then-put TOCTOU in returnToPoolSafely. The old code read sd.inUse,
// decided to return it, then wrote inUse=false and Put the session back —
// so two concurrent returns (request path + a background goroutine) could
// both decide to return the SAME SessionData, putting it into the pool
// twice and double-decrementing activeSessions. The fix uses a single
// atomic CompareAndSwap so exactly one caller claims and returns the
// object. The observable contract: N concurrent returns of one in-use
// session decrement activeSessions by exactly 1.
func TestSessionPool_ReturnToPool_ExactlyOnce(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	oidc := makeBearerOIDC(t, next)
	sm := oidc.sessionManager

	sd, err := sm.GetSession(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	before := atomic.LoadInt64(&sm.activeSessions)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sd.returnToPoolSafely()
		}()
	}
	wg.Wait()

	got := before - atomic.LoadInt64(&sm.activeSessions)
	if got != 1 {
		t.Fatalf("returnToPoolSafely returned session %d times, want exactly 1 (double-return would corrupt the pool)", got)
	}
}
