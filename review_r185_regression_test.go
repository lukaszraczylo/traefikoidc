package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// R185: per-source rate limiting at the OIDC gate
// ---------------------------------------------------------------------------
// Previously the only rate limit was the shared token-origin bucket, so a
// single external host hammering the login gate (initiate-auth redirects or
// authorization-code callbacks) consumed the shared bucket and degraded
// every user's callback to a 429/500. A per-external-source throttle
// (PerSourceLoginRateLimit, auth events per minute) now isolates a burst:
// one external source roughly exceeding the rate gets 429 + Retry-After,
// while internal / loopback / link-local sources (reverse proxies,
// in-cluster callers) are trusted and never throttled.
// Fail-on-old: no per-source limiter existed, so repeated callbacks from
// the same external source were never throttled (never a 429).
func TestR185_ExternalSourceIsThrottled(t *testing.T) {
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
		perSourceLimiter:             newPerSourceAuthLimiter(2), // burst 2 / min
	}
	close(oidc.initComplete)

	var throttled bool
	for i := 0; i < 6; i++ {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("X-Forwarded-For", "8.8.8.8") // external source
		oidc.ServeHTTP(rw, req)
		if rw.Code == http.StatusTooManyRequests {
			throttled = true
			if rr := rw.Header().Get("Retry-After"); rr == "" {
				t.Errorf("429 must carry Retry-After; got none")
			}
			break
		}
	}
	if !throttled {
		t.Fatalf("external source performing repeated auth events was never throttled (no 429)")
	}
}

// Internal / loopback sources are trusted and must never be throttled.
func TestR185_InternalSourceNeverThrottled(t *testing.T) {
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
		perSourceLimiter:             newPerSourceAuthLimiter(2),
	}
	close(oidc.initComplete)

	for _, src := range []string{"127.0.0.1", "10.1.2.3", "::1", "169.254.1.1"} {
		for i := 0; i < 10; i++ {
			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("X-Forwarded-For", src)
			oidc.ServeHTTP(rw, req)
			if rw.Code == http.StatusTooManyRequests {
				t.Fatalf("internal source %s must not be throttled; got 429", src)
			}
		}
	}
}
