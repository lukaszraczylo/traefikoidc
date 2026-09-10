package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPerSourceRateLimit_XFFSpoofDoesNotBypassThrottle regresses FIX-11:
// sourceIP() preferred the first X-Forwarded-For value, and isInternalSource
// then classified a spoofed loopback/private address as internal, trusting
// it unconditionally. An external attacker sending
// X-Forwarded-For: 127.0.0.1 (or any RFC 1918 address) was therefore
// classified internal and never throttled, making PerSourceLoginRateLimit a
// no-op against the exact attacker it exists to stop. The request's real
// source (RemoteAddr, set by Traefik/net/http from the TCP peer, not
// attacker-controlled) must be the only thing PerSourceLoginRateLimit keys
// and classifies on - mirroring clientIPForBearer (bearer_auth.go), which
// already deliberately ignores X-Forwarded-For for the same reason.
func TestPerSourceRateLimit_XFFSpoofDoesNotBypassThrottle(t *testing.T) {
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
		// httptest.NewRequest sets RemoteAddr to "192.0.2.1:1234" (RFC 5737
		// TEST-NET-1: a real, external, non-internal address) - the genuine
		// source of this request. The attacker spoofs X-Forwarded-For to a
		// loopback address to try to be classified internal and skip the
		// throttle.
		req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		oidc.ServeHTTP(rw, req)
		if rw.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatalf("external source spoofing X-Forwarded-For: 127.0.0.1 was never throttled (XFF-spoofed loopback bypassed PerSourceLoginRateLimit)")
	}
}

// TestSourceIP_IgnoresXForwardedFor pins the same contract directly at the
// sourceIP() unit: the returned address must always be derived from
// RemoteAddr, never from the attacker-controlled X-Forwarded-For header.
func TestSourceIP_IgnoresXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.RemoteAddr = "203.0.113.7:54321" // RFC 5737 TEST-NET-3, external
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	got := sourceIP(req)
	if got != "203.0.113.7" {
		t.Fatalf("sourceIP = %q, want RemoteAddr-derived %q (X-Forwarded-For must be ignored)", got, "203.0.113.7")
	}
}
