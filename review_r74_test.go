package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServeHTTP_RecoversHandlerPanic regresses the request-handler path
// having no panic recovery: a panic anywhere in the chain is caught here
// and never escapes to net/http (which would otherwise close/truncate the
// connection), so ServeHTTP always returns normally.
//
// It no longer asserts a forced 500 for a panic in the DOWNSTREAM backend
// specifically. FIX-06 requires t.next.ServeHTTP to receive the real
// ResponseWriter Traefik gave this plugin, not a tracking wrapper -- yaegi
// v0.16.1 does not bridge a custom wrapper's Flush/Unwrap methods across
// the interpreted-to-compiled boundary (only a composed
// ResponseWriter+Hijacker wrapper), so wrapping there breaks SSE in
// production. Once next has the real writer, this middleware can no
// longer tell whether next already committed a response before panicking;
// writing a fallback 500 unconditionally would risk corrupting an
// already-sent body (see TestR155_ServeHTTP_PanicAfterCommitKeepsBodyIntact),
// which is the worse failure mode. A panic in this middleware's OWN
// pre-forward code still gets a clean 500 (TestR179_PanicRecoverySetsNoStore).
func TestServeHTTP_RecoversHandlerPanic(t *testing.T) {
	oidc := &TraefikOidc{
		next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("boom")
		}),
		logger:       NewLogger("error"),
		excludedURLs: map[string]struct{}{"/health": {}},
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	oidc.ServeHTTP(rw, req) // must not panic

	// Go's net/http sends the default 200 when a handler returns having
	// never called WriteHeader/Write -- the same outcome a plain http.Server
	// gives any handler that recovers a downstream panic without itself
	// writing a response.
	if rw.Code != http.StatusOK {
		t.Fatalf("expected the unwritten-response default (200) after a recovered downstream panic, got %d", rw.Code)
	}
}
