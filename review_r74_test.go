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
// FIX-06 requires t.next.ServeHTTP to receive the real ResponseWriter
// Traefik gave this plugin, not a tracking wrapper -- yaegi v0.16.1 does
// not bridge a custom wrapper's Flush/Unwrap methods across the
// interpreted-to-compiled boundary (only a composed ResponseWriter+
// Hijacker wrapper), so wrapping there breaks SSE in production. Once
// next has the real writer, this middleware can no longer tell from
// tw.wroteHeader alone whether next already committed a response before
// panicking, so the recover block sends a header-only 500
// (Cache-Control: no-store) unconditionally once nothing was written
// through the tracking wrapper -- WriteHeader is idempotent, so this is a
// no-op if next already committed one -- and writes the "Internal Server
// Error" body only when next was never reached, so it can never corrupt a
// response next already sent (see TestR155_ServeHTTP_PanicAfterCommitKeepsBodyIntact).
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

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from recovered panic, got %d", rw.Code)
	}
}
