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
// Hijacker wrapper), so wrapping there breaks SSE in production. Once next
// has the real writer, this middleware can no longer tell from
// tw.wroteHeader alone whether next already committed a response before
// panicking (a re-review at middleware.go:440 found the old "send a
// header-only 500 unconditionally" rule sent a superfluous second
// WriteHeader whenever next HAD already committed one). The recover block
// now stops guessing entirely once next has been reached: it logs the
// panic and returns without writing anything of its own. The accepted
// trade-off (documented at the recover site in middleware.go) is that a
// panic in next before it writes anything -- this test's case -- no longer
// gets an explicit 500 from this middleware; ServeHTTP simply returns
// having written nothing, and it is net/http itself (a real server, not
// this unit test's Recorder) that decides what a handler which wrote
// nothing gets. What the fix still guarantees, and what this test pins, is
// the ORIGINAL R74 contract: the panic never escapes ServeHTTP, so the
// connection is never abruptly closed/truncated by an unrecovered panic.
// The commit-preserving half of the old contract (never corrupt a response
// next already sent) is unaffected and stays pinned by
// TestR155_ServeHTTP_PanicAfterCommitKeepsBodyIntact and
// TestServeHTTP_PanicAfterNextCommitted_NoSuperfluousWriteHeader.
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
	oidc.ServeHTTP(rw, req) // must not panic, and must not re-panic ErrAbortHandler-only exemption

	if rw.Code != http.StatusOK {
		t.Fatalf("a panic in next before it writes anything no longer gets an explicit status from this middleware (documented trade-off, middleware.go:440 re-review); httptest.Recorder's unwritten default is 200, got %d", rw.Code)
	}
	if rw.Body.Len() != 0 {
		t.Fatalf("nothing should have been written, got body %q", rw.Body.String())
	}
}
