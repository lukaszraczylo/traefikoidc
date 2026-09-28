package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServeHTTP_RecoversHandlerPanic regresses the request-handler path
// having no panic recovery for a panic that happens BEFORE t.next is ever
// reached: that case is still answered with a clean 500 and never escapes
// to net/http (which would otherwise close/truncate the connection). See
// TestServeHTTP_PanicBeforeNextCalled_StillAnswers500 for that half.
//
// FIX-06 requires t.next.ServeHTTP to receive the real ResponseWriter
// Traefik gave this plugin, not a tracking wrapper -- yaegi v0.16.1 does
// not bridge a custom wrapper's Flush/Unwrap methods across the
// interpreted-to-compiled boundary (only a composed ResponseWriter+
// Hijacker wrapper), so wrapping there breaks SSE in production. Once next
// has the real writer, this middleware can no longer tell from
// tw.wroteHeader alone whether next already committed a response before
// panicking. A re-review at middleware.go:440 found that the old "send a
// header-only 500 unconditionally" rule sent a superfluous second
// WriteHeader whenever next HAD already committed one; the fix that
// followed instead stopped guessing by returning normally once next had
// been reached. A further re-review at middleware.go:466 found THAT
// swallowed the panic and let ServeHTTP report success either way: a panic
// in next before it wrote anything (this test's case) delivered an empty
// 200, and a panic mid-body delivered a truncated body as a cleanly
// terminated 200 -- the exact defect class http.ErrAbortHandler already
// gets a dedicated re-panic for. The recover now re-panics the ORIGINAL
// value once next has been reached, so net/http's own top-level recovery
// (or, in production, Traefik's compiled recovery middleware) makes the
// real call from outside this plugin: a 500 when nothing was sent yet, or
// an aborted connection when a response was already committed. This test
// pins that ServeHTTP re-panics the unmodified value and writes nothing of
// its own first; TestR155_ServeHTTP_PanicAfterCommitKeepsBodyIntact and
// TestServeHTTP_PanicAfterNextCommitted_NoSuperfluousWriteHeader pin the
// commit-preserving half (never corrupt a response next already sent).
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

	recovered := func() (r any) {
		defer func() { r = recover() }()
		oidc.ServeHTTP(rw, req)
		return nil
	}()

	if recovered != "boom" {
		t.Fatalf("once next has been reached, ServeHTTP must re-panic the original value instead of swallowing it, got %v (type %T)", recovered, recovered)
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("ServeHTTP must not write a response of its own before re-panicking; httptest.Recorder's unwritten default is 200, got %d", rw.Code)
	}
	if rw.Body.Len() != 0 {
		t.Fatalf("ServeHTTP must not write a response of its own before re-panicking, got body %q", rw.Body.String())
	}
}
