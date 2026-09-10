package traefikoidc

// Regression tests for FIX-06 (review-2026-09-10 finding at
// middleware.go:309, high severity): ServeHTTP wraps the response writer
// in *trackingWriter for panic-commit tracking (rw = tw) and then hands
// that SAME wrapped writer to every t.next.ServeHTTP call, including the
// SSE/WebSocket bypass and the authenticated forwarding path. Traefik runs
// this plugin interpreted under yaegi v0.16.1, and yaegi's stdlib
// interop layer composes a boundary wrapper only for ResponseWriter+
// Hijacker crossing into compiled code -- not for Flusher or Unwrap. So
// Traefik's compiled ReverseProxy calling
// http.NewResponseController(rw).Flush() on the interpreted trackingWriter
// gets "feature not supported" in production, even though trackingWriter
// declares Flush/Unwrap and native tests (which never cross an
// interpreter boundary) pass. See cmd/yaegiflushcheck/main.go (its own
// nested Go module, not part of this package -- it depends on
// github.com/traefik/yaegi/interp to drive the real plugin under yaegi with
// a compiled next; run with `go run .` from cmd/yaegiflushcheck, with
// GOPATH pointing at a src/github.com/lukaszraczylo/traefikoidc symlink to
// this checkout) for the interop reproduction.
//
// The fix hands t.next.ServeHTTP the ORIGINAL writer ServeHTTP received
// (trackingWriter.Unwrap()), never the wrapper, on every forwarding path.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// nextWriterSpy is a minimal next handler that records whether the
// http.ResponseWriter it was handed is (or, transitively, still wraps) a
// *trackingWriter, so a test can assert the downstream writer is the real
// one Traefik would give a compiled ReverseProxy -- not the interpreted
// wrapper.
func nextWriterSpy(called *bool, sawTrackingWriter *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		if _, ok := w.(*trackingWriter); ok {
			*sawTrackingWriter = true
		}
		w.WriteHeader(http.StatusOK)
	})
}

// authenticatedRequestWithCookie builds a request carrying a saved,
// authenticated session cookie for user, so the SSE/WebSocket bypass's
// cookie-only auth check (applyBypassUserHeaders) admits it.
func authenticatedRequestWithCookie(t *testing.T, sm *SessionManager, user string) *http.Request {
	t.Helper()
	setupReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/stream", nil)
	session, err := sm.GetSession(setupReq)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetAuthenticated(true)
	session.SetUserIdentifier(user)
	rr := httptest.NewRecorder()
	if err := session.Save(setupReq, rr); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/stream", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

// TestServeHTTP_SSEBypass_NextReceivesUnwrappedWriter pins FIX-06 on the
// SSE bypass path.
func TestServeHTTP_SSEBypass_NextReceivesUnwrappedWriter(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	var called, sawTrackingWriter bool
	initComplete := make(chan struct{})
	close(initComplete)
	tObj := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		name:           "test",
		next:           nextWriterSpy(&called, &sawTrackingWriter),
		sessionManager: sm,
		initComplete:   initComplete,
	}

	req := authenticatedRequestWithCookie(t, sm, "user@example.com")
	req.Header.Set("Accept", "text/event-stream")
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if !called {
		t.Fatalf("next handler was not invoked (status=%d body=%q); the authenticated SSE bypass must forward", rw.Code, rw.Body.String())
	}
	if sawTrackingWriter {
		t.Fatal("next handler received the interpreted trackingWriter on the SSE bypass path, not the original ResponseWriter")
	}
}

// TestServeHTTP_WebSocketBypass_NextReceivesUnwrappedWriter pins FIX-06 on
// the WebSocket upgrade bypass path.
func TestServeHTTP_WebSocketBypass_NextReceivesUnwrappedWriter(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	var called, sawTrackingWriter bool
	initComplete := make(chan struct{})
	close(initComplete)
	tObj := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		name:           "test",
		next:           nextWriterSpy(&called, &sawTrackingWriter),
		sessionManager: sm,
		initComplete:   initComplete,
	}

	req := authenticatedRequestWithCookie(t, sm, "user@example.com")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if !called {
		t.Fatalf("next handler was not invoked (status=%d body=%q); the authenticated WebSocket bypass must forward", rw.Code, rw.Body.String())
	}
	if sawTrackingWriter {
		t.Fatal("next handler received the interpreted trackingWriter on the WebSocket bypass path, not the original ResponseWriter")
	}
}

// TestForwardAuthorized_NextReceivesUnwrappedWriter pins FIX-06 on the
// authenticated forwarding path (forwardAuthorized is ServeHTTP's and
// bearer_auth.go's shared tail call to t.next.ServeHTTP). ServeHTTP always
// calls forwardAuthorized with rw already wrapped in *trackingWriter (see
// middleware.go:309); reproduce that shape directly here.
func TestForwardAuthorized_NextReceivesUnwrappedWriter(t *testing.T) {
	var called, sawTrackingWriter bool
	oidc := &TraefikOidc{
		logger: GetSingletonNoOpLogger(),
		next:   nextWriterSpy(&called, &sawTrackingWriter),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	tw := &trackingWriter{ResponseWriter: rec}
	p := &principal{Identifier: "user@example.com"}

	oidc.forwardAuthorized(tw, req, p)

	if !called {
		t.Fatal("next handler was not invoked")
	}
	if sawTrackingWriter {
		t.Fatal("next handler received the interpreted trackingWriter on the authenticated path, not the original ResponseWriter")
	}
}
