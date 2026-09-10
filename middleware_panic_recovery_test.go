package traefikoidc

// Regression tests for the re-review finding at middleware.go:440
// (medium): ServeHTTP's deferred panic recovery swallows
// http.ErrAbortHandler, and after t.next has been called it can still send
// a superfluous WriteHeader(500) on top of a response next already
// committed.
//
// http.ErrAbortHandler is the sentinel net/http (and httputil.ReverseProxy,
// when copyResponse fails mid-body) panics with to mean "abort this
// connection silently, write nothing else" -- recovering it here and
// returning normally lets net/http finish the in-flight response as if it
// were complete, so a truncated upstream body reaches the client as a
// clean 200 instead of a closed/reset connection.
//
// Separately, t.next.ServeHTTP always receives the real ResponseWriter
// (FIX-06, downstreamWriter), never *trackingWriter, so tw.wroteHeader
// stays false even after next fully commits a response. A downstream panic
// after that point must not guess at a second WriteHeader(500): once next
// has been called, we cannot tell whether it already committed a response,
// so the safest and simplest rule is to never send our own status in that
// state.
import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// writeHeaderCountingWriter is a bare http.ResponseWriter (deliberately not
// wrapping httptest.ResponseRecorder, which silently discards a second
// WriteHeader call) that records every WriteHeader/Write call it receives,
// so a test can assert exactly how many times -- and with what status --
// the panic recovery writes to the real writer.
type writeHeaderCountingWriter struct {
	header           http.Header
	writeHeaderCalls []int
	bodyWrites       [][]byte
}

func (w *writeHeaderCountingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *writeHeaderCountingWriter) WriteHeader(code int) {
	w.writeHeaderCalls = append(w.writeHeaderCalls, code)
}

func (w *writeHeaderCountingWriter) Write(b []byte) (int, error) {
	w.bodyWrites = append(w.bodyWrites, append([]byte(nil), b...))
	return len(b), nil
}

// newExcludedPathTraefikOidc builds the minimal TraefikOidc needed to drive
// ServeHTTP down the bypassReasonExcluded path straight to next, with no
// session manager, provider init wait, or cookie required.
func newExcludedPathTraefikOidc(next http.Handler) *TraefikOidc {
	return &TraefikOidc{
		logger:       GetSingletonNoOpLogger(),
		name:         "test",
		excludedURLs: map[string]struct{}{"/public": {}},
		next:         next,
	}
}

// TestServeHTTP_PanicWithErrAbortHandler_Repanics pins that ServeHTTP must
// not swallow http.ErrAbortHandler: it must re-panic with the same value
// (so the outer net/http conn.serve recovers it and aborts the connection
// silently) and must not write any response of its own first.
func TestServeHTTP_PanicWithErrAbortHandler_Repanics(t *testing.T) {
	tObj := newExcludedPathTraefikOidc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	spy := &writeHeaderCountingWriter{}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/public", nil)

	recovered := func() (r any) {
		defer func() { r = recover() }()
		tObj.ServeHTTP(spy, req)
		return nil
	}()

	if recovered != http.ErrAbortHandler {
		t.Fatalf("ServeHTTP must re-panic http.ErrAbortHandler instead of swallowing it, got %v (type %T)", recovered, recovered)
	}
	if len(spy.writeHeaderCalls) != 0 {
		t.Fatalf("no response must be written before re-panicking ErrAbortHandler, got WriteHeader calls %v", spy.writeHeaderCalls)
	}
}

// TestServeHTTP_PanicAfterNextCommitted_NoSuperfluousWriteHeader pins that
// once t.next has been called and has already committed a full response,
// a later panic (e.g. in code that runs after t.next.ServeHTTP returns)
// must not send a second WriteHeader on the real writer. net/http logs
// "superfluous response.WriteHeader call" for this and it serves no
// purpose: the client already has next's response.
func TestServeHTTP_PanicAfterNextCommitted_NoSuperfluousWriteHeader(t *testing.T) {
	tObj := newExcludedPathTraefikOidc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		panic("boom after next committed a response")
	}))
	spy := &writeHeaderCountingWriter{}
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/public", nil)

	tObj.ServeHTTP(spy, req)

	if len(spy.writeHeaderCalls) != 1 || spy.writeHeaderCalls[0] != http.StatusOK {
		t.Fatalf("next's own WriteHeader(200) must be the only WriteHeader call, got %v", spy.writeHeaderCalls)
	}
	if len(spy.bodyWrites) != 1 || string(spy.bodyWrites[0]) != "ok" {
		t.Fatalf("the panic recovery must not touch a response next already committed, got body writes %v", spy.bodyWrites)
	}
}

// TestServeHTTP_PanicBeforeNextCalled_StillAnswers500 is the existing
// contract this fix must not regress: a panic that happens BEFORE t.next
// is ever reached (e.g. in this middleware's own auth/session code) must
// still answer a clean 500 with no cached response, exactly as before.
func TestServeHTTP_PanicBeforeNextCalled_StillAnswers500(t *testing.T) {
	tObj := &TraefikOidc{
		logger: GetSingletonNoOpLogger(),
		name:   "test",
		securityHeadersApplier: func(http.ResponseWriter, *http.Request) {
			panic("boom before next is ever reached")
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/protected", nil)

	tObj.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a pre-next panic must still answer 500, got %d", rec.Code)
	}
	if rec.Body.String() != "Internal Server Error" {
		t.Fatalf("a pre-next panic must still answer a body, got %q", rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("a panic-induced 500 must not be cached, got Cache-Control %q", rec.Header().Get("Cache-Control"))
	}
}
