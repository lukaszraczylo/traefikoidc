package traefikoidc

// Regression test for the re-review finding at middleware.go:141:
// optionsPreflightWriter.WriteHeader deletes any stale Content-Length next
// set, but only WriteHeader does that -- Write does not commit through
// WriteHeader at all, it just discards the body bytes. A next handler that
// uses the common "set Content-Length, then Write with no explicit
// WriteHeader" idiom (net/http's implicit-200 path) therefore leaves the
// real Content-Length header in place while zero body bytes actually reach
// the client: the browser's preflight request gets "Content-Length: 5" and
// an empty body, net/http (or the test transport here) reports it as a
// truncated/incomplete response instead of a clean empty 200.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOptionsPreflightWriter_WriteWithoutExplicitWriteHeaderDropsContentLength
// pins that Write alone (no preceding WriteHeader call from next) must still
// strip a Content-Length next set, exactly as an explicit WriteHeader call
// would.
func TestOptionsPreflightWriter_WriteWithoutExplicitWriteHeaderDropsContentLength(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &optionsPreflightWriter{ResponseWriter: rec}

	// The implicit-200 idiom: a handler sets headers (including
	// Content-Length, as it would for a real response body) and calls
	// Write directly, never WriteHeader.
	w.Header().Set("Content-Length", "5")
	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if n != len("hello") {
		t.Fatalf("Write must report the full length was accepted (so callers don't retry/error), got %d", n)
	}

	if cl := rec.Header().Get("Content-Length"); cl != "" {
		t.Fatalf("Content-Length must be stripped even when next never calls WriteHeader explicitly, got %q", cl)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("the body must still be discarded, got %q", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("an implicit-200 write must still commit a 200 status, got %d", rec.Code)
	}
}

// TestOptionsPreflightWriter_ExplicitWriteHeaderStillWorks is the existing
// (already-passing) contract: an explicit WriteHeader call strips
// Content-Length and commits the given status. Kept alongside the new test
// so a future change to WriteHeader can't silently break this path while
// fixing the implicit one.
func TestOptionsPreflightWriter_ExplicitWriteHeaderStillWorks(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &optionsPreflightWriter{ResponseWriter: rec}

	w.Header().Set("Content-Length", "5")
	w.WriteHeader(http.StatusNoContent)
	_, _ = w.Write([]byte("hello"))

	if cl := rec.Header().Get("Content-Length"); cl != "" {
		t.Fatalf("Content-Length must be stripped, got %q", cl)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("the explicit status must be preserved, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("the body must be discarded, got %q", rec.Body.String())
	}
}
