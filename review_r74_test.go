package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServeHTTP_RecoversHandlerPanic regresses the request-handler path
// having no panic recovery: a panic in the chain (here, the downstream
// backend) now answers a clean 500 + body instead of escaping to
// net/http (which closes/truncates the connection).
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
