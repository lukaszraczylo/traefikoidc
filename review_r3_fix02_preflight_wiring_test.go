package traefikoidc

// Round-3 verifier regression (FIX-02, low): deleting
// Config.AllowUnauthenticatedPreflight -> allowUnauthenticatedPreflight in
// main.go's NewWithContext (around line 333) fails no test, because every
// existing middleware test builds *TraefikOidc as a struct literal and sets
// allowUnauthenticatedPreflight directly, never exercising the
// constructor's own field assignment. The tests below build the plugin
// through NewWithContext instead, so they actually depend on that wiring
// line.
//
// Real OIDC provider discovery is not needed to exercise this: the
// preflight bypass check runs before ServeHTTP ever waits on provider
// metadata (see shouldBypassAuth's doc comment in middleware.go), and the
// "default config" companion case only needs the "no session -> redirect
// into the login flow" path, which does not require a live provider
// either. buildFIX02PreflightTestPlugin publishes the metadata a
// successful discovery would have produced and closes initComplete
// directly (the same technique middleware_edge_cases_test.go uses for a
// raw struct literal) so the test stays fast and hermetic while still
// going through the real constructor.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// buildFIX02PreflightTestPlugin builds a real *TraefikOidc through
// NewWithContext with config.AllowUnauthenticatedPreflight set to
// allowPreflight, and returns it alongside a counter of how many times the
// next handler was invoked.
func buildFIX02PreflightTestPlugin(t *testing.T, allowPreflight bool) (*TraefikOidc, *int32) {
	t.Helper()

	var nextCalled int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&nextCalled, 1)
		w.Header().Set("Access-Control-Allow-Origin", "https://frontend.example.com")
		w.WriteHeader(http.StatusNoContent)
		_, _ = w.Write([]byte("protected-backend-body"))
	})

	config := CreateConfig()
	config.ProviderURL = "https://provider.example.com"
	config.ClientID = "test-client-id"
	config.ClientSecret = "test-secret"
	config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	config.CallbackURL = "/callback"
	config.AllowUnauthenticatedPreflight = allowPreflight

	oidc, err := NewWithContext(context.Background(), config, next, "test")
	if err != nil {
		t.Fatalf("failed to build plugin via NewWithContext: %v", err)
	}
	t.Cleanup(func() { _ = oidc.Close() })

	// Publish the metadata a successful discovery would have set, and mark
	// initialization complete, without waiting on (or depending on) a real
	// network round trip to config.ProviderURL. Mirrors what
	// initializeMetadata itself would do on success.
	oidc.metadataMu.Lock()
	oidc.issuerURL = config.ProviderURL
	oidc.authURL = config.ProviderURL + "/auth"
	oidc.metadataMu.Unlock()
	select {
	case <-oidc.initComplete:
		// Already closed (the background metadata goroutine got there first).
	default:
		close(oidc.initComplete)
	}

	return oidc, &nextCalled
}

// newFIX02PreflightRequest builds a genuine CORS preflight: OPTIONS with
// both Origin and Access-Control-Request-Method, no session cookie. Real
// browsers send no other OPTIONS request shaped like this (see
// shouldBypassAuth's doc comment).
func newFIX02PreflightRequest() *http.Request {
	req := httptest.NewRequest(http.MethodOptions, "https://example.com/protected", nil)
	req.Header.Set("Origin", "https://frontend.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	return req
}

// TestFIX02_AllowUnauthenticatedPreflightWiring_Enabled pins that
// Config.AllowUnauthenticatedPreflight, set through NewWithContext, reaches
// TraefikOidc.allowUnauthenticatedPreflight. With the flag on, a genuine
// CORS preflight must reach next, and the response body must be discarded
// (optionsPreflightWriter) so a forged OPTIONS-with-Origin-header request
// still cannot read a protected resource's body.
func TestFIX02_AllowUnauthenticatedPreflightWiring_Enabled(t *testing.T) {
	oidc, nextCalled := buildFIX02PreflightTestPlugin(t, true)

	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, newFIX02PreflightRequest())

	if got := atomic.LoadInt32(nextCalled); got != 1 {
		t.Fatalf("expected next to be called exactly once for an allowed CORS preflight, got %d", got)
	}
	if body := rw.Body.String(); body != "" {
		t.Fatalf("expected the preflight response body to be discarded, got %q", body)
	}
	if rw.Code != http.StatusNoContent {
		t.Fatalf("expected next's status (204) to still be forwarded, got %d", rw.Code)
	}
}

// TestFIX02_AllowUnauthenticatedPreflightWiring_DefaultRequiresAuth is the
// companion case: with the default config (AllowUnauthenticatedPreflight
// unset), the identical request must NOT bypass authentication. next must
// not be called, and the session-less request must be sent into the login
// flow (redirect) rather than forwarded.
func TestFIX02_AllowUnauthenticatedPreflightWiring_DefaultRequiresAuth(t *testing.T) {
	oidc, nextCalled := buildFIX02PreflightTestPlugin(t, false)

	rw := httptest.NewRecorder()
	oidc.ServeHTTP(rw, newFIX02PreflightRequest())

	if got := atomic.LoadInt32(nextCalled); got != 0 {
		t.Fatalf("expected next NOT to be called without the preflight opt-in, got %d calls", got)
	}
	if rw.Code != http.StatusFound && rw.Code != http.StatusSeeOther {
		t.Fatalf("expected the unauthenticated request to be redirected into the auth flow, got %d", rw.Code)
	}
}
