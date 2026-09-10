package traefikoidc

// Regression tests for FIX-02 (review-2026-09-10 finding at
// middleware.go:105): shouldBypassAuth bypassed OIDC auth for ANY request
// whose method is OPTIONS, not only genuine CORS preflights. A real
// preflight always carries both an Origin header and an
// Access-Control-Request-Method header; the R124 fix checked only the
// method, so an unauthenticated `OPTIONS <protected-path>` with neither
// header reached the backend unauthenticated (reproduced against
// http.FileServer: 200 with the protected file's body).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestShouldBypassAuth_BareOptionsDoesNotBypass pins the negative case: a
// bare OPTIONS request carrying neither Origin nor
// Access-Control-Request-Method is not a CORS preflight and must go
// through the normal auth pipeline like any other method.
func TestShouldBypassAuth_BareOptionsDoesNotBypass(t *testing.T) {
	tObj := &TraefikOidc{logger: GetSingletonNoOpLogger()}
	req := httptest.NewRequest(http.MethodOptions, "/api/resource", nil)

	if bypass, reason := tObj.shouldBypassAuth(req); bypass {
		t.Fatalf("bare OPTIONS (no Origin, no Access-Control-Request-Method) must not bypass auth, got bypass reason %q", reason)
	}
}

// TestShouldBypassAuth_OptionsWithOnlyOriginDoesNotBypass pins a partial
// case: Origin alone (e.g. a plain cross-origin GET, not a preflight) must
// not bypass either -- both headers are required.
func TestShouldBypassAuth_OptionsWithOnlyOriginDoesNotBypass(t *testing.T) {
	tObj := &TraefikOidc{logger: GetSingletonNoOpLogger()}
	req := httptest.NewRequest(http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "https://app.example.com")

	if bypass, reason := tObj.shouldBypassAuth(req); bypass {
		t.Fatalf("OPTIONS with only Origin set must not bypass auth, got bypass reason %q", reason)
	}
}

// TestShouldBypassAuth_GenuinePreflightBypasses pins the positive case: a
// real CORS preflight (Origin + Access-Control-Request-Method) must still
// bypass auth, so a browser's actual preflight keeps working.
func TestShouldBypassAuth_GenuinePreflightBypasses(t *testing.T) {
	tObj := &TraefikOidc{logger: GetSingletonNoOpLogger()}
	req := httptest.NewRequest(http.MethodOptions, "/api/resource", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	bypass, reason := tObj.shouldBypassAuth(req)
	if !bypass {
		t.Fatal("a genuine CORS preflight (Origin + Access-Control-Request-Method) must bypass auth")
	}
	if reason != bypassReasonOptions {
		t.Fatalf("preflight bypass reason = %q, want %q", reason, bypassReasonOptions)
	}
}

// TestServeHTTP_UnauthenticatedBareOptionsDoesNotReachBackend is the
// end-to-end reproduction from the finding: an unauthenticated OPTIONS
// request against a protected path, with no session cookie and no CORS
// headers, must not reach the next handler. Mirrors the reviewer's
// http.FileServer repro that returned the protected file's body.
func TestServeHTTP_UnauthenticatedBareOptionsDoesNotReachBackend(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TOP-SECRET-PAYROLL"))
	})

	initComplete := make(chan struct{})
	close(initComplete)

	tObj := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		name:           "test",
		next:           next,
		sessionManager: sm,
		redirURLPath:   "/callback",
		authURL:        "https://idp.example.com/authorize",
		issuerURL:      "https://idp.example.com",
		clientID:       "test-client-id",
		scopes:         []string{"openid"},
		initComplete:   initComplete,
	}

	req := httptest.NewRequest(http.MethodOptions, "https://app.example.com/secret.txt", nil)
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if nextCalled {
		t.Fatalf("unauthenticated bare OPTIONS must not reach the backend, but next handler ran (status=%d body=%q)", rw.Code, rw.Body.String())
	}
	if rw.Code == http.StatusOK && strings.Contains(rw.Body.String(), "TOP-SECRET-PAYROLL") {
		t.Fatalf("protected content leaked through an unauthenticated OPTIONS request: status=%d body=%q", rw.Code, rw.Body.String())
	}
}

// TestServeHTTP_GenuinePreflightReachesBackend confirms the fix does not
// regress the R124 behavior it builds on: a real CORS preflight for the
// same protected path must still reach the backend unconditionally.
func TestServeHTTP_GenuinePreflightReachesBackend(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
		w.WriteHeader(http.StatusNoContent)
	})

	initComplete := make(chan struct{})
	close(initComplete)

	tObj := &TraefikOidc{
		logger:         GetSingletonNoOpLogger(),
		name:           "test",
		next:           next,
		sessionManager: sm,
		redirURLPath:   "/callback",
		authURL:        "https://idp.example.com/authorize",
		issuerURL:      "https://idp.example.com",
		clientID:       "test-client-id",
		scopes:         []string{"openid"},
		initComplete:   initComplete,
	}

	req := httptest.NewRequest(http.MethodOptions, "https://app.example.com/secret.txt", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if !nextCalled {
		t.Fatalf("a genuine CORS preflight must still reach the backend, got status=%d body=%q", rw.Code, rw.Body.String())
	}
}
