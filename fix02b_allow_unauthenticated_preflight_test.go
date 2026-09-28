package traefikoidc

// Regression tests for the FIX-02 maintainer decision: the released
// behavior required authentication for every OPTIONS request by default.
// FIX-02 (fix02_options_bypass_test.go) narrowed an accidental
// unconditional OPTIONS bypass down to genuine CORS preflights (Origin +
// Access-Control-Request-Method), but that still left every preflight
// unauthenticated by default -- a behavior change from the release. This
// file pins the maintainer decision to restore released behavior: the
// preflight bypass now only applies when the operator opts in via
// AllowUnauthenticatedPreflight (default false). With the flag off, OPTIONS
// goes through the normal auth pipeline like any other method.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServeHTTP_DefaultConfigGenuinePreflightRequiresAuth pins the default
// (AllowUnauthenticatedPreflight=false) behavior: even a genuine CORS
// preflight (Origin + Access-Control-Request-Method) must NOT reach the
// backend without a session -- it goes through the normal auth pipeline
// (redirect or 401) exactly like any other unauthenticated request. This is
// the released behavior FIX-02 must restore by default.
func TestServeHTTP_DefaultConfigGenuinePreflightRequiresAuth(t *testing.T) {
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
		// AllowUnauthenticatedPreflight left at its zero value (false):
		// default config must not bypass auth for OPTIONS.
	}

	req := httptest.NewRequest(http.MethodOptions, "https://app.example.com/secret.txt", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if nextCalled {
		t.Fatalf("default config (allowUnauthenticatedPreflight=false) must send a genuine OPTIONS preflight through the normal auth pipeline, but the backend was called unconditionally: status=%d body=%q", rw.Code, rw.Body.String())
	}
	if rw.Code == http.StatusNoContent {
		t.Fatalf("default config must not answer the preflight bypass response (204 from next); got status=%d", rw.Code)
	}
}

// TestServeHTTP_AllowUnauthenticatedPreflight_GenuinePreflightBypassesBodyDiscarded
// pins the opt-in behavior: with AllowUnauthenticatedPreflight=true, a
// genuine CORS preflight still bypasses auth (so real browser preflights
// keep working) and the optionsPreflightWriter still discards the body
// (FIX-02's forged-preflight hardening keeps applying when the flag is on).
func TestServeHTTP_AllowUnauthenticatedPreflight_GenuinePreflightBypassesBodyDiscarded(t *testing.T) {
	sm, err := NewSessionManager(strings.Repeat("k", 32), false, "", "", time.Hour, NewLogger("error"))
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sm.Shutdown()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("TOP-SECRET-PAYROLL"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	next := http.FileServer(http.Dir(dir))

	initComplete := make(chan struct{})
	close(initComplete)

	tObj := &TraefikOidc{
		logger:                        GetSingletonNoOpLogger(),
		name:                          "test",
		next:                          next,
		sessionManager:                sm,
		redirURLPath:                  "/callback",
		authURL:                       "https://idp.example.com/authorize",
		issuerURL:                     "https://idp.example.com",
		clientID:                      "test-client-id",
		scopes:                        []string{"openid"},
		initComplete:                  initComplete,
		allowUnauthenticatedPreflight: true,
	}

	req := httptest.NewRequest(http.MethodOptions, "https://app.example.com/secret.txt", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if strings.Contains(rw.Body.String(), "TOP-SECRET-PAYROLL") {
		t.Fatalf("allowUnauthenticatedPreflight=true must still discard the preflight response body: status=%d body=%q", rw.Code, rw.Body.String())
	}
}

// TestServeHTTP_AllowUnauthenticatedPreflight_BareOptionsStillRequiresAuth
// pins that the flag only widens the genuine-preflight gate -- a bare
// OPTIONS request (no Origin, no Access-Control-Request-Method) still needs
// auth even with AllowUnauthenticatedPreflight=true.
func TestServeHTTP_AllowUnauthenticatedPreflight_BareOptionsStillRequiresAuth(t *testing.T) {
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
		logger:                        GetSingletonNoOpLogger(),
		name:                          "test",
		next:                          next,
		sessionManager:                sm,
		redirURLPath:                  "/callback",
		authURL:                       "https://idp.example.com/authorize",
		issuerURL:                     "https://idp.example.com",
		clientID:                      "test-client-id",
		scopes:                        []string{"openid"},
		initComplete:                  initComplete,
		allowUnauthenticatedPreflight: true,
	}

	req := httptest.NewRequest(http.MethodOptions, "https://app.example.com/secret.txt", nil)
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if nextCalled {
		t.Fatalf("allowUnauthenticatedPreflight=true must not bypass auth for a bare OPTIONS request (no Origin/Access-Control-Request-Method), but the backend was called: status=%d body=%q", rw.Code, rw.Body.String())
	}
}
