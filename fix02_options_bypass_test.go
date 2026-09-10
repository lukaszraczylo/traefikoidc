package traefikoidc

// Regression tests for FIX-02 (review-2026-09-10 finding at
// middleware.go:105): shouldBypassAuth bypassed OIDC auth for ANY request
// whose method is OPTIONS, not only genuine CORS preflights. A real
// preflight always carries both an Origin header and an
// Access-Control-Request-Method header; the R124 fix checked only the
// method, so an unauthenticated `OPTIONS <protected-path>` with neither
// header reached the backend unauthenticated (reproduced against
// http.FileServer: 200 with the protected file's body).
//
// TestServeHTTP_ForgedPreflightDoesNotLeakBody hardens the residual gap a
// follow-up review found in that fix: the Origin +
// Access-Control-Request-Method check only rules out an accidental bare
// OPTIONS request, not a deliberate attacker, since any non-browser client
// can set both headers itself. bypassReasonOptions still forwarded to next
// with no session check, so a forged preflight against http.FileServer
// still returned the protected file's body.
//
// A later maintainer decision (the AllowUnauthenticatedPreflight config
// option, settings.go) restored the released default: every OPTIONS request
// -- genuine preflight or not -- needs auth unless the operator opts in.
// Every test below that exercises the bypass path (positive or negative)
// sets allowUnauthenticatedPreflight: true so it keeps testing the
// Origin+Access-Control-Request-Method gate itself rather than the flag
// gate placed in front of it. The default-off case is pinned separately by
// TestServeHTTP_DefaultConfigGenuinePreflightRequiresAuth in
// fix02b_allow_unauthenticated_preflight_test.go.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestShouldBypassAuth_BareOptionsDoesNotBypass pins the negative case: a
// bare OPTIONS request carrying neither Origin nor
// Access-Control-Request-Method is not a CORS preflight and must go
// through the normal auth pipeline like any other method.
func TestShouldBypassAuth_BareOptionsDoesNotBypass(t *testing.T) {
	tObj := &TraefikOidc{logger: GetSingletonNoOpLogger(), allowUnauthenticatedPreflight: true}
	req := httptest.NewRequest(http.MethodOptions, "/api/resource", nil)

	if bypass, reason := tObj.shouldBypassAuth(req); bypass {
		t.Fatalf("bare OPTIONS (no Origin, no Access-Control-Request-Method) must not bypass auth, got bypass reason %q", reason)
	}
}

// TestShouldBypassAuth_OptionsWithOnlyOriginDoesNotBypass pins a partial
// case: Origin alone (e.g. a plain cross-origin GET, not a preflight) must
// not bypass either -- both headers are required.
func TestShouldBypassAuth_OptionsWithOnlyOriginDoesNotBypass(t *testing.T) {
	tObj := &TraefikOidc{logger: GetSingletonNoOpLogger(), allowUnauthenticatedPreflight: true}
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
	tObj := &TraefikOidc{logger: GetSingletonNoOpLogger(), allowUnauthenticatedPreflight: true}
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

	if !nextCalled {
		t.Fatalf("a genuine CORS preflight must still reach the backend, got status=%d body=%q", rw.Code, rw.Body.String())
	}
}

// TestServeHTTP_ForgedPreflightDoesNotLeakBody reproduces the finding's own
// exploit: a non-browser client sends an OPTIONS request carrying BOTH
// Origin and Access-Control-Request-Method (indistinguishable from a real
// preflight to shouldBypassAuth) against a protected path, with no session
// cookie. It must not receive the backend's response body, even though the
// request still forwards unauthenticated so a real browser preflight keeps
// getting its CORS headers answered.
func TestServeHTTP_ForgedPreflightDoesNotLeakBody(t *testing.T) {
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
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rw := httptest.NewRecorder()

	tObj.ServeHTTP(rw, req)

	if strings.Contains(rw.Body.String(), "TOP-SECRET-PAYROLL") {
		t.Fatalf("forged preflight leaked protected content: status=%d body=%q", rw.Code, rw.Body.String())
	}
}
