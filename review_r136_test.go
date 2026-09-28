package traefikoidc

// R136 review-fix round regressions.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsOriginAllowed_HttpsWildcardRejectsHttpScheme guards the R136 fix:
// the CORS wildcard branch for "https://*.example.com" previously checked
// only the Host suffix, so "http://api.example.com" was admitted and then
// reflected verbatim as Access-Control-Allow-Origin with AllowCredentials
// (a credentialed http brother for an https-only wildcard). The scheme part
// of the wildcard must be honored.
func TestIsOriginAllowed_HttpsWildcardRejectsHttpScheme(t *testing.T) {
	allowed := []string{"https://*.example.com"}

	// https siblings (exact apex or subdomain) still allowed.
	if !isOriginAllowed("https://example.com", allowed) {
		t.Errorf("expected https apex to be allowed")
	}
	if !isOriginAllowed("https://api.example.com", allowed) {
		t.Errorf("expected https subdomain to be allowed")
	}
	if !isOriginAllowed("https://a.b.example.com", allowed) {
		t.Errorf("expected nested https subdomain to be allowed")
	}

	// http sibling must be rejected (fail-on-old: it was previously allowed).
	for _, origin := range []string{"http://example.com", "http://api.example.com"} {
		if isOriginAllowed(origin, allowed) {
			t.Errorf("expected %q to be rejected for https wildcard", origin)
		}
	}

	// http wildcard branch behaves symmetrically.
	httpAllowed := []string{"http://*.example.com"}
	if !isOriginAllowed("http://api.example.com", httpAllowed) {
		t.Errorf("expected http subdomain to be allowed for http wildcard")
	}
	if isOriginAllowed("https://api.example.com", httpAllowed) {
		t.Errorf("expected https origin to be rejected for http wildcard")
	}
}

// TestApplySecurityHeaders_CorsWildcardEnsuresScheme asserts that the CORS
// reflection path (which feeds isOriginAllowed) does not set
// Access-Control-Allow-Origin for a scheme-mismatched origin.
func TestApplySecurityHeaders_CorsWildcardEnsuresScheme(t *testing.T) {
	c := CreateConfig()
	c.SecurityHeaders.CORSEnabled = true
	c.SecurityHeaders.CORSAllowedOrigins = []string{"https://*.example.com"}
	c.SecurityHeaders.CORSAllowCredentials = true

	req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	req.Header.Set("Origin", "http://api.example.com")
	rw := httptest.NewRecorder()

	applier := c.GetSecurityHeadersApplier()
	applier(rw, req)

	if got := rw.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no CORS allow-origin for scheme-mismatched origin, got %q", got)
	}
}

// TestCallback_UsesPersistedRedirectURL guards the R136 fix: the token
// exchange must use the redirect_uri persisted at auth initiate, not a value
// rebuilt from the (client-affectable) callback request's X-Forwarded-Host.
// An attacker who steers the callback request's host must not change the
// redirect_uri sent to the provider (mismatch would fail the login; a
// provider-registered attacker origin makes it a bounded open redirect).
func TestCallback_UsesPersistedRedirectURL(t *testing.T) {
	const persistedRedirect = "https://app.example/callback"

	testLogger := newNoOpLogger()
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		testLogger,
	)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer sessionManager.Shutdown()

	var gotRedirect string
	oidc := &TraefikOidc{
		sessionManager: sessionManager,
		logger:         testLogger,
		enablePKCE:     false,
		tokenExchanger: &EnhancedMockTokenExchanger{
			ExchangeCodeFunc: func(ctx context.Context, grantType, code, redirectURL, codeVerifier string) (*TokenResponse, error) {
				gotRedirect = redirectURL
				return &TokenResponse{AccessToken: "access-token", IDToken: "id-token"}, nil
			},
		},
		// Ends the flow after the exchange so we can assert redirect_uri.
		tokenVerifier: &EnhancedMockTokenVerifier{Err: errRedirectIntoStub},
	}

	csrf := "csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rw := httptest.NewRecorder()
	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetCSRF(csrf)
	session.SetNonce("nonce")
	session.SetRedirectURL(persistedRedirect)
	if err := session.Save(req, rw); err != nil {
		t.Fatalf("Save: %v", err)
	}
	session.returnToPoolSafely()

	// Callback request that, if the redirect_uri were rebuilt from it, would
	// yield a different value (simulating a drifted X-Forwarded-Host).
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrf, nil)
	for _, c := range rw.Result().Cookies() {
		req2.AddCookie(c)
	}
	rw2 := httptest.NewRecorder()
	oidc.handleCallback(rw2, req2, "https://attacker.example/callback")

	if gotRedirect != persistedRedirect {
		t.Fatalf("expected exchange to use persisted redirect_uri %q, got %q", persistedRedirect, gotRedirect)
	}
}

// errRedirectIntoStub is a marker error for the test's token verifier stub.
var errRedirectIntoStub = &testRedirectError{}

type testRedirectError struct{}

func (*testRedirectError) Error() string { return "stub verify error" }
