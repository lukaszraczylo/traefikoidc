package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestValidateAzureTokensRS_UnauthNoRefresh_FailsClosed regresses the Azure
// validation copy-paste: an unauthenticated session with NO refresh token
// must fail closed (force re-auth) instead of returning needsRefresh=true
// with nothing to refresh with.
func TestValidateAzureTokensRS_UnauthNoRefresh_FailsClosed(t *testing.T) {
	oidc := &TraefikOidc{}
	rs := &requestState{authenticated: false}
	auth, refresh, expired := oidc.validateAzureTokensRS(rs)
	if auth || refresh || expired {
		t.Fatalf("want (false,false,false) matching standard path for unauth+no-refresh, got (%v,%v,%v)", auth, refresh, expired)
	}
}

// TestDefaultInitiateAuthentication_DCRNoClientID_Returns503 regresses that
// dynamic client registration that has not yet produced a client_id does not
// send the user to the provider on a broken authorize URL (client_id="").
func TestDefaultInitiateAuthentication_DCRNoClientID_Returns503(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()
	ts.tOidc.dcrConfig = &DynamicClientRegistrationConfig{Enabled: true}
	ts.tOidc.clientID = ""

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()
	session, err := ts.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}

	ts.tOidc.defaultInitiateAuthentication(rw, req, session, "http://example.com/callback")

	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when DCR has no client_id, got %d", rw.Code)
	}
}

// TestEnhanceSessionSecurity_BoundsCookieDomainToServingHost regresses that a
// broader/unrelated X-Forwarded-Host does not widen the token-bearing
// session cookie's Domain to sibling subdomains — it is bounded to the
// serving host.
func TestEnhanceSessionSecurity_BoundsCookieDomainToServingHost(t *testing.T) {
	sm := createTestSessionManager(t)
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-Host", "example.com") // broader parent
	opts := sm.EnhanceSessionSecurity(nil, req)
	if opts.Domain != "app.example.com" {
		t.Fatalf("want Domain bounded to serving host app.example.com, got %q", opts.Domain)
	}
}
