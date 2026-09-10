package traefikoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestHandleLogout_RebuildsPostLogoutRedirectURIFromTrustedOrigin pins
// FIX-07: RP-initiated logout must still send post_logout_redirect_uri to
// the end_session_endpoint under the default ('/') postLogoutRedirectURI
// config, so the IdP returns the user to the app instead of stranding them
// on the provider's own logout page.
//
// At head, helpers.go sends any postLogoutRedirectURI value that doesn't
// start with "http" (including the default "/") to a branch that sets
// postLogoutRedirectURI = "", and BuildLogoutURL then omits the parameter
// entirely (d5fddeb / R68). The fix rebuilds an absolute value from the
// scheme+host of the redirect_url persisted at authentication-initiate
// time (R136) — already accepted by the IdP as this deployment's
// redirect_uri, so it is a trusted origin.
//
// Table-driven per FIX-07's review: "/" is the value main.go actually
// derives for an unset config (the documented default) and runs through
// helpers.go's `default:` branch; "/bye" exercises that same branch with a
// non-root path; "" is the zero Go string a caller could set directly and
// runs through a separate `case postLogoutRedirectURI == "":` branch that
// happens to produce the same result. Only "/" is what production ever
// actually sends this function, so it is the case that must not regress.
func TestHandleLogout_RebuildsPostLogoutRedirectURIFromTrustedOrigin(t *testing.T) {
	tests := []struct {
		name                  string
		postLogoutRedirectURI string
		want                  string
	}{
		{
			name:                  "production default '/'",
			postLogoutRedirectURI: "/",
			want:                  "https://app.example.com/",
		},
		{
			name:                  "relative path",
			postLogoutRedirectURI: "/bye",
			want:                  "https://app.example.com/bye",
		},
		{
			name:                  "zero-value empty string",
			postLogoutRedirectURI: "",
			want:                  "https://app.example.com/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sm := createTestSessionManager(t)

			base := httptest.NewRequest(http.MethodGet, "/protected", nil)
			baseRec := httptest.NewRecorder()
			session, err := sm.GetSession(base)
			if err != nil {
				t.Fatalf("GetSession: %v", err)
			}
			// SetIDToken persists through the chunk manager's content validation
			// (session_chunk_manager.go), which requires a well-formed JWT; a
			// realistic RSA-signed token is needed for it to survive the cookie
			// round trip. handleLogout itself never verifies the token.
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			now := time.Now()
			idToken, err := createTestJWT(key, "RS256", "test-key", map[string]interface{}{
				"iss": "https://idp.example.com",
				"aud": "test-client",
				"exp": float64(now.Add(time.Hour).Unix()),
				"iat": float64(now.Unix()),
				"sub": "test-user",
			})
			if err != nil {
				t.Fatalf("createTestJWT: %v", err)
			}
			session.SetIDToken(idToken)
			session.SetRedirectURL("https://app.example.com/oidc/callback")
			if err := session.Save(base, baseRec); err != nil {
				t.Fatalf("Save: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/logout", nil)
			for _, c := range baseRec.Result().Cookies() {
				req.AddCookie(c)
			}
			rw := httptest.NewRecorder()

			oidc := &TraefikOidc{
				logger:                NewLogger("error"),
				sessionManager:        sm,
				postLogoutRedirectURI: tc.postLogoutRedirectURI,
				endSessionURL:         "https://idp.example.com/end-session",
				tokenCache:            NewTokenCache(),
			}
			oidc.handleLogout(rw, req)

			if rw.Code != http.StatusFound {
				t.Fatalf("expected 302 redirect to the IdP end-session endpoint, got %d", rw.Code)
			}
			loc := rw.Header().Get("Location")
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("Location header %q did not parse: %v", loc, err)
			}
			got := u.Query().Get("post_logout_redirect_uri")
			if got != tc.want {
				t.Fatalf("post_logout_redirect_uri = %q, want %q (derived from the persisted redirect_url origin)", got, tc.want)
			}
		})
	}
}
