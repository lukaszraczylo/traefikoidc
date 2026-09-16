package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestR172_LogoutResponsesAreNoStore verifies the R147 cache-directive contract
// ("every auth response must be no-store") is honored for the two logout
// surfaces that previously wrote responses without Cache-Control: no-store:
//   - handleLogout's RP-side redirect (helpers.go): a heuristic-caching proxy
//     replaying the 302 would re-trigger logout for an already-logged-out
//     session.
//   - handleBackchannelLogout's 200 OK acknowledgement (logout.go): a stale
//     replayable 200 could be cached and re-delivered.
func TestR172_LogoutResponsesAreNoStore(t *testing.T) {
	t.Run("handleLogout redirect is no-store", func(t *testing.T) {
		oidc := &TraefikOidc{
			logger:                NewLogger("error"),
			sessionManager:        createTestSessionManager(t),
			postLogoutRedirectURI: "",
		}
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		rw := httptest.NewRecorder()
		oidc.handleLogout(rw, req)

		if rw.Code != http.StatusFound {
			t.Fatalf("handleLogout should redirect (302), got %d", rw.Code)
		}
		if got := rw.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Fatalf("logout redirect must carry Cache-Control: no-store, got %q", got)
		}
		if loc := rw.Header().Get("Location"); loc == "" {
			t.Fatal("expected a Location header on the logout redirect")
		}
	})

	t.Run("handleBackchannelLogout 200 is no-store", func(t *testing.T) {
		h := newR87LogoutHarness(t)
		claims := r87BaseClaims()
		claims["exp"] = int64(1) << 40 // far-future exp, valid

		req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
			strings.NewReader("logout_token="+url.QueryEscape(h.tok(claims))))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rw := httptest.NewRecorder()
		h.oidc.handleBackchannelLogout(rw, req)

		if rw.Code != http.StatusOK {
			t.Fatalf("backchannel logout should 200, got %d", rw.Code)
		}
		if got := rw.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Fatalf("backchannel 200 must carry Cache-Control: no-store, got %q", got)
		}
	})
}
