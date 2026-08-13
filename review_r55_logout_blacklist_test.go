package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// Review regression: RP user logout must blacklist the session's tokens so a
// token captured before logout (e.g. a bearer-mode access token) cannot be
// reused until its natural expiry. Registers the OIDC end-session endpoint
// so logout completes, then checks the token blacklist was populated.
func TestLogoutBlacklistsSessionTokens(t *testing.T) {
	require := require.New(t)

	logger := NewLogger("info")
	sessionManager, _ := NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", "", 0, logger)
	tOidc := &TraefikOidc{
		endSessionURL:  "", // no provider end-session -> local redirect path
		logger:         logger,
		tokenBlacklist: NewCache(), // generic cache used as the blacklist
		httpClient:     &http.Client{},
		clientID:       "test-client-id",
		audience:       "test-client-id",
		clientSecret:   "test-client-secret",
		tokenCache:     NewTokenCache(),
		forceHTTPS:     false,
		sessionManager: sessionManager,
	}

	req := httptest.NewRequest("GET", "/logout", nil)
	req.Header.Set("Host", "test-host")
	rr := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	require.NoError(err)
	session.SetAuthenticated(true)
	session.SetAccessToken(ValidAccessToken)
	session.SetIDToken(ValidIDToken)
	session.SetRefreshToken(ValidRefreshToken)
	require.NoError(session.Save(req, rr))
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rr = httptest.NewRecorder()

	tOidc.handleLogout(rr, req)
	require.Equal(http.StatusFound, rr.Code, "logout should redirect")

	// The access token (and the others) must now be blacklisted so a captured
	// copy cannot be reused after logout.
	for _, tok := range []string{ValidAccessToken, ValidIDToken, ValidRefreshToken} {
		if _, found := tOidc.tokenBlacklist.Get(tok); !found {
			t.Errorf("token %q must be blacklisted after logout", tok)
		}
	}
}
