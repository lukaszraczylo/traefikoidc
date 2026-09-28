package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLogoutRevokesTokensWithProvider guards the R127 fix to helpers.go
// handleLogout: RP-initiated logout previously only blacklisted tokens in
// the local cache, so access and refresh tokens stayed valid at the IdP
// after logout (a captured refresh token could keep minting new tokens).
// Logout must best-effort revoke the access and refresh tokens at the
// provider's revocation endpoint too.
func TestLogoutRevokesTokensWithProvider(t *testing.T) {
	require := require.New(t)

	var (
		mu       sync.Mutex
		revoked  = map[string]string{} // token -> token_type_hint
		revCalls int
	)
	revServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		revCalls++
		revoked[r.PostFormValue("token")] = r.PostFormValue("token_type_hint")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer revServer.Close()

	logger := NewLogger("info")
	sessionManager, _ := NewSessionManager("test-secret-key-that-is-at-least-32-bytes", false, "", "", 0, logger)
	tOidc := &TraefikOidc{
		endSessionURL:  "",
		revocationURL:  revServer.URL,
		logger:         logger,
		tokenBlacklist: NewCache(),
		httpClient:     &http.Client{},
		clientID:       "test-client-id",
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
	require.Equal(2, revCalls, "provider revocation should be attempted for the access and refresh tokens")
	mu.Lock()
	require.Equal("access_token", revoked[ValidAccessToken], "access token must be revoked with hint access_token")
	require.Equal("refresh_token", revoked[ValidRefreshToken], "refresh token must be revoked with hint refresh_token")
	mu.Unlock()
}
