package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	jwtWithExp := makeTestJWT(t, map[string]interface{}{"exp": float64(1_700_007_200)})
	jwtNoExp := makeTestJWT(t, map[string]interface{}{"sub": "u"})

	cases := []struct {
		name string
		tr   *TokenResponse
		want int64
	}{
		{"nil response", nil, 0},
		{"expires_in from the response", &TokenResponse{AccessToken: "opaque-access-token-0123456789", ExpiresIn: 1800}, 1_700_001_800},
		{"expires_in wins over the JWT exp", &TokenResponse{AccessToken: jwtWithExp, ExpiresIn: 60}, 1_700_000_060},
		{"JWT exp when the response has no expires_in", &TokenResponse{AccessToken: jwtWithExp}, 1_700_007_200},
		{"opaque token without expires_in", &TokenResponse{AccessToken: "opaque-access-token-0123456789"}, 0},
		{"JWT without exp and no expires_in", &TokenResponse{AccessToken: jwtNoExp}, 0},
		{"non-positive expires_in is ignored", &TokenResponse{AccessToken: jwtWithExp, ExpiresIn: -5}, 1_700_007_200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, accessTokenExpiry(c.tr, now))
		})
	}
}

// saveAndReload stores sd's state and loads it back through a fresh request,
// the way a following request would see it.
func saveAndReload(t *testing.T, sm *SessionManager, sd *SessionData) *SessionData {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	require.NoError(t, sd.Save(req, rec))
	next := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		next.AddCookie(c)
	}
	loaded, err := sm.GetSession(next)
	require.NoError(t, err)
	return loaded
}

func TestSessionAccessTokenExpiresAt(t *testing.T) {
	const tokenA = "test-access-token-0123456789abcdefghijklmnopqrstuvwxyz"
	const tokenB = "other-access-token-0123456789abcdefghijklmnopqrstuvwxyz"
	exp := time.Now().Add(30 * time.Minute).Unix()

	for _, storage := range []struct {
		name     string
		combined bool
	}{{"combined cookie storage", true}, {"legacy cookie storage", false}} {
		t.Run("survives a save and reload with "+storage.name, func(t *testing.T) {
			sm := createTestSessionManager(t)
			sd, err := sm.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
			require.NoError(t, err)
			sd.useCombinedStorage = storage.combined
			sd.SetAccessToken(tokenA)
			sd.SetAccessTokenExpiresAt(exp)

			loaded := saveAndReload(t, sm, sd)
			assert.Equal(t, tokenA, loaded.GetAccessToken())
			assert.Equal(t, exp, loaded.GetAccessTokenExpiresAt())
		})
	}

	t.Run("a session saved without one reports unknown", func(t *testing.T) {
		sm := createTestSessionManager(t)
		sd, err := sm.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
		require.NoError(t, err)
		sd.SetAccessToken(tokenA)
		assert.Zero(t, saveAndReload(t, sm, sd).GetAccessTokenExpiresAt())
	})

	t.Run("the expiry belongs to its token", func(t *testing.T) {
		sm := createTestSessionManager(t)
		sd, err := sm.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
		require.NoError(t, err)

		sd.SetAccessToken(tokenA)
		sd.SetAccessTokenExpiresAt(exp)
		sd.SetAccessToken(tokenA) // unchanged token keeps its expiry
		assert.Equal(t, exp, sd.GetAccessTokenExpiresAt())

		sd.SetAccessToken(tokenB) // a different token drops it
		assert.Zero(t, sd.GetAccessTokenExpiresAt())

		sd.SetAccessTokenExpiresAt(exp)
		sd.SetAccessToken("") // clearing the token drops it
		assert.Zero(t, sd.GetAccessTokenExpiresAt())
	})

	t.Run("a non-positive value clears it", func(t *testing.T) {
		sm := createTestSessionManager(t)
		sd, err := sm.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
		require.NoError(t, err)
		sd.SetAccessToken(tokenA)
		sd.SetAccessTokenExpiresAt(exp)
		sd.SetAccessTokenExpiresAt(0)
		assert.Zero(t, sd.GetAccessTokenExpiresAt())
	})

	t.Run("does not leak into the next user of a pooled session", func(t *testing.T) {
		sm := createTestSessionManager(t)
		sd, err := sm.GetSession(httptest.NewRequest(http.MethodGet, "/", nil))
		require.NoError(t, err)
		sd.SetAccessToken(tokenA)
		sd.SetAccessTokenExpiresAt(exp)
		sd.Reset()
		assert.Zero(t, sd.GetAccessTokenExpiresAt())
	})
}
