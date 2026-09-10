package traefikoidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRefreshToken_PersistsRotatedRefreshTokenOnClaimsExtractFailure guards the
// R119 fix: the ONE rotation-persistence branch R116 missed. Rotation IdPs
// consume the presented refresh token on EVERY successful token exchange,
// regardless of whether the follow-up claims extraction of the newly issued
// ID token succeeds. refreshToken returns false here (claims can't be
// extracted), so without persisting the just-rotated token the next refresh
// presents a consumed token, hits invalid_grant, and forces a re-login.
func TestRefreshToken_PersistsRotatedRefreshTokenOnClaimsExtractFailure(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		NewLogger("error"),
	)
	require.NoError(t, err)
	defer sessionManager.Shutdown()

	tOidc := &TraefikOidc{
		logger:              NewLogger("error"),
		userIdentifierClaim: "email",
		sessionManager:      sessionManager,
		tokenExchanger: &EnhancedMockTokenExchanger{
			RefreshResponse: &TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "rotated-refresh-token",
				IDToken:      "new-id-token-jwt",
				ExpiresIn:    3600,
			},
		},
		// ID-token verification passes; it is the CLAIMS EXTRACTION that fails.
		tokenVerifier: &EnhancedMockTokenVerifier{},
		extractClaimsFunc: func(token string) (map[string]any, error) {
			return nil, errors.New("claims decode failed")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	require.NoError(t, err)
	defer session.returnToPoolSafely()

	session.SetRefreshToken("initial-refresh-token")

	refreshed := tOidc.refreshToken(rw, req, session)
	require.False(t, refreshed, "refreshToken must report failure when claims cannot be extracted")

	got := session.GetRefreshToken()
	require.Equal(t, "rotated-refresh-token", got,
		"rotated refresh token must be salvaged even when claims extraction fails")
}
