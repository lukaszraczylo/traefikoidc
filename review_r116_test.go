package traefikoidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRefreshToken_PersistsRotatedRefreshTokenOnGateFailure guards the R116
// fix. Rotation IdPs (Zitadel, Authentik, Auth0, ...) consume the presented
// refresh token on EVERY successful token exchange, regardless of which
// downstream validation gate (missing ID token, verification failure, empty
// access token) subsequently rejects the response. If the just-rotated
// refresh token is not persisted when refreshToken returns false, the next
// refresh presents the now-consumed token, hits invalid_grant, and forces a
// full logout. The rotated token must be salvaged even on a failed gate.
func TestRefreshToken_PersistsRotatedRefreshTokenOnGateFailure(t *testing.T) {
	tests := []struct {
		name            string
		refreshResponse *TokenResponse
		verifierErr     error
	}{
		{
			name: "missing ID token in refresh response",
			refreshResponse: &TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "rotated-refresh-token",
				ExpiresIn:    3600,
				// IDToken intentionally absent
			},
		},
		{
			name: "ID token verification failure",
			refreshResponse: &TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "rotated-refresh-token",
				IDToken:      "new-id-token-jwt",
				ExpiresIn:    3600,
			},
			verifierErr: errors.New("signature verification failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionManager, err := NewSessionManager(
				"test-encryption-key-32-bytes-long!!",
				false,
				"",
				"",
				0,
				NewLogger("error"),
			)
			if err != nil {
				t.Fatalf("session manager: %v", err)
			}
			defer sessionManager.Shutdown()

			tOidc := &TraefikOidc{
				logger:              NewLogger("error"),
				userIdentifierClaim: "email",
				sessionManager:      sessionManager,
				tokenExchanger: &EnhancedMockTokenExchanger{
					RefreshResponse: tt.refreshResponse,
				},
				tokenVerifier: &EnhancedMockTokenVerifier{Err: tt.verifierErr},
				extractClaimsFunc: func(token string) (map[string]any, error) {
					return map[string]any{"sub": "existing-sub", "exp": float64(9999999999)}, nil
				},
			}

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			rw := httptest.NewRecorder()

			session, err := sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("get session: %v", err)
			}
			defer session.returnToPoolSafely()

			session.SetRefreshToken("initial-refresh-token")

			refreshed := tOidc.refreshToken(rw, req, session)

			if refreshed {
				t.Fatal("expected refreshToken to report failure given the gate condition")
			}

			got := session.GetRefreshToken()
			if got != "rotated-refresh-token" {
				t.Fatalf("expected rotated refresh token to be persisted, got %q", got)
			}
		})
	}
}
