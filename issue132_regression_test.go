package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIssue132_RefreshTokenHonorsUserIdentifierClaim reproduces and verifies
// the fix for issue #132: token refresh path hardcoded the "email" claim and
// ignored the configured userIdentifierClaim. Keycloak users without an email
// claim (using sub or another identifier) were being kicked out on refresh
// even though their initial login worked.
//
// The callback path (auth_flow.go) already honored userIdentifierClaim with
// "sub" fallback. The refresh path (token_manager.go) had drifted out of sync
// after PR #100 (commit a316a98).
func TestIssue132_RefreshTokenHonorsUserIdentifierClaim(t *testing.T) {
	tests := []struct {
		claims              map[string]any
		name                string
		userIdentifierClaim string
		expectedIdentifier  string
		expectSuccess       bool
	}{
		{
			name:                "sub claim configured, only sub present (Keycloak no-email case)",
			userIdentifierClaim: "sub",
			claims: map[string]any{
				"sub": "user-uuid-keycloak-12345",
				"exp": float64(9999999999),
			},
			expectSuccess:      true,
			expectedIdentifier: "user-uuid-keycloak-12345",
		},
		{
			name:                "preferred_username configured, claim present",
			userIdentifierClaim: "preferred_username",
			claims: map[string]any{
				"sub":                "user-uuid-12345",
				"preferred_username": "alice",
				"exp":                float64(9999999999),
			},
			expectSuccess:      true,
			expectedIdentifier: "alice",
		},
		{
			name:                "configured claim missing, falls back to sub",
			userIdentifierClaim: "preferred_username",
			claims: map[string]any{
				"sub": "fallback-sub-id",
				"exp": float64(9999999999),
			},
			expectSuccess:      true,
			expectedIdentifier: "fallback-sub-id",
		},
		{
			name:                "email default, email present (backward compatibility)",
			userIdentifierClaim: "email",
			claims: map[string]any{
				"sub":   "user-uuid-12345",
				"email": "user@example.com",
				"exp":   float64(9999999999),
			},
			expectSuccess:      true,
			expectedIdentifier: "user@example.com",
		},
		{
			name:                "email default, no email and no sub - refresh fails",
			userIdentifierClaim: "email",
			claims: map[string]any{
				"exp": float64(9999999999),
			},
			expectSuccess:      false,
			expectedIdentifier: "",
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

			capturedClaims := tt.claims
			tOidc := &TraefikOidc{
				logger:              NewLogger("error"),
				userIdentifierClaim: tt.userIdentifierClaim,
				sessionManager:      sessionManager,
				tokenExchanger: &EnhancedMockTokenExchanger{
					RefreshResponse: &TokenResponse{
						AccessToken:  "new-access-token",
						RefreshToken: "new-refresh-token",
						IDToken:      "new-id-token-jwt",
						ExpiresIn:    3600,
					},
				},
				tokenVerifier: &EnhancedMockTokenVerifier{Err: nil},
				extractClaimsFunc: func(token string) (map[string]any, error) {
					return capturedClaims, nil
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

			if refreshed != tt.expectSuccess {
				t.Fatalf("refreshToken() = %v, want %v", refreshed, tt.expectSuccess)
			}

			if got := session.GetUserIdentifier(); got != tt.expectedIdentifier {
				t.Errorf("session.GetUserIdentifier() = %q, want %q", got, tt.expectedIdentifier)
			}
		})
	}
}
