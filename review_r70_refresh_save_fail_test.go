package traefikoidc

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRefresh_SaveFailureClearsRotatedTokens regresses the refresh path
// leaving a half-rotated session when the post-refresh Save fails: the
// IdP had already consumed the old refresh token (rotation), but the old
// code only flipped authenticated to false and kept the new rotated
// tokens in memory — so the in-memory session carried a fresh refresh
// token while flagged unauthenticated. The Save-failure branch must clear
// the rotated tokens (mirroring the SetAuthenticated-error branch).
func TestRefresh_SaveFailureClearsRotatedTokens(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!", false, "", "", 0, NewLogger("error"))
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	claims := map[string]any{"email": "user@example.com", "exp": float64(9999999999)}
	tOidc := &TraefikOidc{
		logger:              NewLogger("error"),
		userIdentifierClaim: "email",
		sessionManager:      sessionManager,
		tokenExchanger: &EnhancedMockTokenExchanger{
			RefreshResponse: &TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				IDToken:      "new-id-token",
				ExpiresIn:    3600,
			},
		},
		tokenVerifier:     &EnhancedMockTokenVerifier{Err: nil},
		extractClaimsFunc: func(token string) (map[string]any, error) { return claims, nil },
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	session, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	defer session.returnToPoolSafely()

	session.SetRefreshToken("initial-refresh-token")

	// Bloat the session with incompressible data so the combined-cookie
	// Save overflows maxCombinedChunks (10) and fails deterministically.
	bloat := make([]byte, 4000)
	_, _ = rand.Read(bloat)
	for i := 0; i < 25; i++ {
		session.mainSession.Values[fmt.Sprintf("bulk%d", i)] = string(bloat)
	}

	refreshed := tOidc.refreshToken(rw, req, session)
	if refreshed {
		t.Fatal("expected refresh to fail when the session Save fails")
	}

	if session.GetAuthenticated() {
		t.Error("session must not be authenticated after a failed refresh Save")
	}
	// Rotated tokens must not linger in memory (half-rotated state).
	if got := session.GetRefreshToken(); got != "" {
		t.Errorf("refresh token not cleared after failed Save, got %q", got)
	}
	if got := session.GetAccessToken(); got != "" {
		t.Errorf("access token not cleared after failed Save, got %q", got)
	}
	if got := session.GetIDToken(); got != "" {
		t.Errorf("id token not cleared after failed Save, got %q", got)
	}
}
