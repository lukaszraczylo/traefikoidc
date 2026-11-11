package traefikoidc

import (
	"strings"
	"testing"
	"time"
)

// Entra ID refresh tokens start with "1." and contain two dots, but are not JWTs.
func TestRefreshTokenWithDotsIsOpaque(t *testing.T) {
	cm := NewChunkManager(NewLogger(""))
	entra := "1.AXwAbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-" +
		"." + strings.Repeat("Ab9_-xYz+/", 40) +
		"." + strings.Repeat("Qw3rTy7u!~", 40)

	t.Run("refresh config accepts dotted opaque token", func(t *testing.T) {
		if res := cm.validateToken(entra, RefreshTokenConfig); res.Error != nil {
			t.Fatalf("refresh token rejected: %v", res.Error)
		}
	})

	t.Run("access config still validates dotted token as JWT", func(t *testing.T) {
		res := cm.validateToken(entra, AccessTokenConfig)
		if res.Error == nil {
			t.Fatal("malformed JWT-shaped access token was accepted")
		}
	})

	t.Run("refresh config still rejects control characters", func(t *testing.T) {
		bad := strings.Replace(entra, "AXwA", "AX\x01A", 1)
		if res := cm.validateToken(bad, RefreshTokenConfig); res.Error == nil {
			t.Fatal("refresh token with control character was accepted")
		}
	})

	t.Run("valid JWT refresh token keeps JWT validation", func(t *testing.T) {
		future := time.Now().Add(time.Hour).Unix()
		jwt := tokenWithGroups(t, map[string]interface{}{"sub": "a", "exp": float64(future + 3600), "iat": float64(future)})
		res := cm.validateToken(jwt, RefreshTokenConfig)
		if res.Error == nil || !strings.Contains(res.Error.Error(), "issued in future") {
			t.Fatalf("error = %v, want issued-in-future from the JWT path", res.Error)
		}
	})

	t.Run("malformed JWT refresh token stays rejected", func(t *testing.T) {
		future := time.Now().Add(time.Hour).Unix()
		jwt := tokenWithGroups(t, map[string]interface{}{"sub": "a", "exp": float64(future + 3600), "iat": float64(time.Now().Unix())})
		parts := strings.Split(jwt, ".")
		corrupt := parts[0] + "." + parts[1] + ".!!!not-base64!!!"
		if res := cm.validateToken(corrupt, RefreshTokenConfig); res.Error == nil {
			t.Fatal("JWT with a corrupt signature was accepted as opaque")
		}
	})
}
