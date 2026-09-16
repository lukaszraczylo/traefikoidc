package traefikoidc

import (
	"testing"
	"time"
)

// R92 regression: on the lenient-audience access-token path,
// accessTokenUnexpired previously re-checked only 'exp' after jwt.Verify
// short-circuited at the aud check, leaving 'nbf' (and 'iat') unvalidated.
// A token with a not-yet-reached nbf (valid exp) was therefore trusted for
// authorization before it was valid. It must now reject not-yet-valid
// tokens just like the main verification path (verifyNotBefore).
func TestR92LenientPathRejectsFutureNbf(t *testing.T) {
	tm := &TraefikOidc{}
	now := time.Now()

	notYetValid := makeTestJWT(t, map[string]interface{}{
		"exp": float64(now.Add(time.Hour).Unix()),
		"iat": float64(now.Add(-time.Minute).Unix()),
		"nbf": float64(now.Add(10 * time.Minute).Unix()), // not yet valid
	})
	if tm.accessTokenUnexpired(notYetValid) {
		t.Error("access token with future nbf was accepted on the lenient-audience path (not-yet-valid token trusted)")
	}

	// Control: a token with no nbf and a valid exp must still be accepted.
	valid := makeTestJWT(t, map[string]interface{}{
		"exp": float64(now.Add(time.Hour).Unix()),
		"iat": float64(now.Add(-time.Minute).Unix()),
	})
	if !tm.accessTokenUnexpired(valid) {
		t.Error("token with valid exp and no nbf should be accepted")
	}
}
