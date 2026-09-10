package traefikoidc

import (
	"testing"
	"time"
)

// FIX-27 regression test.
//
// accessTokenUnexpired (the lenient-audience-path time-claims re-check)
// returned false whenever iat was absent, even though 8640451 made iat
// OPTIONAL in jwt.Verify itself (R126: "Hard-requiring it here also
// rejected otherwise-valid access ... tokens whose provider omits iat").
// The two paths had drifted onto different contracts for the same claim.
// A lenient (wrong-audience) access token without iat, in a session with
// no ID token to corroborate it, was always forced to refresh or
// re-authenticate, while the identical token with a matching audience
// authenticated fine via the main jwt.Verify path.
//
// Fail-on-old: a syntactically valid, unexpired token with no iat is
// rejected by accessTokenUnexpired (returns false).
func TestAccessTokenUnexpired_IatOptional(t *testing.T) {
	tm := &TraefikOidc{}
	now := time.Now()

	noIat := makeTestJWT(t, map[string]interface{}{
		"exp": float64(now.Add(time.Hour).Unix()),
		// intentionally no "iat", matching jwt.Verify's R126 contract
	})
	if !tm.accessTokenUnexpired(noIat) {
		t.Error("a token with a valid exp and no iat must be accepted, matching jwt.Verify's iat-optional contract (R126/FIX-27)")
	}
}

// TestAccessTokenUnexpired_IatStillBoundedWhenPresent is the positive
// control: an iat far in the future (used-before-issued) must still be
// rejected when iat IS present — the fix makes iat optional, not ignored.
func TestAccessTokenUnexpired_IatStillBoundedWhenPresent(t *testing.T) {
	tm := &TraefikOidc{}
	now := time.Now()

	futureIat := makeTestJWT(t, map[string]interface{}{
		"exp": float64(now.Add(time.Hour).Unix()),
		"iat": float64(now.Add(time.Hour).Unix()), // far in the future
	})
	if tm.accessTokenUnexpired(futureIat) {
		t.Error("a present iat far in the future (used-before-issued) must still be rejected")
	}
}
