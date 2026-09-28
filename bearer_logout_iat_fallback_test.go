package traefikoidc

import (
	"testing"
	"time"
)

// FIX-24 regression test.
//
// buildPrincipalFromBearerToken derived the IdP-logout-invalidation
// "createdAt" from the token's iat claim, falling back to time.Now() when
// iat was absent. Since 8640451 made iat OPTIONAL in jwt.Verify (R126), an
// access token without iat now reaches this check. time.Now() makes such a
// token always look newer than any logout event (isSessionInvalidated only
// matches when invalidationTime >= createdAt), so IdP-initiated
// (backchannel) logout never revokes it — reintroducing the R98 defect the
// cookie path already fixed by falling back to zero time instead.
//
// Fail-on-old: a bearer token without iat, for a sid invalidated by
// backchannel logout, still authenticates (200) after the logout.
func TestBearerLogoutInvalidation_NoIatFallsClosedNotOpen(t *testing.T) {
	cache := NewCache()
	defer cache.Close()

	oidc := makeBearerOIDC(t, nil)
	oidc.sessionInvalidationCache = cache
	// Disable the unrelated maxTokenAge/enforceIatAge bound (a DIFFERENT
	// check that also rejects a missing iat, and that New() always turns on
	// in production — 0/unset becomes 24h, main.go:357-362 — this override
	// only exists because this test constructs *TraefikOidc directly,
	// bypassing New()) so this test isolates the isSessionInvalidated
	// createdAt fallback under test. That fallback is what actually matters
	// once maxTokenAge is 0: with maxTokenAge > 0 (the production default),
	// enforceIatAge rejects an iat-less token before this logout check is
	// even reached.
	oidc.maxTokenAge = 0

	claims := defaultBearerClaims()
	delete(claims, "iat") // provider omits iat (now legal per R126)
	claims["sub"] = "user-1"
	claims["sid"] = "session-1"

	token := makeBearerJWT(t, defaultBearerHeader(), claims)
	seedVerified(t, oidc, token, claims)

	// Backchannel logout invalidates the session a full hour before this
	// request (set directly rather than via invalidateSession's real-clock
	// Unix() call, so the comparison is deterministic regardless of
	// test-execution timing rather than depending on two time.Now() calls
	// landing in the same second). The buggy time.Now() fallback for
	// createdAt makes the token look newer than this invalidation
	// (invalidationTime.Before(createdAt) == true -> NOT invalidated); the
	// fix's zero-time fallback is never after any invalidation timestamp.
	invalidatedAt := time.Now().Add(-time.Hour).Unix()
	cache.Set(oidc.buildSessionInvalidationKey("sid", "session-1"), invalidatedAt, time.Hour)

	_, bErr := oidc.buildPrincipalFromBearerToken(token)
	if bErr == nil {
		t.Fatal("a bearer token without iat, whose sid was invalidated by backchannel logout, must be rejected (fail closed), not authenticated as if issued after the logout")
	}
}

// TestBearerLogoutInvalidation_WithIatStillHonored is the positive control:
// a token WITH iat issued before the logout must still be invalidated (the
// existing R146 behavior), and one issued after must still pass.
func TestBearerLogoutInvalidation_WithIatStillHonored(t *testing.T) {
	cache := NewCache()
	defer cache.Close()

	oidc := makeBearerOIDC(t, nil)
	oidc.sessionInvalidationCache = cache

	if err := oidc.invalidateSession("session-2", ""); err != nil {
		t.Fatalf("invalidateSession: %v", err)
	}

	// Issued well before the logout above.
	staleClaims := defaultBearerClaims()
	staleClaims["sub"] = "user-2"
	staleClaims["sid"] = "session-2"
	staleClaims["iat"] = float64(time.Now().Add(-time.Hour).Unix())
	staleToken := makeBearerJWT(t, defaultBearerHeader(), staleClaims)
	seedVerified(t, oidc, staleToken, staleClaims)

	if _, bErr := oidc.buildPrincipalFromBearerToken(staleToken); bErr == nil {
		t.Fatal("a token issued before the logout must still be invalidated")
	}

	// Freshly issued after the logout, for an unrelated sid.
	freshClaims := defaultBearerClaims()
	freshClaims["sub"] = "user-3"
	freshClaims["sid"] = "session-3"
	freshClaims["iat"] = float64(time.Now().Unix())
	freshToken := makeBearerJWT(t, defaultBearerHeader(), freshClaims)
	seedVerified(t, oidc, freshToken, freshClaims)

	if _, bErr := oidc.buildPrincipalFromBearerToken(freshToken); bErr != nil {
		t.Fatalf("a freshly issued token for an uninvalidated sid must pass, got: %v", bErr)
	}
}
