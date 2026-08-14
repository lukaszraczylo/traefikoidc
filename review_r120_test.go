package traefikoidc

import (
	"testing"
	"time"
)

// TestRevokeToken_EvictsIntrospectionCache guards the R120 fix: RevokeToken
// cleared tokenCache + blacklist but never the positive introspection cache,
// so a revoked OPAQUE access token (which has no jti and is therefore not
// covered by the JTI blacklist) kept passing via a cached "active"
// introspection verdict after logout. Revocation must evict that verdict so
// the next request re-introspects and sees active=false.
func TestRevokeToken_EvictsIntrospectionCache(t *testing.T) {
	introCache := NewCache()
	introCache.Set("opaque-token", &IntrospectionResponse{Active: true}, time.Minute)

	oidc := &TraefikOidc{
		logger:             NewLogger("error"),
		introspectionCache: introCache,
		tokenCache:         NewTokenCache(),
		tokenBlacklist:     NewCache(),
	}

	oidc.RevokeToken("opaque-token")

	if _, found := introCache.Get("opaque-token"); found {
		t.Fatal("revoked opaque token must not be served a cached active introspection result")
	}
}

// TestShouldSkipGraceRefresh_UsesAccessTokenExpiry guards the R120 fix: the
// proactive-refresh grace check was keyed off the ID token's expiry even
// though the token forwarded downstream is the ACCESS token (and needsRefresh
// is derived from the access token's expiry for verifiable-JWT access
// tokens). With an access token inside the grace window but a longer-lived
// ID token, the old code skipped the refresh and forwarded a stale access
// token. The skip decision must be access-first (ID fallback only for
// opaque access tokens).
func TestShouldSkipGraceRefresh_UsesAccessTokenExpiry(t *testing.T) {
	now := time.Now()
	const grace = 60 * time.Second

	accessWithinGrace := makeJWTForTest(map[string]any{"exp": float64(now.Add(30 * time.Second).Unix())})
	accessFresh := makeJWTForTest(map[string]any{"exp": float64(now.Add(time.Hour).Unix())})
	idFresh := makeJWTForTest(map[string]any{"exp": float64(now.Add(time.Hour).Unix())})

	// Access within grace (needs refresh), ID still fresh: must NOT skip.
	if skipRefreshForTokens(accessWithinGrace, idFresh, grace) {
		t.Fatal("access token inside the grace window must trigger refresh even when the ID token is fresh")
	}

	// Access far outside grace: should skip.
	if !skipRefreshForTokens(accessFresh, idFresh, grace) {
		t.Fatal("access token outside the grace window should skip the refresh")
	}

	// Opaque access token: fall back to the ID token (safe direction).
	if !skipRefreshForTokens("opaque-access-token", idFresh, grace) {
		t.Fatal("opaque access token should fall back to the fresh ID token and skip")
	}
}
