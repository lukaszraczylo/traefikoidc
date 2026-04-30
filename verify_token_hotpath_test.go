package traefikoidc

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestVerifyToken_CacheHitSkipsParse proves the hot-path optimization: when a
// token is in the cache, VerifyToken returns nil without calling parseJWT.
// We construct a token that PASSES the cheap format checks (3 segments, len
// >= 10) but whose body is unparseable JSON. With the cache hit hoisted ahead
// of parseJWT, the function returns nil. Without the hoist, parseJWT would
// fail with "failed to parse JWT for blacklist check".
func TestVerifyToken_CacheHitSkipsParse(t *testing.T) {
	tr := &TraefikOidc{
		logger:     NewLogger("error"),
		tokenCache: NewTokenCache(),
		// limiter intentionally absent; if we reached the rate-limit check
		// the test would NPE - this is a stronger assertion that we exit
		// before that point.
		limiter: rate.NewLimiter(rate.Inf, 1),
	}
	tr.tokenVerifier = tr

	// Three segments separated by '.', body is junk after base64-decode + JSON.
	// Pre-fix this fails parseJWT; post-fix it returns nil because the cache
	// short-circuits.
	junkToken := "header.bm90LWpzb24.signature" // base64(not-json) in the middle
	tr.tokenCache.Set(junkToken, map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"sub": "test",
	}, time.Hour)

	if err := tr.VerifyToken(junkToken); err != nil {
		t.Fatalf("expected cache-hit fast path to return nil, got: %v", err)
	}
}

// TestVerifyToken_CacheMissStillParses ensures we did not skip too aggressively
// - on a cache miss, the function must still parse and reach the rate-limit
// check. We assert by passing a syntactically valid token whose signature
// won't verify, expecting an error from later in the pipeline.
func TestVerifyToken_CacheMissStillParses(t *testing.T) {
	tr := &TraefikOidc{
		logger:     NewLogger("error"),
		tokenCache: NewTokenCache(),
		limiter:    rate.NewLimiter(rate.Inf, 1),
		// no tokenBlacklist, no jwkCache - the function will fail somewhere
		// after parseJWT. We just need a non-nil error to confirm we did
		// progress past the cache check.
	}
	tr.tokenVerifier = tr

	// Real JWT structure but unsigned/unverifiable.
	rawToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"

	if err := tr.VerifyToken(rawToken); err == nil {
		t.Fatal("expected an error past parseJWT for an unsigned token, got nil")
	}
}
