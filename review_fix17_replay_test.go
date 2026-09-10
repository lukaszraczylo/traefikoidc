package traefikoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestVerifyTokenWithOpts_DoesNotWriteToSharedReplayCache pins FIX-17:
// verifyTokenWithOpts (the cookie-path production verify call, via
// VerifyToken) must not write into the shared shardedReplayCache. Nothing
// in production reads that cache: the only reader is jwt.Verify's replay
// branch, and the only production caller of Verify
// (VerifyJWTSignatureAndClaims) always passes skipReplayCheck=true, so the
// branch never runs on the live path. The write was therefore pure
// overhead (an exclusive replayCacheMu.Lock on every cache-miss verify via
// initReplayCache) with no reader.
func TestVerifyTokenWithOpts_DoesNotWriteToSharedReplayCache(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "fix17-kid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJWKS(t, w, kid, &key.PublicKey)
	}))
	defer srv.Close()

	now := time.Now()
	const jti = "fix17-replay-write-jti"
	claims := map[string]any{
		"iss": "https://fix17-issuer.example.com",
		"sub": "user-1",
		"aud": "fix17-audience",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"jti": jti,
	}
	token := signRSAJWTForTest(t, key, kid, claims)

	oidc := &TraefikOidc{
		jwkCache:               NewJWKCache(),
		jwksURL:                srv.URL,
		issuerURL:              "https://fix17-issuer.example.com",
		audience:               "fix17-audience",
		clientID:               "fix17-client",
		httpClient:             http.DefaultClient,
		limiter:                rate.NewLimiter(rate.Inf, 1),
		suppressDiagnosticLogs: true,
		tokenCache:             NewTokenCache(),
	}

	cleanupReplayCache()
	initReplayCache()
	cacheKey := replayCacheKey(oidc.issuerURL, jti)
	if shardedReplayCache != nil && shardedReplayCache.Exists(cacheKey) {
		t.Fatalf("precondition failed: jti %q already present in shardedReplayCache before verify", jti)
	}

	if err := oidc.VerifyToken(token); err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	if shardedReplayCache != nil && shardedReplayCache.Exists(cacheKey) {
		t.Fatalf("verifyTokenWithOpts wrote jti %q into the shared shardedReplayCache; "+
			"that store is write-only in production (FIX-17)", jti)
	}
}
