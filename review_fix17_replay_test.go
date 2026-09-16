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

// TestJWTVerify_PerformsNoReplayDetection pins the completed FIX-17: JWT.Verify
// no longer tracks JTIs or rejects a repeated one. The replay-check branch
// (and the shardedReplayCache/replayCache globals it was the sole reader of)
// has been removed outright, not merely left unreachable behind a
// skipReplayCheck flag that the one production caller always set to true.
// Fail-on-old: a second direct Verify call for the same jti returns
// "token replay detected" because the pre-removal code still ran its replay
// branch whenever a caller omitted the (then-variadic) skipReplayCheck
// argument, which this test deliberately does.
func TestJWTVerify_PerformsNoReplayDetection(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"sub": "test-subject",
		"jti": "fix17-no-replay-jti",
	})
	if err != nil {
		t.Fatalf("createTestJWT: %v", err)
	}

	first, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT (first): %v", err)
	}
	if err := first.Verify("https://test-issuer.com", "test-client-id"); err != nil {
		t.Fatalf("first Verify call should succeed, got: %v", err)
	}

	second, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT (second): %v", err)
	}
	if err := second.Verify("https://test-issuer.com", "test-client-id"); err != nil {
		t.Fatalf("Verify must not perform replay detection on a repeated jti (FIX-17), got: %v", err)
	}
}

// TestVerifyTokenWithOpts_ProductionPathUnaffectedByReplayRemoval pins FIX-17's
// production behavior after the replay-cache removal: verifyTokenWithOpts (the
// cookie-path production verify call, via VerifyToken) still accepts a
// legitimate token on repeated presentation - it never depended on jwt.Verify's
// now-deleted replay branch, since the sole production caller
// (VerifyJWTSignatureAndClaims) always disabled that branch before it was
// removed. JTI-based revocation for this path is still enforced independently
// via tokenBlacklist.Get(jti), which this test also exercises.
func TestVerifyTokenWithOpts_ProductionPathUnaffectedByReplayRemoval(t *testing.T) {
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
	const jti = "fix17-repeat-presentation-jti"
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
		tokenBlacklist:         NewCache(),
	}

	if err := oidc.VerifyToken(token); err != nil {
		t.Fatalf("first VerifyToken: %v", err)
	}
	if blacklisted, exists := oidc.tokenBlacklist.Get(jti); exists && blacklisted != nil {
		t.Error("VerifyToken must not self-record the jti into the per-instance tokenBlacklist")
	}
	// Re-presentation of the same still-valid token (the cookie path's normal
	// case: the same session token is verified on every request) must keep
	// succeeding now that no replay logic runs anywhere in this path.
	if err := oidc.VerifyToken(token); err != nil {
		t.Errorf("re-presentation of the same valid token should succeed, got: %v", err)
	}
}
