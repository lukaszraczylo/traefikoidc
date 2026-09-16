package traefikoidc

import (
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"
)

// TestR163_StrictAudienceRejectsClientIdOnlyAccessToken guards the
// strictAudienceValidation audience selection in VerifyJWTSignatureAndClaims
// (token_manager.go). detectTokenType classifies any token whose aud
// contains clientID as an ID token, which previously swapped the
// expected audience to clientID — so an access token carrying only
// clientID (never the configured API audience) always passed the
// audience check and strict mode never rejected it. The fix enforces the
// configured audience for such tokens when strict mode is on.
// Fail-on-old: an access token with aud=clientID only is accepted.
func TestR163_StrictAudienceRejectsClientIdOnlyAccessToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	ts.tOidc.strictAudienceValidation = true
	ts.tOidc.audience = "https://my-api.example.com" // distinct from clientID

	tok, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id", // clientID only; not the configured audience
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"iat": float64(time.Now().Unix()),
		"sub": "test-user",
		"jti": "r163-aud-jti",
	})
	if err != nil {
		t.Fatalf("createTestJWT: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	session, err := ts.tOidc.sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	session.SetAuthenticated(true)
	session.SetAccessToken(tok)

	rs := (&requestState{}).captureSession(session)
	authenticated, _, _ := ts.tOidc.validateStandardTokensRS(rs)
	if authenticated {
		t.Error("strict mode must reject an access token whose aud is only the client id, not the configured audience")
	}
}

// TestR163_ChunkOverflowExpiresStaleCombined guards the combined→legacy
// fallback in saveCombined (session.go). When the combined payload
// exceeds maxCombinedChunks, Save falls back to the legacy per-token
// chunk format but previously left the OLD combined chunk cookies in
// place; GetSession loads combined-first, so it kept serving the stale
// combined payload and shadowing the freshly written legacy tokens. The
// fix expires the old combined chunks during the fallback.
// Fail-on-old: after the fallback the combined chunk cookie is not
// expired (still live).
func TestR163_ChunkOverflowExpiresStaleCombined(t *testing.T) {
	sm := createTestSessionManager(t)
	chunkName := sm.combinedChunkCookieName(0)

	// First write a small combined session so a combined chunk cookie exists.
	reqA := httptest.NewRequest("GET", "/", nil)
	sA, err := sm.GetSession(reqA)
	if err != nil {
		t.Fatalf("create small session: %v", err)
	}
	sA.useCombinedStorage = true
	sA.SetRefreshToken("small-token")
	recA := httptest.NewRecorder()
	if err := sA.Save(reqA, recA); err != nil {
		t.Fatalf("save small combined session: %v", err)
	}

	// Overwrite with a large incompressible token that overflows the
	// combined envelope and triggers the legacy fallback.
	big := make([]byte, 17*1024)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	bigToken := base64.RawURLEncoding.EncodeToString(big)

	reqB := httptest.NewRequest("GET", "/", nil)
	for _, c := range recA.Result().Cookies() {
		reqB.AddCookie(c)
	}
	sB, err := sm.GetSession(reqB)
	if err != nil {
		t.Fatalf("load session for overflow: %v", err)
	}
	sB.useCombinedStorage = true
	sB.SetRefreshToken(bigToken)
	recB := httptest.NewRecorder()
	if err := sB.Save(reqB, recB); err != nil {
		t.Fatalf("overflow Save must fall back to legacy, got: %v", err)
	}

	// The stale combined chunk cookie must be expired by the fallback.
	chunkExpired := false
	for _, c := range recB.Result().Cookies() {
		if c.Name == chunkName && c.MaxAge <= 0 {
			chunkExpired = true
			break
		}
	}
	if !chunkExpired {
		t.Fatalf("overflow fallback must expire the stale combined chunk cookie %q; without it GetSession keeps serving the old combined payload", chunkName)
	}
}
