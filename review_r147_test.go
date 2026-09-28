package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// r147AzureUnverifiableToken builds a JWT whose header carries the Microsoft
// proprietary `nonce` that makes isUnverifiableAzureAccessToken return true
// (the documented mechanism that keeps Azure access tokens opaque), with an
// exp deep in the future so only a blacklist/leeway gate can reject it.
func r147AzureUnverifiableToken(exp time.Time) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kty": "RSA", "nonce": "proprietary-nonce"})
	payload, _ := json.Marshal(map[string]any{
		"sub": "user-123",
		"exp": float64(exp.Unix()),
		"aud": "graph.windows.net",
	})
	part := func(b []byte) string {
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return part(header) + "." + part(payload) + "." + part([]byte("sig"))
}

// TestAzureUnverifiable_BlacklistedRejected verifies the Azure
// no-ID-token unverifiable branch now consults the token blacklist before
// authenticating (and applies clock-skew leeway). A revoked but
// still-present access token must not authenticate through this branch,
// which previously returned authenticated=true with no blacklist check
// (R147).
func TestAzureUnverifiable_BlacklistedRejected(t *testing.T) {
	oidc := &TraefikOidc{
		logger:         newNoOpLogger(),
		issuerURL:      "https://login.microsoftonline.com/common",
		tokenBlacklist: newMapCache(),
	}

	tok := r147AzureUnverifiableToken(time.Now().Add(time.Hour))
	rs := &requestState{
		authenticated: true,
		accessToken:   tok,
		// no ID token -> unverifiable branch
	}

	// Blacklist the exact raw token.
	oidc.tokenBlacklist.Set(tok, time.Now().Unix(), time.Minute)

	authenticated, _, _ := oidc.validateAzureTokensRS(rs)
	if authenticated {
		t.Fatal("revoked Azure unverifiable token must not authenticate (R147 blacklist gate)")
	}
}

// TestAzureUnverifiable_NotBlacklistedPasses sanity-checks the other side:
// an unrevoked, unexpired unverifiable Azure token still authenticates.
func TestAzureUnverifiable_NotBlacklistedPasses(t *testing.T) {
	oidc := &TraefikOidc{
		logger:         newNoOpLogger(),
		issuerURL:      "https://login.microsoftonline.com/common",
		tokenBlacklist: newMapCache(),
	}

	rs := &requestState{
		authenticated: true,
		accessToken:   r147AzureUnverifiableToken(time.Now().Add(time.Hour)),
	}

	authenticated, _, _ := oidc.validateAzureTokensRS(rs)
	if !authenticated {
		t.Fatal("unrevoked, unexpired unverifiable Azure token should authenticate")
	}
}

// TestInitializeAuthentication_RedirectNoStore verifies the 302 into the
// IdP carries Cache-Control: no-store, so the pre-auth redirect is not
// heuristically cacheable and replayed after re-authentication (R147).
func TestInitializeAuthentication_RedirectNoStore(t *testing.T) {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false, "", "", 0,
		newNoOpLogger(),
	)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	defer sessionManager.Shutdown()

	oidc := &TraefikOidc{
		sessionManager: sessionManager,
		logger:         newNoOpLogger(),
		issuerURL:      "https://provider.example.com",
		authURL:        "https://provider.example.com/authorize",
		clientID:       "client-123",
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	sess, err := sessionManager.GetSession(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	defer sess.returnToPoolSafely()

	rw := httptest.NewRecorder()
	oidc.defaultInitiateAuthentication(rw, req, sess, "https://provider.example.com/callback")

	if rw.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to IdP, got %d", rw.Code)
	}
	if got := rw.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("auth redirect must be no-store, got Cache-Control=%q", got)
	}
}
