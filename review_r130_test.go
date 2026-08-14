package traefikoidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rotatingJWKCacheForLogout simulates a provider that rotated its signing key
// in place, REUSING the same kid. GetPublicKey returns the STALE key (as
// would remain cached for the JWKS TTL) and getPublicKeyFresh returns the
// FRESH key, so signature verification only succeeds after a refresh —
// exactly the same-kid in-place rotation the normal verify path already
// handles (R109) and that logout previously lacked (R130).
type rotatingJWKCacheForLogout struct {
	stale *ecdsa.PrivateKey
	fresh *ecdsa.PrivateKey
}

func (m *rotatingJWKCacheForLogout) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	return nil, fmt.Errorf("not used")
}
func (m *rotatingJWKCacheForLogout) GetPublicKey(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error) {
	return &m.stale.PublicKey, nil
}
func (m *rotatingJWKCacheForLogout) getPublicKeyFresh(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error) {
	return &m.fresh.PublicKey, nil
}
func (m *rotatingJWKCacheForLogout) Cleanup() {}
func (m *rotatingJWKCacheForLogout) Close()   {}

// es256SignToken builds an ES256 JWT signed with the given private key.
func es256SignToken(t *testing.T, key *ecdsa.PrivateKey, kid string) (string, *JWT) {
	t.Helper()
	header := map[string]interface{}{"alg": "ES256", "kid": kid}
	hb, _ := json.Marshal(header)
	hb64 := base64.RawURLEncoding.EncodeToString(hb)

	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": now,
		"exp": now + 3600,
	}
	cb, _ := json.Marshal(claims)
	cb64 := base64.RawURLEncoding.EncodeToString(cb)

	signingInput := hb64 + "." + cb64
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, &JWT{Header: map[string]interface{}{"alg": "ES256", "kid": kid}}
}

// TestVerifyLogoutTokenSignature_RefreshesOnInPlaceKeyRotation guards the
// logout path handling of same-kid in-place key rotation. A logout token
// signed with the rotated fresh key must still verify when the cached key
// (same kid, stale) fails, by refreshing once — mirroring the normal
// verify path (token_manager.go R109). Previously logout returned an error
// here, leaving the user's session alive after the IdP logged them out.
func TestVerifyLogoutTokenSignature_RefreshesOnInPlaceKeyRotation(t *testing.T) {
	stale, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fresh, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	token, jwt := es256SignToken(t, fresh, "rot-kid")

	oidc := &TraefikOidc{
		logger:     NewLogger("debug"),
		jwkCache:   &rotatingJWKCacheForLogout{stale: stale, fresh: fresh},
		jwksURL:    "https://provider.example.com/.well-known/jwks.json",
		metadataMu: sync.RWMutex{},
	}

	if err := oidc.verifyLogoutTokenSignature(jwt, token); err != nil {
		t.Fatalf("logout token signed with in-place-rotated key must verify after refresh: %v", err)
	}
}

// TestVerifyLogoutTokenSignature_RejectsGenuinelyBadSignature is a control:
// a token whose signature is valid against neither the cached nor the
// fresh key must still be rejected (the refresh retry must not turn a bad
// signature into an acceptance).
func TestVerifyLogoutTokenSignature_RejectsGenuinelyBadSignature(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	token, jwt := es256SignToken(t, key1, "rot-kid")

	oidc := &TraefikOidc{
		logger:     NewLogger("debug"),
		jwkCache:   &rotatingJWKCacheForLogout{stale: key2, fresh: key2},
		jwksURL:    "https://provider.example.com/.well-known/jwks.json",
		metadataMu: sync.RWMutex{},
	}

	if err := oidc.verifyLogoutTokenSignature(jwt, token); err == nil {
		t.Fatalf("token whose signature matches neither key must be rejected")
	}
}

// TestGetPublicKey_BoundsUngatedPickup guards the anti-amplification bound
// on the R124 immediate refresh. An attacker sending many tokens with an
// unknown kid would otherwise drive one upstream JWKS fetch PER request:
// within the cooldown forceJWKSRefresh returns the cached (kid-lacking)
// set, yet GetPublicKey's R124 `if !fresh` path then live-fetched again
// and re-slid lastForceRefresh each time — defeating R54's cooldown.
// Now the immediate pick-up runs at most once per cooldown window, so a
// flood of absent-kid requests maps to a bounded number of upstream
// fetches (1 gated + 1 immediate pick-up) instead of N.
func TestGetPublicKey_BoundsUngatedPickup(t *testing.T) {
	otherJWK := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "some-other-key",
		N: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(65537)).Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
	}

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{otherJWK}})
	}))
	defer server.Close()

	backend, err := NewMemoryBackendForTest()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	defer backend.Close()

	cache := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Type:   CacheTypeJWK,
		Logger: GetSingletonNoOpLogger(),
	}, backend)
	defer cache.Close()

	jwkCache := &JWKCache{cache: cache}
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if _, err := jwkCache.GetPublicKey(ctx, server.URL, "rotating-kid", http.DefaultClient); err == nil {
			t.Fatalf("call %d must fail: key never published", i+1)
		}
	}

	// 1 gated live refresh (call 1) + 1 immediate pick-up (call 2), then
	// the bound kicks in. On the old (unbounded) code all 4 calls fetch.
	if got := atomic.LoadInt32(&fetchCount); got != 2 {
		t.Fatalf("expected at most 2 upstream fetches across 4 absent-kid calls, got %d", got)
	}
}
