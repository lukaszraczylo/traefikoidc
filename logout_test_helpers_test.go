package traefikoidc

// Shared back-channel-logout test harness for round-regression tests.
//
// Moved here for FIX-41: r87LogoutHarness/newR87LogoutHarness/r87BaseClaims
// were declared inside review_r87_test.go but consumed by
// review_r172_regression_test.go, so deleting or renaming the declaring file
// silently broke the consumer. Every review_rNN*_test.go file must depend
// only on shared helpers like this one, never on another round file.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// r87LogoutHarness builds an ES256 logout token with the exact given claims
// (so a test can omit or age the exp claim) and posts it to a *TraefikOidc's
// back-channel-logout endpoint.
type r87LogoutHarness struct {
	oidc *TraefikOidc
	tok  func(map[string]interface{}) string
}

func newR87LogoutHarness(t *testing.T) *r87LogoutHarness {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes())
	oidc := newTestOIDC(t, func(o *TraefikOidc) {
		o.enableBackchannelLogout = true
		o.backchannelLogoutPath = "/backchannel-logout"
		o.sessionInvalidationCache = &mockCacheInterface{data: map[string]interface{}{}}
		o.jwkCache = &staticJWKCache{jwks: &JWKSet{Keys: []JWK{{
			Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256",
		}}}}
		o.jwksURL = "https://provider.example.com/.well-known/jwks.json"
	})
	tok := func(claims map[string]interface{}) string {
		h, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "typ": "logout+jwt", "kid": "test-key-1"})
		hb := base64.RawURLEncoding.EncodeToString(h)
		c, _ := json.Marshal(claims)
		cb := base64.RawURLEncoding.EncodeToString(c)
		hash := sha256.Sum256([]byte(hb + "." + cb))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
		sig := make([]byte, 64)
		rb, sb := r.Bytes(), s.Bytes()
		copy(sig[32-len(rb):32], rb)
		copy(sig[64-len(sb):], sb)
		return hb + "." + cb + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	return &r87LogoutHarness{oidc: oidc, tok: tok}
}

func (h *r87LogoutHarness) post(claims map[string]interface{}) int {
	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(h.tok(claims))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	h.oidc.handleBackchannelLogout(rw, req)
	return rw.Code
}

// r87BaseClaims returns a valid, unique-per-call logout-token claim set;
// callers add/delete/age individual claims to drive a specific test case.
func r87BaseClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("r87-%d", time.Now().UnixNano()), // unique per call
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-1",
	}
}
