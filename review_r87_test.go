package traefikoidc

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

// signR87LogoutToken builds an ES256 logout token with the exact given claims
// (so a test can omit or age the exp claim).
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
	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: &mockCacheInterface{data: map[string]interface{}{}},
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache: &staticJWKCache{jwks: &JWKSet{Keys: []JWK{{
			Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256",
		}}}},
		jwksURL: "https://provider.example.com/.well-known/jwks.json",
	}
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

// TestBackchannelLogout_RequiresExp is a regression: OIDC Back-Channel
// Logout 1.0 §2.4 makes exp REQUIRED and §2.6 requires it to be
// validated. The code previously accepted an exp-less logout token (the
// comment claimed "logout tokens don't have exp", which is false) and
// still invalidated the session, letting an unbounded-lifetime captured
// token be replayed.
func TestBackchannelLogout_RequiresExp(t *testing.T) {
	h := newR87LogoutHarness(t)
	claims := r87BaseClaims()
	delete(claims, "exp") // ensure absent
	if code := h.post(claims); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for logout token missing exp, got %d", code)
	}
}

// TestBackchannelLogout_RejectsExpiredExp is a regression: a logout token
// whose exp is already past must be rejected even when iat is fresh, as
// the spec's validation-is-like-ID-Tokens rule requires. Previously only
// iat was capped (15 min), so an expired exp was silently accepted and the
// session was still invalidated.
func TestBackchannelLogout_RejectsExpiredExp(t *testing.T) {
	h := newR87LogoutHarness(t)
	claims := r87BaseClaims()
	claims["iat"] = time.Now().Add(-2 * time.Minute).Unix()  // fresh (within 15 min)
	claims["exp"] = time.Now().Add(-10 * time.Minute).Unix() // expired beyond the 5-min skew
	if code := h.post(claims); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for logout token with expired exp, got %d", code)
	}
}

// TestBackchannelLogout_AcceptsValidExp is the control: an in-window
// exp must still be accepted and must invalidate the session.
func TestBackchannelLogout_AcceptsValidExp(t *testing.T) {
	h := newR87LogoutHarness(t)
	claims := r87BaseClaims()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	if code := h.post(claims); code != http.StatusOK {
		t.Fatalf("expected 200 for valid logout token, got %d", code)
	}
}
