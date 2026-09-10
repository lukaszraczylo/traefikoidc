package traefikoidc

// Shared JWT/JWKS construction helpers for round-regression tests.
//
// Moved here for FIX-41: writeJWKS, signRSAJWTForTest and makeJWTForTest
// were each declared inside a single round file (review_r54, review_r109,
// review_r102) but consumed by other round files, so deleting or renaming
// the declaring file silently broke the consumer. Every review_rNN*_test.go
// file must depend only on shared helpers like this one, never on another
// round file.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

// writeJWKS encodes a single-key RSA JWKS response for kid/pub to w. Used by
// JWKS-rotation and live-refresh tests that stand up an httptest.Server.
func writeJWKS(t *testing.T, w http.ResponseWriter, kid string, pub *rsa.PublicKey) {
	t.Helper()
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
	_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{jwk}})
}

// signRSAJWTForTest builds an RS256-signed JWT with the given kid and claims,
// suitable for exercising real signature verification (unlike makeJWTForTest
// which uses alg=none).
func signRSAJWTForTest(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hasher := sha256.New()
	hasher.Write([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// makeJWTForTest builds an unsigned (alg=none) JWT carrying claims. Used by
// tests that only need claims to parse, not a verifiable signature.
func makeJWTForTest(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}
