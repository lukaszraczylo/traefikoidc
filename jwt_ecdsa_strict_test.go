package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"testing"
)

func signES(t *testing.T, key *ecdsa.PrivateKey, signed string, h256 bool, size int) (sigRS []byte) {
	t.Helper()
	var digest []byte
	if h256 {
		d := sha256.Sum256([]byte(signed))
		digest = d[:]
	} else {
		d := sha512.Sum384([]byte(signed))
		digest = d[:]
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

func TestECDSAVerifyIsStrict(t *testing.T) {
	const signed = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1In0"
	enc := base64.RawURLEncoding.EncodeToString
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err := verifySignatureWithKey(signed+"."+enc(signES(t, p256, signed, true, 32)), &p256.PublicKey, "ES256"); err != nil {
		t.Fatalf("valid ES256 rejected: %v", err)
	}
	if err := verifySignatureWithKey(signed+"."+enc(signES(t, p384, signed, false, 48)), &p384.PublicKey, "ES384"); err != nil {
		t.Fatalf("valid ES384 rejected: %v", err)
	}
	// ES256 token verified against a P-384 key.
	if err := verifySignatureWithKey(signed+"."+enc(signES(t, p384, signed, true, 48)), &p384.PublicKey, "ES256"); err == nil {
		t.Error("ES256 accepted with a P-384 key")
	}
	// Zero-padded halves: 66 bytes for ES256.
	if err := verifySignatureWithKey(signed+"."+enc(signES(t, p256, signed, true, 33)), &p256.PublicKey, "ES256"); err == nil {
		t.Error("ES256 accepted a 66-byte signature")
	}
}
