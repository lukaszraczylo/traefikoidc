package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestClientAssertionESAlgCurveMatch ensures the client-assertion signer
// validates that an ES* key is on the NIST curve the algorithm requires
// (ES256→P-256, ES384→P-384, ES512→P-521). Previously any EC key passed
// construction regardless of curve, so a wrong-curve key built successfully
// yet always produced a signature the IdP rejected (deterministic
// client-authentication failure).
func TestClientAssertionESAlgCurveMatch(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	t.Run("ES512 with P-256 key rejected", func(t *testing.T) {
		if _, err := NewClientAssertionSigner(pemBytes, "ES512", "k"); err == nil {
			t.Fatal("expected error for ES512 with a P-256 key")
		}
	})

	t.Run("ES256 with P-256 key accepted", func(t *testing.T) {
		if _, err := NewClientAssertionSigner(pemBytes, "ES256", "k"); err != nil {
			t.Fatalf("ES256 with P-256 key should build: %v", err)
		}
	})
}
