package traefikoidc

// R135 review-fix round regressions.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestValidate_IntrospectionOrOpaqueWithDCR_RequiresNoStaticSecret guards the
// R135 fix: with Dynamic Client Registration enabled (and no static clientID),
// the client secret is provisioned at runtime by the registrar, so the
// Config.Validate() secret gate for requireTokenIntrospection /
// allowOpaqueTokens must be skipped the same way the clientID gate is.
// Fail-on-old: before the fix Validate() returned the introspect-secret error
// for an otherwise-valid DCR + opaque-token config.
func TestValidate_IntrospectionOrOpaqueWithDCR_RequiresNoStaticSecret(t *testing.T) {
	c := r134ValidConfig()
	c.ClientID = ""
	c.ClientSecret = ""
	c.RateLimit = CreateConfig().RateLimit
	c.DynamicClientRegistration = &DynamicClientRegistrationConfig{Enabled: true}
	c.AllowOpaqueTokens = true

	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid DCR + opaque-token config, got %v", err)
	}

	// Sanity: without DCR the secret is still required.
	c2 := r134ValidConfig()
	c2.ClientSecret = ""
	c2.AllowOpaqueTokens = true
	if err := c2.Validate(); err == nil {
		t.Fatal("expected clientSecret to be required for opaque-token introspection without DCR")
	}
}

// TestNewClientAssertionSigner_RejectsWeakRSAKey guards the R135 fix: RFC
// 7518 §3.3 requires RS*/PS* client-assertion keys of at least 2048 bits.
// A smaller key signs locally but conformant IdPs reject it, so every
// exchange/refresh/revocation fails at runtime — reject at construction.
// Fail-on-old: a 1024-bit key was accepted by NewClientAssertionSigner.
func TestNewClientAssertionSigner_RejectsWeakRSAKey(t *testing.T) {
	for _, bits := range []int{1024, 1536} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("keygen(%d): %v", bits, err)
		}
		der := x509.MarshalPKCS1PrivateKey(k)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		if _, err := NewClientAssertionSigner(pemBytes, "RS256", "kid-1"); err == nil {
			t.Fatalf("expected %d-bit RSA key to be rejected, but it was accepted", bits)
		}
	}

	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen(2048): %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(strong)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if _, err := NewClientAssertionSigner(pemBytes, "RS256", "kid-1"); err != nil {
		t.Fatalf("expected 2048-bit RSA key to be accepted, got %v", err)
	}
}
