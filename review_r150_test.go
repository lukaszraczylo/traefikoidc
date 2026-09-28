package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// TestConfigMarshal_RoundTripSurvives guards the R150 fix in
// config_marshalling.go: the hand-maintained redaction list silently
// dropped entire config areas (dynamicClientRegistration, audience,
// client assertion settings) and never redacted their embedded secrets.
// A JSON round-trip must now retain config and redact every secret.
func TestConfigMarshal_RoundTripSurvives(t *testing.T) {
	cfg := Config{
		ProviderURL:               "https://provider.example.com",
		ClientID:                  "client-abc",
		ClientSecret:              "super-secret-client",
		SessionEncryptionKey:      "enc-key-here",
		Audience:                  "https://api.example.com",
		OverrideScopes:            true,
		EnablePKCE:                true,
		AllowOpaqueTokens:         true,
		ClientAssertionPrivateKey: "-----BEGIN PRIVATE KEY-----\nLEAK-CA-ASSERT\n-----END PRIVATE KEY-----\n",
		DynamicClientRegistration: &DynamicClientRegistrationConfig{
			Enabled:            true,
			InitialAccessToken: "dcr-bearer-secret",
			StorageBackend:     "redis",
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	s := string(raw)

	// Config areas that the legacy list dropped must now be present.
	for _, want := range []string{
		"\"audience\":\"https://api.example.com\"",
		"\"overrideScopes\":true",
		"\"enablePKCE\":true",
		"\"dynamicClientRegistration\"",
		"\"clientAssertionPrivateKey\":\"[REDACTED]\"",
	} {
		if !containsStr(s, want) {
			t.Errorf("marshaled config missing %s in:\n%s", want, s)
		}
	}
	// The DCR initial access token must be redacted, not leaked.
	if containsStr(s, "dcr-bearer-secret") {
		t.Error("marshaled config leaked DCR initialAccessToken")
	}
	if !containsStr(s, "initialAccessToken\":\"[REDACTED]\"") {
		t.Error("marshaled DCR block must redact initialAccessToken")
	}
	// Existing secrets still redacted, none of the raw secrets leaked.
	for _, secret := range []string{"super-secret-client", "enc-key-here", "LEAK-CA-ASSERT"} {
		if containsStr(s, secret) {
			t.Errorf("marshaled config leaked secret %q", secret)
		}
	}
}

// TestClientAssertionSign_EmptyAudienceRejected guards the R150 fix in
// ClientAssertionSigner.Sign: signing with an empty audience previously
// minted an assertion with "aud":"" that the IdP would reject.
func TestClientAssertionSign_EmptyAudienceRejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := NewClientAssertionSigner(pemBytes, "ES256", "test-kid")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if _, err := signer.Sign("", "client-abc"); err == nil {
		t.Fatal("Sign with an empty audience must return an error")
	}
	// A real audience still works.
	if tok, err := signer.Sign("https://provider.example.com/token", "client-abc"); err != nil || tok == "" {
		t.Fatalf("Sign with a valid audience must succeed, err=%v", err)
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
