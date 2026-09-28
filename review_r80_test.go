package traefikoidc

import (
	"strings"
	"testing"
)

// TestIntrospectionRequiresClientSecret is a regression: Config.Validate allowed
// requireTokenIntrospection together with clientAuthMethod=private_key_jwt and no
// client secret, but the introspection path always authenticates via
// client_secret_basic (SetBasicAuth in token_introspection.go) — so the dead
// config passed validation yet every introspection sent empty Basic credentials
// and failed. Validate must reject it.
func TestIntrospectionRequiresClientSecret(t *testing.T) {
	mk := func() *Config {
		c := CreateConfig()
		c.ProviderURL = "https://provider.example.com"
		c.ClientID = "test-client"
		c.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		c.CallbackURL = "/callback"
		c.RequireTokenIntrospection = true
		c.ClientAuthMethod = "private_key_jwt"
		c.ClientAssertionPrivateKey = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"
		c.ClientAssertionKeyID = "key-id-1"
		return c
	}

	// OLD behavior: no client secret -> Validate still passed, introspection dead.
	noSecret := mk()
	noSecret.ClientSecret = ""
	if err := noSecret.Validate(); err == nil {
		t.Fatalf("expected Validate to require clientSecret when introspection is enabled")
	} else if !strings.Contains(err.Error(), "clientSecret is required when requireTokenIntrospection") {
		t.Fatalf("unexpected error: %v", err)
	}

	// With a secret the config is valid.
	withSecret := mk()
	withSecret.ClientSecret = "secret"
	if err := withSecret.Validate(); err != nil {
		t.Fatalf("expected Validate to pass with a client secret, got: %v", err)
	}
}
