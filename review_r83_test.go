package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDCR_MissingClientSecretRejected is a regression: a registration
// response carrying client_id but no client_secret was accepted and adopted,
// although the plugin's client-auth default is client_secret_post (RFC 7591
// confidential client) — every subsequent token exchange would fail. The fix
// rejects a secret-less response for secret-based auth methods.
func TestDCR_MissingClientSecretRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ClientRegistrationResponse{ClientID: "client-123"})
	}))
	defer server.Close()

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		&DynamicClientRegistrationConfig{
			Enabled: true,
			ClientMetadata: &ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/callback"},
			},
		},
		server.URL,
	)

	_, err := registrar.RegisterClient(context.Background(), server.URL+"/register")
	if err == nil {
		t.Fatalf("expected registration to fail when the response lacks a client_secret for client_secret_post")
	}
}

// TestConfig_RejectsCallbackQueryOrFragment is a regression: a callbackURL
// containing a query string or fragment passed config validation but can
// never match the request path (req.URL.Path == redirURLPath) and breaks
// redirect_uri, causing an endless re-auth loop. The fix rejects it.
func TestConfig_RejectsCallbackQueryOrFragment(t *testing.T) {
	tests := []string{
		"/callback?from=idp",
		"/callback#frag",
	}
	for _, cb := range tests {
		cfg := &Config{
			ProviderURL:          "https://issuer.example.com",
			CallbackURL:          cb,
			ClientID:             "client-id",
			ClientSecret:         "client-secret",
			SessionEncryptionKey: "0123456789abcdef0123456789abcdef",
			ClientAuthMethod:     "client_secret_post",
			RateLimit:            100,
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("expected Validate to reject callbackURL %q with query/fragment", cb)
		}
	}
}

// TestDCR_InvalidRedirectURIScheme is a regression: redirect_uris entries
// were sent to the IdP without validating scheme/host, so a malformed or
// wrong-scheme URI reached the provider and corrupted the registered
// callback. The fix rejects non-absolute http(s) entries before the POST.
func TestDCR_InvalidRedirectURIScheme(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID:     "client-123",
			ClientSecret: "secret-456",
		})
	}))
	defer server.Close()

	registrar := NewDynamicClientRegistrar(
		server.Client(),
		NewLogger("DEBUG"),
		&DynamicClientRegistrationConfig{
			Enabled: true,
			ClientMetadata: &ClientRegistrationMetadata{
				RedirectURIs: []string{"ftp://example.com/not-a-web-callback"},
			},
		},
		server.URL,
	)

	if _, err := registrar.RegisterClient(context.Background(), server.URL+"/register"); err == nil {
		t.Fatalf("expected registration to reject a non-http(s) redirect_uri")
	}
}
