package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestR169_DiscoveryRequiresJwksURI regresses the required-field gate in
// metadata_cache.go (GetProviderMetadata): a discovery document that provides
// authorization_endpoint and token_endpoint but OMITS jwks_uri (a required
// field per OIDC Discovery 1.0) must be rejected at discovery time. Old code
// checked only auth/token and accepted+adopted the document, leaving
// t.jwksURL empty (jwksURL has no non-discovery source); JWT signature
// verification then failed only at runtime on the first request. Failing at
// discovery surfaces the misconfiguration at startup.
func TestR169_DiscoveryRequiresJwksURI(t *testing.T) {
	mc := NewMetadataCacheWithLogger(nil, newNoOpLogger())

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			// deliberately no jwks_uri
		})
	}))
	defer server.Close()
	serverURL = server.URL

	_, err := mc.GetProviderMetadata(context.Background(), server.URL, server.Client())
	if err == nil {
		t.Fatalf("expected error on a discovery document missing jwks_uri")
	}
	if !strings.Contains(err.Error(), "missing required endpoints") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestR169_DiscoveryAcceptsCompleteGuards the positive case: a discovery
// document with auth, token and jwks_uri passes the required-field gate.
func TestR169_DiscoveryAcceptsComplete(t *testing.T) {
	mc := NewMetadataCacheWithLogger(nil, newNoOpLogger())

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/authorize",
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
		})
	}))
	defer server.Close()
	serverURL = server.URL

	if _, err := mc.GetProviderMetadata(context.Background(), server.URL, server.Client()); err != nil {
		t.Fatalf("complete discovery document should be accepted: %v", err)
	}
}
