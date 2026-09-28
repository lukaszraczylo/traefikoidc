package traefikoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// R181: DCR secret with finite client_secret_expires_at must be re-registered
// ---------------------------------------------------------------------------
// performDynamicClientRegistration installed a client once and update-
// MetadataEndpoints' gate was "clientID == \"\"" — so a provider that
// returns a finite client_secret_expires_at had its install be a one-shot:
// once the secret lapsed, the 2h metadata refresh (the only path re-running
// the gate) saw clientID != "" and never re-registered, and every token
// exchange then failed invalid_client with no self-heal. The gate now
// re-registers when the installed secret has expired (or is within the
// 5-minute buffer areCredentialsValid uses on the load path).
// Fail-on-old: the second refresh sees clientID != "" and skips re-registration.
func TestR181_DCRReRegistersWhenSecretExpired(t *testing.T) {
	var regCount atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		regCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID:              "reg-client",
			ClientSecret:          "reg-secret",
			ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tObj := &TraefikOidc{
		logger:      GetSingletonNoOpLogger(),
		httpClient:  ts.Client(),
		ctx:         ctx,
		providerURL: ts.URL,
		dcrConfig: &DynamicClientRegistrationConfig{
			Enabled: true,
			ClientMetadata: &ClientRegistrationMetadata{
				RedirectURIs: []string{"https://example.com/callback"},
			},
		},
	}

	md := &ProviderMetadata{
		Issuer:          ts.URL,
		RegistrationURL: ts.URL,
	}

	// First refresh installs a client with a 1h secret.
	tObj.updateMetadataEndpoints(md)
	if got := regCount.Load(); got != 1 {
		t.Fatalf("expected one registration on first refresh, got %d", got)
	}
	if tObj.clientID == "" {
		t.Fatal("expected DCR to have installed a client ID")
	}
	if tObj.dcrRegistrationNeeded() {
		t.Fatal("a freshly registered, non-expired secret must not need re-registration")
	}

	// Simulate the installed secret having lapsed since the last refresh.
	tObj.metadataMu.Lock()
	tObj.clientSecretExpiresAt = time.Now().Add(-time.Hour).Unix()
	tObj.metadataMu.Unlock()

	// Next metadata refresh must re-register (self-heal) rather than keep
	// the dead secret.
	tObj.updateMetadataEndpoints(md)
	if got := regCount.Load(); got != 2 {
		t.Errorf("expired DCR secret must be re-registered on refresh: got %d registrations, want 2", got)
	}

	// A non-expiring secret (exp=0) must keep the installed client.
	tObj.metadataMu.Lock()
	tObj.clientSecretExpiresAt = 0
	tObj.metadataMu.Unlock()
	if tObj.dcrRegistrationNeeded() {
		t.Error("a non-expiring secret (client_secret_expires_at = 0) must keep the installed client")
	}
}
