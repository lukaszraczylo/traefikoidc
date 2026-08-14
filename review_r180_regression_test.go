package traefikoidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// R180-1: OIDC env fallback
// ---------------------------------------------------------------------------
// The example deployment (examples/complete-traefik-config.yaml) documents
// OIDC_CLIENT_ID / OIDC_CLIENT_SECRET / OIDC_PROVIDER_URL as optional env
// fallbacks ("Plugin configuration takes precedence!"), but Config had no
// ApplyEnvFallbacks and zero code read those vars — an operator following the
// docs got a silent no-op and then "providerURL is required". Config now
// applies them before the required-field guards in Validate.
// Fail-on-old: providerURL is required → Validate returns error, fields
// stay empty.
func TestR180_OIDCEnvFallback_PopulatesEmptyFields(t *testing.T) {
	t.Setenv("OIDC_PROVIDER_URL", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "env-client")
	t.Setenv("OIDC_CLIENT_SECRET", "env-secret")

	config := CreateConfig()
	// The three OIDC fields are intentionally left empty so the env
	// fallback must supply them.
	config.CallbackURL = "/callback"
	config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate with env-supplied OIDC fields: expected providers to be filled by env, got error: %v", err)
	}
	if config.ProviderURL != "https://auth.example.com" {
		t.Errorf("ProviderURL should come from OIDC_PROVIDER_URL; got %q", config.ProviderURL)
	}
	if config.ClientID != "env-client" {
		t.Errorf("ClientID should come from OIDC_CLIENT_ID; got %q", config.ClientID)
	}
	if config.ClientSecret != "env-secret" {
		t.Errorf("ClientSecret should come from OIDC_CLIENT_SECRET; got %q", config.ClientSecret)
	}
}

// Config (dynamic) must take precedence over env: an explicitly-set field
// is never overwritten by an env fallback.
func TestR180_OIDCEnvFallback_ConfigTakesPrecedence(t *testing.T) {
	t.Setenv("OIDC_CLIENT_ID", "env-client")
	t.Setenv("OIDC_PROVIDER_URL", "https://env.example.com")

	config := CreateConfig()
	config.ClientID = "static-client"
	config.ProviderURL = "https://static.example.com"
	config.CallbackURL = "/callback"
	config.SessionEncryptionKey = strings.Repeat("a", MinSessionEncryptionKeyLength)

	config.ApplyEnvFallbacks()
	if config.ClientID != "static-client" {
		t.Errorf("explicit ClientID must take precedence over env; got %q", config.ClientID)
	}
	if config.ProviderURL != "https://static.example.com" {
		t.Errorf("explicit ProviderURL must take precedence over env; got %q", config.ProviderURL)
	}
}

// ============================================================================
// R180-2: main circuit breaker counts open-rejects as failures
// ---------------------------------------------------------------------------
// ExecuteWithContext returned "circuit breaker is open" after only
// RecordRequest(); a request rejected while open was never recorded as a
// failure, so GetBaseMetrics success_rate (successes/total_requests) and
// total_failures understated actual admission (inconsistent with the
// internal/recovery circuit breaker). Open-rejects now call RecordFailure.
// Fail-on-old: total_failures stays 0 after an open-reject.
func TestR180_CircuitBreakerOpenRejectionCountedAsFailure(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), NewLogger("error"))
	// Force the circuit open and keep it open (lastFailureTime now, so the
	// open→half-open timer has not elapsed).
	cb.state = CircuitBreakerOpen
	cb.lastFailureTime = time.Now()

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("should not be called")
	})
	if err == nil || !strings.Contains(err.Error(), "circuit breaker is open") {
		t.Fatalf("expected 'circuit breaker is open', got: %v", err)
	}

	metrics := cb.GetBaseMetrics()
	totalRequests := metrics["total_requests"].(int64)
	totalFailures := metrics["total_failures"].(int64)

	if totalRequests != 1 { // the single ExecuteWithContext below
		t.Errorf("total_requests = %d, want 1", totalRequests)
	}
	if totalFailures != 1 {
		t.Errorf("open-rejection must be counted as a failure: total_failures = %d, want 1", totalFailures)
	}
}

// ============================================================================
// R180-3: DCR clientAssertion write must hold metadataMu (data race)
// ---------------------------------------------------------------------------
// The R162 private_key_jwt reconcile wrote t.clientAssertion AFTER
// metadataMu.Unlock(), but every reader (clientCredentials) snapshots it
// under metadataMu.RLock — a lock-mismatch data race with the request
// path (performDynamicClientRegistration runs in the metadata-refresh and
// recovery goroutines). The write is now folded under the lock.
// Fail-on-old: go test -race reports a DATA RACE between the unlocked
// R162 write and concurrent clientCredentials reads.
func TestR180_DCRAssertionWriteHoldsMetadataLock(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ClientRegistrationResponse{
			ClientID:     "reg-client",
			ClientSecret: "reg-secret",
		})
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tObj := &TraefikOidc{
		logger:          GetSingletonNoOpLogger(),
		httpClient:      ts.Client(),
		ctx:             ctx,
		providerURL:     ts.URL,
		registrationURL: ts.URL,
		dcrConfig: &DynamicClientRegistrationConfig{
			Enabled: true,
			ClientMetadata: &ClientRegistrationMetadata{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "private_key_jwt",
			},
		},
		clientAuthMethod: "client_secret_post",
		dcrClientAssertionBuilder: func() (*ClientAssertionSigner, error) {
			return &ClientAssertionSigner{}, nil
		},
	}

	var wg sync.WaitGroup
	// Continuous readers: mirror the request path that snapshots client
	// credentials (and clientAssertion) under metadataMu.RLock.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50000; j++ {
				tObj.clientCredentials()
			}
		}()
	}
	for i := 0; i < 300; i++ {
		// Re-arm the R162 reconcile while holding the lock (so this reset
		// itself is not the source of any race).
		tObj.metadataMu.Lock()
		tObj.clientAssertion = nil
		tObj.metadataMu.Unlock()
		tObj.performDynamicClientRegistration()
	}
	wg.Wait()

	if tObj.clientID == "" {
		t.Fatalf("expected DCR to have installed a client id")
	}
}
