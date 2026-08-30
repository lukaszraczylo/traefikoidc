package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// R157 review-round regressions.

// TestR157_Retry4xxWithCertWordNotRetried guards the isRetryableError
// reordering (error_recovery.go). isCertificateError string-matches
// "certificate"/"tls"/"ssl" and used to run BEFORE the HTTP-status
// check, so a real terminal 4xx whose body merely mentions such a word
// (e.g. IdP: "invalid_grant: certificate mismatch") was classified
// retryable and repeated to MaxAttempts on a permanent error (R123
// class). The fix classifies any real HTTP status (<500, !=429) first.
// Fail-on-old: 4xx mentioning "certificate" → retried → 3 calls.
func TestR157_Retry4xxWithCertWordNotRetried(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    time.Millisecond,
		MaxDelay:        2 * time.Millisecond,
		BackoffFactor:   1,
		EnableJitter:    false,
		RetryableErrors: []string{"timeout", "temporary failure"},
	}, GetSingletonNoOpLogger())

	var calls int32
	err := re.ExecuteWithContext(context.Background(), func() error {
		atomic.AddInt32(&calls, 1)
		// A permanent 4xx whose message contains a cert keyword.
		return &HTTPError{StatusCode: 400, Message: "invalid_grant: certificate mismatch"}
	})
	if err == nil {
		t.Fatal("expected the HTTPError to be returned")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("permanent 4xx mentioning 'certificate' must not be retried; got %d calls (want 1)", n)
	}
}

// TestR157_GoroutineManagerPrunesFinished guards the goroutine manager map
// pruning (goroutine_manager.go). Finished goroutines used to linger in
// m.goroutines forever (only running=false was set), so any caller that
// started distinct-named goroutines grew the map unboundedly and
// GetStatus returned stale dead entries. The fix deletes the entry when
// the goroutine exits.
// Fail-on-old: all finished entries remain in the map.
func TestR157_GoroutineManagerPrunesFinished(t *testing.T) {
	gm := NewGoroutineManager(GetSingletonNoOpLogger())
	defer func() { _ = gm.Shutdown(time.Second) }()

	const n = 8
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("worker-%d", i)
		gm.StartGoroutine(name, func(ctx context.Context) {}) // returns immediately
	}

	// Wait until every goroutine has actually finished (running=false).
	deadline := time.Now().Add(5 * time.Second)
	for {
		allDone := true
		for _, st := range gm.GetStatus() {
			if st.Running {
				allDone = false
			}
		}
		if allDone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for goroutines to finish")
		}
		time.Sleep(time.Millisecond)
	}

	// All are finished: the map must have been pruned.
	if got := len(gm.GetStatus()); got > 0 {
		t.Errorf("finished goroutines should be pruned from the map; got %d stale entries", got)
	}
}

// TestR157_DCRReconcilesClientAuthMethod guards the DCR auth-method
// reconciliation (main.go performDynamicClientRegistration +
// dynamic_client_registration.go). The IdP provisions the registered
// client with the token_endpoint_auth_method from ClientMetadata, but
// the runtime authenticated with the independent Config.ClientAuthMethod
// and never adopted the registered method — so a DCR deployment using a
// non-default auth method (e.g. client_secret_basic) diverged and every
// token exchange failed. The fix points the runtime at the effectively
// registered method.
// Fail-on-old: runtime clientAuthMethod stays at the static default.
func TestR157_DCRReconcilesClientAuthMethod(t *testing.T) {
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
				TokenEndpointAuthMethod: "client_secret_basic",
			},
		},
		clientAuthMethod: "client_secret_post", // static runtime default
	}

	tObj.performDynamicClientRegistration()

	if got := tObj.clientAuthMethod; got != "client_secret_basic" {
		t.Errorf("runtime clientAuthMethod should follow the DCR-registered method; got %q, want client_secret_basic", got)
	}
}
