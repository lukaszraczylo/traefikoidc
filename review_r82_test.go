package traefikoidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMetadataDiscovery_RequiresEndpoints is a regression: an OIDC discovery
// document missing the core endpoints (authorization_endpoint or
// token_endpoint) was accepted, cached, and adopted as the working
// auth/token URL, failing only at runtime (wrong authorize redirect, token
// exchange failure). The fix validates the endpoints at startup.
func TestMetadataDiscovery_RequiresEndpoints(t *testing.T) {
	mc := NewMetadataCacheWithLogger(nil, newNoOpLogger())

	// Discovery document with a matching issuer but no authorization/token
	// endpoint: the issuer check passes, so only the missing-endpoint
	// validation can reject it.
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"issuer": serverURL})
	}))
	defer server.Close()
	serverURL = server.URL

	_, err := mc.GetProviderMetadata(context.Background(), server.URL, server.Client())
	if err == nil {
		t.Fatalf("expected error on an incomplete discovery document")
	}
	if !strings.Contains(err.Error(), "missing required endpoints") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRetryExecutor_SingleUse_DoesNotRetryTimeout guards the single-use
// (authorization-code exchange) retry policy: a timeout is NOT retried,
// because the provider may already have consumed the one-time code; re-sending
// would surface invalid_grant permanently even though the first attempt
// succeeded.
func TestRetryExecutor_SingleUse_DoesNotRetryTimeout(t *testing.T) {
	cfg := DefaultRetryConfig()
	cfg.MaxAttempts = 3
	cfg.EnableJitter = false
	cfg.InitialDelay = time.Millisecond
	cfg.MaxDelay = time.Millisecond

	re := NewRetryExecutor(cfg, newNoOpLogger())
	calls := 0
	err := re.ExecuteSingleUseWithContext(context.Background(), func() error {
		calls++
		return errors.New("Post https://idp.example.com/token: context deadline exceeded (Client.Timeout)")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected single-use request to NOT retry a timeout, got %d calls", calls)
	}
}

// TestRetryExecutor_SingleUse_RetriesPreSendError guards that single-use still
// retries errors which prove the request was never sent (connection refused),
// so a transient dial failure of the token endpoint does not lose the
// (unconsumed) authorization code.
func TestRetryExecutor_SingleUse_RetriesPreSendError(t *testing.T) {
	cfg := DefaultRetryConfig()
	cfg.MaxAttempts = 3
	cfg.EnableJitter = false
	cfg.InitialDelay = time.Millisecond
	cfg.MaxDelay = time.Millisecond

	re := NewRetryExecutor(cfg, newNoOpLogger())
	calls := 0
	err := re.ExecuteSingleUseWithContext(context.Background(), func() error {
		calls++
		if calls < 3 {
			return errors.New("dial tcp 10.0.0.1:443: connect: connection refused")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retrying a connection-refused error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts for a pre-send error, got %d", calls)
	}
}
