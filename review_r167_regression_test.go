package traefikoidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// r167TimeoutErr implements net.Error with Timeout()==true so the retry
// executor classifies it as a client-side timeout (as http.Client.Do does
// when the server takes longer than Client.Timeout).
type r167TimeoutErr struct{}

func (r167TimeoutErr) Error() string   { return "net/http: request canceled (Client.Timeout exceeded)" }
func (r167TimeoutErr) Timeout() bool   { return true }
func (r167TimeoutErr) Temporary() bool { return true }

// r167RoundTripper always returns a client-side timeout and counts the number
// of token requests actually sent.
type r167RoundTripper struct {
	calls *int32
}

func (rt r167RoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	atomic.AddInt32(rt.calls, 1)
	return nil, &url.Error{Op: "Post", URL: "http://token.example.com/token", Err: r167TimeoutErr{}}
}

// TestR167_RefreshSingleUseOnTimeout regresses the token refresh retry path
// (token_resilience.go): ExecuteTokenRefresh now runs single-use, so a
// client-side timeout is NOT retried — it yields after exactly one exchange
// attempt. On a refresh-token-rotating provider a timed-out-but-processed
// first attempt rotates the token, so a retry would re-present the stale
// token, surface invalid_grant, and clear the session (full logout) — a
// transient timeout escalating to logout. Old code passed singleUse=false,
// retrying on timeout up to MaxAttempts (3) and hitting the token endpoint
// 3 times.
func TestR167_RefreshSingleUseOnTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive retry regression")
	}

	var calls int32
	oidc := &TraefikOidc{
		tokenURL:        "http://token.example.com/token",
		clientID:        "test_client",
		clientSecret:    "test_secret",
		tokenHTTPClient: &http.Client{Transport: r167RoundTripper{calls: &calls}},
		logger:          GetSingletonNoOpLogger(),
	}

	cfg := DefaultTokenResilienceConfig()
	// Keep the old (retrying) path fast for the fail-on-old run.
	cfg.RetryConfig.InitialDelay = time.Millisecond
	cfg.RetryConfig.MaxDelay = time.Millisecond
	rm := NewTokenResilienceManager(cfg, GetSingletonNoOpLogger())

	_, err := rm.ExecuteTokenRefresh(context.Background(), oidc, "refresh_token")
	if err == nil {
		t.Fatal("expect a timeout error from the token endpoint")
	}

	got := atomic.LoadInt32(&calls)
	if got != 1 {
		t.Fatalf("refresh must be single-use and not retried on timeout: got %d token-exchange attempts, want 1 (old code retried to %d on a timeout, which on a rotating provider surfaces invalid_grant and logs out the user)", got, 1)
	}

	// Sanity: the error surfaced is the timeout, not something down-track.
	var netErr interface {
		Timeout() bool
	}
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a timeout error, got: %v", err)
	}
}
