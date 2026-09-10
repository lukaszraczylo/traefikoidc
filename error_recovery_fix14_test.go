package traefikoidc

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestExecuteSingleUseWithContextNeverRetriesAfterHTTPResponse is a
// regression test for FIX-14.
//
// helpers.go's token-endpoint exchange returns a *HTTPError whose Message
// carries up to 10 KiB of the raw response body once a non-200 status is
// received (helpers.go:192-195). Before the fix, ExecuteSingleUseWithContext
// matched singleUseRetryableErrors as a plain substring of err.Error(), so
// an IdP 500 whose body happens to mention "connection refused" (e.g. the
// IdP's own downstream error) was retried up to MaxAttempts times even
// though the request had definitely already reached the server. For a
// single-use operation (authorization-code exchange, refresh) re-sending
// consumed input causes invalid_grant or refresh-token-family revocation.
//
// Fail-on-old: fn is called 3 times (MaxAttempts) instead of once.
func TestExecuteSingleUseWithContextNeverRetriesAfterHTTPResponse(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1,
		MaxDelay:      1,
		BackoffFactor: 1,
	}, NewLogger("error"))

	calls := 0
	err := re.ExecuteSingleUseWithContext(context.Background(), func() error {
		calls++
		return &HTTPError{
			StatusCode: 500,
			Message:    "token endpoint returned status 500: {\"error\":\"server_error\",\"detail\":\"upstream: connection refused\"}",
		}
	})

	if err == nil {
		t.Fatal("expected the HTTPError to be returned")
	}
	if calls != 1 {
		t.Fatalf("fn called %d times, want 1: an HTTP response proves the request was already sent and must never be retried for a single-use operation", calls)
	}
}

// TestExecuteSingleUseWithContextStillRetriesRealDialError guards against
// over-broadening the FIX-14 fix: a genuine dial/connect failure -- proof
// the request never reached the server -- must still be retried.
func TestExecuteSingleUseWithContextStillRetriesRealDialError(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1,
		MaxDelay:      1,
		BackoffFactor: 1,
	}, NewLogger("error"))

	calls := 0
	err := re.ExecuteSingleUseWithContext(context.Background(), func() error {
		calls++
		if calls == 1 {
			return &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected the retried call to succeed, got: %v", err)
	}
	if calls != 2 {
		t.Fatalf("fn called %d times, want 2: a real dial error must still be retried", calls)
	}
}
