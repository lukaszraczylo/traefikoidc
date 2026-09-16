package recovery

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestR175_WrappedRetryableErrorIsRetried regresses isRetryableError: it used
// direct type assertions (err.(*HTTPError)) instead of errors.As, so any
// retryable error that was WRAPPED (fmt.Errorf("...: %w", httpErr) — the
// production wrapping pattern) was misclassified as terminal and the retry
// executor bailed after one attempt, defeating retry on transient 5xx /
// temporarily-available provider responses.
func TestR175_WrappedRetryableErrorIsRetried(t *testing.T) {
	logger := &mockLogger{}
	executor := NewRetryExecutor(RetryConfig{
		RetryableStatusCodes: []int{500, 503},
	}, logger)

	// A 5xx HTTPError wrapped the way callers actually wrap it must still be
	// classified retryable (old code: direct assertion missed the wrap).
	wrappedHTTP := fmt.Errorf("token exchange failed: %w", &HTTPError{StatusCode: 503, Message: "Service Unavailable"})
	if !executor.isRetryableError(wrappedHTTP) {
		t.Fatal("a wrapped 503 *HTTPError must be retryable (errors.As), old code bailed after one attempt")
	}

	// A wrapped retryable OIDCError must also be retried.
	wrappedOIDC := fmt.Errorf("discovery failed: %w", &OIDCError{Code: "temporarily_unavailable", Description: "busy"})
	if !executor.isRetryableError(wrappedOIDC) {
		t.Fatal("a wrapped retryable *OIDCError must be retryable (errors.As)")
	}

	// Wrapped context errors remain non-retryable (errors.Is).
	wrappedCtx := fmt.Errorf("retry canceled: %w", context.Canceled)
	if executor.isRetryableError(wrappedCtx) {
		t.Fatal("a wrapped context.Canceled must remain non-retryable")
	}

	// A wrapped non-retryable HTTPError stays non-retryable.
	wrapped400 := fmt.Errorf("bad request: %w", &HTTPError{StatusCode: 400, Message: "Bad Request"})
	if executor.isRetryableError(wrapped400) {
		t.Fatal("a wrapped 400 *HTTPError must stay non-retryable")
	}

	// Sanity: an unwrapped error that equals a retryable status still retries.
	_ = errors.New("sentinel")
}
