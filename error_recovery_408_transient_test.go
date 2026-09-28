package traefikoidc

import (
	"context"
	"testing"
)

// TestIsTerminalClientError408IsTransient pins that HTTP 408 Request Timeout
// is treated as a transient, service-health signal by isTerminalClientError,
// not as a terminal per-request client error. A token endpoint (or a proxy
// in front of it) returns 408 when the upstream is slow, which is the same
// reasoning FIX-13 already applies in token_validation_rs.go's classifier
// and bearer_auth.go, and that internal/recovery/base.go and metrics.go
// apply via their RetryableStatusCodes/isRetryable checks. isTerminalClientError
// must classify 408 the same way, or a burst of token-endpoint 408s never
// opens the refresh circuit breaker.
//
// Fail-on-old: isTerminalClientError excluded only 429, so it reported 408
// as terminal.
func TestIsTerminalClientError408IsTransient(t *testing.T) {
	err := &HTTPError{StatusCode: 408, Message: "request timeout"}
	if isTerminalClientError(err) {
		t.Fatal("408 Request Timeout must be treated as transient (like 429), not a terminal client error")
	}
}

// TestCircuitBreakerHalfOpenRequestTimeoutReopens pins the same contract at
// the circuit-breaker level: a 408 probe result must still reopen a
// half-open breaker, exactly like the existing 429 case
// (TestCircuitBreakerHalfOpenRateLimitReopens in error_recovery_fix09_test.go).
//
// Fail-on-old: with 408 misclassified as terminal, recordFailure's HalfOpen
// exemption for terminal client errors (FIX-09) swallowed it and the breaker
// stayed HalfOpen instead of reopening.
func TestCircuitBreakerHalfOpenRequestTimeoutReopens(t *testing.T) {
	cb := newFix09HalfOpenBreaker(t)

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &HTTPError{StatusCode: 408, Message: "request timeout"}
	})
	if err == nil {
		t.Fatal("expected the probe's own error to be returned to the caller")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("a 408 must still reopen a half-open circuit like 429, got %v", circuitBreakerStateToString(cb.GetState()))
	}
}
