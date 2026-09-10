package traefikoidc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// newFix09HalfOpenBreaker builds a breaker, trips it with one real (non
// client) failure, and waits past Timeout so the next ExecuteWithContext
// call performs the Open -> HalfOpen probe transition itself.
func newFix09HalfOpenBreaker(t *testing.T) *CircuitBreaker {
	t.Helper()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      100 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, NewLogger("error"))

	if err := cb.ExecuteWithContext(context.Background(), func() error {
		return &HTTPError{StatusCode: 500, Message: "downstream unavailable"}
	}); err == nil {
		t.Fatal("expected the tripping call to return its own error")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("setup: expected circuit open after the tripping failure, got %v", circuitBreakerStateToString(cb.GetState()))
	}

	time.Sleep(150 * time.Millisecond) // past Timeout: next call probes half-open
	return cb
}

// TestCircuitBreakerHalfOpenTerminalClientErrorStaysHalfOpen is a regression
// test for FIX-09. A terminal client error (HTTPError 4xx other than 429,
// e.g. invalid_grant from a replayed code) reflects a per-user problem, not
// a downstream-service failure, so it must not reopen a half-open breaker.
//
// Fail-on-old: recordFailure's HalfOpen case reopened unconditionally on
// any fn() error, so the circuit is Open (not HalfOpen) right after this
// probe.
func TestCircuitBreakerHalfOpenTerminalClientErrorStaysHalfOpen(t *testing.T) {
	cb := newFix09HalfOpenBreaker(t)

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &HTTPError{StatusCode: 400, Message: "invalid_grant"}
	})
	if err == nil {
		t.Fatal("expected the probe's own error to be returned to the caller")
	}
	if cb.GetState() != CircuitBreakerHalfOpen {
		t.Fatalf("a terminal client 4xx must not reopen a half-open circuit, got %v", circuitBreakerStateToString(cb.GetState()))
	}

	// Past resetTimeout relative to the half-open entry: a subsequent
	// success must still be able to fully close the circuit.
	time.Sleep(60 * time.Millisecond)

	if err := cb.ExecuteWithContext(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("expected the closing probe to succeed, got %v", err)
	}
	if cb.GetState() != CircuitBreakerClosed {
		t.Fatalf("expected circuit to close after a half-open success following the ignored client error, got %v", circuitBreakerStateToString(cb.GetState()))
	}
}

// TestCircuitBreakerHalfOpenRateLimitReopens pins that HTTP 429 (the
// service itself signaling it is overloaded) still reopens a half-open
// circuit, unlike an ordinary terminal client 4xx.
func TestCircuitBreakerHalfOpenRateLimitReopens(t *testing.T) {
	cb := newFix09HalfOpenBreaker(t)

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &HTTPError{StatusCode: 429, Message: "rate limited"}
	})
	if err == nil {
		t.Fatal("expected the probe's own error to be returned to the caller")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("a 429 must still reopen a half-open circuit, got %v", circuitBreakerStateToString(cb.GetState()))
	}
}

// TestCircuitBreakerHalfOpenNetworkErrorReopens pins that a genuine network
// error still reopens a half-open circuit.
func TestCircuitBreakerHalfOpenNetworkErrorReopens(t *testing.T) {
	cb := newFix09HalfOpenBreaker(t)

	err := cb.ExecuteWithContext(context.Background(), func() error {
		return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	})
	if err == nil {
		t.Fatal("expected the probe's own error to be returned to the caller")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("a network error must still reopen a half-open circuit, got %v", circuitBreakerStateToString(cb.GetState()))
	}
}
