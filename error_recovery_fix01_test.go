package traefikoidc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCircuitBreakerOpenRejectionsDoNotExtendOpenWindow is a regression test
// for FIX-01.
//
// Before the fix, ExecuteWithContext called the promoted
// BaseRecoveryMechanism.RecordFailure() on every request rejected while the
// circuit is open. RecordFailure sets lastFailureTime, the same field
// allowRequest reads as the Open -> HalfOpen timer. Every rejection then
// re-armed the timer, so under steady traffic shorter than Timeout the
// breaker never left Open (see error_recovery.go:253,288 pre-fix).
//
// Fail-on-old: with a request every 10ms and Timeout 50ms, no request is
// ever admitted within the 500ms budget, because each rejection pushes the
// open window forward by another Timeout.
func TestCircuitBreakerOpenRejectionsDoNotExtendOpenWindow(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      50 * time.Millisecond,
		ResetTimeout: 30 * time.Second,
	}, NewLogger("error"))

	// Trip the breaker open with a single real failure.
	if err := cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("boom")
	}); err == nil {
		t.Fatal("expected the tripping call to return its own error")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("expected circuit to be open after the tripping failure, got %v", circuitBreakerStateToString(cb.GetState()))
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	admitted := false
	for time.Now().Before(deadline) {
		callErr := cb.ExecuteWithContext(context.Background(), func() error {
			return nil
		})
		if callErr == nil {
			admitted = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !admitted {
		t.Fatal("expected a probe to be admitted once Timeout elapsed with no real failure in between; open-circuit rejections must not re-arm the open timer")
	}
}

// TestCircuitBreakerOpenRejectionStillCountedInMetrics pins the R180 intent
// alongside FIX-01: an open-circuit rejection is still an admission outcome
// and must still increment total_failures, even though it may no longer
// touch the open timer.
func TestCircuitBreakerOpenRejectionStillCountedInMetrics(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      time.Hour,
		ResetTimeout: time.Hour,
	}, NewLogger("error"))

	if err := cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("boom")
	}); err == nil {
		t.Fatal("expected the tripping call to return its own error")
	}

	if err := cb.ExecuteWithContext(context.Background(), func() error {
		t.Fatal("fn must not be called while the circuit is open")
		return nil
	}); err == nil {
		t.Fatal("expected the rejected call to return an error")
	}

	metrics := cb.GetBaseMetrics()
	totalFailures := metrics["total_failures"].(int64)
	if totalFailures != 2 {
		t.Errorf("total_failures = %d, want 2 (1 real failure + 1 open rejection)", totalFailures)
	}
}
