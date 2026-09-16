package recovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCircuitBreaker_HalfOpenRecoversWhenSuccessThresholdExceedsMaxRequests
// guards the fix that releases the half-open probe slot when a probe
// completes below the success threshold.
//
// Repro scenario: SuccessThreshold (3) exceeds MaxRequests (1). Without
// the fix, the single allowed half-open probe stays counted in
// halfOpenRequests after it completes, so every later request is rejected
// by the MaxRequests gate and consecutiveSuccesses can never reach the
// threshold — the circuit hangs half-open forever. With the fix the slot
// is released on completion, so sequential successful probes accumulate
// to the threshold and the circuit closes.
func TestCircuitBreaker_HalfOpenRecoversWhenSuccessThresholdExceedsMaxRequests(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 3,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      1,
	}
	cb := NewCircuitBreaker(config, &mockLogger{})

	// Drive the circuit open with a single failure.
	if err := cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("fail")
	}); err == nil {
		t.Fatal("expected error from failed execution")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("expected open after failure, got %s", cb.GetState())
	}

	// Wait for the open timeout so the next request transitions to half-open.
	time.Sleep(70 * time.Millisecond)

	// Accumulate successes one at a time (MaxRequests == 1). With the fix
	// each completed probe releases its slot, so the breaker reaches the
	// success threshold and closes.
	for i := 0; i < config.SuccessThreshold; i++ {
		err := cb.ExecuteWithContext(context.Background(), func() error {
			return nil
		})
		if err != nil {
			t.Fatalf("successful execution %d returned error: %v (state %s)", i, err, cb.GetState())
		}
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Fatalf("expected circuit to close after %d half-open successes, got %s",
			config.SuccessThreshold, cb.GetState())
	}
}
