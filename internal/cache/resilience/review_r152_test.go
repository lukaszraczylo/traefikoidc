package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCircuitBreaker_HalfOpenGateNotExceeded guards the R152 fix to
// AllowRequest: the open→half-open transition returned true without
// incrementing halfOpenRequests, so the very probe that opens the
// half-open window was free — allowing exactly one more request than
// the configured gate (on a serial refusal loop: gate+1 pass). The
// probe must be counted so cumulative half-open admissions stay
// within HalfOpenMaxRequests.
func TestCircuitBreaker_HalfOpenGateNotExceeded(t *testing.T) {
	config := &CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		HalfOpenMaxRequests: 2,
	}
	cb := NewCircuitBreaker(config)
	ctx := context.Background()

	// Open the circuit.
	for i := 0; i < 2; i++ {
		cb.Execute(ctx, func() error { return errors.New("boom") })
	}
	if cb.GetState() != StateOpen {
		t.Fatal("expected open after failures")
	}

	time.Sleep(100 * time.Millisecond) // past timeout → cooldown expired

	// Serially offer gate+overflow admission slots. The transition probe
	// must count toward the gate; un-fixed code allows one extra.
	allowed := 0
	for i := 0; i < config.HalfOpenMaxRequests+5; i++ {
		if !cb.AllowRequest() {
			break
		}
		allowed++
	}
	if allowed > config.HalfOpenMaxRequests {
		t.Fatalf("half-open gate exceeded: %d admitted, max %d", allowed, config.HalfOpenMaxRequests)
	}
	if allowed == 0 {
		t.Fatal("at least one probe must be allowed once the cooldown expires")
	}
}
