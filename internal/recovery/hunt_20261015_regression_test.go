package recovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCircuitBreaker_PanickingProbeReleasesHalfOpenSlot(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          20 * time.Millisecond,
		MaxRequests:      1,
	}, &mockLogger{})

	_ = cb.ExecuteWithContext(context.Background(), func() error { return errors.New("fail") })
	time.Sleep(40 * time.Millisecond)

	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic must still propagate to the caller")
			}
		}()
		_ = cb.ExecuteWithContext(context.Background(), func() error { panic("boom") })
	}()

	if cb.GetState() != CircuitBreakerOpen {
		t.Fatalf("state after panicking probe = %s, want open", cb.GetState())
	}
	time.Sleep(40 * time.Millisecond)
	if err := cb.ExecuteWithContext(context.Background(), func() error { return nil }); err != nil {
		t.Fatalf("probe after next timeout rejected: %v", err)
	}
	if cb.GetState() != CircuitBreakerClosed {
		t.Fatalf("state = %s, want closed", cb.GetState())
	}
}
