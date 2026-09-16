package resilience

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// TestHalfOpenProbeLargeHalfOpenMaxRequests pins the gosec G115 fix: the
// half-open gate compared against int32(HalfOpenMaxRequests), so a value
// above MaxInt32 wrapped negative and the first half-open probe was rejected.
// The short sleep waits out the breaker's own open Timeout.
func TestHalfOpenProbeLargeHalfOpenMaxRequests(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("int cannot exceed MaxInt32 on this platform")
	}
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		MaxFailures:         1,
		Timeout:             time.Millisecond,
		HalfOpenMaxRequests: math.MaxInt32 + 1,
		ResetTimeout:        time.Second,
	})
	cb.RecordFailure()
	if cb.GetState() != StateOpen {
		t.Fatalf("state = %v, want open after MaxFailures", cb.GetState())
	}
	time.Sleep(20 * time.Millisecond)
	if !cb.AllowRequest() {
		t.Fatal("first half-open probe rejected although HalfOpenMaxRequests is large")
	}
}
