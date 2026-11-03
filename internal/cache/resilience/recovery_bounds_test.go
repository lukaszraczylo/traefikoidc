package resilience

import (
	"testing"
	"time"
)

// With HealthyThreshold >= 2 an Unhealthy backend must recover once it
// answers HealthyThreshold times in a row.
func TestHealthCheckRecoversWithThresholdTwo(t *testing.T) {
	h := &HealthCheckBackend{config: &HealthCheckConfig{HealthyThreshold: 2, UnhealthyThreshold: 3}}
	for i := 0; i < 6; i++ {
		h.recordResult(false)
	}
	if HealthStatus(h.status.Load()) != HealthUnhealthy {
		t.Fatalf("precondition: status=%v, want unhealthy", HealthStatus(h.status.Load()))
	}
	for i := 0; i < 5; i++ {
		h.recordResult(true)
	}
	if got := HealthStatus(h.status.Load()); got != HealthHealthy {
		t.Fatalf("status after 5 successes = %v, want healthy", got)
	}
}

// Half-open closes after HalfOpenMaxRequests successes, not admissions.
func TestHalfOpenClosesOnSuccessesNotAdmissions(t *testing.T) {
	cb := NewCircuitBreaker(&CircuitBreakerConfig{
		MaxFailures: 1, Timeout: time.Millisecond, HalfOpenMaxRequests: 3, ResetTimeout: time.Second,
	})
	cb.RecordFailure()
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if !cb.AllowRequest() {
			t.Fatalf("probe %d rejected", i)
		}
	}
	cb.RecordSuccess()
	if cb.GetState() != StateHalfOpen {
		t.Fatalf("closed after 1 of 3 probe successes; state=%v", cb.GetState())
	}
	cb.RecordFailure()
	if cb.GetState() != StateOpen {
		t.Fatalf("a failing probe must reopen; state=%v", cb.GetState())
	}
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 3; i++ {
		cb.AllowRequest()
	}
	for i := 0; i < 3; i++ {
		cb.RecordSuccess()
	}
	if cb.GetState() != StateClosed {
		t.Fatalf("state after 3 successes = %v, want closed", cb.GetState())
	}
}
