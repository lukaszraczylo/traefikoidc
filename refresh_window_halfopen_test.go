package traefikoidc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// After a window reset the tracker must allow the full MaxRefreshAttempts,
// the same as a fresh tracker.
func TestRefreshWindowResetAllowsFullQuota(t *testing.T) {
	cfg := DefaultRefreshCoordinatorConfig()
	cfg.MaxRefreshAttempts = 3
	cfg.RefreshAttemptWindow = 50 * time.Millisecond
	cfg.RefreshCooldownPeriod = time.Hour
	rc := NewRefreshCoordinator(cfg, GetSingletonNoOpLogger())
	defer rc.Shutdown()

	pass := func() int {
		n := 0
		for i := 0; i < 10; i++ {
			if rc.isInCooldown("s") {
				break
			}
			rc.recordRefreshAttempt("s")
			n++
		}
		return n
	}
	if got := pass(); got != 3 {
		t.Fatalf("fresh window passes=%d want 3", got)
	}
	// Window expiry alone cannot reset while in cooldown, so use a new
	// session that never hits the cap: record 1, wait out the window.
	rc.recordRefreshAttempt("w")
	time.Sleep(80 * time.Millisecond)
	n := 0
	for i := 0; i < 10; i++ {
		if rc.isInCooldown("w") {
			break
		}
		rc.recordRefreshAttempt("w")
		n++
	}
	if n != 3 {
		t.Fatalf("post-reset window passes=%d want 3", n)
	}
}

// Half-open admits a single probe until it reports.
func TestRefreshBreakerHalfOpenSingleProbe(t *testing.T) {
	cb := &RefreshCircuitBreaker{config: RefreshCircuitBreakerConfig{
		MaxFailures: 1, OpenDuration: 20 * time.Millisecond, HalfOpenRequests: 1,
	}}
	cb.RecordFailure()
	time.Sleep(40 * time.Millisecond)
	var admitted int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cb.AllowRequest() {
				atomic.AddInt32(&admitted, 1)
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("half-open admitted %d, want 1", admitted)
	}
	cb.RecordSuccess()
	if !cb.AllowRequest() {
		t.Fatal("breaker must close after probe success")
	}
}

// A probe that never reports must not wedge the breaker.
func TestRefreshBreakerHalfOpenProbeTimeout(t *testing.T) {
	cb := &RefreshCircuitBreaker{config: RefreshCircuitBreakerConfig{
		MaxFailures: 1, OpenDuration: 20 * time.Millisecond, HalfOpenRequests: 1,
	}}
	cb.RecordFailure()
	time.Sleep(40 * time.Millisecond)
	if !cb.AllowRequest() || cb.AllowRequest() {
		t.Fatal("want exactly one probe")
	}
	time.Sleep(40 * time.Millisecond)
	if !cb.AllowRequest() {
		t.Fatal("stale probe must allow a new one")
	}
}
