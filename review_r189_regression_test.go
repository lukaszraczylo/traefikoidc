package traefikoidc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// R189: the global health-check pass is single-threaded
// ---------------------------------------------------------------------------
// globalPerformHealthChecks runs from more than one goroutine — the shared
// singleton task's run loop AND the once-guarded StartBackgroundTask path —
// so a health check registered via the public RegisterHealthCheck API could
// be invoked concurrently (a latent production race, and the source of an
// intermittent full-suite race once tests register a health check that
// mutates a captured value). The global pass is now serialized.
// Fail-on-old: a slow health check, invoked from many goroutines at once,
// sees concurrent (overlapping) invocations.
func TestR189_GlobalHealthCheckPassIsSerialized(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()

	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	var active, maxActive int64
	gd.RegisterHealthCheck("svc", func() bool {
		cur := atomic.AddInt64(&active, 1)
		// Record peak concurrency.
		for {
			m := atomic.LoadInt64(&maxActive)
			if cur <= m || atomic.CompareAndSwapInt64(&maxActive, m, cur) {
				break
			}
		}
		// Widen the window so an unsynchronized implementation overlaps.
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt64(&active, -1)
		return true
	})

	// Ensure the instance is visible to the global pass regardless of the
	// async startHealthCheckRoutine registration timing.
	gdInstances.Lock()
	gdInstances.set[gd] = struct{}{}
	gdInstances.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			globalPerformHealthChecks()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&maxActive); got != 1 {
		t.Fatalf("health check ran with peak concurrency %d; want 1 (global pass must be serialized)", got)
	}
}
