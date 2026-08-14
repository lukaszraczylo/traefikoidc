package traefikoidc

import (
	"sync/atomic"
	"testing"
)

// TestR165_ConcurrentTaskCapIsHard guards TaskCircuitBreaker.OnTaskStart
// (autocleanup.go). Previously the concurrency check (CanCreateTask)
// and the slot commit (OnTaskStart's unconditional Counter++ ) were
// separate calls, so under concurrent starts two tasks could both pass
// the limit check (read current < max) and then both start — live
// tasks could exceed maxConcurrent and the DoS backstop was not a hard
// guarantee. OnTaskStart now enforces maxConcurrent atomically (CAS):
// once maxConcurrent slots are held, further calls return without
// incrementing, so the counter can never exceed max.
// Fail-on-old: max+1 sequential OnTaskStart calls push concurrentTasks
// to max+1 on old code; on the fix it is pinned at max.
func TestR165_ConcurrentTaskCapIsHard(t *testing.T) {
	reg := GetGlobalTaskRegistry()
	prevMax := atomic.LoadInt32(&reg.cb.maxConcurrent)
	defer atomic.StoreInt32(&reg.cb.maxConcurrent, prevMax)
	atomic.StoreInt32(&reg.cb.maxConcurrent, 5)

	const max = int32(5)
	const attempts = 25 // >> max

	// Take the max slots, then attempt far more.
	for i := 0; i < attempts; i++ {
		reg.cb.OnTaskStart("r165-cap-task") // return value ignored: compiles for void or bool
	}

	got := atomic.LoadInt32(&reg.cb.concurrentTasks)
	if got > max {
		t.Fatalf("concurrency cap is not hard: after %d starts concurrentTasks = %d, want <= %d", attempts, got, max)
	}

	// Release the slots we pinned so the shared registry's counter returns
	// to baseline for other tests.
	for i := int32(0); i < got; i++ {
		reg.cb.OnTaskComplete("r165-cap-task")
	}
}
