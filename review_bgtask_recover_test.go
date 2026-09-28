package traefikoidc

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestReview_BackgroundTaskRecoversFromPanic verifies that a panicking
// background task function is recovered and the periodic loop keeps running.
// Previously a panic in taskFunc unwound the goroutine, permanently killing
// the background task (metadata refresh, autocleanup, memory monitor) with no
// log. An unrecovered panic here would crash the whole test binary.
func TestReview_BackgroundTaskRecoversFromPanic(t *testing.T) {
	ResetGlobalTaskRegistry()
	defer ResetGlobalTaskRegistry()

	var runCount int32
	logger := newNoOpLogger()
	task := NewBackgroundTask("review-recover-task", 40*time.Millisecond, func() {
		n := atomic.AddInt32(&runCount, 1)
		if n == 1 {
			panic("review: first run panics")
		}
	}, logger)
	task.Start()
	defer task.Stop()

	// Give the task time to run several intervals past the initial panic.
	time.Sleep(GetTestDuration(250 * time.Millisecond))

	if got := atomic.LoadInt32(&runCount); got < 2 {
		t.Fatalf("Background task should have recovered and continued running after the panic; runCount=%d", got)
	}
}
