package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// FIX-35: Close() decided "am I the last live instance" once, early in its
// shutdown sequence (unregisterLiveInstance()'s return value), then reused
// that stale boolean much later to decide whether to stop process-global
// singleton tasks (memory-monitor, singleton-token-cleanup,
// singleton-metadata-refresh-*). Session/cache teardown happens in between,
// taking real time. A concurrently-created new instance (an overlapping
// Traefik reload) can register and adopt those same singletons in that
// window; the old instance's stale decision then stops them anyway, and the
// new instance runs with no memory monitor, token cleanup, or health checks
// until the next reload.
//
// TestFix35_ConcurrentNewKeepsSingletonAliveAcrossOldClose drives the REAL
// (*TraefikOidc).Close() through this exact window via closeTestHook, rather
// than re-implementing Close's stop decision inline: a test that never calls
// Close itself stays green even if the production fix (utilities.go's fresh,
// lock-guarded re-check; main.go's registerLiveInstance-before-adoption
// ordering) is reverted, which is a much weaker regression pin.
func TestFix35_ConcurrentNewKeepsSingletonAliveAcrossOldClose(t *testing.T) {
	ResetGlobalMemoryMonitor()
	t.Cleanup(ResetGlobalMemoryMonitor)
	t.Cleanup(func() { closeTestHook = nil })

	// --- Old instance: already live, has adopted the memory-monitor singleton
	// (mirrors main.go's registerLiveInstance() followed by
	// memoryMonitor.StartMonitoring()).
	registerLiveInstance()
	mm := GetGlobalMemoryMonitor()
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	mm.StartMonitoring(oldCtx, time.Second)
	if !GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("precondition: memory-monitor must be running after StartMonitoring")
	}

	// --- Simulate the concurrent New(): a new instance registers and adopts
	// the memory-monitor singleton in the window between the old instance's
	// unregisterLiveInstance() and its gated singleton stops. closeTestHook
	// fires from inside the real Close(), at exactly that point.
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	closeTestHook = func() {
		registerLiveInstance()
		mm.StartMonitoring(newCtx, time.Second) // adopts: already running, so this is a no-op start.
	}

	// --- Drive the real Close() on an instance built the same way New()
	// builds one for this purpose: registered live, nothing else set (every
	// other field Close touches is nil-guarded).
	oldInstance := &TraefikOidc{logger: GetSingletonNoOpLogger()}
	if err := oldInstance.Close(); err != nil {
		t.Fatalf("Close returned an error: %v", err)
	}

	if !GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("memory-monitor must keep running: a new instance registered and adopted it before Close's last-instance decision")
	}

	// Cleanup: bring liveInstanceCount back to its baseline (Close's own
	// unregisterLiveInstance already accounted for the old instance; the
	// hook's registerLiveInstance for the new one is undone here) and
	// actually stop the task so it does not outlive this test.
	unregisterLiveInstance()
	_ = GetResourceManager().StopBackgroundTask("memory-monitor")
}

// TestFix35_StopIfLastInstanceHoldsLockAcrossCheckAndStop pins the FIX-35
// review's major finding: isLastInstanceNow() alone only wraps the counter
// read. Used as `if isLastInstanceNow() { stop() }`, liveInstanceMu is
// released as soon as the check returns, before stop() (which can block for
// real time — BackgroundTask.Stop waits up to 5s per task) ever runs. A
// concurrent registerLiveInstance() can land in that gap and have its
// just-adopted singleton killed by a stop decision made before it
// registered.
//
// stopIfLastInstance closes that window by holding liveInstanceMu across
// both the check and the stop call. This test proves the lock is genuinely
// held for the stop's full duration: while a slow stop callback is running,
// a concurrent registerLiveInstance() must not be able to complete.
func TestFix35_StopIfLastInstanceHoldsLockAcrossCheckAndStop(t *testing.T) {
	resetLiveInstanceCountForTest()
	t.Cleanup(resetLiveInstanceCountForTest)

	stopStarted := make(chan struct{})
	releaseStop := make(chan struct{})
	stopDone := make(chan struct{})

	go func() {
		stopIfLastInstance(func() {
			close(stopStarted)
			<-releaseStop // hold the "stop" open, simulating BackgroundTask.Stop's wait.
		})
		close(stopDone)
	}()

	select {
	case <-stopStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("stopIfLastInstance never invoked its stop callback at baseline (count 0)")
	}

	registerDone := make(chan struct{})
	go func() {
		registerLiveInstance()
		close(registerDone)
	}()

	select {
	case <-registerDone:
		t.Fatal("registerLiveInstance completed while the stop callback was still running — liveInstanceMu was not held across the stop, reopening the check-then-stop window")
	case <-time.After(100 * time.Millisecond):
		// Expected: still blocked on liveInstanceMu.
	}

	close(releaseStop)

	select {
	case <-registerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("registerLiveInstance did not complete after the stop callback released liveInstanceMu")
	}
	<-stopDone

	unregisterLiveInstance() // balance the registerLiveInstance above
}

// resetLiveInstanceCountForTest establishes a clean baseline (0) for the
// package-level liveInstanceCount so a test's last-instance decisions are not
// skewed by instances registered-and-never-unregistered by earlier tests in
// the same process. Test-only; mirrors resetGdInstancesForTest.
func resetLiveInstanceCountForTest() {
	liveInstanceMu.Lock()
	defer liveInstanceMu.Unlock()
	liveInstanceCount = 0
}
