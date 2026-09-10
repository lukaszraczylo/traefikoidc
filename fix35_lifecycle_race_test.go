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
// This test drives the exact functions New()/Close() call — registerLiveInstance,
// unregisterLiveInstance, isLastInstanceNow, GetGlobalMemoryMonitor().StartMonitoring
// (the memory-monitor singleton adoption call in main.go) and
// GetGlobalTaskRegistry().StopAllTasks() (the call in utilities.go's Close) —
// in the exact sequence the finding's interleaving describes, without relying
// on real goroutine scheduling.
func TestFix35_ConcurrentNewKeepsSingletonAliveAcrossOldClose(t *testing.T) {
	ResetGlobalMemoryMonitor()
	t.Cleanup(ResetGlobalMemoryMonitor)

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

	// --- Old instance begins Close(): unregister happens first (mirrors
	// utilities.go's unregisterLiveInstance() call at the top of Close).
	unregisterLiveInstance()

	// --- Between that unregister and the eventual singleton stop, session
	// and cache teardown takes real time. A NEW instance is created in that
	// window (an overlapping Traefik reload). It registers BEFORE adopting
	// the singleton, exactly as the fixed main.go now orders these calls.
	registerLiveInstance()
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	mm.StartMonitoring(newCtx, time.Second) // adopts: already running, so this is a no-op start.

	// --- Old instance now reaches the point where it stops process-global
	// singletons (mirrors utilities.go's fresh isLastInstanceNow() check
	// immediately before taskRegistry.StopAllTasks()).
	if isLastInstanceNow() {
		GetGlobalTaskRegistry().StopAllTasks()
	}

	if !GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("memory-monitor must keep running: a new instance registered and adopted it before the old instance's last-instance decision")
	}

	// Cleanup: bring liveInstanceCount back to its baseline and actually
	// stop the task so it does not outlive this test.
	unregisterLiveInstance()
	_ = GetResourceManager().StopBackgroundTask("memory-monitor")
}
