package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// TestStartMonitoring_ResumesAfterTeardown guards the R121 fix to
// memory_monitor.go: StartMonitoring is gated by the process-global
// globalMonitoringStarted flag, but plugin Close (utilities.go) tears down
// the singleton task via TaskRegistry.StopAllTasks WITHOUT resetting that
// flag. After a config reload the flag was left true, so a recreated
// plugin's StartMonitoring early-returned and memory monitoring
// permanently died. StartMonitoring must detect the torn-down task and
// resume for the recreated instance.
func TestStartMonitoring_ResumesAfterTeardown(t *testing.T) {
	ResetGlobalMemoryMonitor()
	defer ResetGlobalMemoryMonitor()

	mm := GetGlobalMemoryMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mm.StartMonitoring(ctx, time.Second)
	if !GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("precondition: memory monitoring should be running after first StartMonitoring")
	}

	// Simulate process-global teardown (plugin Close -> StopAllTasks),
	// which stops the task without resetting the global started flag.
	if err := GetResourceManager().StopBackgroundTask("memory-monitor"); err != nil {
		t.Fatalf("stop background task: %v", err)
	}
	if GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("precondition: task should be stopped after teardown")
	}

	// A recreated plugin instance calls StartMonitoring again; it must resume.
	mm.StartMonitoring(ctx, time.Second)
	if !GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("memory monitoring must resume after teardown + recreate; globalMonitoringStarted was left set")
	}
}
