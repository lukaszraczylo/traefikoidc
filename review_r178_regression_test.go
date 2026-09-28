package traefikoidc

import (
	"context"
	"testing"
	"time"
)

// TestR178_StopMonitoringActuallyStopsGlobalTask regresses memory_monitor.go:
// StopMonitoring looked up the "memory-monitor" task via
// GetGlobalTaskRegistry().GetTask, but CreateSingletonTask stores the task in
// the ResourceManager's registry, NOT in TaskRegistry.tasks (the R88 split).
// So GetTask always returned not-exists, Stop was never called, the monitor's
// ticker goroutine ran on past shutdown, and globalMonitoringStarted stayed
// true. StopMonitoring must actually stop the task and clear the flag.
func TestR178_StopMonitoringActuallyStopsGlobalTask(t *testing.T) {
	ResetGlobalMemoryMonitor()
	ResetGlobalTaskRegistry()
	defer ResetGlobalMemoryMonitor()
	defer ResetGlobalTaskRegistry()

	mm := GetGlobalMemoryMonitor()
	mm.StartMonitoring(context.Background(), 50*time.Millisecond)

	if !GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("precondition: memory monitoring should be running after StartMonitoring")
	}
	if !mm.IsMonitoringActive() {
		t.Fatal("precondition: IsMonitoringActive should be true after StartMonitoring")
	}

	mm.StopMonitoring()

	if mm.IsMonitoringActive() {
		t.Fatal("StopMonitoring must clear the global started flag (previously it never stopped the task)")
	}
	if GetResourceManager().IsTaskRunning("memory-monitor") {
		t.Fatal("StopMonitoring must actually stop the singleton ticker goroutine")
	}
}
