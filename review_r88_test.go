package traefikoidc

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// R88 regression: process-global singleton tasks are created via
// TaskRegistry.CreateSingletonTask but stored in the ResourceManager's
// registry, not in TaskRegistry.tasks. TaskRegistry.StopAllTasks previously
// iterated its own (always-empty) registry, silently leaking every singleton
// task's ticker goroutine past the last Close (memory-monitor,
// replay-cache-cleanup). It must now delegate to the ResourceManager that
// actually owns the tasks so a last-instance shutdown stops them.
func TestR88StopAllTasksStopsResourceManagerOwnedTasks(t *testing.T) {
	rm := GetResourceManager()
	reg := GetGlobalTaskRegistry()

	// Snapshot the currently-running singleton tasks so we can re-create them
	// after the global teardown below and leave the shared suite un-polluted.
	type restore struct {
		name     string
		interval time.Duration
		fn       func()
		logger   *Logger
		wg       *sync.WaitGroup
	}
	var toRestore []restore
	rm.tasksMu.RLock()
	for name, task := range rm.tasks {
		if atomic.LoadInt32(&task.started) == 1 && atomic.LoadInt32(&task.stopped) == 0 {
			toRestore = append(toRestore, restore{name, task.interval, task.taskFunc, task.logger, task.externalWG})
		}
	}
	rm.tasksMu.RUnlock()

	var wg sync.WaitGroup
	name := fmt.Sprintf("shutdown-probe-%d", time.Now().UnixNano())
	if _, err := reg.CreateSingletonTask(name, time.Hour, func() {}, newNoOpLogger(), &wg); err != nil {
		t.Fatalf("CreateSingletonTask: %v", err)
	}
	if !rm.IsTaskRunning(name) {
		t.Fatalf("expected singleton task %q to be running after CreateSingletonTask", name)
	}

	// This is the exact shutdown path Close() relies on
	// (utilities.go: lastInstance -> GetGlobalTaskRegistry().StopAllTasks()).
	reg.StopAllTasks()

	if rm.IsTaskRunning(name) {
		t.Fatalf("singleton task %q still running after StopAllTasks: global task teardown is a no-op (task lived in ResourceManager, registry iterated its own empty map)", name)
	}

	// Restore the pre-existing running singletons so this global teardown does
	// not destabilize sibling tests that still hold live instances.
	for _, r := range toRestore {
		if _, err := reg.CreateSingletonTask(r.name, r.interval, r.fn, r.logger, r.wg); err != nil {
			t.Errorf("restore task %q: %v", r.name, err)
		}
	}
}
