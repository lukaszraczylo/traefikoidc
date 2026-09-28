package traefikoidc

import (
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const gdHealthTaskName = "graceful-degradation-health-check"

// TestSharedHealthTaskNotRestartedAfterLastClose pins the stop-versus-start
// race behind the flaky TestSharedHealthTaskSurvivesOtherInstanceClose.
//
// startHealthCheckRoutine checks gd.stopChan under gd.mutex and then creates
// or adopts the shared health-check task. Close() used to close stopChan
// without gd.mutex, so a routine that had already passed its check could
// reach the task registry AFTER the last Close() stopped the task.
// RegisterBackgroundTask replaces a stopped task with a fresh one, so the
// routine restarted the shared task with no live instance left to stop it.
//
// The test parks gd2's routine right after its stopChan check by holding the
// task-registry mutex (Close never takes it), closes both instances, and then
// releases the routine. The shared task must stay stopped.
func TestSharedHealthTaskNotRestartedAfterLastClose(t *testing.T) {
	t.Cleanup(snapshotAndClearGdInstancesForTest())

	cfg := DefaultGracefulDegradationConfig()
	cfg.HealthCheckInterval = time.Hour
	logger := GetSingletonNoOpLogger()

	gd1 := NewGracefulDegradation(cfg, logger)
	defer gd1.Close()
	waitForHealthRoutineSettled(t, gd1)
	if !GetResourceManager().IsTaskRunning(gdHealthTaskName) {
		t.Fatal("precondition: shared health-check task must run while gd1 is live")
	}

	globalTaskRegistryMutex.Lock()
	registryLocked := true
	releaseRegistry := func() {
		if registryLocked {
			registryLocked = false
			globalTaskRegistryMutex.Unlock()
		}
	}
	defer releaseRegistry()

	gd2 := NewGracefulDegradation(cfg, logger)
	defer gd2.Close()
	waitForGoroutineParkedIn(t, "(*GracefulDegradation).startHealthCheckRoutine", "traefikoidc.GetGlobalTaskRegistry")

	gd1.Close()

	closed := make(chan struct{})
	go func() {
		gd2.Close()
		close(closed)
	}()

	// Release the parked routine once the last Close() has stopped the task.
	// A Close() that waits for the in-flight routine keeps the task running,
	// so the bound only limits how long this test waits in that case.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && GetResourceManager().IsTaskRunning(gdHealthTaskName) {
		time.Sleep(time.Millisecond)
	}
	releaseRegistry()

	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("gd2.Close did not return")
	}

	// gd2's routine holds gd2.mutex until it has created or adopted a task,
	// so taking the lock waits for the routine to finish.
	gd2.mutex.RLock()
	routineTask := gd2.healthCheckTask
	gd2.mutex.RUnlock()

	if routineTask != nil && atomic.LoadInt32(&routineTask.stopped) == 0 {
		routineTask.Stop()
		t.Error("gd2's health routine holds a running task after the last GracefulDegradation closed")
	}
	if GetResourceManager().IsTaskRunning(gdHealthTaskName) {
		_ = GetResourceManager().StopBackgroundTask(gdHealthTaskName)
		t.Error("shared health-check task was restarted after the last GracefulDegradation closed")
	}
}

// waitForGoroutineParkedIn polls all goroutine stacks until one stack contains
// every given frame substring.
func waitForGoroutineParkedIn(t *testing.T, frames ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if goroutineStackContains(frames...) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no goroutine parked in %v", frames)
}

func goroutineStackContains(frames ...string) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if stackHasAllFrames(stack, frames) {
			return true
		}
	}
	return false
}

func stackHasAllFrames(stack string, frames []string) bool {
	for _, f := range frames {
		if !strings.Contains(stack, f) {
			return false
		}
	}
	return true
}
