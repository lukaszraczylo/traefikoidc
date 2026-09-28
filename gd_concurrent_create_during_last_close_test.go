package traefikoidc

import (
	"testing"
	"time"
)

// TestSharedHealthTaskSurvivesCreateDuringLastClose pins the create-versus-
// last-close race on the shared graceful-degradation health-check task.
//
// Close() decides it is the last live instance and then stops the shared task.
// A GracefulDegradation created between that decision and the stop used to
// register at once, and its health routine adopted the still-running task.
// The stop then killed the task that the new, live instance relies on, and
// nothing restarted it.
//
// The test pauses the last instance's Close() between the decision and the
// stop (beforeSharedTaskStop), creates a new instance, and then lets the stop
// run. The new instance is live, so the shared task must be running at the end.
func TestSharedHealthTaskSurvivesCreateDuringLastClose(t *testing.T) {
	t.Cleanup(snapshotAndClearGdInstancesForTest())

	cfg := DefaultGracefulDegradationConfig()
	cfg.HealthCheckInterval = time.Hour
	logger := GetSingletonNoOpLogger()

	gdA := NewGracefulDegradation(cfg, logger)
	waitForHealthRoutineSettled(t, gdA)
	if !GetResourceManager().IsTaskRunning(gdHealthTaskName) {
		t.Fatal("precondition: shared health-check task must run while gdA is live")
	}

	parked := make(chan struct{})
	release := make(chan struct{})
	gdA.beforeSharedTaskStop = func() {
		close(parked)
		<-release
	}

	closed := make(chan struct{})
	go func() {
		gdA.Close()
		close(closed)
	}()
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("gdA.Close did not reach the shared-task stop")
	}

	created := make(chan *GracefulDegradation, 1)
	go func() { created <- NewGracefulDegradation(cfg, logger) }()

	// Without serialization, gdB registers at once and its routine adopts the
	// still-running task before gdA stops it. With serialization, gdB waits
	// behind gdA's stop; the bound only limits how long the test waits then.
	var gdB *GracefulDegradation
	select {
	case gdB = <-created:
		waitForHealthRoutineSettled(t, gdB)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("gdA.Close did not return")
	}
	if gdB == nil {
		select {
		case gdB = <-created:
		case <-time.After(10 * time.Second):
			t.Fatal("NewGracefulDegradation did not return after gdA.Close")
		}
	}
	defer gdB.Close()
	waitForHealthRoutineSettled(t, gdB)

	if !GetResourceManager().IsTaskRunning(gdHealthTaskName) {
		t.Fatal("shared health-check task is stopped although gdB is still live")
	}
}
