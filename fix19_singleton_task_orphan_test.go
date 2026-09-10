package traefikoidc

import (
	"sync/atomic"
	"testing"
	"time"
)

// FIX-19: RegisterBackgroundTask replaced a registered-but-not-yet-started
// task (started==0, stopped==0) unconditionally. CreateSingletonTask runs
// Register -> IsTaskRunning -> StartBackgroundTask without holding tasksMu
// across the three calls (autocleanup.go:612-632), so a second concurrent
// caller can land in RegisterBackgroundTask in the window before the first
// caller's own Start() call runs.
//
// This test reproduces that exact interleaving deterministically, without
// real goroutines, by issuing the calls in the documented race order:
//
//  1. Caller A registers the task (T1).
//  2. Caller A reads its handle from the registry (mirrors
//     CreateSingletonTask's internal StartBackgroundTask lookup) but has not
//     called Start() on it yet.
//  3. Caller B registers the SAME name before A calls Start() — at head this
//     replaces the map entry with a fresh task (T2).
//  4. Caller A calls Start() on the handle it read in step 2.
//  5. Caller B starts whatever is now registered under the name.
//
// At head this starts two independent tickers (T1 wrapping count1, T2
// wrapping count2). Only the object actually stored in the registry (T2) is
// reachable from StopAllTasks, so T1 becomes an orphan that keeps running
// forever past Close/StopAllTasks. After the fix, step 3's register call
// keeps the existing (still-pending) T1 instead of replacing it, so there is
// only ever one task, and count2 (which would wrap a second, orphaned task)
// never starts at all.
func TestFix19_RegisterBackgroundTaskKeepsPendingTaskNoOrphan(t *testing.T) {
	rm := GetResourceManager()
	name := "fix19-" + t.Name()

	var count1, count2 int32

	// Step 1: caller A registers T1.
	if err := rm.RegisterBackgroundTask(name, 5*time.Millisecond, func() {
		atomic.AddInt32(&count1, 1)
	}); err != nil {
		t.Fatalf("first RegisterBackgroundTask: %v", err)
	}

	// Step 2: caller A reads its handle, but has not started it yet.
	rm.tasksMu.RLock()
	aTask := rm.tasks[name]
	rm.tasksMu.RUnlock()
	if aTask == nil {
		t.Fatal("task not present in registry after first RegisterBackgroundTask")
	}

	// Step 3: caller B registers the same name before A calls Start().
	if err := rm.RegisterBackgroundTask(name, 5*time.Millisecond, func() {
		atomic.AddInt32(&count2, 1)
	}); err != nil {
		t.Fatalf("second RegisterBackgroundTask: %v", err)
	}

	// Step 4: caller A starts the handle it read in step 2.
	aTask.Start()

	// Step 5: caller B starts whatever is now registered under the name.
	if err := rm.StartBackgroundTask(name); err != nil {
		t.Fatalf("StartBackgroundTask: %v", err)
	}

	// Let both tickers (or, after the fix, the single ticker) tick a few
	// times before stopping.
	time.Sleep(60 * time.Millisecond)

	// Stop only the named task this test created, not rm.StopAllTasks(): the
	// ResourceManager is a process-global singleton, and StopAllTasks stops
	// every task registered on it, including unrelated singletons (e.g.
	// memory-monitor, singleton-token-cleanup) that other tests in the same
	// binary may have started and still expect running.
	if err := rm.StopBackgroundTask(name); err != nil {
		t.Fatalf("StopBackgroundTask(%q): %v", name, err)
	}

	// Snapshot count1 right after the stop, then again after another window
	// long enough for several more ticks. A well-stopped task's counter must
	// not move between the two snapshots.
	afterStop1 := atomic.LoadInt32(&count1)
	time.Sleep(60 * time.Millisecond)
	final1 := atomic.LoadInt32(&count1)

	if final1 != afterStop1 {
		t.Fatalf("task wrapping count1 kept running after StopBackgroundTask (orphan escaped registry): %d -> %d", afterStop1, final1)
	}
	if afterStop1 == 0 {
		t.Fatal("precondition: task wrapping count1 never ran at all")
	}

	// count2 must never have run: after the fix, the second
	// RegisterBackgroundTask call keeps the existing pending task instead of
	// constructing and starting a second one.
	if got := atomic.LoadInt32(&count2); got != 0 {
		t.Fatalf("second RegisterBackgroundTask call must not create and start a second task while the first is still pending; count2=%d", got)
	}

	// Cleanup: make sure the task this test created cannot keep running past
	// the test even if an assertion above already failed it.
	aTask.Stop()
	rm.tasksMu.RLock()
	bTask := rm.tasks[name]
	rm.tasksMu.RUnlock()
	if bTask != nil {
		bTask.Stop()
	}
}
