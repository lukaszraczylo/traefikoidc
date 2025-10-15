package traefikoidc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Test GoroutineManager Creation

func TestNewGoroutineManager(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	if gm == nil {
		t.Fatal("Expected non-nil goroutine manager")
	}

	if gm.ctx == nil {
		t.Error("Expected context to be initialized")
	}

	if gm.cancel == nil {
		t.Error("Expected cancel function to be initialized")
	}

	if gm.goroutines == nil {
		t.Error("Expected goroutines map to be initialized")
	}

	if gm.logger != logger {
		t.Error("Expected logger to be set")
	}
}

// Test Starting Goroutines

func TestStartGoroutine(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	executed := atomic.Bool{}

	gm.StartGoroutine("test-goroutine", func(ctx context.Context) {
		executed.Store(true)
	})

	// Give goroutine time to execute
	time.Sleep(50 * time.Millisecond)

	if !executed.Load() {
		t.Error("Expected goroutine to execute")
	}

	status := gm.GetStatus()
	if len(status) != 1 {
		t.Errorf("Expected 1 goroutine in status, got %d", len(status))
	}

	if _, exists := status["test-goroutine"]; !exists {
		t.Error("Expected goroutine 'test-goroutine' in status")
	}
}

func TestStartGoroutineDuplicate(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	counter := atomic.Int32{}

	// Start a long-running goroutine
	gm.StartGoroutine("duplicate-test", func(ctx context.Context) {
		counter.Add(1)
		<-ctx.Done()
	})

	// Give first goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// Try to start another with same name (should be skipped)
	gm.StartGoroutine("duplicate-test", func(ctx context.Context) {
		counter.Add(1)
	})

	time.Sleep(50 * time.Millisecond)

	// Should only have executed once
	if counter.Load() != 1 {
		t.Errorf("Expected counter to be 1 (duplicate should be skipped), got %d", counter.Load())
	}
}

func TestStartGoroutineContextCancellation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	started := atomic.Bool{}
	cancelled := atomic.Bool{}

	gm.StartGoroutine("cancel-test", func(ctx context.Context) {
		started.Store(true)
		<-ctx.Done()
		cancelled.Store(true)
	})

	// Wait for goroutine to start
	time.Sleep(50 * time.Millisecond)

	if !started.Load() {
		t.Error("Expected goroutine to start")
	}

	// Stop the goroutine
	gm.StopGoroutine("cancel-test")

	// Wait for cancellation
	time.Sleep(50 * time.Millisecond)

	if !cancelled.Load() {
		t.Error("Expected goroutine to be cancelled")
	}
}

func TestStartGoroutineWithPanic(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	executed := atomic.Bool{}

	gm.StartGoroutine("panic-test", func(ctx context.Context) {
		executed.Store(true)
		panic("test panic")
	})

	// Give goroutine time to panic and recover
	time.Sleep(100 * time.Millisecond)

	if !executed.Load() {
		t.Error("Expected goroutine to execute before panic")
	}

	// Check that goroutine is marked as not running after panic
	status := gm.GetStatus()
	if goroutineStatus, exists := status["panic-test"]; exists {
		if goroutineStatus.Running {
			t.Error("Expected goroutine to be marked as not running after panic")
		}
	}

	// Manager should still be functional
	counter := atomic.Int32{}
	gm.StartGoroutine("after-panic", func(ctx context.Context) {
		counter.Add(1)
	})

	time.Sleep(50 * time.Millisecond)

	if counter.Load() != 1 {
		t.Error("Expected manager to still be functional after panic recovery")
	}
}

// Test Periodic Tasks

func TestStartPeriodicTask(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	counter := atomic.Int32{}

	gm.StartPeriodicTask("periodic-test", 50*time.Millisecond, func() {
		counter.Add(1)
	})

	// Wait for multiple executions
	time.Sleep(160 * time.Millisecond)

	// Should have executed at least 2-3 times
	count := counter.Load()
	if count < 2 {
		t.Errorf("Expected periodic task to execute at least 2 times, got %d", count)
	}
}

func TestStartPeriodicTaskCancellation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	counter := atomic.Int32{}

	gm.StartPeriodicTask("cancel-periodic", 50*time.Millisecond, func() {
		counter.Add(1)
	})

	// Wait for some executions
	time.Sleep(120 * time.Millisecond)

	// Stop the task
	gm.StopGoroutine("cancel-periodic")

	countBeforeStop := counter.Load()

	// Wait and verify no more executions
	time.Sleep(120 * time.Millisecond)

	countAfterStop := counter.Load()

	// Allow 1 additional execution (could be in progress when stopped)
	if countAfterStop > countBeforeStop+1 {
		t.Errorf("Expected periodic task to stop executing, before: %d, after: %d",
			countBeforeStop, countAfterStop)
	}
}

// Test Stopping Goroutines

func TestStopGoroutine(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	stopped := atomic.Bool{}

	gm.StartGoroutine("stop-test", func(ctx context.Context) {
		<-ctx.Done()
		stopped.Store(true)
	})

	// Wait for goroutine to start
	time.Sleep(50 * time.Millisecond)

	gm.StopGoroutine("stop-test")

	// Wait for goroutine to stop
	time.Sleep(50 * time.Millisecond)

	if !stopped.Load() {
		t.Error("Expected goroutine to be stopped")
	}

	status := gm.GetStatus()
	if goroutineStatus, exists := status["stop-test"]; exists {
		if goroutineStatus.Running {
			t.Error("Expected goroutine to be marked as not running")
		}
	}
}

func TestStopGoroutineNonExistent(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	// Should not panic or error when stopping non-existent goroutine
	gm.StopGoroutine("non-existent")
}

func TestStopGoroutineAlreadyStopped(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	gm.StartGoroutine("already-stopped", func(ctx context.Context) {
		// Exit immediately
	})

	// Wait for goroutine to finish
	time.Sleep(50 * time.Millisecond)

	// Try to stop already-stopped goroutine (should be safe)
	gm.StopGoroutine("already-stopped")
}

// Test Shutdown

func TestShutdownGraceful(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	counter := atomic.Int32{}

	// Start multiple goroutines
	for i := 0; i < 5; i++ {
		name := "goroutine-" + string(rune('0'+i))
		gm.StartGoroutine(name, func(ctx context.Context) {
			counter.Add(1)
			<-ctx.Done()
			counter.Add(-1)
		})
	}

	// Wait for all to start
	time.Sleep(100 * time.Millisecond)

	if counter.Load() != 5 {
		t.Errorf("Expected 5 goroutines running, got %d", counter.Load())
	}

	// Shutdown with generous timeout
	err := gm.Shutdown(time.Second)

	if err != nil {
		t.Errorf("Expected graceful shutdown, got error: %v", err)
	}

	if counter.Load() != 0 {
		t.Errorf("Expected all goroutines to complete cleanup, got %d still running", counter.Load())
	}
}

func TestShutdownWithTimeout(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	// Start a goroutine that ignores cancellation (bad behavior, but testing timeout)
	gm.StartGoroutine("stubborn", func(ctx context.Context) {
		// Simulate a goroutine that takes too long to stop
		time.Sleep(500 * time.Millisecond)
	})

	time.Sleep(50 * time.Millisecond)

	// Shutdown with very short timeout
	err := gm.Shutdown(10 * time.Millisecond)

	if err == nil {
		t.Error("Expected timeout error")
	}

	if err != ErrShutdownTimeout {
		t.Errorf("Expected ErrShutdownTimeout, got %v", err)
	}
}

func TestShutdownEmpty(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	// Shutdown with no goroutines should succeed immediately
	err := gm.Shutdown(time.Second)

	if err != nil {
		t.Errorf("Expected no error for empty shutdown, got: %v", err)
	}
}

// Test Status

func TestGetStatus(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	// Start multiple goroutines with different states
	gm.StartGoroutine("running", func(ctx context.Context) {
		<-ctx.Done()
	})

	gm.StartGoroutine("quick", func(ctx context.Context) {
		// Exits immediately
	})

	time.Sleep(50 * time.Millisecond)

	status := gm.GetStatus()

	if len(status) != 2 {
		t.Errorf("Expected 2 goroutines in status, got %d", len(status))
	}

	if runningStatus, exists := status["running"]; exists {
		if !runningStatus.Running {
			t.Error("Expected 'running' goroutine to be marked as running")
		}

		if runningStatus.Name != "running" {
			t.Errorf("Expected name 'running', got %s", runningStatus.Name)
		}

		if runningStatus.StartTime.IsZero() {
			t.Error("Expected non-zero start time")
		}

		if runningStatus.Runtime <= 0 {
			t.Error("Expected positive runtime")
		}
	} else {
		t.Error("Expected 'running' goroutine in status")
	}

	if quickStatus, exists := status["quick"]; exists {
		if quickStatus.Running {
			t.Error("Expected 'quick' goroutine to be marked as not running")
		}
	} else {
		t.Error("Expected 'quick' goroutine in status")
	}
}

func TestGetStatusEmpty(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	status := gm.GetStatus()

	if status == nil {
		t.Fatal("Expected non-nil status map")
	}

	if len(status) != 0 {
		t.Errorf("Expected empty status, got %d entries", len(status))
	}
}

// Test Concurrent Operations

func TestConcurrentStartGoroutine(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(2 * time.Second)

	counter := atomic.Int32{}
	const numGoroutines = 50

	// Start many goroutines concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			name := "concurrent-" + string(rune('0'+id%10)) + string(rune('0'+id/10))
			gm.StartGoroutine(name, func(ctx context.Context) {
				counter.Add(1)
				time.Sleep(50 * time.Millisecond)
				counter.Add(-1)
			})
		}(i)
	}

	// Wait for all to start
	time.Sleep(150 * time.Millisecond)

	// Verify goroutines are tracked
	status := gm.GetStatus()
	if len(status) < numGoroutines/2 {
		t.Errorf("Expected at least %d goroutines, got %d", numGoroutines/2, len(status))
	}
}

func TestConcurrentStopGoroutine(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	const numGoroutines = 20

	// Start goroutines
	for i := 0; i < numGoroutines; i++ {
		name := "stop-concurrent-" + string(rune('0'+i%10))
		gm.StartGoroutine(name, func(ctx context.Context) {
			<-ctx.Done()
		})
	}

	time.Sleep(50 * time.Millisecond)

	// Stop all concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			name := "stop-concurrent-" + string(rune('0'+id%10))
			gm.StopGoroutine(name)
		}(i)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify all stopped
	status := gm.GetStatus()
	for _, s := range status {
		if s.Running {
			t.Errorf("Expected goroutine %s to be stopped", s.Name)
		}
	}
}

func TestConcurrentGetStatus(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	// Start some goroutines
	for i := 0; i < 10; i++ {
		name := "status-test-" + string(rune('0'+i))
		gm.StartGoroutine(name, func(ctx context.Context) {
			<-ctx.Done()
		})
	}

	// Concurrently read status many times (should not race)
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = gm.GetStatus()
			}
			done <- struct{}{}
		}()
	}

	// Wait for all concurrent reads
	for i := 0; i < 20; i++ {
		<-done
	}
}

// Test Error Cases

func TestShutdownTimeoutError(t *testing.T) {
	err := ErrShutdownTimeout

	if err.Error() != "shutdown timeout: some goroutines did not stop in time" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

// Test Edge Cases

func TestStartGoroutineAfterShutdown(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	// Shutdown immediately
	_ = gm.Shutdown(time.Second)

	executed := atomic.Bool{}

	// Try to start goroutine after shutdown
	gm.StartGoroutine("after-shutdown", func(ctx context.Context) {
		executed.Store(true)
		<-ctx.Done()
	})

	time.Sleep(50 * time.Millisecond)

	// Goroutine should have started but context already cancelled
	// It may or may not execute depending on timing, but shouldn't panic
	status := gm.GetStatus()
	if _, exists := status["after-shutdown"]; exists {
		// If it's in status, it was tracked (acceptable)
		t.Log("Goroutine was tracked even after shutdown")
	}
}

func TestMultipleShutdowns(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)

	// First shutdown
	err1 := gm.Shutdown(time.Second)
	if err1 != nil {
		t.Errorf("Expected first shutdown to succeed, got: %v", err1)
	}

	// Second shutdown (should not panic or error)
	err2 := gm.Shutdown(time.Second)
	if err2 != nil {
		t.Errorf("Expected second shutdown to succeed, got: %v", err2)
	}
}

func TestGoroutineWithImmediateReturn(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	executed := atomic.Bool{}

	gm.StartGoroutine("immediate", func(ctx context.Context) {
		executed.Store(true)
		// Return immediately
	})

	time.Sleep(50 * time.Millisecond)

	if !executed.Load() {
		t.Error("Expected goroutine to execute")
	}

	status := gm.GetStatus()
	if goroutineStatus, exists := status["immediate"]; exists {
		if goroutineStatus.Running {
			t.Error("Expected immediately-returning goroutine to be marked as not running")
		}
	}
}

func TestPeriodicTaskPanicRecovery(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	gm := NewGoroutineManager(logger)
	defer gm.Shutdown(time.Second)

	counter := atomic.Int32{}

	gm.StartPeriodicTask("panic-periodic", 50*time.Millisecond, func() {
		counter.Add(1)
		if counter.Load() == 2 {
			panic("periodic panic")
		}
	})

	// Wait for panic to occur
	time.Sleep(200 * time.Millisecond)

	// After panic, the goroutine should have stopped
	status := gm.GetStatus()
	if goroutineStatus, exists := status["panic-periodic"]; exists {
		if goroutineStatus.Running {
			t.Error("Expected panicked periodic task to stop")
		}
	}
}
