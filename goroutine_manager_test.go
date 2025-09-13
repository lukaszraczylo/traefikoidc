package traefikoidc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoroutineManager(t *testing.T) {
	logger := NewLogger("debug")

	t.Run("start and stop goroutine", func(t *testing.T) {
		manager := NewGoroutineManager(logger)

		started := make(chan struct{})
		stopped := make(chan struct{})

		manager.StartGoroutine("test", func(ctx context.Context) {
			close(started)
			<-ctx.Done()
			close(stopped)
		})

		// Wait for goroutine to start
		select {
		case <-started:
			// Good
		case <-time.After(time.Second):
			t.Fatal("Goroutine did not start")
		}

		// Stop the goroutine
		manager.StopGoroutine("test")

		// Wait for goroutine to stop
		select {
		case <-stopped:
			// Good
		case <-time.After(time.Second):
			t.Fatal("Goroutine did not stop")
		}

		// Cleanup
		manager.Shutdown(time.Second)
	})

	t.Run("periodic task", func(t *testing.T) {
		manager := NewGoroutineManager(logger)

		var counter int32
		manager.StartPeriodicTask("counter", 50*time.Millisecond, func() {
			atomic.AddInt32(&counter, 1)
		})

		// Let it run for a bit
		time.Sleep(200 * time.Millisecond)

		// Should have executed at least 3 times
		count := atomic.LoadInt32(&counter)
		if count < 3 {
			t.Errorf("Expected at least 3 executions, got %d", count)
		}

		// Cleanup
		manager.Shutdown(time.Second)

		// Counter should stop increasing
		finalCount := atomic.LoadInt32(&counter)
		time.Sleep(100 * time.Millisecond)
		if atomic.LoadInt32(&counter) != finalCount {
			t.Error("Task continued after shutdown")
		}
	})

	t.Run("multiple goroutines", func(t *testing.T) {
		manager := NewGoroutineManager(logger)

		var running int32

		for i := 0; i < 5; i++ {
			name := string(rune('a' + i))
			manager.StartGoroutine(name, func(ctx context.Context) {
				atomic.AddInt32(&running, 1)
				<-ctx.Done()
				atomic.AddInt32(&running, -1)
			})
		}

		// Wait for all to start
		time.Sleep(50 * time.Millisecond)

		if atomic.LoadInt32(&running) != 5 {
			t.Errorf("Expected 5 running goroutines, got %d", running)
		}

		// Shutdown all
		err := manager.Shutdown(time.Second)
		if err != nil {
			t.Fatalf("Shutdown failed: %v", err)
		}

		if atomic.LoadInt32(&running) != 0 {
			t.Errorf("Expected 0 running goroutines after shutdown, got %d", running)
		}
	})

	t.Run("duplicate goroutine name", func(t *testing.T) {
		manager := NewGoroutineManager(logger)

		var starts int32

		for i := 0; i < 3; i++ {
			manager.StartGoroutine("same-name", func(ctx context.Context) {
				atomic.AddInt32(&starts, 1)
				<-ctx.Done()
			})
		}

		time.Sleep(50 * time.Millisecond)

		// Should only start once
		if atomic.LoadInt32(&starts) != 1 {
			t.Errorf("Expected 1 start for duplicate name, got %d", starts)
		}

		manager.Shutdown(time.Second)
	})

	t.Run("panic recovery", func(t *testing.T) {
		manager := NewGoroutineManager(logger)
		defer manager.Shutdown(time.Second)

		// Start a goroutine that will panic
		manager.StartGoroutine("panicker", func(ctx context.Context) {
			panic("test panic")
		})

		// Give it time to panic and recover
		time.Sleep(100 * time.Millisecond)

		// Manager should still be functional - test with a simple task
		completed := make(chan struct{})
		manager.StartGoroutine("after-panic", func(ctx context.Context) {
			close(completed)
		})

		select {
		case <-completed:
			// Good - manager is still functional
		case <-time.After(time.Second):
			t.Error("Manager not functional after panic")
		}
	})

	t.Run("status tracking", func(t *testing.T) {
		manager := NewGoroutineManager(logger)

		manager.StartGoroutine("task1", func(ctx context.Context) {
			<-ctx.Done()
		})

		manager.StartGoroutine("task2", func(ctx context.Context) {
			time.Sleep(10 * time.Millisecond)
		})

		time.Sleep(50 * time.Millisecond)

		status := manager.GetStatus()

		if len(status) != 2 {
			t.Errorf("Expected 2 goroutines in status, got %d", len(status))
		}

		if status["task1"].Running != true {
			t.Error("task1 should be running")
		}

		if status["task2"].Running != false {
			t.Error("task2 should have finished")
		}

		manager.Shutdown(time.Second)
	})

	t.Run("shutdown timeout", func(t *testing.T) {
		manager := NewGoroutineManager(logger)

		// Start a goroutine that won't stop
		manager.StartGoroutine("stubborn", func(ctx context.Context) {
			// Ignore context cancellation
			select {}
		})

		// Try to shutdown with short timeout
		err := manager.Shutdown(100 * time.Millisecond)

		if err == nil {
			t.Error("Expected shutdown timeout error")
		}
	})
}
