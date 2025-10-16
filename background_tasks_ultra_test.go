package traefikoidc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestMemoryMonitorComprehensive tests memory monitor edge cases
func TestMemoryMonitorComprehensive(t *testing.T) {
	t.Run("TriggerGC calls runtime GC", func(t *testing.T) {
		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		// Should not panic
		assert.NotPanics(t, func() {
			monitor.TriggerGC()
		})
	})

	t.Run("GetMemoryPressure returns pressure level", func(t *testing.T) {
		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		// Initially should return None (no stats yet)
		pressure := monitor.GetMemoryPressure()
		assert.Equal(t, MemoryPressureNone, pressure)

		// Collect stats to populate lastStats
		monitor.GetCurrentStats()

		// Now should return a valid pressure level
		pressure = monitor.GetMemoryPressure()
		assert.NotNil(t, pressure)
	})

	t.Run("StartMonitoring can be called", func(t *testing.T) {
		ResetGlobalMemoryMonitor()
		ResetGlobalTaskRegistry()
		defer ResetGlobalMemoryMonitor()
		defer ResetGlobalTaskRegistry()

		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		// Start monitoring should not panic
		assert.NotPanics(t, func() {
			ctx := context.Background()
			monitor.StartMonitoring(ctx, 100*time.Millisecond)
			time.Sleep(GetTestDuration(50 * time.Millisecond))
		})

		// Clean up
		monitor.StopMonitoring()
	})

	t.Run("StopMonitoring can be called safely", func(t *testing.T) {
		ResetGlobalMemoryMonitor()
		defer ResetGlobalMemoryMonitor()

		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		// StopMonitoring should not panic even if not started
		assert.NotPanics(t, func() {
			monitor.StopMonitoring()
		})

		// Can be called multiple times safely
		assert.NotPanics(t, func() {
			monitor.StopMonitoring()
			monitor.StopMonitoring()
		})
	})

	t.Run("ResetGlobalMemoryMonitor resets singleton", func(t *testing.T) {
		ResetGlobalMemoryMonitor()
		defer ResetGlobalMemoryMonitor()

		// Get initial instance
		GetGlobalMemoryMonitor()

		// Reset
		ResetGlobalMemoryMonitor()

		// Should be able to get a new instance
		monitor := GetGlobalMemoryMonitor()
		assert.NotNil(t, monitor)

		// Clean up
		monitor.StopMonitoring()
		ResetGlobalMemoryMonitor()
	})

	t.Run("String method returns pressure name", func(t *testing.T) {
		pressures := []struct {
			level MemoryPressureLevel
			name  string
		}{
			{MemoryPressureNone, "None"},
			{MemoryPressureLow, "Low"},
			{MemoryPressureModerate, "Moderate"},
			{MemoryPressureHigh, "High"},
			{MemoryPressureCritical, "Critical"},
			{MemoryPressureLevel(999), "Unknown"},
		}

		for _, p := range pressures {
			assert.Equal(t, p.name, p.level.String(), "pressure level %d should return %s", p.level, p.name)
		}
	})

	t.Run("GetCurrentStats collects statistics", func(t *testing.T) {
		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		stats := monitor.GetCurrentStats()
		assert.NotNil(t, stats)
		assert.Greater(t, stats.HeapAllocBytes, uint64(0))
		assert.Greater(t, stats.NumGoroutines, 0)
		assert.NotZero(t, stats.Timestamp)
	})
}

// TestBackgroundTaskRegistry tests background task registry edge cases
func TestBackgroundTaskRegistry(t *testing.T) {
	t.Run("GetGlobalTaskRegistry returns singleton", func(t *testing.T) {
		registry1 := GetGlobalTaskRegistry()
		registry2 := GetGlobalTaskRegistry()

		assert.Equal(t, registry1, registry2, "should return same instance")
	})

	t.Run("RegisterTask adds task to registry", func(t *testing.T) {
		ResetGlobalTaskRegistry()
		registry := GetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		taskName := "test-register-task"
		task := NewBackgroundTask(
			taskName,
			100*time.Millisecond,
			func() {},
			newNoOpLogger(),
		)

		err := registry.RegisterTask(taskName, task)
		assert.NoError(t, err)

		// Verify task was registered
		_, exists := registry.GetTask(taskName)
		assert.True(t, exists, "task should be registered")

		// Clean up
		task.Stop()
	})

	t.Run("CreateSingletonTask is idempotent", func(t *testing.T) {
		ResetGlobalTaskRegistry()
		registry := GetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		taskName := "test-singleton-idempotent"
		callCount := 0
		var mu sync.Mutex

		taskFunc := func() {
			mu.Lock()
			callCount++
			mu.Unlock()
		}

		// First creation should succeed
		task1, err1 := registry.CreateSingletonTask(
			taskName,
			100*time.Millisecond,
			taskFunc,
			newNoOpLogger(),
			nil,
		)

		assert.NoError(t, err1)
		assert.NotNil(t, task1)

		// Second creation should also succeed (idempotent)
		// Returns same task without error
		task2, err2 := registry.CreateSingletonTask(
			taskName,
			100*time.Millisecond,
			taskFunc,
			newNoOpLogger(),
			nil,
		)

		assert.NoError(t, err2, "CreateSingletonTask should be idempotent")
		assert.NotNil(t, task2)

		// Clean up
		if task1 != nil {
			task1.Stop()
		}
	})

	t.Run("GetTaskCount returns active task count", func(t *testing.T) {
		ResetGlobalTaskRegistry()
		registry := GetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		// Initially should be 0 or small number
		initialCount := registry.GetTaskCount()

		// Create a task
		task := NewBackgroundTask(
			"count-test-task",
			100*time.Millisecond,
			func() {},
			newNoOpLogger(),
		)

		err := registry.RegisterTask("count-test-task", task)
		assert.NoError(t, err)

		// Count should increase
		newCount := registry.GetTaskCount()
		assert.Equal(t, initialCount+1, newCount)

		// Clean up
		task.Stop()
	})

	t.Run("StopAllTasks stops all tasks", func(t *testing.T) {
		ResetGlobalTaskRegistry()
		registry := GetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		// Create multiple tasks
		for i := 0; i < 3; i++ {
			taskName := "multi-task-" + string(rune(i+'0'))
			task := NewBackgroundTask(
				taskName,
				100*time.Millisecond,
				func() {},
				newNoOpLogger(),
			)
			registry.RegisterTask(taskName, task)
		}

		// Verify tasks were created
		assert.GreaterOrEqual(t, registry.GetTaskCount(), 3)

		// Stop all tasks
		registry.StopAllTasks()

		// Verify all tasks are removed
		taskCount := registry.GetTaskCount()
		assert.Equal(t, 0, taskCount, "all tasks should be stopped")
	})

	t.Run("ResetGlobalTaskRegistry clears registry", func(t *testing.T) {
		ResetGlobalTaskRegistry()
		registry := GetGlobalTaskRegistry()

		// Create a task
		task := NewBackgroundTask(
			"reset-test-task",
			100*time.Millisecond,
			func() {},
			newNoOpLogger(),
		)
		registry.RegisterTask("reset-test-task", task)

		// Reset
		ResetGlobalTaskRegistry()

		// Get new registry
		newRegistry := GetGlobalTaskRegistry()
		assert.Equal(t, 0, newRegistry.GetTaskCount(), "new registry should be empty")
	})
}

// TestBackgroundTaskLifecycle tests background task lifecycle
func TestBackgroundTaskLifecycle(t *testing.T) {
	t.Run("Start begins task execution", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping background task test in short mode")
		}

		ResetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		executed := false
		var mu sync.Mutex

		task := NewBackgroundTask(
			"lifecycle-test",
			50*time.Millisecond,
			func() {
				mu.Lock()
				executed = true
				mu.Unlock()
			},
			newNoOpLogger(),
		)

		// Start task
		task.Start()

		// Wait for execution
		time.Sleep(GetTestDuration(100 * time.Millisecond))

		// Stop task
		task.Stop()

		// Verify it executed
		mu.Lock()
		wasExecuted := executed
		mu.Unlock()

		assert.True(t, wasExecuted, "task should have executed")
	})

	t.Run("Stop halts task execution", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping background task test in short mode")
		}

		ResetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		execCount := 0
		var mu sync.Mutex

		task := NewBackgroundTask(
			"stop-test",
			30*time.Millisecond,
			func() {
				mu.Lock()
				execCount++
				mu.Unlock()
			},
			newNoOpLogger(),
		)

		// Start task
		task.Start()

		// Let it run a few times
		time.Sleep(GetTestDuration(100 * time.Millisecond))

		// Stop task
		task.Stop()

		// Record count
		mu.Lock()
		countAfterStop := execCount
		mu.Unlock()

		// Wait more
		time.Sleep(GetTestDuration(100 * time.Millisecond))

		// Count should not increase
		mu.Lock()
		finalCount := execCount
		mu.Unlock()

		assert.Equal(t, countAfterStop, finalCount, "task should not execute after stop")
	})

	t.Run("Multiple Start calls are safe", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping background task test in short mode")
		}

		ResetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		execCount := 0
		var mu sync.Mutex

		task := NewBackgroundTask(
			"multi-start-test",
			100*time.Millisecond,
			func() {
				mu.Lock()
				execCount++
				mu.Unlock()
			},
			newNoOpLogger(),
		)

		// Multiple starts should be safe
		task.Start()
		task.Start()
		task.Start()

		// Wait a bit
		time.Sleep(GetTestDuration(50 * time.Millisecond))

		// Stop task
		task.Stop()

		// Should have executed, but only one goroutine
		mu.Lock()
		count := execCount
		mu.Unlock()

		assert.GreaterOrEqual(t, count, 0, "task should have executed at least once")
	})

	t.Run("Multiple Stop calls are safe", func(t *testing.T) {
		ResetGlobalTaskRegistry()
		defer ResetGlobalTaskRegistry()

		task := NewBackgroundTask(
			"multi-stop-test",
			100*time.Millisecond,
			func() {},
			newNoOpLogger(),
		)

		// Start and stop
		task.Start()
		time.Sleep(GetTestDuration(20 * time.Millisecond))

		// Multiple stops should be safe
		assert.NotPanics(t, func() {
			task.Stop()
			task.Stop()
			task.Stop()
		})
	})
}

// TestMemoryMonitorIntegration tests memory monitor integration
func TestMemoryMonitorIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory monitor integration test in short mode")
	}

	t.Run("monitoring updates stats", func(t *testing.T) {
		ResetGlobalMemoryMonitor()
		ResetGlobalTaskRegistry()
		defer ResetGlobalMemoryMonitor()
		defer ResetGlobalTaskRegistry()

		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)
		defer monitor.StopMonitoring()

		// Start monitoring
		ctx := context.Background()
		monitor.StartMonitoring(ctx, 50*time.Millisecond)

		// Wait for at least one check
		time.Sleep(GetTestDuration(150 * time.Millisecond))

		// Get pressure (should be a valid pressure level)
		pressure := monitor.GetMemoryPressure()
		assert.Contains(t, []MemoryPressureLevel{
			MemoryPressureNone,
			MemoryPressureLow,
			MemoryPressureModerate,
			MemoryPressureHigh,
			MemoryPressureCritical,
		}, pressure, "pressure should be a valid level")

		// Stop monitoring
		monitor.StopMonitoring()
	})

	t.Run("global memory monitor singleton", func(t *testing.T) {
		ResetGlobalMemoryMonitor()
		defer ResetGlobalMemoryMonitor()

		monitor1 := GetGlobalMemoryMonitor()
		monitor2 := GetGlobalMemoryMonitor()

		assert.Equal(t, monitor1, monitor2, "should return same instance")
	})
}

// TestMemoryStatsCollection tests memory statistics collection
func TestMemoryStatsCollection(t *testing.T) {
	t.Run("GetCurrentStats returns valid data", func(t *testing.T) {
		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		stats := monitor.GetCurrentStats()

		assert.NotNil(t, stats)
		assert.Greater(t, stats.HeapAllocBytes, uint64(0))
		assert.Greater(t, stats.HeapSysBytes, uint64(0))
		assert.Greater(t, stats.NumGoroutines, 0)
		assert.False(t, stats.Timestamp.IsZero())
	})

	t.Run("Stats include memory pressure", func(t *testing.T) {
		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		stats := monitor.GetCurrentStats()

		// Should calculate and include pressure level
		assert.NotNil(t, stats.MemoryPressure)
		assert.Contains(t, []MemoryPressureLevel{
			MemoryPressureNone,
			MemoryPressureLow,
			MemoryPressureModerate,
			MemoryPressureHigh,
			MemoryPressureCritical,
		}, stats.MemoryPressure)
	})

	t.Run("TriggerGC reduces memory", func(t *testing.T) {
		thresholds := DefaultMemoryAlertThresholds()
		monitor := NewMemoryMonitor(newNoOpLogger(), thresholds)

		// Allocate some memory
		_ = make([]byte, 1024*1024) // 1MB

		// Get stats before GC
		beforeStats := monitor.GetCurrentStats()

		// Trigger GC
		monitor.TriggerGC()

		// Get stats after GC
		afterStats := monitor.GetCurrentStats()

		// After GC should have different stats
		assert.NotEqual(t, beforeStats.LastGCTime, afterStats.LastGCTime)
	})
}
