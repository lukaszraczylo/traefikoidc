package traefikoidc

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMemoryMonitorSingleton(t *testing.T) {
	// Use proper cleanup helper
	TestCleanupHelper(t)

	// Reset global state before test
	ResetGlobalTaskRegistry()
	ResetGlobalMemoryMonitor()

	// Clear task registry for clean test
	registry := GetGlobalTaskRegistry()
	registry.StopAllTasks()

	// Add cleanup at the end of test
	defer func() {
		ResetGlobalMemoryMonitor()
		ResetGlobalTaskRegistry()
	}()

	// Test that multiple StartMonitoring calls don't create multiple monitors
	monitor := GetGlobalMemoryMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	goroutinesBefore := runtime.NumGoroutine()

	// Call StartMonitoring multiple times (simulating multiple middleware instances)
	var wg sync.WaitGroup
	numCalls := 10

	for i := 0; i < numCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitor.StartMonitoring(ctx, 100*time.Millisecond)
		}()
	}

	wg.Wait()

	// Give some time for goroutines to start
	time.Sleep(50 * time.Millisecond)

	goroutinesAfter := runtime.NumGoroutine()

	// Should only create one additional goroutine for the singleton task
	goroutineDiff := goroutinesAfter - goroutinesBefore
	if goroutineDiff > 2 { // Allow some tolerance for test runner goroutines
		t.Errorf("Expected at most 2 additional goroutines, got %d", goroutineDiff)
	}

	// Check that monitoring is active
	if !monitor.IsMonitoringActive() {
		t.Error("Memory monitoring should be active")
	}

	// Verify only one task is registered
	taskCount := registry.GetTaskCount()
	if taskCount != 1 {
		t.Errorf("Expected 1 task, got %d", taskCount)
	}

	// Check that the task is specifically memory-monitor
	if task, exists := registry.GetTask("memory-monitor"); !exists {
		t.Error("memory-monitor task should exist")
	} else if task == nil {
		t.Error("memory-monitor task should not be nil")
	}

	// Stop monitoring
	monitor.StopMonitoring()

	// Verify monitoring is no longer active
	if monitor.IsMonitoringActive() {
		t.Error("Memory monitoring should be inactive after stopping")
	}

	// Clean up
	registry.StopAllTasks()
}

func TestMemoryMonitorSingletonTaskCreation(t *testing.T) {
	// Use proper cleanup helper
	TestCleanupHelper(t)

	// Reset global state before test
	ResetGlobalTaskRegistry()
	ResetGlobalMemoryMonitor()

	registry := GetGlobalTaskRegistry()
	registry.StopAllTasks()

	// Add cleanup at the end of test
	defer func() {
		ResetGlobalMemoryMonitor()
		ResetGlobalTaskRegistry()
	}()

	monitor1 := GetGlobalMemoryMonitor()
	monitor2 := GetGlobalMemoryMonitor()

	// Should be the same instance
	if monitor1 != monitor2 {
		t.Error("GetGlobalMemoryMonitor should return the same instance")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First start should succeed
	monitor1.StartMonitoring(ctx, 50*time.Millisecond)

	if !monitor1.IsMonitoringActive() {
		t.Error("First StartMonitoring should activate monitoring")
	}

	// Second start should be skipped
	monitor2.StartMonitoring(ctx, 50*time.Millisecond)

	// Should still only have one task
	taskCount := registry.GetTaskCount()
	if taskCount != 1 {
		t.Errorf("Expected 1 task after duplicate start, got %d", taskCount)
	}

	// Clean up
	monitor1.StopMonitoring()
	registry.StopAllTasks()
}

func TestMemoryMonitorTaskRegistryEnforcement(t *testing.T) {
	// Use proper cleanup helper
	TestCleanupHelper(t)

	// Reset global state before test
	ResetGlobalTaskRegistry()
	ResetGlobalMemoryMonitor()

	registry := GetGlobalTaskRegistry()
	registry.StopAllTasks()

	// Add cleanup at the end of test
	defer func() {
		ResetGlobalMemoryMonitor()
		ResetGlobalTaskRegistry()
	}()

	// Try to create memory-monitor task directly through registry
	task1, err1 := registry.CreateSingletonTask("memory-monitor", 50*time.Millisecond,
		func() {}, GetSingletonNoOpLogger(), nil)

	if err1 != nil {
		t.Fatalf("First memory-monitor task creation should succeed: %v", err1)
	}

	// Try to create another memory-monitor task - should fail
	task2, err2 := registry.CreateSingletonTask("memory-monitor-2", 50*time.Millisecond,
		func() {}, GetSingletonNoOpLogger(), nil)

	if err2 == nil {
		t.Error("Second memory-monitor task creation should fail due to singleton enforcement")
		if task2 != nil {
			task2.Stop()
		}
	}

	// Clean up
	if task1 != nil {
		task1.Stop()
	}
	registry.StopAllTasks()
}
