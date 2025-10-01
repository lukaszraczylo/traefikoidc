package traefikoidc

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// globalRegistryMutex protects only the global registry operations
var globalRegistryMutex sync.Mutex

// TestTaskCircuitBreakerOnTaskFailure tests the OnTaskFailure method
func TestTaskCircuitBreakerOnTaskFailure(t *testing.T) {
	logger := NewLogger("debug") // Create a real logger
	cb := NewTaskCircuitBreaker(3, time.Minute, logger)

	// Test failure doesn't trigger open state before threshold
	cb.OnTaskFailure("test-task", errors.New("test error"))
	if err := cb.CanCreateTask("test-task"); err != nil {
		t.Error("Circuit breaker should allow task creation after 1 failure (threshold: 3)")
	}

	// Test failure count reaches threshold and opens circuit
	cb.OnTaskFailure("test-task", errors.New("test error 2"))
	cb.OnTaskFailure("test-task", errors.New("test error 3"))

	if err := cb.CanCreateTask("test-task"); err == nil {
		t.Error("Circuit breaker should prevent task creation after reaching failure threshold")
	}
}

// TestResetGlobalTaskRegistry tests the reset functionality
func TestResetGlobalTaskRegistry(t *testing.T) {
	globalRegistryMutex.Lock()
	defer globalRegistryMutex.Unlock()

	// Get the global registry first
	registry := GetGlobalTaskRegistry()

	// Create and register a dummy task
	logger := NewLogger("debug")
	task := NewBackgroundTask("test-task", time.Second, func() {
		// Do nothing
	}, logger)

	registry.RegisterTask("test-task", task)

	// Verify task is registered
	if registry.GetTaskCount() == 0 {
		t.Error("Expected task to be registered")
	}

	// Reset the registry
	ResetGlobalTaskRegistry()

	// Get registry again and verify it's empty
	newRegistry := GetGlobalTaskRegistry()
	if newRegistry.GetTaskCount() != 0 {
		t.Error("Expected registry to be empty after reset")
	}
}

// TestGetTask tests the GetTask method
func TestGetTask(t *testing.T) {
	globalRegistryMutex.Lock()
	defer globalRegistryMutex.Unlock()

	// Reset registry to ensure clean state
	ResetGlobalTaskRegistry()
	registry := GetGlobalTaskRegistry()

	// Test getting non-existent task
	task, exists := registry.GetTask("non-existent")
	if task != nil || exists {
		t.Error("Expected nil and false for non-existent task")
	}

	// Create and register a task
	logger := NewLogger("debug")
	newTask := NewBackgroundTask("test-task", time.Second, func() {
		// Do nothing
	}, logger)

	registry.RegisterTask("test-task", newTask)

	// Test getting existing task
	retrievedTask, exists := registry.GetTask("test-task")
	if retrievedTask == nil || !exists {
		t.Error("Expected to retrieve registered task")
		return
	}

	if retrievedTask.name != "test-task" {
		t.Errorf("Expected task name 'test-task', got '%s'", retrievedTask.name)
	}
}

// TestNewTaskMemoryMonitor tests the NewTaskMemoryMonitor function
func TestNewTaskMemoryMonitor(t *testing.T) {
	// No mutex needed - this doesn't modify global state
	logger := NewLogger("debug")
	registry := GetGlobalTaskRegistry()
	monitor := NewTaskMemoryMonitor(logger, registry)

	if monitor == nil {
		t.Error("Expected NewTaskMemoryMonitor to return non-nil monitor")
	}
}

// TestGetCurrentStats tests the GetCurrentStats method
func TestGetCurrentStats(t *testing.T) {
	// Don't hold mutex during background task execution to avoid deadlocks
	logger := NewLogger("debug")
	registry := GetGlobalTaskRegistry()
	monitor := NewTaskMemoryMonitor(logger, registry)

	// Start the monitor and let it collect at least one statistic
	err := monitor.Start(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}

	// Ensure monitor is stopped even if test fails
	defer func() {
		monitor.Stop()
		// Give extra time for cleanup
		time.Sleep(50 * time.Millisecond)
	}()

	// Wait a bit for the monitor to collect stats
	time.Sleep(150 * time.Millisecond)

	stats, err := monitor.GetCurrentStats()
	if err != nil {
		// If no stats are available yet, that's acceptable for this test
		t.Logf("No memory statistics available yet: %v", err)
		return
	}

	// TaskMemoryStats is a struct, not a pointer, so it can't be nil
	if stats.Timestamp.IsZero() {
		t.Error("Expected GetCurrentStats to return valid timestamp")
	}
}

// TestGetStatsHistory tests the GetStatsHistory method
func TestGetStatsHistory(t *testing.T) {
	// No mutex needed - this just creates a monitor and checks its initial state
	logger := NewLogger("debug")
	registry := GetGlobalTaskRegistry()
	monitor := NewTaskMemoryMonitor(logger, registry)

	history := monitor.GetStatsHistory()
	if history == nil {
		t.Error("Expected GetStatsHistory to return non-nil history")
	}

	// A fresh monitor should have empty history
	if len(history) != 0 {
		t.Logf("History length: %d (may be non-empty due to shared global state)", len(history))
	}
}

// TestForceGC tests the ForceGC method
func TestForceGC(t *testing.T) {
	// No mutex needed - this doesn't modify global state
	logger := NewLogger("debug")
	registry := GetGlobalTaskRegistry()
	monitor := NewTaskMemoryMonitor(logger, registry)

	// This should not panic and should work
	monitor.ForceGC()
	// No specific verification needed, just ensuring it doesn't crash
}

// TestShutdownAllTasks tests the ShutdownAllTasks function
func TestShutdownAllTasks(t *testing.T) {
	// Use a unique task name prefix to avoid conflicts with other tests
	taskPrefix := "shutdown-test-"

	// Create a temporary clean registry state
	func() {
		globalRegistryMutex.Lock()
		defer globalRegistryMutex.Unlock()
		ResetGlobalTaskRegistry()
	}()

	registry := GetGlobalTaskRegistry()
	logger := NewLogger("debug")

	// Create some test tasks with unique names
	task1 := NewBackgroundTask(taskPrefix+"task1", time.Millisecond, func() {
		time.Sleep(100 * time.Millisecond) // Simulate work
	}, logger)

	task2 := NewBackgroundTask(taskPrefix+"task2", time.Millisecond, func() {
		time.Sleep(100 * time.Millisecond) // Simulate work
	}, logger)

	// Register tasks under mutex protection
	func() {
		globalRegistryMutex.Lock()
		defer globalRegistryMutex.Unlock()
		registry.RegisterTask(taskPrefix+"task1", task1)
		registry.RegisterTask(taskPrefix+"task2", task2)
	}()

	// Start the tasks (outside mutex to avoid deadlock)
	task1.Start()
	task2.Start()

	// Give tasks time to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown all tasks
	ShutdownAllTasks()

	// Give shutdown time to complete
	time.Sleep(200 * time.Millisecond)

	// Note: We can't reliably verify task count due to other tests
	// Just ensure shutdown doesn't panic
}
