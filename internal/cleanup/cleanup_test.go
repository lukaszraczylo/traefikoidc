//go:build !yaegi

package cleanup

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock logger for testing
type mockLogger struct {
	mu       sync.Mutex
	logs     []string
	errLogs  []string
	debugLog []string
}

func (m *mockLogger) Logf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, format)
}

func (m *mockLogger) ErrorLogf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errLogs = append(m.errLogs, format)
}

func (m *mockLogger) DebugLogf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLog = append(m.debugLog, format)
}

func (m *mockLogger) getLogCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.logs)
}

// BackgroundTask tests
func TestNewBackgroundTask(t *testing.T) {
	logger := &mockLogger{}
	var wg sync.WaitGroup
	runCount := 0

	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {
		runCount++
	}, logger, &wg)

	if task == nil {
		t.Fatal("Expected NewBackgroundTask to return non-nil")
	}

	if task.name != "test-task" {
		t.Errorf("Expected name 'test-task', got '%s'", task.name)
	}

	if task.interval != 100*time.Millisecond {
		t.Errorf("Expected interval 100ms, got %v", task.interval)
	}

	if task.IsRunning() {
		t.Error("Expected task to not be running initially")
	}
}

func TestBackgroundTask_Start(t *testing.T) {
	logger := &mockLogger{}
	runCount := int32(0)

	task := NewBackgroundTask("test-task", 50*time.Millisecond, func() {
		atomic.AddInt32(&runCount, 1)
	}, logger)

	task.Start()

	if !task.IsRunning() {
		t.Error("Expected task to be running after Start()")
	}

	// Wait for at least 2 executions
	time.Sleep(120 * time.Millisecond)

	task.Stop()

	count := atomic.LoadInt32(&runCount)
	if count < 2 {
		t.Errorf("Expected at least 2 executions, got %d", count)
	}
}

func TestBackgroundTask_Stop(t *testing.T) {
	logger := &mockLogger{}
	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)

	task.Start()
	time.Sleep(50 * time.Millisecond)
	task.Stop()

	if task.IsRunning() {
		t.Error("Expected task to not be running after Stop()")
	}

	// Calling Stop again should not panic
	task.Stop()
}

func TestBackgroundTask_DoubleStart(t *testing.T) {
	logger := &mockLogger{}
	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)

	task.Start()
	logCountBefore := logger.getLogCount()

	// Second start should be ignored
	task.Start()

	logCountAfter := logger.getLogCount()
	if logCountAfter <= logCountBefore {
		t.Error("Expected log message about task already running")
	}

	task.Stop()
}

func TestBackgroundTask_ExecuteWithPanic(t *testing.T) {
	logger := &mockLogger{}
	panicCount := int32(0)

	task := NewBackgroundTask("panic-task", 50*time.Millisecond, func() {
		count := atomic.AddInt32(&panicCount, 1)
		if count == 1 {
			panic("test panic")
		}
	}, logger)

	task.Start()
	time.Sleep(120 * time.Millisecond)
	task.Stop()

	// Task should recover from panic and continue
	finalCount := atomic.LoadInt32(&panicCount)
	if finalCount < 2 {
		t.Errorf("Expected task to continue after panic, got %d executions", finalCount)
	}

	stats := task.GetStats()
	if stats["errorCount"].(int64) < 1 {
		t.Error("Expected error count to be at least 1")
	}
}

func TestBackgroundTask_GetStats(t *testing.T) {
	logger := &mockLogger{}
	runCount := int32(0)

	task := NewBackgroundTask("test-task", 50*time.Millisecond, func() {
		atomic.AddInt32(&runCount, 1)
	}, logger)

	task.Start()
	time.Sleep(120 * time.Millisecond)
	task.Stop()

	stats := task.GetStats()

	if stats["name"] != "test-task" {
		t.Errorf("Expected name 'test-task', got %v", stats["name"])
	}

	if !stats["isRunning"].(bool) == true {
		// Task should be stopped
	}

	if stats["runCount"].(int64) < 2 {
		t.Errorf("Expected runCount >= 2, got %v", stats["runCount"])
	}
}

func TestBackgroundTask_WithWaitGroup(t *testing.T) {
	logger := &mockLogger{}
	var wg sync.WaitGroup
	runCount := int32(0)

	task := NewBackgroundTask("test-task", 50*time.Millisecond, func() {
		atomic.AddInt32(&runCount, 1)
	}, logger, &wg)

	task.Start()

	// Wait for task to start
	time.Sleep(100 * time.Millisecond)

	// Stop and wait
	done := make(chan bool)
	go func() {
		task.Stop()
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for task to stop")
	}
}

// TaskRegistry tests
func TestNewTaskRegistry(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	if registry == nil {
		t.Fatal("Expected NewTaskRegistry to return non-nil")
	}

	if registry.maxTasks != 10 {
		t.Errorf("Expected maxTasks 10, got %d", registry.maxTasks)
	}

	if registry.GetTaskCount() != 0 {
		t.Error("Expected initial task count to be 0")
	}
}

func TestTaskRegistry_RegisterTask(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	err := registry.RegisterTask("test-task", task)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if registry.GetTaskCount() != 1 {
		t.Error("Expected task count to be 1")
	}
}

func TestTaskRegistry_RegisterTask_Duplicate(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task1 := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	task2 := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)

	err1 := registry.RegisterTask("test-task", task1)
	if err1 != nil {
		t.Errorf("Expected no error on first registration, got %v", err1)
	}

	err2 := registry.RegisterTask("test-task", task2)
	if err2 == nil {
		t.Error("Expected error when registering duplicate task")
	}
}

func TestTaskRegistry_RegisterTask_Nil(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	err := registry.RegisterTask("test-task", nil)
	if err == nil {
		t.Error("Expected error when registering nil task")
	}
}

func TestTaskRegistry_RegisterTask_MaxLimit(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 2)

	task1 := NewBackgroundTask("task1", 100*time.Millisecond, func() {}, logger)
	task2 := NewBackgroundTask("task2", 100*time.Millisecond, func() {}, logger)
	task3 := NewBackgroundTask("task3", 100*time.Millisecond, func() {}, logger)

	registry.RegisterTask("task1", task1)
	registry.RegisterTask("task2", task2)
	err := registry.RegisterTask("task3", task3)

	if err == nil {
		t.Error("Expected error when exceeding max tasks")
	}
}

func TestTaskRegistry_UnregisterTask(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	registry.RegisterTask("test-task", task)

	if registry.GetTaskCount() != 1 {
		t.Error("Expected task count to be 1")
	}

	registry.UnregisterTask("test-task")

	if registry.GetTaskCount() != 0 {
		t.Error("Expected task count to be 0 after unregister")
	}
}

func TestTaskRegistry_UnregisterTask_Running(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	registry.RegisterTask("test-task", task)
	task.Start()

	time.Sleep(50 * time.Millisecond)

	registry.UnregisterTask("test-task")

	if task.IsRunning() {
		t.Error("Expected task to be stopped after unregister")
	}
}

func TestTaskRegistry_GetTask(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	registry.RegisterTask("test-task", task)

	retrieved, exists := registry.GetTask("test-task")
	if !exists {
		t.Error("Expected task to exist")
	}

	if retrieved != task {
		t.Error("Expected to retrieve the same task")
	}

	_, exists = registry.GetTask("non-existent")
	if exists {
		t.Error("Expected non-existent task to not exist")
	}
}

func TestTaskRegistry_StopAllTasks(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task1 := NewBackgroundTask("task1", 100*time.Millisecond, func() {}, logger)
	task2 := NewBackgroundTask("task2", 100*time.Millisecond, func() {}, logger)

	registry.RegisterTask("task1", task1)
	registry.RegisterTask("task2", task2)

	task1.Start()
	task2.Start()

	time.Sleep(50 * time.Millisecond)

	registry.StopAllTasks()

	if task1.IsRunning() || task2.IsRunning() {
		t.Error("Expected all tasks to be stopped")
	}

	if registry.GetTaskCount() != 0 {
		t.Error("Expected task count to be 0 after StopAllTasks")
	}
}

func TestTaskRegistry_CreateSingletonTask(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	runCount := int32(0)
	task1, err1 := registry.CreateSingletonTask("singleton", 50*time.Millisecond, func() {
		atomic.AddInt32(&runCount, 1)
	}, logger)

	if err1 != nil {
		t.Errorf("Expected no error, got %v", err1)
	}

	if task1 == nil {
		t.Fatal("Expected task to be created")
	}

	if !task1.IsRunning() {
		t.Error("Expected task to be running")
	}

	// Try to create same task again
	task2, err2 := registry.CreateSingletonTask("singleton", 50*time.Millisecond, func() {
		atomic.AddInt32(&runCount, 1)
	}, logger)

	if err2 != nil {
		t.Errorf("Expected no error on second call, got %v", err2)
	}

	if task2 != task1 {
		t.Error("Expected to get the same task instance")
	}

	time.Sleep(120 * time.Millisecond)
	task1.Stop()

	if atomic.LoadInt32(&runCount) < 2 {
		t.Error("Expected task to have run multiple times")
	}
}

func TestTaskRegistry_GetAllTasks(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task1 := NewBackgroundTask("task1", 100*time.Millisecond, func() {}, logger)
	task2 := NewBackgroundTask("task2", 100*time.Millisecond, func() {}, logger)

	registry.RegisterTask("task1", task1)
	registry.RegisterTask("task2", task2)

	allTasks := registry.GetAllTasks()

	if len(allTasks) != 2 {
		t.Errorf("Expected 2 tasks, got %d", len(allTasks))
	}

	if _, ok := allTasks["task1"]; !ok {
		t.Error("Expected task1 in results")
	}

	if _, ok := allTasks["task2"]; !ok {
		t.Error("Expected task2 in results")
	}
}

func TestTaskRegistry_GetStats(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)

	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	registry.RegisterTask("test-task", task)
	task.Start()

	time.Sleep(50 * time.Millisecond)

	stats := registry.GetStats()

	if stats["totalTasks"].(int) != 1 {
		t.Errorf("Expected totalTasks 1, got %v", stats["totalTasks"])
	}

	if stats["runningTasks"].(int) != 1 {
		t.Errorf("Expected runningTasks 1, got %v", stats["runningTasks"])
	}

	if _, ok := stats["memory"]; !ok {
		t.Error("Expected memory stats")
	}

	task.Stop()
}

func TestGlobalTaskRegistry(t *testing.T) {
	// Reset before test
	ResetGlobalTaskRegistry()

	registry1 := GetGlobalTaskRegistry()
	registry2 := GetGlobalTaskRegistry()

	if registry1 != registry2 {
		t.Error("Expected singleton to return same instance")
	}

	// Cleanup
	ResetGlobalTaskRegistry()
}

func TestResetGlobalTaskRegistry(t *testing.T) {
	ResetGlobalTaskRegistry()

	registry := GetGlobalTaskRegistry()
	logger := &mockLogger{}
	task := NewBackgroundTask("test-task", 100*time.Millisecond, func() {}, logger)
	registry.RegisterTask("test-task", task)
	task.Start()

	time.Sleep(50 * time.Millisecond)

	ResetGlobalTaskRegistry()

	// Should get a new instance
	newRegistry := GetGlobalTaskRegistry()
	if newRegistry.GetTaskCount() != 0 {
		t.Error("Expected new registry to be empty")
	}
}

// TaskCircuitBreaker tests
func TestNewTaskCircuitBreaker(t *testing.T) {
	logger := &mockLogger{}
	cb := NewTaskCircuitBreaker(5, 30*time.Second, logger)

	if cb == nil {
		t.Fatal("Expected NewTaskCircuitBreaker to return non-nil")
	}

	if cb.failureThreshold != 5 {
		t.Errorf("Expected failureThreshold 5, got %d", cb.failureThreshold)
	}

	if cb.timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", cb.timeout)
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Expected initial state to be closed")
	}
}

func TestTaskCircuitBreaker_CanCreateTask(t *testing.T) {
	logger := &mockLogger{}
	cb := NewTaskCircuitBreaker(3, 100*time.Millisecond, logger)

	err := cb.CanCreateTask("test-task")
	if err != nil {
		t.Errorf("Expected no error initially, got %v", err)
	}
}

func TestTaskCircuitBreaker_OnTaskFailure(t *testing.T) {
	logger := &mockLogger{}
	cb := NewTaskCircuitBreaker(3, 100*time.Millisecond, logger)

	// Record failures
	for i := 0; i < 3; i++ {
		cb.OnTaskFailure("test-task", nil)
	}

	// Circuit should be open
	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Expected circuit breaker to be open after threshold failures")
	}

	// Should not be able to create task
	err := cb.CanCreateTask("test-task")
	if err == nil {
		t.Error("Expected error when circuit breaker is open")
	}
}

func TestTaskCircuitBreaker_OnTaskSuccess(t *testing.T) {
	logger := &mockLogger{}
	cb := NewTaskCircuitBreaker(5, 100*time.Millisecond, logger)

	cb.OnTaskFailure("test-task", nil)
	cb.OnTaskFailure("test-task", nil)

	cb.OnTaskSuccess("test-task")

	// Task-specific failures should be reset
	err := cb.CanCreateTask("test-task")
	if err != nil {
		t.Errorf("Expected no error after success, got %v", err)
	}
}

func TestTaskCircuitBreaker_Reset(t *testing.T) {
	logger := &mockLogger{}
	cb := NewTaskCircuitBreaker(2, 100*time.Millisecond, logger)

	cb.OnTaskFailure("test-task", nil)
	cb.OnTaskFailure("test-task", nil)

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Expected circuit breaker to be open")
	}

	cb.Reset()

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Expected circuit breaker to be closed after reset")
	}

	err := cb.CanCreateTask("test-task")
	if err != nil {
		t.Errorf("Expected no error after reset, got %v", err)
	}
}

func TestTaskCircuitBreaker_TimeoutRecovery(t *testing.T) {
	logger := &mockLogger{}
	cb := NewTaskCircuitBreaker(2, 100*time.Millisecond, logger)

	// Open circuit breaker
	cb.OnTaskFailure("test-task", nil)
	cb.OnTaskFailure("test-task", nil)

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Expected circuit breaker to be open")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Circuit breaker should reset, but task-specific failures remain
	// Need to check with a different task name
	err := cb.CanCreateTask("different-task")
	if err != nil {
		t.Errorf("Expected no error for different task after timeout, got %v", err)
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Expected circuit breaker to be closed after timeout")
	}

	// Original task still has too many failures
	err = cb.CanCreateTask("test-task")
	if err == nil {
		t.Error("Expected error for original task with too many failures")
	}
}

// TaskMemoryMonitor tests
func TestNewTaskMemoryMonitor(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)
	monitor := NewTaskMemoryMonitor(logger, registry)

	if monitor == nil {
		t.Fatal("Expected NewTaskMemoryMonitor to return non-nil")
	}

	if monitor.registry != registry {
		t.Error("Expected registry to be set")
	}

	if monitor.memoryThreshold != 1024*1024*1024 {
		t.Errorf("Expected default threshold 1GB, got %d", monitor.memoryThreshold)
	}
}

func TestTaskMemoryMonitor_SetMemoryThreshold(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)
	monitor := NewTaskMemoryMonitor(logger, registry)

	monitor.SetMemoryThreshold(512 * 1024 * 1024)

	stats := monitor.GetStats()
	if stats["memoryThreshold"].(uint64) != 512*1024*1024 {
		t.Error("Expected threshold to be updated")
	}
}

func TestTaskMemoryMonitor_StartStop(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)
	monitor := NewTaskMemoryMonitor(logger, registry)

	monitor.StartMonitoring()

	stats := monitor.GetStats()
	if !stats["isMonitoring"].(bool) {
		t.Error("Expected monitor to be running")
	}

	// Double start should be ignored
	monitor.StartMonitoring()

	monitor.StopMonitoring()

	stats = monitor.GetStats()
	if stats["isMonitoring"].(bool) {
		t.Error("Expected monitor to be stopped")
	}

	// Double stop should be safe
	monitor.StopMonitoring()
}

func TestTaskMemoryMonitor_GetStats(t *testing.T) {
	logger := &mockLogger{}
	registry := NewTaskRegistry(logger, 10)
	monitor := NewTaskMemoryMonitor(logger, registry)

	stats := monitor.GetStats()

	if _, ok := stats["isMonitoring"]; !ok {
		t.Error("Expected isMonitoring in stats")
	}

	if _, ok := stats["currentMemory"]; !ok {
		t.Error("Expected currentMemory in stats")
	}

	if _, ok := stats["memoryThreshold"]; !ok {
		t.Error("Expected memoryThreshold in stats")
	}
}

// WorkerPool tests
func TestNewWorkerPool(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(4, 10, logger)

	if pool == nil {
		t.Fatal("Expected NewWorkerPool to return non-nil")
	}

	if pool.workers != 4 {
		t.Errorf("Expected 4 workers, got %d", pool.workers)
	}
}

func TestWorkerPool_DefaultWorkers(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(0, 0, logger)

	// Should default to NumCPU
	if pool.workers <= 0 {
		t.Error("Expected positive number of workers")
	}
}

func TestWorkerPool_StartStop(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(2, 5, logger)

	pool.Start()

	metrics := pool.GetMetrics()
	if !metrics["isRunning"].(bool) {
		t.Error("Expected worker pool to be running")
	}

	// Double start should be ignored
	pool.Start()

	pool.Stop()

	metrics = pool.GetMetrics()
	if metrics["isRunning"].(bool) {
		t.Error("Expected worker pool to be stopped")
	}

	// Double stop should be safe
	pool.Stop()
}

func TestWorkerPool_Submit(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(2, 5, logger)

	pool.Start()
	defer pool.Stop()

	executed := int32(0)
	var wg sync.WaitGroup

	for i := 0; i < 3; i++ {
		wg.Add(1)
		err := pool.Submit(func() {
			defer wg.Done()
			atomic.AddInt32(&executed, 1)
		})

		if err != nil {
			t.Errorf("Expected no error submitting task, got %v", err)
		}
	}

	// Wait for tasks to complete
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for tasks to complete")
	}

	if atomic.LoadInt32(&executed) != 3 {
		t.Errorf("Expected 3 tasks executed, got %d", atomic.LoadInt32(&executed))
	}
}

func TestWorkerPool_SubmitWhenStopped(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(2, 5, logger)

	err := pool.Submit(func() {})
	if err == nil {
		t.Error("Expected error when submitting to stopped pool")
	}
}

func TestWorkerPool_TaskPanic(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(2, 5, logger)

	pool.Start()
	defer pool.Stop()

	executed := int32(0)
	var wg sync.WaitGroup

	wg.Add(2)
	// Submit task that panics
	pool.Submit(func() {
		defer wg.Done()
		panic("test panic")
	})

	// Submit normal task
	pool.Submit(func() {
		defer wg.Done()
		atomic.AddInt32(&executed, 1)
	})

	// Wait for tasks
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for tasks")
	}

	// Pool should still be functional
	metrics := pool.GetMetrics()
	if metrics["tasksFailed"].(int64) < 1 {
		t.Error("Expected at least one failed task")
	}
}

func TestWorkerPool_GetMetrics(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(2, 5, logger)

	pool.Start()
	defer pool.Stop()

	var wg sync.WaitGroup
	wg.Add(2)

	pool.Submit(func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
	})

	pool.Submit(func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond)
	})

	wg.Wait()

	metrics := pool.GetMetrics()

	if metrics["workers"].(int) != 2 {
		t.Errorf("Expected 2 workers, got %v", metrics["workers"])
	}

	if metrics["tasksProcessed"].(int64) != 2 {
		t.Errorf("Expected 2 processed tasks, got %v", metrics["tasksProcessed"])
	}

	if metrics["tasksQueued"].(int64) != 2 {
		t.Errorf("Expected 2 queued tasks, got %v", metrics["tasksQueued"])
	}
}

func TestWorkerPool_Concurrent(t *testing.T) {
	logger := &mockLogger{}
	pool := NewWorkerPool(4, 20, logger)

	pool.Start()
	defer pool.Stop()

	executed := int32(0)
	var wg sync.WaitGroup

	taskCount := 10
	for i := 0; i < taskCount; i++ {
		wg.Add(1)
		err := pool.Submit(func() {
			defer wg.Done()
			atomic.AddInt32(&executed, 1)
			time.Sleep(10 * time.Millisecond)
		})

		if err != nil {
			wg.Done()
			t.Errorf("Failed to submit task: %v", err)
		}
	}

	// Wait for all tasks
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for concurrent tasks")
	}

	if atomic.LoadInt32(&executed) != int32(taskCount) {
		t.Errorf("Expected %d tasks executed, got %d", taskCount, atomic.LoadInt32(&executed))
	}
}
