// Package cleanup provides background task management and cleanup functionality.
package cleanup

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// TaskCircuitBreaker prevents task creation failures from cascading
type TaskCircuitBreaker struct {
	lastFailureTime  time.Time
	logger           Logger
	taskFailures     map[string]int32
	timeout          time.Duration
	mu               sync.RWMutex
	failureThreshold int32
	failureCount     int32
	state            int32
}

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int32

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
)

// NewTaskCircuitBreaker creates a new circuit breaker for task management
func NewTaskCircuitBreaker(failureThreshold int32, timeout time.Duration, logger Logger) *TaskCircuitBreaker {
	return &TaskCircuitBreaker{
		failureThreshold: failureThreshold,
		timeout:          timeout,
		logger:           logger,
		taskFailures:     make(map[string]int32),
	}
}

// CanCreateTask checks if a new task can be created
func (cb *TaskCircuitBreaker) CanCreateTask(taskName string) error {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Check circuit breaker state
	if atomic.LoadInt32(&cb.state) == int32(CircuitBreakerOpen) {
		// Check if timeout has elapsed
		if time.Since(cb.lastFailureTime) < cb.timeout {
			return fmt.Errorf("circuit breaker open: too many task failures")
		}
		// Reset circuit breaker
		atomic.StoreInt32(&cb.state, int32(CircuitBreakerClosed))
		atomic.StoreInt32(&cb.failureCount, 0)
		if cb.logger != nil {
			cb.logger.Logf("Circuit breaker reset after timeout")
		}
	}

	// Check task-specific failures
	if failures, exists := cb.taskFailures[taskName]; exists {
		if failures >= cb.failureThreshold {
			return fmt.Errorf("task %s has too many failures (%d)", taskName, failures)
		}
	}

	return nil
}

// OnTaskStart records that a task has started
func (cb *TaskCircuitBreaker) OnTaskStart(taskName string) {
	// Currently just for tracking, could add rate limiting here
	if cb.logger != nil {
		cb.logger.DebugLogf("Task %s started", taskName)
	}
}

// OnTaskComplete records that a task completed (success or failure)
func (cb *TaskCircuitBreaker) OnTaskComplete(taskName string) {
	// Currently just for tracking
	if cb.logger != nil {
		cb.logger.DebugLogf("Task %s completed", taskName)
	}
}

// OnTaskSuccess records a successful task execution
func (cb *TaskCircuitBreaker) OnTaskSuccess(taskName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Reset task-specific failure count on success
	delete(cb.taskFailures, taskName)
}

// OnTaskFailure records a task failure
func (cb *TaskCircuitBreaker) OnTaskFailure(taskName string, err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Increment task-specific failure count
	cb.taskFailures[taskName]++

	// Increment overall failure count
	failures := atomic.AddInt32(&cb.failureCount, 1)
	cb.lastFailureTime = time.Now()

	if cb.logger != nil {
		cb.logger.ErrorLogf("Task %s failed: %v (failure count: %d)", taskName, err, cb.taskFailures[taskName])
	}

	// Open circuit breaker if threshold reached
	if failures >= cb.failureThreshold {
		atomic.StoreInt32(&cb.state, int32(CircuitBreakerOpen))
		if cb.logger != nil {
			cb.logger.ErrorLogf("Circuit breaker opened due to %d failures", failures)
		}
	}
}

// Reset resets the circuit breaker
func (cb *TaskCircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	atomic.StoreInt32(&cb.state, int32(CircuitBreakerClosed))
	atomic.StoreInt32(&cb.failureCount, 0)
	cb.taskFailures = make(map[string]int32)
	cb.lastFailureTime = time.Time{}

	if cb.logger != nil {
		cb.logger.Logf("Circuit breaker reset")
	}
}

// GetState returns the current state of the circuit breaker
func (cb *TaskCircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(atomic.LoadInt32(&cb.state))
}

// TaskMemoryMonitor monitors memory usage and can trigger cleanup
type TaskMemoryMonitor struct {
	lastCheck       time.Time
	logger          Logger
	registry        *TaskRegistry
	stopChan        chan bool
	memoryThreshold uint64
	checkInterval   time.Duration
	mu              sync.RWMutex
	isMonitoring    int32
}

var (
	globalMemoryMonitor *TaskMemoryMonitor
	monitorOnce         sync.Once
)

// GetGlobalTaskMemoryMonitor returns the global memory monitor singleton
func GetGlobalTaskMemoryMonitor(logger Logger) *TaskMemoryMonitor {
	monitorOnce.Do(func() {
		globalMemoryMonitor = NewTaskMemoryMonitor(logger, GetGlobalTaskRegistry())
	})
	return globalMemoryMonitor
}

// NewTaskMemoryMonitor creates a new memory monitor
func NewTaskMemoryMonitor(logger Logger, registry *TaskRegistry) *TaskMemoryMonitor {
	return &TaskMemoryMonitor{
		logger:          logger,
		registry:        registry,
		memoryThreshold: 1024 * 1024 * 1024, // 1GB default
		checkInterval:   1 * time.Minute,
		stopChan:        make(chan bool, 1),
	}
}

// SetMemoryThreshold sets the memory threshold for triggering cleanup
func (tmm *TaskMemoryMonitor) SetMemoryThreshold(bytes uint64) {
	tmm.mu.Lock()
	defer tmm.mu.Unlock()
	tmm.memoryThreshold = bytes
}

// StartMonitoring starts the memory monitoring routine
func (tmm *TaskMemoryMonitor) StartMonitoring() {
	if !atomic.CompareAndSwapInt32(&tmm.isMonitoring, 0, 1) {
		if tmm.logger != nil {
			tmm.logger.Logf("Memory monitor is already running")
		}
		return
	}

	go tmm.monitorLoop()

	if tmm.logger != nil {
		tmm.logger.Logf("Started memory monitoring (threshold: %d bytes, interval: %v)",
			tmm.memoryThreshold, tmm.checkInterval)
	}
}

// StopMonitoring stops the memory monitoring routine
func (tmm *TaskMemoryMonitor) StopMonitoring() {
	if !atomic.CompareAndSwapInt32(&tmm.isMonitoring, 1, 0) {
		if tmm.logger != nil {
			tmm.logger.Logf("Memory monitor is not running")
		}
		return
	}

	select {
	case tmm.stopChan <- true:
	case <-time.After(5 * time.Second):
		if tmm.logger != nil {
			tmm.logger.ErrorLogf("Timeout stopping memory monitor")
		}
	}

	if tmm.logger != nil {
		tmm.logger.Logf("Stopped memory monitoring")
	}
}

// monitorLoop is the main monitoring loop
func (tmm *TaskMemoryMonitor) monitorLoop() {
	ticker := time.NewTicker(tmm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tmm.checkMemory()
		case <-tmm.stopChan:
			return
		}
	}
}

// checkMemory checks current memory usage and triggers cleanup if needed
func (tmm *TaskMemoryMonitor) checkMemory() {
	tmm.mu.Lock()
	tmm.lastCheck = time.Now()
	tmm.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if tmm.logger != nil {
		tmm.logger.DebugLogf("Memory check - Alloc: %d MB, Sys: %d MB, NumGC: %d",
			m.Alloc/1024/1024, m.Sys/1024/1024, m.NumGC)
	}

	// Check if memory usage exceeds threshold
	if m.Alloc > tmm.memoryThreshold {
		if tmm.logger != nil {
			tmm.logger.Logf("Memory usage (%d MB) exceeds threshold (%d MB), triggering cleanup",
				m.Alloc/1024/1024, tmm.memoryThreshold/1024/1024)
		}

		// Trigger garbage collection
		runtime.GC()

		// Could also trigger task-specific cleanup here
		tmm.triggerTaskCleanup()
	}
}

// triggerTaskCleanup triggers cleanup operations on tasks
func (tmm *TaskMemoryMonitor) triggerTaskCleanup() {
	if tmm.registry == nil {
		return
	}

	// Get all tasks and potentially pause non-critical ones
	tasks := tmm.registry.GetAllTasks()
	for name, task := range tasks {
		// Could implement task priority here
		if tmm.logger != nil {
			tmm.logger.DebugLogf("Checking task %s for cleanup opportunities", name)
		}
		// Tasks could implement a Cleanup() method
		_ = task // Placeholder for future cleanup logic
	}
}

// GetStats returns memory monitor statistics
func (tmm *TaskMemoryMonitor) GetStats() map[string]interface{} {
	tmm.mu.RLock()
	lastCheck := tmm.lastCheck
	tmm.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"isMonitoring":    atomic.LoadInt32(&tmm.isMonitoring) == 1,
		"lastCheck":       lastCheck.Format(time.RFC3339),
		"checkInterval":   tmm.checkInterval.String(),
		"memoryThreshold": tmm.memoryThreshold,
		"currentMemory": map[string]interface{}{
			"alloc":      m.Alloc,
			"totalAlloc": m.TotalAlloc,
			"sys":        m.Sys,
			"mallocs":    m.Mallocs,
			"frees":      m.Frees,
			"numGC":      m.NumGC,
			"goroutines": runtime.NumGoroutine(),
		},
	}
}

// WorkerPool manages a pool of worker goroutines for task execution
type WorkerPool struct {
	logger    Logger
	taskQueue chan func()
	stopChan  chan bool
	metrics   WorkerPoolMetrics
	workerWg  sync.WaitGroup
	workers   int
	isRunning int32
}

// WorkerPoolMetrics tracks worker pool performance
type WorkerPoolMetrics struct {
	tasksProcessed int64
	tasksQueued    int64
	tasksFailed    int64
	avgProcessTime int64 // nanoseconds
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int, queueSize int, logger Logger) *WorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if queueSize <= 0 {
		queueSize = workers * 10
	}

	return &WorkerPool{
		workers:   workers,
		taskQueue: make(chan func(), queueSize),
		stopChan:  make(chan bool),
		logger:    logger,
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start() {
	if !atomic.CompareAndSwapInt32(&wp.isRunning, 0, 1) {
		if wp.logger != nil {
			wp.logger.Logf("Worker pool is already running")
		}
		return
	}

	for i := 0; i < wp.workers; i++ {
		wp.workerWg.Add(1)
		go wp.worker(i)
	}

	if wp.logger != nil {
		wp.logger.Logf("Started worker pool with %d workers", wp.workers)
	}
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
	if !atomic.CompareAndSwapInt32(&wp.isRunning, 1, 0) {
		if wp.logger != nil {
			wp.logger.Logf("Worker pool is not running")
		}
		return
	}

	close(wp.stopChan)
	close(wp.taskQueue)
	wp.workerWg.Wait()

	if wp.logger != nil {
		wp.logger.Logf("Stopped worker pool")
	}
}

// Submit submits a task to the worker pool
func (wp *WorkerPool) Submit(task func()) error {
	if atomic.LoadInt32(&wp.isRunning) != 1 {
		return fmt.Errorf("worker pool is not running")
	}

	select {
	case wp.taskQueue <- task:
		atomic.AddInt64(&wp.metrics.tasksQueued, 1)
		return nil
	default:
		return fmt.Errorf("worker pool queue is full")
	}
}

// worker is the main worker routine
func (wp *WorkerPool) worker(id int) {
	defer wp.workerWg.Done()

	for {
		select {
		case task, ok := <-wp.taskQueue:
			if !ok {
				return // Channel closed
			}
			wp.executeTask(task)
		case <-wp.stopChan:
			return
		}
	}
}

// executeTask executes a task with error handling
func (wp *WorkerPool) executeTask(task func()) {
	startTime := time.Now()
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&wp.metrics.tasksFailed, 1)
			if wp.logger != nil {
				wp.logger.ErrorLogf("Worker pool task panicked: %v", r)
			}
		}
		// Update average process time
		duration := time.Since(startTime).Nanoseconds()
		processed := atomic.AddInt64(&wp.metrics.tasksProcessed, 1)
		currentAvg := atomic.LoadInt64(&wp.metrics.avgProcessTime)
		newAvg := (currentAvg*(processed-1) + duration) / processed
		atomic.StoreInt64(&wp.metrics.avgProcessTime, newAvg)
	}()

	task()
}

// GetMetrics returns worker pool metrics
func (wp *WorkerPool) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"workers":        wp.workers,
		"isRunning":      atomic.LoadInt32(&wp.isRunning) == 1,
		"queueSize":      len(wp.taskQueue),
		"queueCapacity":  cap(wp.taskQueue),
		"tasksProcessed": atomic.LoadInt64(&wp.metrics.tasksProcessed),
		"tasksQueued":    atomic.LoadInt64(&wp.metrics.tasksQueued),
		"tasksFailed":    atomic.LoadInt64(&wp.metrics.tasksFailed),
		"avgProcessTime": time.Duration(atomic.LoadInt64(&wp.metrics.avgProcessTime)),
	}
}
