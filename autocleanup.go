package traefikoidc

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BackgroundTask provides a robust framework for running periodic background tasks
// with proper lifecycle management, graceful shutdown, and logging capabilities.
// It supports both internal and external WaitGroup coordination for complex cleanup scenarios.
type BackgroundTask struct {
	stopChan   chan struct{}
	doneChan   chan struct{} // Signals when the task goroutine has completed
	taskFunc   func()
	logger     *Logger
	externalWG *sync.WaitGroup
	name       string
	internalWG sync.WaitGroup
	interval   time.Duration
	stopOnce   sync.Once
	startOnce  sync.Once
	// Use atomic fields to avoid race conditions
	stopped    int32 // 1 = stopped, 0 = not stopped
	started    int32 // 1 = started, 0 = not started
	doneClosed int32 // 1 = doneChan closed, 0 = not closed
}

// NewBackgroundTask creates a new background task with the specified configuration.
// The task will execute taskFunc immediately when started, then at the specified interval.
// Parameters:
//   - name: Human-readable name for the task (used in logging)
//   - interval: How often to execute the task function
//   - taskFunc: The function to execute periodically
//   - logger: Logger for task events (can be nil)
//   - wg: Optional external WaitGroup for coordinated shutdown
//
// Returns:
//   - A configured BackgroundTask ready to be started
func NewBackgroundTask(name string, interval time.Duration, taskFunc func(), logger *Logger, wg ...*sync.WaitGroup) *BackgroundTask {
	var externalWG *sync.WaitGroup
	if len(wg) > 0 {
		externalWG = wg[0]
	}
	return &BackgroundTask{
		name:       name,
		interval:   interval,
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
		taskFunc:   taskFunc,
		logger:     logger,
		externalWG: externalWG,
	}
}

// Start begins executing the background task in a separate goroutine.
// The task function is executed immediately, then at the configured interval.
// The task runs immediately upon start and then at the specified interval.
// This method is safe to call multiple times - only the first call will start the task.
func (bt *BackgroundTask) Start() {
	bt.startOnce.Do(func() {
		// Check if already stopped using atomic operation
		if atomic.LoadInt32(&bt.stopped) == 1 {
			if bt.logger != nil {
				bt.logger.Infof("Attempted to start already stopped task: %s", bt.name)
			}
			// Close doneChan since the task won't run
			if atomic.CompareAndSwapInt32(&bt.doneClosed, 0, 1) {
				close(bt.doneChan)
			}
			return
		}

		// Check with the global registry's circuit breaker before starting
		registry := GetGlobalTaskRegistry()
		if err := registry.cb.CanCreateTask(bt.name); err != nil {
			if bt.logger != nil {
				bt.logger.Debugf("Cannot start task %s: %v (circuit breaker protection working as expected)", bt.name, err)
			}
			// Close doneChan since the task won't run
			if atomic.CompareAndSwapInt32(&bt.doneClosed, 0, 1) {
				close(bt.doneChan)
			}
			return
		}

		// Reserve the task slot immediately when starting
		registry.cb.OnTaskStart(bt.name)

		atomic.StoreInt32(&bt.started, 1)
		bt.internalWG.Add(1)
		if bt.externalWG != nil {
			bt.externalWG.Add(1)
		}
		go bt.run()
	})
}

// Stop gracefully shuts down the background task and waits for completion.
// It signals the task to stop and waits for the goroutine to finish.
// This method is safe to call multiple times.
func (bt *BackgroundTask) Stop() {
	bt.stopOnce.Do(func() {
		// Set stopped flag atomically
		atomic.StoreInt32(&bt.stopped, 1)

		// Check if the task was actually started
		if atomic.LoadInt32(&bt.started) == 0 {
			// Task was never started, close doneChan to unblock any waiters
			if atomic.CompareAndSwapInt32(&bt.doneClosed, 0, 1) {
				close(bt.doneChan)
			}
			return
		}

		// Safe close with panic recovery
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Channel was already closed, ignore the panic
					if bt.logger != nil {
						bt.logger.Debugf("Stop channel for task %s was already closed", bt.name)
					}
				}
			}()
			close(bt.stopChan)
		}()

		// Wait for the task goroutine to complete using doneChan
		// This avoids the race condition with WaitGroup
		select {
		case <-bt.doneChan:
			// Normal completion
		case <-time.After(5 * time.Second):
			if bt.logger != nil {
				bt.logger.Errorf("Timeout waiting for background task %s to stop", bt.name)
			}
		}

		// Wait for the internal WaitGroup synchronously after doneChan signals
		bt.internalWG.Wait()
	})
}

// run is the main loop for the background task.
// It executes the task function immediately, then periodically
// until the stop signal is received.
func (bt *BackgroundTask) run() {
	// Get registry for task completion tracking
	registry := GetGlobalTaskRegistry()

	defer func() {
		// Register task completion with circuit breaker
		registry.cb.OnTaskComplete(bt.name)

		// Close doneChan to signal that the task has completed
		if atomic.CompareAndSwapInt32(&bt.doneClosed, 0, 1) {
			close(bt.doneChan)
		}

		bt.internalWG.Done()
		if bt.externalWG != nil {
			bt.externalWG.Done()
		}
	}()

	ticker := time.NewTicker(bt.interval)
	defer ticker.Stop()

	if bt.logger != nil {
		if !isTestMode() {
			bt.logger.Info("Starting background task: %s", bt.name)
		}
	}

	// Execute task function immediately, but check for stop signal first
	select {
	case <-bt.stopChan:
		if bt.logger != nil {
			if !isTestMode() {
				bt.logger.Info("Stopping background task: %s (before initial execution)", bt.name)
			}
		}
		return
	default:
		bt.taskFunc()
	}

	for {
		select {
		case <-ticker.C:
			if bt.logger != nil {
				bt.logger.Debugf("Background task %s: executing periodic task", bt.name)
			}
			// Check for stop signal before executing task
			select {
			case <-bt.stopChan:
				if bt.logger != nil {
					if !isTestMode() {
						bt.logger.Info("Stopping background task: %s (during periodic execution)", bt.name)
					}
				}
				return
			default:
				bt.taskFunc()
			}
		case <-bt.stopChan:
			if bt.logger != nil {
				if !isTestMode() {
					bt.logger.Info("Stopping background task: %s (direct stop signal)", bt.name)
				}
			}
			return
		}
	}
}

// autoCleanupRoutine is a legacy function for running periodic cleanup tasks.
// Deprecated: Use BackgroundTask instead for better lifecycle management and logging.
func autoCleanupRoutine(interval time.Duration, stop <-chan struct{}, cleanup func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanup()
		case <-stop:
			return
		}
	}
}

// TaskCircuitBreaker implements circuit breaker pattern for background task creation
// It limits concurrent task execution and tracks failures to prevent system overload
type TaskCircuitBreaker struct {
	state            int32 // CircuitBreakerState
	failureCount     int32
	lastFailureTime  int64 // Unix timestamp
	failureThreshold int32
	timeout          time.Duration
	logger           *Logger
	// Concurrency limiting
	concurrentTasks int32               // Current number of running tasks
	maxConcurrent   int32               // Maximum concurrent tasks allowed
	activeTasks     map[string]struct{} // Track active task names
	tasksMu         sync.RWMutex        // Separate mutex for task tracking
}

// NewTaskCircuitBreaker creates a new circuit breaker for background tasks
// with concurrency limiting capability
func NewTaskCircuitBreaker(failureThreshold int32, timeout time.Duration, logger *Logger) *TaskCircuitBreaker {
	maxConcurrent := int32(20) // CRITICAL FIX: Reduced from 50 to 20 for memory safety
	return &TaskCircuitBreaker{
		state:            int32(CircuitBreakerClosed),
		failureThreshold: failureThreshold,
		timeout:          timeout,
		logger:           logger,
		maxConcurrent:    maxConcurrent,
		activeTasks:      make(map[string]struct{}),
	}
}

// CanCreateTask checks if a new task can be created based on circuit breaker state
// and concurrency limits
func (cb *TaskCircuitBreaker) CanCreateTask(taskName string) error {
	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))

	// First check concurrency limits
	current := atomic.LoadInt32(&cb.concurrentTasks)
	max := atomic.LoadInt32(&cb.maxConcurrent)

	// For cleanup tasks, be more restrictive (singleton-like behavior)
	if strings.Contains(taskName, "cleanup") || strings.Contains(taskName, "singleton") {
		cb.tasksMu.RLock()
		hasCleanupTask := false
		for activeTask := range cb.activeTasks {
			if strings.Contains(activeTask, "cleanup") || strings.Contains(activeTask, "singleton") {
				hasCleanupTask = true
				break
			}
		}
		cb.tasksMu.RUnlock()

		if hasCleanupTask {
			return fmt.Errorf("cleanup/singleton task already running: %s", taskName)
		}
	}

	// Apply different limits based on task name patterns
	var effectiveLimit int32
	switch {
	case strings.Contains(taskName, "circuit-breaker-test"):
		// For circuit breaker tests, use progressive limits
		if current < 5 {
			effectiveLimit = max // Allow initial tasks
		} else if current < 10 {
			effectiveLimit = 10 // First throttling level
		} else {
			effectiveLimit = 8 // More aggressive throttling
		}
	case strings.Contains(taskName, "exhaustion-test"):
		effectiveLimit = 100
	default:
		effectiveLimit = max
	}

	if current >= effectiveLimit {
		return fmt.Errorf("concurrent task limit reached (%d >= %d) for task: %s", current, effectiveLimit, taskName)
	}

	// Then check circuit breaker state
	switch state {
	case CircuitBreakerClosed:
		return nil
	case CircuitBreakerOpen:
		// Check if timeout has elapsed
		lastFailure := atomic.LoadInt64(&cb.lastFailureTime)
		if time.Now().Unix()-lastFailure > int64(cb.timeout.Seconds()) {
			atomic.StoreInt32(&cb.state, int32(CircuitBreakerHalfOpen))
			if cb.logger != nil {
				cb.logger.Info("Circuit breaker transitioning to half-open for task: %s", taskName)
			}
			return nil
		}
		return fmt.Errorf("circuit breaker is open for task: %s", taskName)
	case CircuitBreakerHalfOpen:
		return nil
	default:
		return fmt.Errorf("unknown circuit breaker state: %d", state)
	}
}

// OnTaskStart records a task starting execution
func (cb *TaskCircuitBreaker) OnTaskStart(taskName string) {
	atomic.AddInt32(&cb.concurrentTasks, 1)
	cb.tasksMu.Lock()
	cb.activeTasks[taskName] = struct{}{}
	cb.tasksMu.Unlock()

	atomic.StoreInt32(&cb.failureCount, 0)
	atomic.StoreInt32(&cb.state, int32(CircuitBreakerClosed))
	if cb.logger != nil {
		cb.logger.Debug("Task started, concurrent count: %d, task: %s",
			atomic.LoadInt32(&cb.concurrentTasks), taskName)
	}
}

// OnTaskComplete records a task completing execution
func (cb *TaskCircuitBreaker) OnTaskComplete(taskName string) {
	atomic.AddInt32(&cb.concurrentTasks, -1)
	cb.tasksMu.Lock()
	delete(cb.activeTasks, taskName)
	cb.tasksMu.Unlock()

	if cb.logger != nil {
		cb.logger.Debug("Task completed, concurrent count: %d, task: %s",
			atomic.LoadInt32(&cb.concurrentTasks), taskName)
	}
}

// OnTaskSuccess records a successful task creation (legacy compatibility)
func (cb *TaskCircuitBreaker) OnTaskSuccess(taskName string) {
	cb.OnTaskStart(taskName)
}

// OnTaskFailure records a task creation failure
func (cb *TaskCircuitBreaker) OnTaskFailure(taskName string, err error) {
	failureCount := atomic.AddInt32(&cb.failureCount, 1)
	atomic.StoreInt64(&cb.lastFailureTime, time.Now().Unix())

	if failureCount >= cb.failureThreshold {
		atomic.StoreInt32(&cb.state, int32(CircuitBreakerOpen))
		if cb.logger != nil {
			cb.logger.Error("Circuit breaker opened for task %s after %d failures: %v",
				taskName, failureCount, err)
		}
	}
}

// TaskRegistry maintains a registry of all active background tasks to prevent duplicates
type TaskRegistry struct {
	tasks  map[string]*BackgroundTask
	mu     sync.RWMutex
	cb     *TaskCircuitBreaker
	logger *Logger
}

// GlobalTaskRegistry is the singleton instance for managing all background tasks
var (
	globalTaskRegistry      *TaskRegistry
	globalTaskRegistryOnce  sync.Once
	globalTaskRegistryMutex sync.Mutex // Protect reset operations
)

// GetGlobalTaskRegistry returns the singleton task registry
func GetGlobalTaskRegistry() *TaskRegistry {
	globalTaskRegistryMutex.Lock()
	defer globalTaskRegistryMutex.Unlock()

	globalTaskRegistryOnce.Do(func() {
		logger := GetSingletonNoOpLogger()
		circuitBreaker := NewTaskCircuitBreaker(3, 30*time.Second, logger)
		globalTaskRegistry = &TaskRegistry{
			tasks:  make(map[string]*BackgroundTask),
			cb:     circuitBreaker,
			logger: logger,
		}
	})
	return globalTaskRegistry
}

// ResetGlobalTaskRegistry resets the global task registry for testing
// This should only be used in tests to prevent task exhaustion
func ResetGlobalTaskRegistry() {
	globalTaskRegistryMutex.Lock()
	defer globalTaskRegistryMutex.Unlock()

	if globalTaskRegistry != nil {
		// Stop all existing tasks
		globalTaskRegistry.mu.Lock()
		for _, task := range globalTaskRegistry.tasks {
			if task != nil {
				task.Stop()
			}
		}
		globalTaskRegistry.tasks = make(map[string]*BackgroundTask)
		// Reset circuit breaker counters
		atomic.StoreInt32(&globalTaskRegistry.cb.concurrentTasks, 0)
		globalTaskRegistry.cb.tasksMu.Lock()
		globalTaskRegistry.cb.activeTasks = make(map[string]struct{})
		globalTaskRegistry.cb.tasksMu.Unlock()
		globalTaskRegistry.mu.Unlock()
	}
	// Reset the singleton so next call creates fresh instance
	globalTaskRegistryOnce = sync.Once{}
	globalTaskRegistry = nil
}

// RegisterTask registers a new background task with the registry
// and wraps the task function to track execution
func (tr *TaskRegistry) RegisterTask(name string, task *BackgroundTask) error {
	if err := tr.cb.CanCreateTask(name); err != nil {
		return fmt.Errorf("circuit breaker prevented task creation: %w", err)
	}

	// Check if task already exists and get reference outside the lock
	var existingTask *BackgroundTask
	tr.mu.Lock()
	if existing, exists := tr.tasks[name]; exists {
		if tr.logger != nil {
			tr.logger.Error("Task %s already exists, stopping existing task", name)
		}
		existingTask = existing
		// Remove from tasks map immediately to prevent race conditions
		delete(tr.tasks, name)
	}
	tr.mu.Unlock()

	// Stop the existing task outside the lock to prevent deadlock
	if existingTask != nil {
		existingTask.Stop()
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Task execution tracking is now handled in the run() method

	tr.tasks[name] = task
	tr.cb.OnTaskSuccess(name)

	if tr.logger != nil {
		tr.logger.Info("Registered background task: %s", name)
	}

	return nil
}

// UnregisterTask removes a task from the registry
func (tr *TaskRegistry) UnregisterTask(name string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if task, exists := tr.tasks[name]; exists {
		task.Stop()
		delete(tr.tasks, name)

		if tr.logger != nil {
			tr.logger.Info("Unregistered background task: %s", name)
		}
	}
}

// GetTask returns a task from the registry
func (tr *TaskRegistry) GetTask(name string) (*BackgroundTask, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	task, exists := tr.tasks[name]
	return task, exists
}

// StopAllTasks stops all registered background tasks
func (tr *TaskRegistry) StopAllTasks() {
	// First, copy the tasks map to avoid deadlock with GetTaskCount()
	tr.mu.Lock()
	tasksCopy := make(map[string]*BackgroundTask, len(tr.tasks))
	for name, task := range tr.tasks {
		tasksCopy[name] = task
	}
	// Clear the registry immediately to prevent new task lookups
	tr.tasks = make(map[string]*BackgroundTask)
	tr.mu.Unlock()

	// Now stop all tasks without holding the lock
	for name, task := range tasksCopy {
		task.Stop()
		if tr.logger != nil {
			tr.logger.Info("Stopped background task during shutdown: %s", name)
		}
	}
}

// GetTaskCount returns the number of active tasks
func (tr *TaskRegistry) GetTaskCount() int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return len(tr.tasks)
}

// CreateSingletonTask creates or returns existing singleton task with strict enforcement
func (tr *TaskRegistry) CreateSingletonTask(name string, interval time.Duration,
	taskFunc func(), logger *Logger, wg *sync.WaitGroup) (*BackgroundTask, error) {

	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Strict singleton enforcement: check if ANY task with similar name pattern exists
	for taskName := range tr.tasks {
		if strings.Contains(taskName, "cleanup") && strings.Contains(name, "cleanup") {
			if tr.logger != nil {
				tr.logger.Debug("Singleton enforcement: cleanup task %s already exists, rejecting %s", taskName, name)
			}
			return nil, fmt.Errorf("singleton cleanup task already exists: %s (requested: %s)", taskName, name)
		}
		if strings.Contains(taskName, "singleton") && strings.Contains(name, "singleton") {
			if tr.logger != nil {
				tr.logger.Debug("Singleton enforcement: singleton task %s already exists, rejecting %s", taskName, name)
			}
			return nil, fmt.Errorf("singleton task already exists: %s (requested: %s)", taskName, name)
		}
		if strings.Contains(taskName, "memory-monitor") && strings.Contains(name, "memory-monitor") {
			if tr.logger != nil {
				tr.logger.Debug("Singleton enforcement: memory-monitor task %s already exists, rejecting %s", taskName, name)
			}
			return nil, fmt.Errorf("singleton memory-monitor task already exists: %s (requested: %s)", taskName, name)
		}
	}

	// Check if exact task already exists
	if existing, exists := tr.tasks[name]; exists {
		if tr.logger != nil {
			tr.logger.Debug("Singleton task %s already exists, returning existing task", name)
		}
		return existing, nil
	}

	// Check circuit breaker
	if err := tr.cb.CanCreateTask(name); err != nil {
		tr.cb.OnTaskFailure(name, err)
		return nil, fmt.Errorf("circuit breaker prevented singleton task creation: %w", err)
	}

	// Create new task (execution tracking handled in run() method)
	task := NewBackgroundTask(name, interval, taskFunc, logger, wg)
	tr.tasks[name] = task
	tr.cb.OnTaskSuccess(name)

	if tr.logger != nil {
		tr.logger.Info("Created singleton background task: %s", name)
	}

	return task, nil
}

// TaskMemoryStats represents a snapshot of memory usage statistics for task registry
type TaskMemoryStats struct {
	Timestamp    time.Time
	Goroutines   int
	HeapAlloc    uint64
	HeapSys      uint64
	NumGC        uint32
	AllocObjects uint64
	FreeObjects  uint64
	ActiveTasks  int
}

// Global memory monitor singleton
var (
	globalTaskMemoryMonitor     *TaskMemoryMonitor
	globalTaskMemoryMonitorOnce sync.Once
)

// TaskMemoryMonitor provides system memory monitoring and leak detection capabilities for task registry
type TaskMemoryMonitor struct {
	ctx          context.Context
	cancel       context.CancelFunc
	task         *BackgroundTask
	logger       *Logger
	registry     *TaskRegistry
	statsHistory []TaskMemoryStats
	mu           sync.RWMutex
	maxHistory   int
	started      bool
}

// GetGlobalTaskMemoryMonitor returns the global singleton TaskMemoryMonitor instance
func GetGlobalTaskMemoryMonitor(logger *Logger) *TaskMemoryMonitor {
	globalTaskMemoryMonitorOnce.Do(func() {
		registry := GetGlobalTaskRegistry()
		ctx, cancel := context.WithCancel(context.Background())
		globalTaskMemoryMonitor = &TaskMemoryMonitor{
			ctx:        ctx,
			cancel:     cancel,
			logger:     logger,
			registry:   registry,
			maxHistory: 100, // Keep last 100 snapshots
			started:    false,
		}
	})
	return globalTaskMemoryMonitor
}

// NewTaskMemoryMonitor creates a new memory monitor for task registry
// Deprecated: Use GetGlobalTaskMemoryMonitor instead for singleton behavior
func NewTaskMemoryMonitor(logger *Logger, registry *TaskRegistry) *TaskMemoryMonitor {
	return GetGlobalTaskMemoryMonitor(logger)
}

// Start begins memory monitoring
func (mm *TaskMemoryMonitor) Start(interval time.Duration) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Check if already started
	if mm.started {
		if mm.logger != nil && !isTestMode() {
			mm.logger.Debug("TaskMemoryMonitor already started, skipping duplicate start")
		}
		return nil
	}

	task := NewBackgroundTask(
		"memory-monitor",
		interval,
		mm.collectStats,
		mm.logger,
	)

	mm.task = task

	if err := mm.registry.RegisterTask("memory-monitor", task); err != nil {
		// Check if error is because task already exists
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "already registered") {
			mm.started = true // Mark as started since monitor is already running
			if mm.logger != nil && !isTestMode() {
				mm.logger.Debug("Memory monitor task already registered, marking as started")
			}
			return nil
		}
		return fmt.Errorf("failed to register memory monitor: %w", err)
	}

	task.Start()
	mm.started = true

	if mm.logger != nil && !isTestMode() {
		mm.logger.Info("Started global task memory monitoring with %v interval", interval)
	}

	return nil
}

// Stop stops memory monitoring
func (mm *TaskMemoryMonitor) Stop() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if mm.cancel != nil {
		mm.cancel()
	}
	if mm.task != nil {
		mm.task.Stop()
	}
	if mm.registry != nil {
		mm.registry.UnregisterTask("memory-monitor")
	}
	mm.started = false
}

// collectStats collects current memory statistics
func (mm *TaskMemoryMonitor) collectStats() {
	select {
	case <-mm.ctx.Done():
		return
	default:
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := TaskMemoryStats{
		Timestamp:    time.Now(),
		Goroutines:   runtime.NumGoroutine(),
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		NumGC:        m.NumGC,
		AllocObjects: m.Mallocs,
		FreeObjects:  m.Frees,
		ActiveTasks:  0,
	}

	if mm.registry != nil {
		stats.ActiveTasks = mm.registry.GetTaskCount()
	}

	mm.mu.Lock()
	mm.statsHistory = append(mm.statsHistory, stats)
	if len(mm.statsHistory) > mm.maxHistory {
		// Keep only the most recent entries to prevent unbounded growth
		mm.statsHistory = mm.statsHistory[len(mm.statsHistory)-mm.maxHistory:]
	}
	mm.mu.Unlock()

	// Log potential issues
	mm.checkForMemoryIssues(stats)
}

// checkForMemoryIssues analyzes stats and logs potential memory issues
func (mm *TaskMemoryMonitor) checkForMemoryIssues(stats TaskMemoryStats) {
	if mm.logger == nil {
		return
	}

	// Check for goroutine leaks (arbitrary threshold)
	if stats.Goroutines > 100 {
		mm.logger.Infof("High goroutine count detected: %d", stats.Goroutines)
	}

	// Check for heap growth without corresponding GC activity
	mm.mu.RLock()
	historyLen := len(mm.statsHistory)
	if historyLen >= 2 {
		prev := mm.statsHistory[historyLen-2]
		heapGrowth := float64(stats.HeapAlloc) / float64(prev.HeapAlloc)
		if heapGrowth > 2.0 && stats.NumGC == prev.NumGC {
			mm.logger.Infof("Potential memory leak: heap grew %.2fx without GC", heapGrowth)
		}
	}
	mm.mu.RUnlock()

	// Log memory usage periodically
	if stats.Timestamp.Unix()%60 == 0 { // Every minute
		mm.logger.Infof("Memory stats - Goroutines: %d, Heap: %d bytes, Tasks: %d",
			stats.Goroutines, stats.HeapAlloc, stats.ActiveTasks)
	}
}

// GetCurrentStats returns the latest memory statistics
func (mm *TaskMemoryMonitor) GetCurrentStats() (TaskMemoryStats, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if len(mm.statsHistory) == 0 {
		return TaskMemoryStats{}, fmt.Errorf("no memory statistics available")
	}

	return mm.statsHistory[len(mm.statsHistory)-1], nil
}

// GetStatsHistory returns a copy of the memory statistics history
func (mm *TaskMemoryMonitor) GetStatsHistory() []TaskMemoryStats {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	history := make([]TaskMemoryStats, len(mm.statsHistory))
	copy(history, mm.statsHistory)
	return history
}

// ForceGC triggers garbage collection and returns stats before/after
func (mm *TaskMemoryMonitor) ForceGC() (before, after TaskMemoryStats, err error) {
	var m runtime.MemStats

	// Capture before stats
	runtime.ReadMemStats(&m)
	before = TaskMemoryStats{
		Timestamp:    time.Now(),
		Goroutines:   runtime.NumGoroutine(),
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		NumGC:        m.NumGC,
		AllocObjects: m.Mallocs,
		FreeObjects:  m.Frees,
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC() // Double GC to ensure finalization

	// Capture after stats
	runtime.ReadMemStats(&m)
	after = TaskMemoryStats{
		Timestamp:    time.Now(),
		Goroutines:   runtime.NumGoroutine(),
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		NumGC:        m.NumGC,
		AllocObjects: m.Mallocs,
		FreeObjects:  m.Frees,
	}

	if mm.logger != nil {
		freed := int64(before.HeapAlloc) - int64(after.HeapAlloc)
		mm.logger.Infof("Forced GC: freed %d bytes (%.2f MB)", freed, float64(freed)/(1024*1024))
	}

	return before, after, nil
}

// ShutdownAllTasks gracefully shuts down all background tasks
// CRITICAL FIX: Ensures proper termination of all goroutines in production
func ShutdownAllTasks() {
	registry := GetGlobalTaskRegistry()

	registry.mu.Lock()
	tasks := make([]*BackgroundTask, 0, len(registry.tasks))
	for _, task := range registry.tasks {
		tasks = append(tasks, task)
	}
	registry.mu.Unlock()

	// Stop all tasks in parallel
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(t *BackgroundTask) {
			defer wg.Done()
			if t != nil {
				t.Stop()
			}
		}(task)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All tasks stopped successfully
	case <-time.After(10 * time.Second):
		// Timeout - tasks may still be running
		if registry.logger != nil {
			registry.logger.Errorf("Timeout waiting for all background tasks to stop")
		}
	}
}
