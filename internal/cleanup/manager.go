// Package cleanup provides background task management and cleanup functionality.
package cleanup

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Logger defines the logging interface
type Logger interface {
	Logf(format string, args ...interface{})
	ErrorLogf(format string, args ...interface{})
	DebugLogf(format string, args ...interface{})
}

// BackgroundTask represents a recurring background task
type BackgroundTask struct {
	lastRun    time.Time
	logger     Logger
	ctx        context.Context
	ticker     *time.Ticker
	stopChan   chan bool
	waitGroup  *sync.WaitGroup
	taskFunc   func()
	cancelFunc context.CancelFunc
	name       string
	runCount   int64
	errorCount int64
	interval   time.Duration
	mu         sync.RWMutex
	isRunning  int32
}

// NewBackgroundTask creates a new background task
func NewBackgroundTask(name string, interval time.Duration, taskFunc func(), logger Logger, wg ...*sync.WaitGroup) *BackgroundTask {
	var waitGroup *sync.WaitGroup
	if len(wg) > 0 && wg[0] != nil {
		waitGroup = wg[0]
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &BackgroundTask{
		name:       name,
		interval:   interval,
		taskFunc:   taskFunc,
		stopChan:   make(chan bool, 1),
		isRunning:  0,
		logger:     logger,
		waitGroup:  waitGroup,
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

// Start begins executing the background task
func (bt *BackgroundTask) Start() {
	if !atomic.CompareAndSwapInt32(&bt.isRunning, 0, 1) {
		if bt.logger != nil {
			bt.logger.Logf("Background task %s is already running", bt.name)
		}
		return
	}

	bt.ticker = time.NewTicker(bt.interval)

	if bt.waitGroup != nil {
		bt.waitGroup.Add(1)
	}

	go bt.run()

	if bt.logger != nil {
		bt.logger.Logf("Started background task: %s (interval: %v)", bt.name, bt.interval)
	}
}

// Stop stops the background task
func (bt *BackgroundTask) Stop() {
	if !atomic.CompareAndSwapInt32(&bt.isRunning, 1, 0) {
		if bt.logger != nil {
			bt.logger.Logf("Background task %s is not running", bt.name)
		}
		return
	}

	// Cancel context
	if bt.cancelFunc != nil {
		bt.cancelFunc()
	}

	// Stop ticker
	if bt.ticker != nil {
		bt.ticker.Stop()
	}

	// Send stop signal
	select {
	case bt.stopChan <- true:
	case <-time.After(5 * time.Second):
		if bt.logger != nil {
			bt.logger.ErrorLogf("Timeout stopping background task: %s", bt.name)
		}
	}

	if bt.logger != nil {
		bt.logger.Logf("Stopped background task: %s", bt.name)
	}
}

// run is the main loop for the background task
func (bt *BackgroundTask) run() {
	defer func() {
		if bt.waitGroup != nil {
			bt.waitGroup.Done()
		}
		if r := recover(); r != nil {
			atomic.AddInt64(&bt.errorCount, 1)
			if bt.logger != nil {
				bt.logger.ErrorLogf("Background task %s panicked: %v", bt.name, r)
			}
		}
	}()

	// Run task immediately on start
	bt.executeTask()

	for {
		select {
		case <-bt.ticker.C:
			bt.executeTask()
		case <-bt.stopChan:
			return
		case <-bt.ctx.Done():
			return
		}
	}
}

// executeTask runs the task function with error handling
func (bt *BackgroundTask) executeTask() {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&bt.errorCount, 1)
			if bt.logger != nil {
				bt.logger.ErrorLogf("Task %s panicked: %v", bt.name, r)
			}
		}
	}()

	bt.mu.Lock()
	bt.lastRun = time.Now()
	bt.mu.Unlock()

	atomic.AddInt64(&bt.runCount, 1)
	bt.taskFunc()
}

// GetStats returns statistics about the task
func (bt *BackgroundTask) GetStats() map[string]interface{} {
	bt.mu.RLock()
	lastRun := bt.lastRun
	bt.mu.RUnlock()

	return map[string]interface{}{
		"name":       bt.name,
		"interval":   bt.interval.String(),
		"isRunning":  atomic.LoadInt32(&bt.isRunning) == 1,
		"lastRun":    lastRun.Format(time.RFC3339),
		"runCount":   atomic.LoadInt64(&bt.runCount),
		"errorCount": atomic.LoadInt64(&bt.errorCount),
	}
}

// IsRunning returns whether the task is currently running
func (bt *BackgroundTask) IsRunning() bool {
	return atomic.LoadInt32(&bt.isRunning) == 1
}

// TaskRegistry manages all background tasks
type TaskRegistry struct {
	logger         Logger
	tasks          map[string]*BackgroundTask
	circuitBreaker *TaskCircuitBreaker
	maxTasks       int
	mu             sync.RWMutex
}

// globalTaskRegistry is the singleton task registry
var (
	globalTaskRegistry *TaskRegistry
	registryOnce       sync.Once
	registryMutex      sync.Mutex
)

// GetGlobalTaskRegistry returns the global task registry singleton
func GetGlobalTaskRegistry() *TaskRegistry {
	registryOnce.Do(func() {
		globalTaskRegistry = &TaskRegistry{
			tasks:    make(map[string]*BackgroundTask),
			maxTasks: 100, // Default maximum tasks
		}
	})
	return globalTaskRegistry
}

// ResetGlobalTaskRegistry resets the global task registry (mainly for testing)
func ResetGlobalTaskRegistry() {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	if globalTaskRegistry != nil {
		globalTaskRegistry.StopAllTasks()
		globalTaskRegistry = nil
	}
	registryOnce = sync.Once{}
}

// NewTaskRegistry creates a new task registry
func NewTaskRegistry(logger Logger, maxTasks int) *TaskRegistry {
	return &TaskRegistry{
		tasks:          make(map[string]*BackgroundTask),
		logger:         logger,
		maxTasks:       maxTasks,
		circuitBreaker: NewTaskCircuitBreaker(5, 30*time.Second, logger),
	}
}

// RegisterTask registers a new background task
func (tr *TaskRegistry) RegisterTask(name string, task *BackgroundTask) error {
	if task == nil {
		return fmt.Errorf("task cannot be nil")
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Check if task already exists
	if _, exists := tr.tasks[name]; exists {
		return fmt.Errorf("task with name %s already exists", name)
	}

	// Check task limit
	if len(tr.tasks) >= tr.maxTasks {
		return fmt.Errorf("maximum number of tasks (%d) reached", tr.maxTasks)
	}

	// Check circuit breaker
	if tr.circuitBreaker != nil {
		if err := tr.circuitBreaker.CanCreateTask(name); err != nil {
			return err
		}
	}

	tr.tasks[name] = task

	if tr.logger != nil {
		tr.logger.Logf("Registered task: %s", name)
	}

	return nil
}

// UnregisterTask removes a task from the registry
func (tr *TaskRegistry) UnregisterTask(name string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if task, exists := tr.tasks[name]; exists {
		if task.IsRunning() {
			task.Stop()
		}
		delete(tr.tasks, name)

		if tr.logger != nil {
			tr.logger.Logf("Unregistered task: %s", name)
		}
	}
}

// GetTask returns a task by name
func (tr *TaskRegistry) GetTask(name string) (*BackgroundTask, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	task, exists := tr.tasks[name]
	return task, exists
}

// StopAllTasks stops all registered tasks
func (tr *TaskRegistry) StopAllTasks() {
	tr.mu.RLock()
	tasks := make([]*BackgroundTask, 0, len(tr.tasks))
	for _, task := range tr.tasks {
		tasks = append(tasks, task)
	}
	tr.mu.RUnlock()

	var wg sync.WaitGroup
	for _, task := range tasks {
		if task.IsRunning() {
			wg.Add(1)
			go func(t *BackgroundTask) {
				defer wg.Done()
				t.Stop()
			}(task)
		}
	}
	wg.Wait()

	// Clear all tasks from the registry after stopping them
	tr.mu.Lock()
	tr.tasks = make(map[string]*BackgroundTask)
	tr.mu.Unlock()

	if tr.logger != nil {
		tr.logger.Logf("Stopped all tasks")
	}
}

// GetTaskCount returns the number of registered tasks
func (tr *TaskRegistry) GetTaskCount() int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return len(tr.tasks)
}

// CreateSingletonTask creates or retrieves an existing task
func (tr *TaskRegistry) CreateSingletonTask(name string, interval time.Duration,
	taskFunc func(), logger Logger, wg ...*sync.WaitGroup) (*BackgroundTask, error) {

	// Check if task already exists
	if existingTask, exists := tr.GetTask(name); exists {
		if existingTask.IsRunning() {
			if logger != nil {
				logger.Logf("Task %s already exists and is running", name)
			}
			return existingTask, nil
		}
		// Task exists but not running, start it
		existingTask.Start()
		return existingTask, nil
	}

	// Create new task
	task := NewBackgroundTask(name, interval, taskFunc, logger, wg...)

	// Register task
	if err := tr.RegisterTask(name, task); err != nil {
		return nil, err
	}

	// Start task
	task.Start()

	return task, nil
}

// GetAllTasks returns all registered tasks
func (tr *TaskRegistry) GetAllTasks() map[string]*BackgroundTask {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	tasks := make(map[string]*BackgroundTask)
	for name, task := range tr.tasks {
		tasks[name] = task
	}
	return tasks
}

// GetStats returns statistics for all tasks
func (tr *TaskRegistry) GetStats() map[string]interface{} {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["totalTasks"] = len(tr.tasks)

	runningCount := 0
	taskStats := make(map[string]interface{})
	for name, task := range tr.tasks {
		if task.IsRunning() {
			runningCount++
		}
		taskStats[name] = task.GetStats()
	}

	stats["runningTasks"] = runningCount
	stats["tasks"] = taskStats

	// Add memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	stats["memory"] = map[string]interface{}{
		"alloc":      m.Alloc,
		"totalAlloc": m.TotalAlloc,
		"sys":        m.Sys,
		"numGC":      m.NumGC,
		"goroutines": runtime.NumGoroutine(),
	}

	return stats
}
