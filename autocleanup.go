package traefikoidc

import (
	"sync"
	"time"
)

// BackgroundTask represents a managed recurring task that runs in the background.
// It provides a clean interface for starting and stopping periodic operations
// with proper lifecycle management and logging.
type BackgroundTask struct {
	stopChan   chan struct{}
	taskFunc   func()
	logger     *Logger
	name       string
	interval   time.Duration
	externalWG *sync.WaitGroup // External WaitGroup (optional, for tracking by parent)
	internalWG sync.WaitGroup  // Internal WaitGroup for this task's goroutine
	stopOnce   sync.Once       // Ensures Stop() can be called multiple times safely
	stopped    bool            // Track if task has been stopped
	mu         sync.Mutex      // Protects stopped flag
}

// NewBackgroundTask creates a new background task with the specified parameters.
//
// Parameters:
//   - name: Identifier for the task (used in logging).
//   - interval: Duration between task executions.
//   - taskFunc: The function to execute periodically.
//   - logger: Logger instance for task lifecycle events.
//   - wg: Optional WaitGroup for synchronizing goroutine completion.
//
// Returns:
//   - A configured BackgroundTask ready to be started.
func NewBackgroundTask(name string, interval time.Duration, taskFunc func(), logger *Logger, wg ...*sync.WaitGroup) *BackgroundTask {
	var externalWG *sync.WaitGroup
	if len(wg) > 0 {
		externalWG = wg[0]
	}
	return &BackgroundTask{
		name:       name,
		interval:   interval,
		stopChan:   make(chan struct{}),
		taskFunc:   taskFunc,
		logger:     logger,
		externalWG: externalWG,
	}
}

// Start begins the background task execution in a separate goroutine.
// The task runs immediately upon start and then at the specified interval.
func (bt *BackgroundTask) Start() {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if bt.stopped {
		if bt.logger != nil {
			bt.logger.Infof("Attempted to start already stopped task: %s", bt.name)
		}
		return
	}

	// Add to both internal and external WaitGroups
	bt.internalWG.Add(1)
	if bt.externalWG != nil {
		bt.externalWG.Add(1)
	}
	go bt.run()
}

// Stop gracefully terminates the background task by closing the stop channel.
// It waits for the goroutine to complete using the internal WaitGroup.
// This method is safe to call multiple times.
func (bt *BackgroundTask) Stop() {
	bt.stopOnce.Do(func() {
		bt.mu.Lock()
		bt.stopped = true
		bt.mu.Unlock()

		close(bt.stopChan)
		// Wait only on the internal WaitGroup
		bt.internalWG.Wait()
	})
}

// run is the main execution loop for the background task.
// It executes the task function immediately and then at regular intervals
// until the stop signal is received.
func (bt *BackgroundTask) run() {
	defer func() {
		// Always decrement internal WaitGroup
		bt.internalWG.Done()
		// Decrement external WaitGroup if provided
		if bt.externalWG != nil {
			bt.externalWG.Done()
		}
	}()
	ticker := time.NewTicker(bt.interval)
	defer ticker.Stop()

	// Only log startup if debug level is enabled
	if bt.logger != nil {
		bt.logger.Info("Starting background task: %s", bt.name)
	}

	// Run task immediately on startup
	bt.taskFunc()

	for {
		select {
		case <-ticker.C:
			bt.taskFunc()
		case <-bt.stopChan:
			// Only log shutdown
			if bt.logger != nil {
				bt.logger.Info("Stopping background task: %s", bt.name)
			}
			return
		}
	}
}

// autoCleanupRoutine periodically calls the provided cleanup function.
// It starts a ticker with the given interval and executes the cleanup function
// on each tick. The routine stops gracefully when a signal is received on the
// stop channel. This is typically used for background cleanup tasks like
// expiring cache entries.
//
// Parameters:
//   - interval: The time duration between cleanup calls.
//   - stop: A channel used to signal the routine to stop. Receiving any value will terminate the loop.
//   - cleanup: The function to call periodically for cleanup tasks.
//
// Deprecated: Use BackgroundTask instead.
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
