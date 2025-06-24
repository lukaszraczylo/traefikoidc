package traefikoidc

import "time"

// BackgroundTask represents a recurring task that runs in the background
type BackgroundTask struct {
	stopChan chan struct{}
	taskFunc func()
	logger   *Logger
	name     string
	interval time.Duration
}

// NewBackgroundTask creates a new background task
func NewBackgroundTask(name string, interval time.Duration, taskFunc func(), logger *Logger) *BackgroundTask {
	return &BackgroundTask{
		name:     name,
		interval: interval,
		stopChan: make(chan struct{}),
		taskFunc: taskFunc,
		logger:   logger,
	}
}

// Start begins the background task execution
func (bt *BackgroundTask) Start() {
	go bt.run()
}

// Stop terminates the background task
func (bt *BackgroundTask) Stop() {
	close(bt.stopChan)
}

// run is the main execution loop for the background task
func (bt *BackgroundTask) run() {
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
