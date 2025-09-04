package traefikoidc

import (
	"sync"
	"time"
)

// BackgroundTask provides a robust framework for running periodic background tasks
// with proper lifecycle management, graceful shutdown, and logging capabilities.
// It supports both internal and external WaitGroup coordination for complex cleanup scenarios.
type BackgroundTask struct {
	stopChan   chan struct{}
	taskFunc   func()
	logger     *Logger
	externalWG *sync.WaitGroup
	name       string
	internalWG sync.WaitGroup
	interval   time.Duration
	stopOnce   sync.Once
	mu         sync.Mutex
	stopped    bool
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
		taskFunc:   taskFunc,
		logger:     logger,
		externalWG: externalWG,
	}
}

// Start begins executing the background task in a separate goroutine.
// The task function is executed immediately, then at the configured interval.
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

	bt.internalWG.Add(1)
	if bt.externalWG != nil {
		bt.externalWG.Add(1)
	}
	go bt.run()
}

// Stop gracefully shuts down the background task and waits for completion.
// It signals the task to stop and waits for the goroutine to finish.
// This method is safe to call multiple times.
func (bt *BackgroundTask) Stop() {
	bt.stopOnce.Do(func() {
		bt.mu.Lock()
		bt.stopped = true
		bt.mu.Unlock()

		close(bt.stopChan)
		bt.internalWG.Wait()
	})
}

// run is the main loop for the background task.
// It executes the task function immediately, then periodically
// until the stop signal is received.
func (bt *BackgroundTask) run() {
	defer func() {
		bt.internalWG.Done()
		if bt.externalWG != nil {
			bt.externalWG.Done()
		}
	}()
	ticker := time.NewTicker(bt.interval)
	defer ticker.Stop()

	if bt.logger != nil {
		bt.logger.Info("Starting background task: %s", bt.name)
	}

	bt.taskFunc()

	for {
		select {
		case <-ticker.C:
			bt.taskFunc()
		case <-bt.stopChan:
			if bt.logger != nil {
				bt.logger.Info("Stopping background task: %s", bt.name)
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
