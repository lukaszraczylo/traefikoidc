package traefikoidc

import (
	"context"
	"sync"
	"time"
)

// GoroutineManager manages background goroutines with proper lifecycle
type GoroutineManager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	goroutines map[string]*managedGoroutine
	logger     *Logger
}

type managedGoroutine struct {
	name      string
	cancel    context.CancelFunc
	startTime time.Time
	running   bool
}

// NewGoroutineManager creates a new goroutine manager
func NewGoroutineManager(logger *Logger) *GoroutineManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &GoroutineManager{
		ctx:        ctx,
		cancel:     cancel,
		goroutines: make(map[string]*managedGoroutine),
		logger:     logger,
	}
}

// StartGoroutine starts a managed goroutine with context-based cancellation
func (m *GoroutineManager) StartGoroutine(name string, fn func(context.Context)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if goroutine with this name already exists
	if existing, exists := m.goroutines[name]; exists && existing.running {
		m.logger.Debugf("Goroutine %s already running, skipping start", name)
		return
	}

	// Create goroutine-specific context
	goroutineCtx, goroutineCancel := context.WithCancel(m.ctx)

	managed := &managedGoroutine{
		name:      name,
		cancel:    goroutineCancel,
		startTime: time.Now(),
		running:   true,
	}

	m.goroutines[name] = managed
	m.wg.Add(1)

	go func(managedGoroutine *managedGoroutine, goroutineName string) {
		defer func() {
			m.wg.Done()
			m.mu.Lock()
			managedGoroutine.running = false
			m.mu.Unlock()

			// Recover from panics
			if r := recover(); r != nil {
				m.logger.Errorf("Goroutine %s panic recovered: %v", goroutineName, r)
			}
		}()

		m.logger.Debugf("Starting goroutine: %s", goroutineName)
		fn(goroutineCtx)
		m.logger.Debugf("Goroutine %s finished", goroutineName)
	}(managed, name)
}

// StartPeriodicTask starts a periodic task with context-based cancellation
func (m *GoroutineManager) StartPeriodicTask(name string, interval time.Duration, task func()) {
	m.StartGoroutine(name, func(ctx context.Context) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				m.logger.Debugf("Periodic task %s canceled", name)
				return
			case <-ticker.C:
				task()
			}
		}
	})
}

// StopGoroutine stops a specific goroutine by name
func (m *GoroutineManager) StopGoroutine(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if managed, exists := m.goroutines[name]; exists && managed.running {
		m.logger.Debugf("Stopping goroutine: %s", name)
		managed.cancel()
	}
}

// Shutdown gracefully shuts down all managed goroutines
func (m *GoroutineManager) Shutdown(timeout time.Duration) error {
	m.logger.Debug("Starting goroutine manager shutdown")

	// Cancel the main context to signal all goroutines to stop
	m.cancel()

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Debug("All goroutines stopped gracefully")
		return nil
	case <-time.After(timeout):
		m.logger.Error("Timeout waiting for goroutines to stop")
		return ErrShutdownTimeout
	}
}

// GetStatus returns the status of all managed goroutines
func (m *GoroutineManager) GetStatus() map[string]GoroutineStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]GoroutineStatus)
	for name, managed := range m.goroutines {
		status[name] = GoroutineStatus{
			Name:      managed.name,
			Running:   managed.running,
			StartTime: managed.startTime,
			Runtime:   time.Since(managed.startTime),
		}
	}
	return status
}

// GoroutineStatus represents the status of a managed goroutine
type GoroutineStatus struct {
	Name      string
	Running   bool
	StartTime time.Time
	Runtime   time.Duration
}

// ErrShutdownTimeout is returned when shutdown times out
var ErrShutdownTimeout = &shutdownTimeoutError{}

type shutdownTimeoutError struct{}

func (e *shutdownTimeoutError) Error() string {
	return "shutdown timeout: some goroutines did not stop in time"
}
