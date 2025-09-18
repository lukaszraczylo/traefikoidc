package traefikoidc

import (
	"net/http"
	"sync"
	"time"
)

// LazyBackgroundTask wraps BackgroundTask to provide delayed initialization.
// This prevents memory leaks from unnecessary background tasks by starting
// them only when actually needed, reducing resource usage in idle scenarios.
type LazyBackgroundTask struct {
	// BackgroundTask is the underlying task implementation
	*BackgroundTask
	// started tracks whether the task has been activated
	started bool
	// startOnce ensures single initialization
	startOnce sync.Once
}

// NewLazyBackgroundTask creates a background task that doesn't start immediately.
// The task will only start when explicitly activated, preventing unnecessary
// resource usage for tasks that may never be needed.
func NewLazyBackgroundTask(name string, interval time.Duration, taskFunc func(), logger *Logger, wg ...*sync.WaitGroup) *LazyBackgroundTask {
	return &LazyBackgroundTask{
		BackgroundTask: NewBackgroundTask(name, interval, taskFunc, logger, wg...),
		started:        false,
	}
}

// StartIfNeeded starts the background task only if it hasn't been started yet.
// Uses sync.Once to ensure thread-safe single initialization.
func (lt *LazyBackgroundTask) StartIfNeeded() {
	lt.startOnce.Do(func() {
		if !lt.started {
			lt.BackgroundTask.Start()
			lt.started = true
		}
	})
}

// Stop stops the background task if it was started.
// Resets the start state to allow potential future re-initialization.
func (lt *LazyBackgroundTask) Stop() {
	if lt.started {
		lt.BackgroundTask.Stop()
		lt.started = false
		lt.startOnce = sync.Once{}
	}
}

// NewLazyCacheWithLogger creates a cache that doesn't start cleanup until first use.
// This reduces memory overhead by avoiding unnecessary cleanup goroutines
// for caches that may remain empty or be used infrequently.
func NewLazyCacheWithLogger(logger *Logger) CacheInterface {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	config := DefaultUnifiedCacheConfig()
	config.Logger = logger
	config.CleanupInterval = 10 * time.Minute
	unifiedCache := NewUniversalCache(config)
	return NewCacheAdapter(unifiedCache)
}

// NewLazyCache creates a cache with delayed cleanup initialization.
// Uses the default no-op logger and defers cleanup task creation.
func NewLazyCache() CacheInterface {
	return NewLazyCacheWithLogger(nil)
}

// CleanupIdleConnections periodically closes idle HTTP connections to prevent memory leaks.
// Runs in a background goroutine and can be stopped via the stop channel.
// This is crucial for long-running applications to prevent connection pool exhaustion.
func CleanupIdleConnections(client *http.Client, interval time.Duration, stopChan <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		case <-stopChan:
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
			return
		}
	}
}

// OptimizedMiddlewareConfig provides configuration options for memory-optimized middleware.
// These settings help reduce memory usage and prevent leaks in resource-constrained environments.
type OptimizedMiddlewareConfig struct {
	// DelayBackgroundTasks defers starting background tasks until needed
	DelayBackgroundTasks bool
	// ReducedCleanupIntervals uses longer intervals to reduce CPU/memory overhead
	ReducedCleanupIntervals bool
	// AggressiveConnectionCleanup closes idle connections more frequently
	AggressiveConnectionCleanup bool
	// MinimalCacheSize uses smaller cache limits to reduce memory footprint
	MinimalCacheSize bool
}

// DefaultOptimizedConfig returns a configuration optimized for low memory usage.
// All optimization features are enabled to minimize memory footprint and prevent leaks.
func DefaultOptimizedConfig() *OptimizedMiddlewareConfig {
	return &OptimizedMiddlewareConfig{
		DelayBackgroundTasks:        true,
		ReducedCleanupIntervals:     true,
		AggressiveConnectionCleanup: true,
		MinimalCacheSize:            true,
	}
}
