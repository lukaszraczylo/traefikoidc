package traefikoidc

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// LazyBackgroundTask wraps BackgroundTask to start only when needed
type LazyBackgroundTask struct {
	*BackgroundTask
	started   bool
	startOnce sync.Once
}

// NewLazyBackgroundTask creates a background task that doesn't start immediately
func NewLazyBackgroundTask(name string, interval time.Duration, taskFunc func(), logger *Logger, wg ...*sync.WaitGroup) *LazyBackgroundTask {
	return &LazyBackgroundTask{
		BackgroundTask: NewBackgroundTask(name, interval, taskFunc, logger, wg...),
		started:        false,
	}
}

// StartIfNeeded starts the task only if it hasn't been started yet
func (lt *LazyBackgroundTask) StartIfNeeded() {
	lt.startOnce.Do(func() {
		if !lt.started {
			lt.BackgroundTask.Start()
			lt.started = true
		}
	})
}

// Stop stops the task if it was started
func (lt *LazyBackgroundTask) Stop() {
	if lt.started {
		lt.BackgroundTask.Stop()
		lt.started = false
		lt.startOnce = sync.Once{} // Reset for potential restart
	}
}

// NewLazyCacheWithLogger creates a cache that doesn't start cleanup until first use
func NewLazyCacheWithLogger(logger *Logger) *Cache {
	if logger == nil {
		logger = newNoOpLogger()
	}

	c := &Cache{
		items:               make(map[string]CacheItem, DefaultMaxSize),
		order:               list.New(),
		elems:               make(map[string]*list.Element, DefaultMaxSize),
		maxSize:             DefaultMaxSize,
		autoCleanupInterval: 10 * time.Minute, // Increased from 5 minutes
		logger:              logger,
	}
	// Don't start cleanup immediately - it will be started on first use
	return c
}

// NewLazyCache creates a cache that doesn't start cleanup immediately
func NewLazyCache() *Cache {
	return NewLazyCacheWithLogger(nil)
}

// CleanupIdleConnections periodically closes idle HTTP connections
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
			// Final cleanup
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
			return
		}
	}
}

// OptimizedMiddlewareConfig provides configuration for memory-optimized middleware
type OptimizedMiddlewareConfig struct {
	// DelayBackgroundTasks delays starting background tasks until first request
	DelayBackgroundTasks bool

	// ReducedCleanupIntervals uses longer intervals for cleanup tasks
	ReducedCleanupIntervals bool

	// AggressiveConnectionCleanup closes idle connections more aggressively
	AggressiveConnectionCleanup bool

	// MinimalCacheSize uses smaller default cache sizes
	MinimalCacheSize bool
}

// DefaultOptimizedConfig returns a configuration optimized for low memory usage
func DefaultOptimizedConfig() *OptimizedMiddlewareConfig {
	return &OptimizedMiddlewareConfig{
		DelayBackgroundTasks:        true,
		ReducedCleanupIntervals:     true,
		AggressiveConnectionCleanup: true,
		MinimalCacheSize:            true,
	}
}
