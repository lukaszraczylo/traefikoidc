package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var (
	globalResourceManager *ResourceManager
	resourceManagerOnce   sync.Once
	resourceManagerMutex  sync.Mutex
)

// ResourceManager manages shared resources across all middleware instances
// to prevent duplication and goroutine leaks when Traefik recreates middleware
type ResourceManager struct {
	// HTTP clients shared across instances
	httpClients map[string]*http.Client
	clientsMu   sync.RWMutex

	// Caches shared across instances
	caches   map[string]interface{}
	cachesMu sync.RWMutex

	// Background tasks registry
	tasks   map[string]*BackgroundTask
	tasksMu sync.RWMutex

	// Goroutine pools for controlled concurrency
	pools   map[string]*GoroutinePool
	poolsMu sync.RWMutex

	// Reference counting for cleanup
	references   map[string]*int32
	referencesMu sync.RWMutex

	// Logger
	logger *Logger

	// Shutdown coordination
	shutdownOnce sync.Once
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// GetResourceManager returns the global singleton ResourceManager instance
func GetResourceManager() *ResourceManager {
	resourceManagerOnce.Do(func() {
		globalResourceManager = &ResourceManager{
			httpClients:  make(map[string]*http.Client),
			caches:       make(map[string]interface{}),
			tasks:        make(map[string]*BackgroundTask),
			pools:        make(map[string]*GoroutinePool),
			references:   make(map[string]*int32),
			logger:       GetSingletonNoOpLogger(),
			shutdownChan: make(chan struct{}),
		}
	})
	return globalResourceManager
}

// GetHTTPClient returns a shared HTTP client for the given key
func (rm *ResourceManager) GetHTTPClient(key string) *http.Client {
	rm.clientsMu.RLock()
	client, exists := rm.httpClients[key]
	rm.clientsMu.RUnlock()

	if exists {
		return client
	}

	rm.clientsMu.Lock()
	defer rm.clientsMu.Unlock()

	// Double-check after acquiring write lock
	if client, exists := rm.httpClients[key]; exists {
		return client
	}

	// SECURITY FIX: Use secure HTTP client configuration with limits
	config := DefaultHTTPClientConfig()
	factory := NewHTTPClientFactory()
	client = factory.CreateHTTPClient(config)

	rm.httpClients[key] = client
	return client
}

// GetCache returns a shared cache for the given key
func (rm *ResourceManager) GetCache(key string) interface{} {
	rm.cachesMu.RLock()
	cache, exists := rm.caches[key]
	rm.cachesMu.RUnlock()

	if exists {
		return cache
	}

	rm.cachesMu.Lock()
	defer rm.cachesMu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists := rm.caches[key]; exists {
		return cache
	}

	// Create cache based on key type
	// Use global cache manager for proper singleton caches
	cacheManager := GetGlobalCacheManager(&rm.wg)
	switch key {
	case "metadata-cache":
		cache = cacheManager.GetSharedMetadataCache()
	case "token-cache":
		cache = cacheManager.GetSharedTokenCache()
	case "jwk-cache":
		cache = cacheManager.GetSharedJWKCache()
	default:
		// Generic cache implementation
		cache = NewGenericCache(1*time.Hour, rm.logger)
	}

	rm.caches[key] = cache
	return cache
}

// RegisterBackgroundTask registers a singleton background task
func (rm *ResourceManager) RegisterBackgroundTask(name string, interval time.Duration, taskFunc func()) error {
	rm.tasksMu.Lock()
	defer rm.tasksMu.Unlock()

	// Check if task already exists
	if _, exists := rm.tasks[name]; exists {
		if rm.logger != nil {
			rm.logger.Debugf("Background task %s already registered", name)
		}
		// Return existing task without error for idempotency
		return nil
	}

	// Create new task with WaitGroup for proper cleanup
	task := NewBackgroundTask(name, interval, taskFunc, rm.logger, &rm.wg)
	rm.tasks[name] = task

	if rm.logger != nil {
		rm.logger.Infof("Registered singleton background task: %s", name)
	}

	return nil
}

// StartBackgroundTask starts a registered background task
func (rm *ResourceManager) StartBackgroundTask(name string) error {
	rm.tasksMu.RLock()
	task, exists := rm.tasks[name]
	rm.tasksMu.RUnlock()

	if !exists {
		return fmt.Errorf("task %s not registered", name)
	}

	task.Start()
	return nil
}

// StopBackgroundTask stops a running background task
func (rm *ResourceManager) StopBackgroundTask(name string) error {
	rm.tasksMu.RLock()
	task, exists := rm.tasks[name]
	rm.tasksMu.RUnlock()

	if !exists {
		return fmt.Errorf("task %s not registered", name)
	}

	task.Stop()
	return nil
}

// IsTaskRunning checks if a background task is running
func (rm *ResourceManager) IsTaskRunning(name string) bool {
	rm.tasksMu.RLock()
	task, exists := rm.tasks[name]
	rm.tasksMu.RUnlock()

	if !exists {
		return false
	}

	// Check if task has been started and not stopped
	return atomic.LoadInt32(&task.started) == 1 && atomic.LoadInt32(&task.stopped) == 0
}

// GetGoroutinePool returns a shared goroutine pool for controlled concurrency
func (rm *ResourceManager) GetGoroutinePool(key string, maxWorkers int) *GoroutinePool {
	rm.poolsMu.RLock()
	pool, exists := rm.pools[key]
	rm.poolsMu.RUnlock()

	if exists {
		return pool
	}

	rm.poolsMu.Lock()
	defer rm.poolsMu.Unlock()

	// Double-check after acquiring write lock
	if pool, exists := rm.pools[key]; exists {
		return pool
	}

	// Create new pool
	pool = NewGoroutinePool(maxWorkers, rm.logger)
	rm.pools[key] = pool

	return pool
}

// AddReference increments the reference count for a given instance
func (rm *ResourceManager) AddReference(instanceID string) {
	rm.referencesMu.Lock()
	defer rm.referencesMu.Unlock()

	if count, exists := rm.references[instanceID]; exists {
		atomic.AddInt32(count, 1)
	} else {
		initial := int32(1)
		rm.references[instanceID] = &initial
	}

	if rm.logger != nil {
		rm.logger.Debugf("Added reference for instance %s", instanceID)
	}
}

// RemoveReference decrements the reference count and triggers cleanup if needed
func (rm *ResourceManager) RemoveReference(instanceID string) {
	rm.referencesMu.Lock()
	defer rm.referencesMu.Unlock()

	if count, exists := rm.references[instanceID]; exists {
		newCount := atomic.AddInt32(count, -1)
		if newCount <= 0 {
			delete(rm.references, instanceID)
			if rm.logger != nil {
				rm.logger.Debugf("Removed last reference for instance %s", instanceID)
			}
			// Trigger cleanup for this instance if needed
			rm.cleanupInstance(instanceID)
		}
	}
}

// GetReferenceCount returns the current reference count for an instance
func (rm *ResourceManager) GetReferenceCount(instanceID string) int32 {
	rm.referencesMu.RLock()
	defer rm.referencesMu.RUnlock()

	if count, exists := rm.references[instanceID]; exists {
		return atomic.LoadInt32(count)
	}
	return 0
}

// cleanupInstance performs cleanup for a specific instance when its reference count reaches zero
func (rm *ResourceManager) cleanupInstance(instanceID string) {
	// Instance-specific cleanup logic
	if rm.logger != nil {
		rm.logger.Infof("Cleaning up resources for instance %s", instanceID)
	}

	// Clean up any instance-specific resources
	// This is a hook for future instance-specific cleanup needs
}

// Shutdown gracefully shuts down all managed resources
func (rm *ResourceManager) Shutdown(ctx context.Context) error {
	var err error

	rm.shutdownOnce.Do(func() {
		close(rm.shutdownChan)

		if rm.logger != nil {
			rm.logger.Info("Starting ResourceManager shutdown")
		}

		// Stop all background tasks
		rm.tasksMu.RLock()
		tasks := make([]*BackgroundTask, 0, len(rm.tasks))
		for _, task := range rm.tasks {
			tasks = append(tasks, task)
		}
		rm.tasksMu.RUnlock()

		for _, task := range tasks {
			task.Stop()
		}

		// Shutdown all goroutine pools
		rm.poolsMu.RLock()
		pools := make([]*GoroutinePool, 0, len(rm.pools))
		for _, pool := range rm.pools {
			pools = append(pools, pool)
		}
		rm.poolsMu.RUnlock()

		for _, pool := range pools {
			if shutdownErr := pool.Shutdown(ctx); shutdownErr != nil && err == nil {
				err = shutdownErr
			}
		}

		// Wait for all goroutines with timeout
		done := make(chan struct{})
		go func() {
			rm.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			if rm.logger != nil {
				rm.logger.Info("ResourceManager shutdown completed successfully")
			}
		case <-ctx.Done():
			err = fmt.Errorf("shutdown timeout: %w", ctx.Err())
			if rm.logger != nil {
				rm.logger.Errorf("ResourceManager shutdown timeout: %v", err)
			}
		}
	})

	return err
}

// GoroutinePool provides a pool of workers for controlled concurrency
type GoroutinePool struct {
	maxWorkers   int
	taskQueue    chan func()
	workerWG     sync.WaitGroup
	shutdownOnce sync.Once
	shutdownChan chan struct{}
	logger       *Logger
	started      int32
}

// NewGoroutinePool creates a new goroutine pool with the specified max workers
func NewGoroutinePool(maxWorkers int, logger *Logger) *GoroutinePool {
	pool := &GoroutinePool{
		maxWorkers:   maxWorkers,
		taskQueue:    make(chan func(), maxWorkers*2), // Buffer for queuing
		shutdownChan: make(chan struct{}),
		logger:       logger,
	}

	// Start workers
	for i := 0; i < maxWorkers; i++ {
		pool.workerWG.Add(1)
		go pool.worker(i)
	}

	atomic.StoreInt32(&pool.started, 1)

	if logger != nil {
		logger.Infof("Created goroutine pool with %d workers", maxWorkers)
	}

	return pool
}

// worker is the main loop for a pool worker
func (p *GoroutinePool) worker(id int) {
	defer p.workerWG.Done()

	for {
		select {
		case task := <-p.taskQueue:
			if task != nil {
				// Execute task with panic recovery
				func() {
					defer func() {
						if r := recover(); r != nil {
							if p.logger != nil {
								p.logger.Errorf("Worker %d panic recovered: %v", id, r)
							}
						}
					}()
					task()
				}()
			}
		case <-p.shutdownChan:
			if p.logger != nil {
				p.logger.Debugf("Worker %d shutting down", id)
			}
			return
		}
	}
}

// Submit submits a task to the pool
func (p *GoroutinePool) Submit(task func()) error {
	if atomic.LoadInt32(&p.started) == 0 {
		return fmt.Errorf("pool is shutdown")
	}

	select {
	case p.taskQueue <- task:
		return nil
	case <-p.shutdownChan:
		return fmt.Errorf("pool is shutting down")
	default:
		// Queue is full, try with a small timeout
		select {
		case p.taskQueue <- task:
			return nil
		case <-time.After(100 * time.Millisecond):
			return fmt.Errorf("task queue is full")
		case <-p.shutdownChan:
			return fmt.Errorf("pool is shutting down")
		}
	}
}

// Wait waits for all submitted tasks to complete
func (p *GoroutinePool) Wait() {
	// Drain the task queue
	for len(p.taskQueue) > 0 {
		time.Sleep(10 * time.Millisecond)
	}
}

// Shutdown gracefully shuts down the pool
func (p *GoroutinePool) Shutdown(ctx context.Context) error {
	var err error

	p.shutdownOnce.Do(func() {
		atomic.StoreInt32(&p.started, 0)
		close(p.shutdownChan)

		// Wait for workers to finish with context timeout
		done := make(chan struct{})
		go func() {
			p.workerWG.Wait()
			close(done)
		}()

		select {
		case <-done:
			if p.logger != nil {
				p.logger.Debug("Goroutine pool shutdown completed")
			}
		case <-ctx.Done():
			err = fmt.Errorf("pool shutdown timeout: %w", ctx.Err())
			if p.logger != nil {
				p.logger.Errorf("Goroutine pool shutdown timeout: %v", err)
			}
		}
	})

	return err
}

// GenericCache provides a simple cache implementation for testing
type GenericCache struct {
	data     map[string]interface{}
	mu       sync.RWMutex
	ttl      time.Duration
	logger   *Logger
	stopChan chan struct{}
}

// NewGenericCache creates a new generic cache
func NewGenericCache(ttl time.Duration, logger *Logger) *GenericCache {
	cache := &GenericCache{
		data:     make(map[string]interface{}),
		ttl:      ttl,
		logger:   logger,
		stopChan: make(chan struct{}),
	}

	// Start cleanup routine
	go cache.cleanupRoutine()

	return cache
}

// Get retrieves a value from the cache
func (gc *GenericCache) Get(key string) (interface{}, bool) {
	gc.mu.RLock()
	defer gc.mu.RUnlock()

	val, exists := gc.data[key]
	return val, exists
}

// Set stores a value in the cache
func (gc *GenericCache) Set(key string, value interface{}) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	gc.data[key] = value
}

// Delete removes a value from the cache
func (gc *GenericCache) Delete(key string) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	delete(gc.data, key)
}

// cleanupRoutine periodically cleans up the cache
func (gc *GenericCache) cleanupRoutine() {
	ticker := time.NewTicker(gc.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gc.mu.Lock()
			// Simple cleanup - clear all data after TTL
			// In production, you'd track individual entry TTLs
			gc.data = make(map[string]interface{})
			gc.mu.Unlock()
		case <-gc.stopChan:
			return
		}
	}
}

// Stop stops the cleanup routine
func (gc *GenericCache) Stop() {
	close(gc.stopChan)
}
