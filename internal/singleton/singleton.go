// Package singleton provides a centralized, thread-safe singleton management system
// that consolidates all singleton patterns used throughout the application.
// It ensures proper initialization, lifecycle management, and graceful shutdown.
package singleton

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Registry is the centralized singleton registry that manages all singleton instances
// in the application. It provides thread-safe initialization, access, and cleanup.
type Registry struct {
	mu        sync.RWMutex
	instances map[string]*Instance
	groups    map[string]*Group
	shutdown  int32
	wg        sync.WaitGroup
}

// Instance represents a singleton instance with lifecycle management
type Instance struct {
	name        string
	value       interface{}
	initializer func() interface{}
	finalizer   func(interface{})
	once        sync.Once
	refCount    int32
}

// Group represents a group of related singletons
type Group struct {
	name      string
	instances map[string]*Instance
	mu        sync.RWMutex
}

var (
	// globalRegistry is the singleton registry instance
	globalRegistry *Registry
	// registryOnce ensures single initialization
	registryOnce sync.Once
)

// Get returns the global singleton registry
func Get() *Registry {
	registryOnce.Do(func() {
		globalRegistry = &Registry{
			instances: make(map[string]*Instance),
			groups:    make(map[string]*Group),
		}
	})
	return globalRegistry
}

// Register registers a new singleton with its initializer and optional finalizer
func (r *Registry) Register(name string, initializer func() interface{}, finalizer func(interface{})) error {
	if atomic.LoadInt32(&r.shutdown) == 1 {
		return fmt.Errorf("registry is shutting down")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.instances[name]; exists {
		return fmt.Errorf("singleton %s already registered", name)
	}

	r.instances[name] = &Instance{
		name:        name,
		initializer: initializer,
		finalizer:   finalizer,
	}

	return nil
}

// GetInstance retrieves or initializes a singleton instance
func (r *Registry) GetInstance(name string) (interface{}, error) {
	if atomic.LoadInt32(&r.shutdown) == 1 {
		return nil, fmt.Errorf("registry is shutting down")
	}

	r.mu.RLock()
	instance, exists := r.instances[name]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("singleton %s not registered", name)
	}

	// Initialize the singleton if needed
	instance.once.Do(func() {
		if instance.initializer != nil {
			instance.value = instance.initializer()
			atomic.AddInt32(&instance.refCount, 1)
		}
	})

	return instance.value, nil
}

// MustGet retrieves a singleton instance, panicking if not found
func (r *Registry) MustGet(name string) interface{} {
	val, err := r.GetInstance(name)
	if err != nil {
		panic(fmt.Sprintf("singleton %s: %v", name, err))
	}
	return val
}

// RegisterGroup creates a new singleton group
func (r *Registry) RegisterGroup(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.groups[name]; exists {
		return fmt.Errorf("group %s already exists", name)
	}

	r.groups[name] = &Group{
		name:      name,
		instances: make(map[string]*Instance),
	}

	return nil
}

// AddToGroup adds a singleton to a group
func (r *Registry) AddToGroup(groupName, singletonName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	group, groupExists := r.groups[groupName]
	if !groupExists {
		return fmt.Errorf("group %s does not exist", groupName)
	}

	instance, instanceExists := r.instances[singletonName]
	if !instanceExists {
		return fmt.Errorf("singleton %s not registered", singletonName)
	}

	group.mu.Lock()
	defer group.mu.Unlock()

	group.instances[singletonName] = instance
	return nil
}

// GetGroup retrieves all singletons in a group
func (r *Registry) GetGroup(name string) (map[string]interface{}, error) {
	r.mu.RLock()
	group, exists := r.groups[name]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("group %s does not exist", name)
	}

	group.mu.RLock()
	defer group.mu.RUnlock()

	result := make(map[string]interface{})
	for name, instance := range group.instances {
		if instance.value != nil {
			result[name] = instance.value
		}
	}

	return result, nil
}

// AddReference increments the reference count for a singleton
func (r *Registry) AddReference(name string) error {
	r.mu.RLock()
	instance, exists := r.instances[name]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("singleton %s not registered", name)
	}

	atomic.AddInt32(&instance.refCount, 1)
	return nil
}

// ReleaseReference decrements the reference count for a singleton
func (r *Registry) ReleaseReference(name string) error {
	r.mu.RLock()
	instance, exists := r.instances[name]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("singleton %s not registered", name)
	}

	count := atomic.AddInt32(&instance.refCount, -1)
	if count == 0 && instance.finalizer != nil && instance.value != nil {
		// Run finalizer when last reference is released
		go instance.finalizer(instance.value)
	}

	return nil
}

// GetReferenceCount returns the reference count for a singleton
func (r *Registry) GetReferenceCount(name string) (int32, error) {
	r.mu.RLock()
	instance, exists := r.instances[name]
	r.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("singleton %s not registered", name)
	}

	return atomic.LoadInt32(&instance.refCount), nil
}

// Shutdown gracefully shuts down all singletons
func (r *Registry) Shutdown(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&r.shutdown, 0, 1) {
		return fmt.Errorf("registry already shutting down")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Create error channel for collecting shutdown errors
	errChan := make(chan error, len(r.instances))

	// Run finalizers for all initialized singletons
	for name, instance := range r.instances {
		if instance.value != nil && instance.finalizer != nil {
			r.wg.Add(1)
			go func(n string, i *Instance) {
				defer r.wg.Done()

				// Run finalizer with panic recovery
				func() {
					defer func() {
						if r := recover(); r != nil {
							errChan <- fmt.Errorf("finalizer for %s panicked: %v", n, r)
						}
					}()
					i.finalizer(i.value)
				}()
			}(name, instance)
		}
	}

	// Wait for all finalizers to complete or timeout
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All finalizers completed
	case <-ctx.Done():
		return fmt.Errorf("shutdown timeout: %w", ctx.Err())
	}

	// Collect any errors
	close(errChan)
	var errs []error
	for err := range errChan {
		if err != nil {
			errs = append(errs, err)
		}
	}

	// Clear all instances
	r.instances = make(map[string]*Instance)
	r.groups = make(map[string]*Group)

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// Reset resets the registry (mainly for testing)
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.instances = make(map[string]*Instance)
	r.groups = make(map[string]*Group)
	atomic.StoreInt32(&r.shutdown, 0)
}

// Stats returns statistics about the registry
type Stats struct {
	TotalRegistered  int
	TotalInitialized int
	TotalGroups      int
	TotalReferences  int32
}

// GetStats returns current registry statistics
func (r *Registry) GetStats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := Stats{
		TotalRegistered: len(r.instances),
		TotalGroups:     len(r.groups),
	}

	for _, instance := range r.instances {
		if instance.value != nil {
			stats.TotalInitialized++
		}
		stats.TotalReferences += atomic.LoadInt32(&instance.refCount)
	}

	return stats
}

// Builder provides a fluent interface for registering singletons
type Builder struct {
	registry    *Registry
	name        string
	initializer func() interface{}
	finalizer   func(interface{})
	group       string
}

// NewBuilder creates a new singleton builder
func NewBuilder(name string) *Builder {
	return &Builder{
		registry: Get(),
		name:     name,
	}
}

// WithInitializer sets the initializer function
func (b *Builder) WithInitializer(init func() interface{}) *Builder {
	b.initializer = init
	return b
}

// WithFinalizer sets the finalizer function
func (b *Builder) WithFinalizer(final func(interface{})) *Builder {
	b.finalizer = final
	return b
}

// InGroup adds the singleton to a group
func (b *Builder) InGroup(group string) *Builder {
	b.group = group
	return b
}

// Register registers the singleton with the configured options
func (b *Builder) Register() error {
	if err := b.registry.Register(b.name, b.initializer, b.finalizer); err != nil {
		return err
	}

	if b.group != "" {
		// Ensure group exists
		if err := b.registry.RegisterGroup(b.group); err != nil {
			// Group might already exist, which is ok
			if !contains(err.Error(), "already exists") {
				return err
			}
		}

		return b.registry.AddToGroup(b.group, b.name)
	}

	return nil
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
