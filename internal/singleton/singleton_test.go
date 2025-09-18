package singleton

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGet_Singleton tests that Get() returns the same instance
func TestGet_Singleton(t *testing.T) {
	registry1 := Get()
	registry2 := Get()

	if registry1 != registry2 {
		t.Error("Get() should return the same instance (singleton)")
	}

	if registry1 == nil {
		t.Error("Get() should not return nil")
	}
}

// TestRegistry_Register tests singleton registration
func TestRegistry_Register(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	initializer := func() interface{} {
		return "test-value"
	}

	finalizer := func(v interface{}) {
		// Mock finalizer
	}

	// Test successful registration
	err := registry.Register("test-singleton", initializer, finalizer)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Verify instance was registered
	if len(registry.instances) != 1 {
		t.Error("Instance should be registered")
	}

	instance := registry.instances["test-singleton"]
	if instance == nil {
		t.Error("Instance should not be nil")
		return
	}

	if instance.name != "test-singleton" {
		t.Errorf("Instance name should be 'test-singleton', got '%s'", instance.name)
	}

	if instance.initializer == nil {
		t.Error("Instance should have initializer")
	}

	if instance.finalizer == nil {
		t.Error("Instance should have finalizer")
	}
}

// TestRegistry_Register_Duplicate tests duplicate registration
func TestRegistry_Register_Duplicate(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	initializer := func() interface{} {
		return "test-value"
	}

	// Register first time
	err := registry.Register("test-singleton", initializer, nil)
	if err != nil {
		t.Errorf("First registration should succeed, got error: %v", err)
	}

	// Register again - should fail
	err = registry.Register("test-singleton", initializer, nil)
	if err == nil {
		t.Error("Duplicate registration should fail")
	}

	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("Error should mention already registered, got: %v", err)
	}
}

// TestRegistry_Register_DuringShutdown tests registration during shutdown
func TestRegistry_Register_DuringShutdown(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
		shutdown:  1, // Already shutting down
	}

	initializer := func() interface{} {
		return "test-value"
	}

	err := registry.Register("test-singleton", initializer, nil)
	if err == nil {
		t.Error("Registration during shutdown should fail")
	}

	if !strings.Contains(err.Error(), "shutting down") {
		t.Errorf("Error should mention shutting down, got: %v", err)
	}
}

// TestRegistry_GetInstance tests singleton retrieval and initialization
func TestRegistry_GetInstance(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	callCount := int32(0)
	testValue := "test-value"

	initializer := func() interface{} {
		atomic.AddInt32(&callCount, 1)
		return testValue
	}

	// Register singleton
	err := registry.Register("test-singleton", initializer, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// First get - should initialize
	value1, err := registry.GetInstance("test-singleton")
	if err != nil {
		t.Errorf("GetInstance should succeed, got error: %v", err)
	}

	if value1 != testValue {
		t.Errorf("Value should be '%s', got '%v'", testValue, value1)
	}

	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("Initializer should be called once, called %d times", callCount)
	}

	// Second get - should return same instance without calling initializer
	value2, err := registry.GetInstance("test-singleton")
	if err != nil {
		t.Errorf("GetInstance should succeed, got error: %v", err)
	}

	if value2 != testValue {
		t.Errorf("Value should be '%s', got '%v'", testValue, value2)
	}

	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("Initializer should still be called only once, called %d times", callCount)
	}
}

// TestRegistry_GetInstance_NotRegistered tests getting unregistered singleton
func TestRegistry_GetInstance_NotRegistered(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	value, err := registry.GetInstance("non-existent")
	if err == nil {
		t.Error("GetInstance of non-existent singleton should fail")
	}

	if value != nil {
		t.Error("Value should be nil for non-existent singleton")
	}

	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("Error should mention not registered, got: %v", err)
	}
}

// TestRegistry_GetInstance_DuringShutdown tests getting instance during shutdown
func TestRegistry_GetInstance_DuringShutdown(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
		shutdown:  1, // Already shutting down
	}

	value, err := registry.GetInstance("test-singleton")
	if err == nil {
		t.Error("GetInstance during shutdown should fail")
	}

	if value != nil {
		t.Error("Value should be nil during shutdown")
	}

	if !strings.Contains(err.Error(), "shutting down") {
		t.Errorf("Error should mention shutting down, got: %v", err)
	}
}

// TestRegistry_MustGet tests MustGet method
func TestRegistry_MustGet(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	testValue := "test-value"
	initializer := func() interface{} {
		return testValue
	}

	// Register singleton
	err := registry.Register("test-singleton", initializer, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// MustGet should succeed
	value := registry.MustGet("test-singleton")
	if value != testValue {
		t.Errorf("Value should be '%s', got '%v'", testValue, value)
	}

	// MustGet non-existent should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGet of non-existent singleton should panic")
		}
	}()

	registry.MustGet("non-existent")
}

// TestRegistry_RegisterGroup tests group registration
func TestRegistry_RegisterGroup(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Test successful group registration
	err := registry.RegisterGroup("test-group")
	if err != nil {
		t.Errorf("RegisterGroup should succeed, got error: %v", err)
	}

	// Verify group was registered
	if len(registry.groups) != 1 {
		t.Error("Group should be registered")
	}

	group := registry.groups["test-group"]
	if group == nil {
		t.Error("Group should not be nil")
		return
	}

	if group.name != "test-group" {
		t.Errorf("Group name should be 'test-group', got '%s'", group.name)
	}

	// Test duplicate group registration
	err = registry.RegisterGroup("test-group")
	if err == nil {
		t.Error("Duplicate group registration should fail")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Error should mention already exists, got: %v", err)
	}
}

// TestRegistry_AddToGroup tests adding singletons to groups
func TestRegistry_AddToGroup(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Register a singleton
	initializer := func() interface{} {
		return "test-value"
	}

	err := registry.Register("test-singleton", initializer, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Register a group
	err = registry.RegisterGroup("test-group")
	if err != nil {
		t.Errorf("RegisterGroup should succeed, got error: %v", err)
	}

	// Add singleton to group
	err = registry.AddToGroup("test-group", "test-singleton")
	if err != nil {
		t.Errorf("AddToGroup should succeed, got error: %v", err)
	}

	// Verify singleton is in group
	group := registry.groups["test-group"]
	if len(group.instances) != 1 {
		t.Error("Group should contain one instance")
	}

	if group.instances["test-singleton"] == nil {
		t.Error("Singleton should be in group")
	}

	// Test adding to non-existent group
	err = registry.AddToGroup("non-existent-group", "test-singleton")
	if err == nil {
		t.Error("Adding to non-existent group should fail")
	}

	// Test adding non-existent singleton to group
	err = registry.AddToGroup("test-group", "non-existent-singleton")
	if err == nil {
		t.Error("Adding non-existent singleton should fail")
	}
}

// TestRegistry_GetGroup tests retrieving group instances
func TestRegistry_GetGroup(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Register singletons
	err := registry.Register("test-singleton-1", func() interface{} {
		return "value-1"
	}, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	err = registry.Register("test-singleton-2", func() interface{} {
		return "value-2"
	}, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Register group and add singletons
	err = registry.RegisterGroup("test-group")
	if err != nil {
		t.Errorf("RegisterGroup should succeed, got error: %v", err)
	}

	err = registry.AddToGroup("test-group", "test-singleton-1")
	if err != nil {
		t.Errorf("AddToGroup should succeed, got error: %v", err)
	}

	err = registry.AddToGroup("test-group", "test-singleton-2")
	if err != nil {
		t.Errorf("AddToGroup should succeed, got error: %v", err)
	}

	// Initialize singletons
	_, _ = registry.GetInstance("test-singleton-1")
	_, _ = registry.GetInstance("test-singleton-2")

	// Get group
	groupInstances, err := registry.GetGroup("test-group")
	if err != nil {
		t.Errorf("GetGroup should succeed, got error: %v", err)
	}

	if len(groupInstances) != 2 {
		t.Errorf("Group should contain 2 instances, got %d", len(groupInstances))
	}

	if groupInstances["test-singleton-1"] != "value-1" {
		t.Error("Group should contain correct instance values")
	}

	if groupInstances["test-singleton-2"] != "value-2" {
		t.Error("Group should contain correct instance values")
	}

	// Test getting non-existent group
	_, err = registry.GetGroup("non-existent-group")
	if err == nil {
		t.Error("Getting non-existent group should fail")
	}
}

// TestRegistry_ReferenceCountingv tests reference counting
func TestRegistry_ReferenceCountingv(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	finalizerCalled := int32(0)
	finalizer := func(v interface{}) {
		atomic.AddInt32(&finalizerCalled, 1)
	}

	// Register singleton
	err := registry.Register("test-singleton", func() interface{} {
		return "test-value"
	}, finalizer)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Initialize singleton (this adds 1 reference)
	_, err = registry.GetInstance("test-singleton")
	if err != nil {
		t.Errorf("GetInstance should succeed, got error: %v", err)
	}

	// Check initial reference count
	count, err := registry.GetReferenceCount("test-singleton")
	if err != nil {
		t.Errorf("GetReferenceCount should succeed, got error: %v", err)
	}

	if count != 1 {
		t.Errorf("Reference count should be 1, got %d", count)
	}

	// Add reference
	err = registry.AddReference("test-singleton")
	if err != nil {
		t.Errorf("AddReference should succeed, got error: %v", err)
	}

	count, _ = registry.GetReferenceCount("test-singleton")
	if count != 2 {
		t.Errorf("Reference count should be 2, got %d", count)
	}

	// Release reference
	err = registry.ReleaseReference("test-singleton")
	if err != nil {
		t.Errorf("ReleaseReference should succeed, got error: %v", err)
	}

	count, _ = registry.GetReferenceCount("test-singleton")
	if count != 1 {
		t.Errorf("Reference count should be 1, got %d", count)
	}

	// Release last reference - should trigger finalizer
	err = registry.ReleaseReference("test-singleton")
	if err != nil {
		t.Errorf("ReleaseReference should succeed, got error: %v", err)
	}

	count, _ = registry.GetReferenceCount("test-singleton")
	if count != 0 {
		t.Errorf("Reference count should be 0, got %d", count)
	}

	// Wait for finalizer to run (it runs in goroutine)
	time.Sleep(10 * time.Millisecond)

	if atomic.LoadInt32(&finalizerCalled) != 1 {
		t.Errorf("Finalizer should be called once, called %d times", finalizerCalled)
	}

	// Test reference operations on non-existent singleton
	err = registry.AddReference("non-existent")
	if err == nil {
		t.Error("AddReference on non-existent singleton should fail")
	}

	err = registry.ReleaseReference("non-existent")
	if err == nil {
		t.Error("ReleaseReference on non-existent singleton should fail")
	}

	_, err = registry.GetReferenceCount("non-existent")
	if err == nil {
		t.Error("GetReferenceCount on non-existent singleton should fail")
	}
}

// TestRegistry_Shutdown tests graceful shutdown
func TestRegistry_Shutdown(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	finalizerCalled := int32(0)
	finalizer := func(v interface{}) {
		atomic.AddInt32(&finalizerCalled, 1)
	}

	// Register and initialize singletons
	err := registry.Register("test-singleton-1", func() interface{} {
		return "value-1"
	}, finalizer)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	err = registry.Register("test-singleton-2", func() interface{} {
		return "value-2"
	}, finalizer)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Initialize singletons
	_, _ = registry.GetInstance("test-singleton-1")
	_, _ = registry.GetInstance("test-singleton-2")

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = registry.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown should succeed, got error: %v", err)
	}

	// Verify finalizers were called
	if atomic.LoadInt32(&finalizerCalled) != 2 {
		t.Errorf("Finalizers should be called 2 times, called %d times", finalizerCalled)
	}

	// Verify registry is cleared
	if len(registry.instances) != 0 {
		t.Error("Instances should be cleared after shutdown")
	}

	if len(registry.groups) != 0 {
		t.Error("Groups should be cleared after shutdown")
	}

	// Verify shutdown flag is set
	if atomic.LoadInt32(&registry.shutdown) != 1 {
		t.Error("Shutdown flag should be set")
	}

	// Test double shutdown
	err = registry.Shutdown(ctx)
	if err == nil {
		t.Error("Double shutdown should fail")
	}
}

// TestRegistry_Shutdown_Timeout tests shutdown timeout
func TestRegistry_Shutdown_Timeout(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Register singleton with slow finalizer
	slowFinalizer := func(v interface{}) {
		time.Sleep(100 * time.Millisecond)
	}

	err := registry.Register("slow-singleton", func() interface{} {
		return "value"
	}, slowFinalizer)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Initialize singleton
	_, _ = registry.GetInstance("slow-singleton")

	// Shutdown with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err = registry.Shutdown(ctx)
	if err == nil {
		t.Error("Shutdown should timeout")
	}

	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("Error should mention timeout, got: %v", err)
	}
}

// TestRegistry_Shutdown_PanicRecovery tests panic recovery during shutdown
func TestRegistry_Shutdown_PanicRecovery(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Register singleton with panicking finalizer
	panicFinalizer := func(v interface{}) {
		panic("finalizer panic")
	}

	err := registry.Register("panic-singleton", func() interface{} {
		return "value"
	}, panicFinalizer)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Initialize singleton
	_, _ = registry.GetInstance("panic-singleton")

	// Shutdown should handle panic
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = registry.Shutdown(ctx)
	if err == nil {
		t.Error("Shutdown should report finalizer panic")
	}

	if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("Error should mention panic, got: %v", err)
	}
}

// TestRegistry_Reset tests registry reset
func TestRegistry_Reset(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
		shutdown:  1,
	}

	// Add some data
	registry.instances["test"] = &Instance{}
	registry.groups["test"] = &Group{}

	// Reset
	registry.Reset()

	// Verify everything is cleared
	if len(registry.instances) != 0 {
		t.Error("Instances should be cleared after reset")
	}

	if len(registry.groups) != 0 {
		t.Error("Groups should be cleared after reset")
	}

	if atomic.LoadInt32(&registry.shutdown) != 0 {
		t.Error("Shutdown flag should be cleared after reset")
	}
}

// TestRegistry_GetStats tests statistics
func TestRegistry_GetStats(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Register singletons
	err := registry.Register("test-singleton-1", func() interface{} {
		return "value-1"
	}, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	err = registry.Register("test-singleton-2", func() interface{} {
		return "value-2"
	}, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Register group
	err = registry.RegisterGroup("test-group")
	if err != nil {
		t.Errorf("RegisterGroup should succeed, got error: %v", err)
	}

	// Initialize one singleton
	_, _ = registry.GetInstance("test-singleton-1")

	// Add reference
	_ = registry.AddReference("test-singleton-1")

	// Get stats
	stats := registry.GetStats()

	if stats.TotalRegistered != 2 {
		t.Errorf("TotalRegistered should be 2, got %d", stats.TotalRegistered)
	}

	if stats.TotalInitialized != 1 {
		t.Errorf("TotalInitialized should be 1, got %d", stats.TotalInitialized)
	}

	if stats.TotalGroups != 1 {
		t.Errorf("TotalGroups should be 1, got %d", stats.TotalGroups)
	}

	if stats.TotalReferences != 2 { // 1 from initialization + 1 from AddReference
		t.Errorf("TotalReferences should be 2, got %d", stats.TotalReferences)
	}
}

// TestBuilder tests the fluent builder interface
func TestBuilder(t *testing.T) {
	// Reset global registry for clean test
	Get().Reset()

	testValue := "builder-test-value"

	initializer := func() interface{} {
		return testValue
	}

	finalizer := func(v interface{}) {
		// Mock finalizer for builder test
	}

	// Test builder
	err := NewBuilder("builder-singleton").
		WithInitializer(initializer).
		WithFinalizer(finalizer).
		InGroup("builder-group").
		Register()

	if err != nil {
		t.Errorf("Builder registration should succeed, got error: %v", err)
	}

	// Verify singleton was registered
	value, err := Get().GetInstance("builder-singleton")
	if err != nil {
		t.Errorf("GetInstance should succeed, got error: %v", err)
	}

	if value != testValue {
		t.Errorf("Value should be '%s', got '%v'", testValue, value)
	}

	// Verify group was created and singleton added
	groupInstances, err := Get().GetGroup("builder-group")
	if err != nil {
		t.Errorf("GetGroup should succeed, got error: %v", err)
	}

	if len(groupInstances) != 1 {
		t.Errorf("Group should contain 1 instance, got %d", len(groupInstances))
	}

	if groupInstances["builder-singleton"] != testValue {
		t.Error("Group should contain correct instance")
	}
}

// TestBuilder_WithoutGroup tests builder without group
func TestBuilder_WithoutGroup(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	builder := &Builder{
		registry: registry,
		name:     "no-group-singleton",
	}

	err := builder.WithInitializer(func() interface{} {
		return "value"
	}).Register()

	if err != nil {
		t.Errorf("Registration without group should succeed, got error: %v", err)
	}

	// Verify singleton was registered
	if len(registry.instances) != 1 {
		t.Error("Singleton should be registered")
	}
}

// TestContainsHelper tests the helper string contains function
func TestContainsHelper(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		expect bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "lo wo", true},
		{"hello world", "xyz", false},
		{"hello", "hello world", false},
		{"", "test", false},
		{"test", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		result := contains(test.s, test.substr)
		if result != test.expect {
			t.Errorf("contains(%q, %q) = %v, want %v", test.s, test.substr, result, test.expect)
		}
	}
}

// TestRegistry_ConcurrentAccess tests concurrent access to registry
func TestRegistry_ConcurrentAccess(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	callCount := int32(0)
	initializer := func() interface{} {
		atomic.AddInt32(&callCount, 1)
		return "concurrent-value"
	}

	// Register singleton
	err := registry.Register("concurrent-singleton", initializer, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent access
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			value, err := registry.GetInstance("concurrent-singleton")
			if err != nil {
				t.Errorf("GetInstance should succeed, got error: %v", err)
				return
			}
			if value != "concurrent-value" {
				t.Errorf("Value should be 'concurrent-value', got '%v'", value)
			}
		}()
	}

	wg.Wait()

	// Initializer should be called only once despite concurrent access
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("Initializer should be called only once, called %d times", callCount)
	}
}

// TestRegistry_ConcurrentReferenceOperations tests concurrent reference operations
func TestRegistry_ConcurrentReferenceOperations(t *testing.T) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	// Register singleton
	err := registry.Register("ref-singleton", func() interface{} {
		return "ref-value"
	}, nil)
	if err != nil {
		t.Errorf("Register should succeed, got error: %v", err)
	}

	// Initialize singleton
	_, _ = registry.GetInstance("ref-singleton")

	var wg sync.WaitGroup
	numGoroutines := 20

	// Concurrent reference operations
	wg.Add(numGoroutines * 2)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = registry.AddReference("ref-singleton")
		}()

		go func() {
			defer wg.Done()
			_ = registry.ReleaseReference("ref-singleton")
		}()
	}

	wg.Wait()

	// Reference count should be consistent (initial 1 + net operations)
	count, err := registry.GetReferenceCount("ref-singleton")
	if err != nil {
		t.Errorf("GetReferenceCount should succeed, got error: %v", err)
	}

	// Count should be >= 0 due to balanced add/release operations
	if count < 0 {
		t.Errorf("Reference count should not be negative, got %d", count)
	}
}

// Benchmark tests for performance verification
func BenchmarkRegistry_GetInstance(b *testing.B) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	registry.Register("benchmark-singleton", func() interface{} {
		return "benchmark-value"
	}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.GetInstance("benchmark-singleton")
	}
}

func BenchmarkRegistry_ConcurrentGetInstance(b *testing.B) {
	registry := &Registry{
		instances: make(map[string]*Instance),
		groups:    make(map[string]*Group),
	}

	registry.Register("concurrent-benchmark", func() interface{} {
		return "concurrent-value"
	}, nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			registry.GetInstance("concurrent-benchmark")
		}
	})
}

func BenchmarkBuilder_Register(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry := &Registry{
			instances: make(map[string]*Instance),
			groups:    make(map[string]*Group),
		}

		builder := &Builder{
			registry: registry,
			name:     fmt.Sprintf("benchmark-%d", i),
		}

		builder.WithInitializer(func() interface{} {
			return "value"
		}).Register()
	}
}
