package traefikoidc

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSingletonResourceManager tests the singleton resource manager implementation
func TestSingletonResourceManager(t *testing.T) {
	t.Run("SingletonInstance", func(t *testing.T) {
		// Test that GetResourceManager returns the same instance
		rm1 := GetResourceManager()
		rm2 := GetResourceManager()

		if rm1 != rm2 {
			t.Error("GetResourceManager did not return singleton instance")
		}
	})

	t.Run("ThreadSafeInitialization", func(t *testing.T) {
		// Reset singleton for test
		resetResourceManagerForTesting()

		const numGoroutines = 100
		instances := make([]*ResourceManager, numGoroutines)
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				instances[idx] = GetResourceManager()
			}(i)
		}

		wg.Wait()

		// Verify all instances are the same
		first := instances[0]
		for i := 1; i < numGoroutines; i++ {
			if instances[i] != first {
				t.Errorf("Instance %d differs from first instance", i)
			}
		}
	})

	t.Run("SharedHTTPClient", func(t *testing.T) {
		rm := GetResourceManager()

		client1 := rm.GetHTTPClient("test-client-1")
		client2 := rm.GetHTTPClient("test-client-1")

		if client1 != client2 {
			t.Error("GetHTTPClient did not return same client for same key")
		}

		client3 := rm.GetHTTPClient("test-client-2")
		if client1 == client3 {
			t.Error("GetHTTPClient returned same client for different keys")
		}
	})

	t.Run("SharedCache", func(t *testing.T) {
		rm := GetResourceManager()

		cache1 := rm.GetCache("test-cache-1")
		cache2 := rm.GetCache("test-cache-1")

		if cache1 != cache2 {
			t.Error("GetCache did not return same cache for same key")
		}
	})

	t.Run("SingletonTaskRegistry", func(t *testing.T) {
		rm := GetResourceManager()

		err := rm.RegisterBackgroundTask("test-task", 1*time.Second, func() {
			// Test task
		})

		if err != nil {
			t.Errorf("Failed to register task: %v", err)
		}

		// Try to register same task again - should return existing
		err = rm.RegisterBackgroundTask("test-task", 1*time.Second, func() {
			// Duplicate task
		})

		if err != nil {
			t.Errorf("Failed to handle duplicate task registration: %v", err)
		}
	})

	t.Run("ReferenceCountingCleanup", func(t *testing.T) {
		rm := GetResourceManager()

		// Add reference
		rm.AddReference("test-instance-1")

		// Get reference count
		if rm.GetReferenceCount("test-instance-1") != 1 {
			t.Error("Reference count should be 1")
		}

		// Add another reference
		rm.AddReference("test-instance-1")
		if rm.GetReferenceCount("test-instance-1") != 2 {
			t.Error("Reference count should be 2")
		}

		// Remove reference
		rm.RemoveReference("test-instance-1")
		if rm.GetReferenceCount("test-instance-1") != 1 {
			t.Error("Reference count should be 1 after removal")
		}

		// Remove last reference
		rm.RemoveReference("test-instance-1")
		if rm.GetReferenceCount("test-instance-1") != 0 {
			t.Error("Reference count should be 0 after removing all references")
		}
	})

	t.Run("GracefulShutdown", func(t *testing.T) {
		rm := GetResourceManager()

		// Register a task with atomic variable to avoid race condition
		var taskExecuted int32
		err := rm.RegisterBackgroundTask("shutdown-test-task", 100*time.Millisecond, func() {
			atomic.StoreInt32(&taskExecuted, 1)
		})

		if err != nil {
			t.Errorf("Failed to register task: %v", err)
		}

		// Start the task
		rm.StartBackgroundTask("shutdown-test-task")

		// Wait for task to execute at least once
		time.Sleep(150 * time.Millisecond)

		if atomic.LoadInt32(&taskExecuted) == 0 {
			t.Error("Task was not executed")
		}

		// Shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = rm.Shutdown(ctx)
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}

		// Verify task is stopped
		if rm.IsTaskRunning("shutdown-test-task") {
			t.Error("Task should be stopped after shutdown")
		}
	})
}

// TestContextAwareGoroutineManagement tests context-aware goroutine management
func TestContextAwareGoroutineManagement(t *testing.T) {
	t.Run("GoroutineCleanupOnContextCancel", func(t *testing.T) {
		// Reset singletons to ensure clean state
		resetResourceManagerForTesting()
		ResetUniversalCacheManagerForTesting()
		defer ResetUniversalCacheManagerForTesting()

		initialGoroutines := runtime.NumGoroutine()

		ctx, cancel := context.WithCancel(context.Background())

		// Create a TraefikOidc instance with context
		config := &Config{
			ProviderURL:  "https://example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		plugin, err := NewWithContext(ctx, config, nil, "test")
		if err != nil {
			t.Fatalf("Failed to create plugin: %v", err)
		}

		// Wait for goroutines to start
		time.Sleep(100 * time.Millisecond)

		midGoroutines := runtime.NumGoroutine()
		if midGoroutines <= initialGoroutines {
			t.Error("No goroutines were created")
		}

		// Cancel context
		cancel()

		// Close the plugin to trigger cleanup
		plugin.Close()

		// Wait for cleanup
		time.Sleep(500 * time.Millisecond)

		finalGoroutines := runtime.NumGoroutine()

		// Allow for some singleton background goroutines (caches, pools, etc.)
		// These are shared across all instances and persist for the test duration
		tolerance := 10
		if finalGoroutines > initialGoroutines+tolerance {
			t.Errorf("Goroutine leak detected: initial=%d, final=%d", initialGoroutines, finalGoroutines)
		}
	})

	t.Run("NoGoroutineLeakOnMultipleInstances", func(t *testing.T) {
		// Reset singletons to ensure clean state
		resetResourceManagerForTesting()
		ResetUniversalCacheManagerForTesting()
		defer ResetUniversalCacheManagerForTesting()

		initialGoroutines := runtime.NumGoroutine()

		configs := []Config{
			{ProviderURL: "https://example1.com", ClientID: "client1", ClientSecret: "secret1"},
			{ProviderURL: "https://example2.com", ClientID: "client2", ClientSecret: "secret2"},
			{ProviderURL: "https://example3.com", ClientID: "client3", ClientSecret: "secret3"},
		}

		var plugins []*TraefikOidc
		var cancels []context.CancelFunc

		// Create multiple instances
		for i, config := range configs {
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)

			plugin, err := NewWithContext(ctx, &config, nil, fmt.Sprintf("test-%d", i))
			if err != nil {
				t.Fatalf("Failed to create plugin %d: %v", i, err)
			}
			plugins = append(plugins, plugin)
		}

		// Wait for all goroutines to start
		time.Sleep(200 * time.Millisecond)

		midGoroutines := runtime.NumGoroutine()

		// Cancel all contexts
		for _, cancel := range cancels {
			cancel()
		}

		// Close all plugins
		for _, plugin := range plugins {
			plugin.Close()
		}

		// Wait for cleanup
		time.Sleep(500 * time.Millisecond)

		finalGoroutines := runtime.NumGoroutine()

		// Check for leaks
		tolerance := 5
		if finalGoroutines > initialGoroutines+tolerance {
			t.Errorf("Goroutine leak with multiple instances: initial=%d, mid=%d, final=%d",
				initialGoroutines, midGoroutines, finalGoroutines)
		}
	})

	t.Run("SingletonTasksAcrossInstances", func(t *testing.T) {
		// Reset singletons to ensure clean state
		ResetGlobalTaskRegistry() // Reset circuit breaker and task registry
		resetResourceManagerForTesting()
		ResetUniversalCacheManagerForTesting()
		defer ResetUniversalCacheManagerForTesting()

		rm := GetResourceManager()

		// Register singleton cleanup task
		var cleanupCount int32
		err := rm.RegisterBackgroundTask("singleton-cleanup", 100*time.Millisecond, func() {
			atomic.AddInt32(&cleanupCount, 1)
		})

		if err != nil {
			t.Fatalf("Failed to register singleton task: %v", err)
		}

		// Start the task
		rm.StartBackgroundTask("singleton-cleanup")

		// Create multiple plugin instances
		var plugins []*TraefikOidc
		for i := 0; i < 3; i++ {
			ctx := context.Background()
			config := &Config{
				ProviderURL:  fmt.Sprintf("https://example%d.com", i),
				ClientID:     fmt.Sprintf("client%d", i),
				ClientSecret: fmt.Sprintf("secret%d", i),
			}

			plugin, err := NewWithContext(ctx, config, nil, fmt.Sprintf("test-%d", i))
			if err != nil {
				t.Fatalf("Failed to create plugin %d: %v", i, err)
			}
			plugins = append(plugins, plugin)
		}

		// Wait for cleanup to run at least 2 times with adaptive timeout
		// This handles race detector overhead which can slow goroutine scheduling significantly
		// When running as part of full test suite, CPU contention is even higher, so use generous timeout
		const minExpectedCount = 2
		const maxExpectedCount = 5
		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		var count int32
	waitLoop:
		for {
			select {
			case <-ticker.C:
				count = atomic.LoadInt32(&cleanupCount)
				if count >= minExpectedCount {
					// Success: reached minimum threshold
					break waitLoop
				}
			case <-timeout:
				count = atomic.LoadInt32(&cleanupCount)
				t.Errorf("Timeout waiting for cleanup count to reach %d, got %d (race detector may be slowing execution)", minExpectedCount, count)
				break waitLoop
			}
		}

		// Verify count is within expected range (should be singleton, not running excessively)
		if count > maxExpectedCount {
			t.Errorf("Cleanup count too high: %d (expected max %d for singleton)", count, maxExpectedCount)
		}

		// Cleanup
		for _, plugin := range plugins {
			plugin.Close()
		}

		rm.StopBackgroundTask("singleton-cleanup")
	})
}

// TestResourcePooling tests resource pooling implementation
func TestResourcePooling(t *testing.T) {
	t.Run("GoroutinePoolLimiting", func(t *testing.T) {
		rm := GetResourceManager()

		// Configure pool with max workers
		pool := rm.GetGoroutinePool("test-pool", 5) // Max 5 workers

		if pool == nil {
			t.Fatal("Failed to get goroutine pool")
		}

		// Submit more tasks than pool size
		var taskCount int32
		var runningCount int32
		maxRunning := int32(0)

		for i := 0; i < 20; i++ {
			err := pool.Submit(func() {
				atomic.AddInt32(&taskCount, 1)
				current := atomic.AddInt32(&runningCount, 1)

				// Track max concurrent tasks
				for {
					oldMax := atomic.LoadInt32(&maxRunning)
					if current <= oldMax || atomic.CompareAndSwapInt32(&maxRunning, oldMax, current) {
						break
					}
				}

				time.Sleep(50 * time.Millisecond)
				atomic.AddInt32(&runningCount, -1)
			})

			if err != nil {
				t.Errorf("Failed to submit task %d: %v", i, err)
			}
		}

		// Wait for all tasks to complete
		pool.Wait()

		// Verify all tasks executed
		if atomic.LoadInt32(&taskCount) != 20 {
			t.Errorf("Expected 20 tasks to execute, got %d", taskCount)
		}

		// Verify concurrency was limited
		if atomic.LoadInt32(&maxRunning) > 5 {
			t.Errorf("Max concurrent tasks exceeded pool size: %d > 5", maxRunning)
		}
	})

	t.Run("PoolShutdown", func(t *testing.T) {
		rm := GetResourceManager()
		pool := rm.GetGoroutinePool("shutdown-pool", 3)

		// Submit tasks
		var completed int32
		for i := 0; i < 10; i++ {
			pool.Submit(func() {
				time.Sleep(10 * time.Millisecond)
				atomic.AddInt32(&completed, 1)
			})
		}

		// Shutdown pool
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err := pool.Shutdown(ctx)
		if err != nil {
			t.Errorf("Pool shutdown failed: %v", err)
		}

		// Try to submit after shutdown - should fail
		err = pool.Submit(func() {
			t.Error("Task should not execute after shutdown")
		})

		if err == nil {
			t.Error("Expected error when submitting to shutdown pool")
		}
	})

	t.Run("ResourceReuse", func(t *testing.T) {
		rm := GetResourceManager()

		// Get same pool multiple times
		pool1 := rm.GetGoroutinePool("reuse-pool", 3)
		pool2 := rm.GetGoroutinePool("reuse-pool", 3)

		if pool1 != pool2 {
			t.Error("Expected same pool instance for same key")
		}

		// Get HTTP client multiple times
		client1 := rm.GetHTTPClient("reuse-client")
		client2 := rm.GetHTTPClient("reuse-client")

		if client1 != client2 {
			t.Error("Expected same HTTP client instance for same key")
		}
	})
}

// TestBackwardCompatibility verifies the changes maintain backward compatibility
func TestBackwardCompatibility(t *testing.T) {
	t.Run("LegacyNewFunction", func(t *testing.T) {
		// Test that the original New function still works
		config := &Config{
			ProviderURL:  "https://example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		handler, err := New(context.Background(), nil, config, "test")
		if err != nil {
			t.Fatalf("Legacy New function failed: %v", err)
		}

		if handler == nil {
			t.Fatal("Handler should not be nil")
		}

		// Cleanup - cast to TraefikOidc if needed
		if plugin, ok := handler.(*TraefikOidc); ok {
			plugin.Close()
		}
	})

	t.Run("ExistingAPICompatibility", func(t *testing.T) {
		config := &Config{
			ProviderURL:  "https://example.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		handler, _ := New(context.Background(), nil, config, "test")

		// Test that the handler works
		if handler == nil {
			t.Error("Handler should not be nil")
		}

		// Cleanup - cast to TraefikOidc if needed
		if plugin, ok := handler.(*TraefikOidc); ok {
			plugin.Close()
		}
	})
}

// TestGoroutinePoolConditionVariable tests the condition variable-based Wait implementation
func TestGoroutinePoolConditionVariable(t *testing.T) {
	t.Run("WaitDoesNotBusyPoll", func(t *testing.T) {
		// This test verifies that Wait() uses condition variable instead of busy-polling
		pool := NewGoroutinePool(2, nil)
		defer pool.Shutdown(context.Background())

		// Submit a slow task
		var taskStarted, taskFinished int32
		pool.Submit(func() {
			atomic.StoreInt32(&taskStarted, 1)
			time.Sleep(100 * time.Millisecond)
			atomic.StoreInt32(&taskFinished, 1)
		})

		// Give task time to start
		time.Sleep(10 * time.Millisecond)

		// Measure CPU-time before Wait
		startCPU := time.Now()

		// Wait should block efficiently without consuming CPU
		pool.Wait()

		elapsed := time.Since(startCPU)

		// Verify task completed
		if atomic.LoadInt32(&taskFinished) != 1 {
			t.Error("Task should have finished")
		}

		// Wait should have taken ~90ms (task was already running for ~10ms)
		// If it was busy-polling, we would see much higher CPU usage
		// This is a sanity check - the real proof is in profiling
		if elapsed < 50*time.Millisecond {
			t.Errorf("Wait returned too quickly: %v", elapsed)
		}
	})

	t.Run("WaitReturnsImmediatelyWhenEmpty", func(t *testing.T) {
		pool := NewGoroutinePool(2, nil)
		defer pool.Shutdown(context.Background())

		// Wait on empty pool should return immediately
		start := time.Now()
		pool.Wait()
		elapsed := time.Since(start)

		// Should return almost immediately
		if elapsed > 10*time.Millisecond {
			t.Errorf("Wait on empty pool took too long: %v", elapsed)
		}
	})

	t.Run("ConcurrentSubmitAndWait", func(t *testing.T) {
		pool := NewGoroutinePool(4, nil)
		defer pool.Shutdown(context.Background())

		var completed int32
		const numTasks = 100

		// Submit tasks concurrently
		var wg sync.WaitGroup
		for i := 0; i < numTasks; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pool.Submit(func() {
					time.Sleep(1 * time.Millisecond)
					atomic.AddInt32(&completed, 1)
				})
			}()
		}

		wg.Wait() // Wait for all submissions

		// Wait for all tasks to complete
		pool.Wait()

		if atomic.LoadInt32(&completed) != numTasks {
			t.Errorf("Expected %d tasks completed, got %d", numTasks, completed)
		}
	})

	t.Run("WaitWithTimeoutSuccess", func(t *testing.T) {
		pool := NewGoroutinePool(2, nil)
		defer pool.Shutdown(context.Background())

		pool.Submit(func() {
			time.Sleep(50 * time.Millisecond)
		})

		// Should complete within timeout
		success := pool.WaitWithTimeout(1 * time.Second)
		if !success {
			t.Error("WaitWithTimeout should have succeeded")
		}
	})

	t.Run("WaitWithTimeoutExpired", func(t *testing.T) {
		pool := NewGoroutinePool(1, nil)
		defer pool.Shutdown(context.Background())

		pool.Submit(func() {
			time.Sleep(500 * time.Millisecond)
		})

		// Should timeout
		success := pool.WaitWithTimeout(50 * time.Millisecond)
		if success {
			t.Error("WaitWithTimeout should have timed out")
		}

		// Wait for actual completion to avoid goroutine leak in test
		pool.Wait()
	})

	t.Run("PendingTasksCounter", func(t *testing.T) {
		// Use pool with larger buffer (maxWorkers=2, buffer=4)
		pool := NewGoroutinePool(2, nil)
		defer pool.Shutdown(context.Background())

		// Initially no pending tasks
		if pool.PendingTasks() != 0 {
			t.Errorf("Expected 0 pending tasks, got %d", pool.PendingTasks())
		}

		// Block both workers with signals that tasks have started
		blocker1 := make(chan struct{})
		blocker2 := make(chan struct{})
		started1 := make(chan struct{})
		started2 := make(chan struct{})

		pool.Submit(func() {
			close(started1)
			<-blocker1
		})
		pool.Submit(func() {
			close(started2)
			<-blocker2
		})

		// Wait for both blocking tasks to actually start
		<-started1
		<-started2

		// Submit 2 more tasks that will queue up (buffer can hold 4)
		for i := 0; i < 2; i++ {
			pool.Submit(func() {
				time.Sleep(1 * time.Millisecond)
			})
		}

		// Should have pending tasks (2 running + 2 queued = 4)
		pending := pool.PendingTasks()
		if pending != 4 {
			t.Errorf("Expected 4 pending tasks, got %d", pending)
		}

		// Release blockers
		close(blocker1)
		close(blocker2)

		// Wait for completion
		pool.Wait()

		// Should have no pending tasks
		if pool.PendingTasks() != 0 {
			t.Errorf("Expected 0 pending tasks after Wait, got %d", pool.PendingTasks())
		}
	})

	t.Run("MultipleWaiters", func(t *testing.T) {
		pool := NewGoroutinePool(2, nil)
		defer pool.Shutdown(context.Background())

		// Submit a slow task
		pool.Submit(func() {
			time.Sleep(100 * time.Millisecond)
		})

		// Multiple goroutines waiting
		var waiters sync.WaitGroup
		var waitCount int32
		for i := 0; i < 5; i++ {
			waiters.Add(1)
			go func() {
				defer waiters.Done()
				pool.Wait()
				atomic.AddInt32(&waitCount, 1)
			}()
		}

		// All waiters should complete
		waiters.Wait()

		if atomic.LoadInt32(&waitCount) != 5 {
			t.Errorf("Expected all 5 waiters to complete, got %d", waitCount)
		}
	})

	t.Run("SubmitFailureDoesNotIncrementPending", func(t *testing.T) {
		pool := NewGoroutinePool(1, nil)

		// Shutdown the pool
		pool.Shutdown(context.Background())

		// Submit should fail
		err := pool.Submit(func() {})
		if err == nil {
			t.Error("Submit should fail on shutdown pool")
		}

		// Pending tasks should still be 0
		if pool.PendingTasks() != 0 {
			t.Errorf("Pending tasks should be 0 after failed submit, got %d", pool.PendingTasks())
		}
	})

	t.Run("PanicRecoveryDecrementsPending", func(t *testing.T) {
		pool := NewGoroutinePool(2, nil)
		defer pool.Shutdown(context.Background())

		// Submit a task that panics
		pool.Submit(func() {
			panic("test panic")
		})

		// Submit a normal task
		var normalCompleted int32
		pool.Submit(func() {
			atomic.StoreInt32(&normalCompleted, 1)
		})

		// Wait should still work (panic is recovered)
		pool.Wait()

		// Normal task should have completed
		if atomic.LoadInt32(&normalCompleted) != 1 {
			t.Error("Normal task should have completed despite panic in other task")
		}

		// Pending should be 0
		if pool.PendingTasks() != 0 {
			t.Errorf("Pending tasks should be 0 after Wait, got %d", pool.PendingTasks())
		}
	})
}

// BenchmarkGoroutinePoolWait benchmarks the Wait implementation
func BenchmarkGoroutinePoolWait(b *testing.B) {
	pool := NewGoroutinePool(4, nil)
	defer pool.Shutdown(context.Background())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Submit a quick task
		pool.Submit(func() {})
		pool.Wait()
	}
}

// BenchmarkGoroutinePoolHighThroughput benchmarks high throughput scenario
func BenchmarkGoroutinePoolHighThroughput(b *testing.B) {
	pool := NewGoroutinePool(8, nil)
	defer pool.Shutdown(context.Background())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			pool.Submit(func() {
				// Minimal work
				_ = 1 + 1
			})
		}
		pool.Wait()
	}
}

// Helper function to reset singleton for testing
func resetResourceManagerForTesting() {
	resourceManagerMutex.Lock()
	defer resourceManagerMutex.Unlock()

	if globalResourceManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		globalResourceManager.Shutdown(ctx)
	}

	resourceManagerOnce = sync.Once{}
	globalResourceManager = nil
}
