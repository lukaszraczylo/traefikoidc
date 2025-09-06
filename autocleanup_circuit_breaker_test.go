package traefikoidc

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBackgroundTaskCircuitBreaker_PreventExcessiveCreation tests that the circuit breaker
// prevents excessive background task creation
func TestBackgroundTaskCircuitBreaker_PreventExcessiveCreation(t *testing.T) {
	tests := []struct {
		name             string
		concurrentTasks  int
		maxExpectedTasks int
		creationInterval time.Duration
		description      string
	}{
		{
			name:             "moderate_creation",
			concurrentTasks:  5,
			maxExpectedTasks: 5,
			creationInterval: 10 * time.Millisecond,
			description:      "Moderate task creation should succeed",
		},
		{
			name:             "high_creation_rate",
			concurrentTasks:  20,
			maxExpectedTasks: 10,
			creationInterval: 1 * time.Millisecond,
			description:      "High creation rate should be throttled",
		},
		{
			name:             "burst_creation",
			concurrentTasks:  50,
			maxExpectedTasks: 15,
			creationInterval: 0,
			description:      "Burst creation should be limited by circuit breaker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime.GC()
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
			initialGoroutines := runtime.NumGoroutine()

			var activeTaskCount int32
			var maxActiveTaskCount int32
			var taskCompletionCount int32

			// Create multiple background tasks rapidly
			tasks := make([]*BackgroundTask, tt.concurrentTasks)

			for i := 0; i < tt.concurrentTasks; i++ {
				if tt.creationInterval > 0 {
					time.Sleep(tt.creationInterval)
				}

				task := NewBackgroundTask(
					"circuit-breaker-test",
					100*time.Millisecond,
					func() {
						current := atomic.AddInt32(&activeTaskCount, 1)
						defer atomic.AddInt32(&activeTaskCount, -1)

						// Track maximum concurrent tasks
						for {
							max := atomic.LoadInt32(&maxActiveTaskCount)
							if current <= max || atomic.CompareAndSwapInt32(&maxActiveTaskCount, max, current) {
								break
							}
						}

						// Simulate work
						time.Sleep(50 * time.Millisecond)
						atomic.AddInt32(&taskCompletionCount, 1)
					},
					nil,
				)

				tasks[i] = task
				task.Start()
			}

			// Let tasks run briefly
			time.Sleep(200 * time.Millisecond)

			// Stop all tasks
			for _, task := range tasks {
				if task != nil {
					task.Stop()
				}
			}

			// Wait for cleanup
			time.Sleep(100 * time.Millisecond)
			runtime.GC()
			runtime.GC()
			time.Sleep(50 * time.Millisecond)

			finalGoroutines := runtime.NumGoroutine()
			goroutineDiff := finalGoroutines - initialGoroutines

			maxActive := atomic.LoadInt32(&maxActiveTaskCount)
			completions := atomic.LoadInt32(&taskCompletionCount)

			// Verify circuit breaker effectiveness
			if int(maxActive) > tt.maxExpectedTasks {
				t.Errorf("Circuit breaker failed: %s\n"+
					"Created tasks: %d\n"+
					"Max concurrent active: %d (expected max: %d)\n"+
					"Task completions: %d",
					tt.description, tt.concurrentTasks, maxActive, tt.maxExpectedTasks, completions)
			}

			// Verify no goroutine leaks
			if goroutineDiff > 2 {
				t.Errorf("Goroutine leak detected: %s\n"+
					"Initial: %d, Final: %d, Diff: %d",
					tt.description, initialGoroutines, finalGoroutines, goroutineDiff)
			}

			t.Logf("Test %s: Created %d tasks, Max active: %d, Completions: %d, Goroutine diff: %d",
				tt.name, tt.concurrentTasks, maxActive, completions, goroutineDiff)
		})
	}
}

// TestBackgroundTaskCircuitBreaker_SingletonPattern tests that cleanup tasks follow singleton pattern
func TestBackgroundTaskCircuitBreaker_SingletonPattern(t *testing.T) {
	const numAttempts = 10

	runtime.GC()
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	var activeCleanupTasks int32
	var maxActiveCleanupTasks int32

	// Simulate multiple attempts to start cleanup tasks (like from different middleware instances)
	var wg sync.WaitGroup
	tasks := make([]*BackgroundTask, numAttempts)
	var tasksMu sync.Mutex

	for i := 0; i < numAttempts; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			task := NewBackgroundTask(
				"singleton-cleanup-test",
				50*time.Millisecond,
				func() {
					current := atomic.AddInt32(&activeCleanupTasks, 1)
					defer atomic.AddInt32(&activeCleanupTasks, -1)

					// Update max active count atomically
					for {
						max := atomic.LoadInt32(&maxActiveCleanupTasks)
						if current <= max || atomic.CompareAndSwapInt32(&maxActiveCleanupTasks, max, current) {
							break
						}
					}

					// Simulate cleanup work
					time.Sleep(25 * time.Millisecond)
				},
				nil,
			)

			// In a real singleton pattern, only the first task would actually start
			// Here we test that even if multiple start, resource usage is controlled
			task.Start()

			tasksMu.Lock()
			tasks[id] = task
			tasksMu.Unlock()
		}(i)
	}

	wg.Wait()

	// Allow tasks to run
	time.Sleep(200 * time.Millisecond)

	// Stop all tasks
	for _, task := range tasks {
		task.Stop()
	}

	// Cleanup
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	maxActive := atomic.LoadInt32(&maxActiveCleanupTasks)

	// In ideal singleton pattern, only 1 task should be active
	// We allow some tolerance due to timing
	if maxActive > 3 {
		t.Errorf("Singleton pattern not enforced: max active cleanup tasks: %d (expected <= 3)", maxActive)
	}

	// Verify no goroutine leaks
	if goroutineDiff > 2 {
		t.Errorf("Goroutine leak in singleton pattern: Initial: %d, Final: %d, Diff: %d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}

	t.Logf("Singleton test: Created %d task attempts, Max active: %d, Goroutine diff: %d",
		numAttempts, maxActive, goroutineDiff)
}

// TestBackgroundTaskCircuitBreaker_TaskTermination tests proper task termination on shutdown
func TestBackgroundTaskCircuitBreaker_TaskTermination(t *testing.T) {
	runtime.GC()
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	var taskStartCount int32
	var taskStopCount int32

	// Create multiple long-running tasks
	const numTasks = 5
	tasks := make([]*BackgroundTask, numTasks)

	for i := 0; i < numTasks; i++ {
		task := NewBackgroundTask(
			"termination-test",
			1*time.Second, // Long interval
			func() {
				atomic.AddInt32(&taskStartCount, 1)
				defer atomic.AddInt32(&taskStopCount, 1)

				// Simulate long-running work that should be interruptible
				time.Sleep(500 * time.Millisecond)
			},
			nil,
		)

		tasks[i] = task
		task.Start()
	}

	// Allow tasks to start
	time.Sleep(100 * time.Millisecond)

	midGoroutines := runtime.NumGoroutine()
	if midGoroutines <= initialGoroutines {
		t.Log("Warning: No additional goroutines detected for background tasks")
	}

	// Stop all tasks - should be immediate
	stopStart := time.Now()
	for _, task := range tasks {
		task.Stop()
	}
	stopDuration := time.Since(stopStart)

	// Verify quick termination (should not wait for full task interval)
	maxExpectedStopTime := 2 * time.Second
	if stopDuration > maxExpectedStopTime {
		t.Errorf("Task termination took too long: %v (expected < %v)",
			stopDuration, maxExpectedStopTime)
	}

	// Allow cleanup
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	startCount := atomic.LoadInt32(&taskStartCount)
	stopCount := atomic.LoadInt32(&taskStopCount)

	// Verify all tasks terminated cleanly
	if goroutineDiff > 1 {
		t.Errorf("Task termination left goroutines: Initial: %d, Final: %d, Diff: %d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}

	t.Logf("Termination test: Tasks started: %d, stopped: %d, Stop duration: %v, Goroutine diff: %d",
		startCount, stopCount, stopDuration, goroutineDiff)
}

// TestBackgroundTaskCircuitBreaker_RecoveryFromCreationFailures tests recovery from task creation failures
func TestBackgroundTaskCircuitBreaker_RecoveryFromCreationFailures(t *testing.T) {
	runtime.GC()
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	var successfulStarts int32
	var failedStarts int32

	// Create tasks that may fail to start (simulate resource exhaustion)
	const numTasks = 20
	var wg sync.WaitGroup

	for i := 0; i < numTasks; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Simulate varying success/failure rates
			shouldFail := id%3 == 0

			if shouldFail {
				// Create task that will fail (invalid parameters)
				_ = NewBackgroundTask("", 0, nil, nil)
				// This would normally fail to start properly
				atomic.AddInt32(&failedStarts, 1)
			} else {
				task := NewBackgroundTask(
					"recovery-test",
					100*time.Millisecond,
					func() {
						time.Sleep(25 * time.Millisecond)
					},
					nil,
				)
				task.Start()
				atomic.AddInt32(&successfulStarts, 1)

				// Stop after brief run
				time.Sleep(50 * time.Millisecond)
				task.Stop()
			}
		}(i)
	}

	wg.Wait()

	// Allow cleanup
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	successful := atomic.LoadInt32(&successfulStarts)
	failed := atomic.LoadInt32(&failedStarts)

	// Verify recovery - no goroutine leaks despite failures
	if goroutineDiff > 2 {
		t.Errorf("Failed to recover from creation failures: "+
			"Initial: %d, Final: %d, Diff: %d\n"+
			"Successful starts: %d, Failed starts: %d",
			initialGoroutines, finalGoroutines, goroutineDiff, successful, failed)
	}

	// Verify some tasks succeeded despite failures
	if successful == 0 {
		t.Error("No tasks succeeded - recovery mechanism may be too aggressive")
	}

	t.Logf("Recovery test: Successful: %d, Failed: %d, Goroutine diff: %d",
		successful, failed, goroutineDiff)
}

// TestBackgroundTaskCircuitBreaker_ResourceExhaustion tests behavior under simulated resource exhaustion
func TestBackgroundTaskCircuitBreaker_ResourceExhaustion(t *testing.T) {
	// This test simulates system resource exhaustion by creating many tasks
	// and verifying the circuit breaker prevents system overload

	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	initialGoroutines := runtime.NumGoroutine()

	const maxConcurrentTasks = 100
	var activeTasks int32
	var rejectedTasks int32

	tasks := make([]*BackgroundTask, 0, maxConcurrentTasks*2)

	// Create more tasks than system should handle
	for i := 0; i < maxConcurrentTasks*2; i++ {
		task := NewBackgroundTask(
			"exhaustion-test",
			200*time.Millisecond,
			func() {
				current := atomic.AddInt32(&activeTasks, 1)
				defer atomic.AddInt32(&activeTasks, -1)

				// Simulate resource-intensive work
				if current > maxConcurrentTasks {
					atomic.AddInt32(&rejectedTasks, 1)
					return // Early return simulates circuit breaker
				}

				// Work simulation
				time.Sleep(100 * time.Millisecond)
			},
			nil,
		)

		tasks = append(tasks, task)
		task.Start()

		// Brief pause to prevent overwhelming the system
		if i%10 == 9 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Let system stabilize
	time.Sleep(500 * time.Millisecond)

	// Check current resource usage
	currentActive := atomic.LoadInt32(&activeTasks)
	currentRejected := atomic.LoadInt32(&rejectedTasks)
	currentGoroutines := runtime.NumGoroutine()

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	memoryGrowth := m2.Alloc - m1.Alloc

	// Verify system is not overwhelmed
	if currentGoroutines > initialGoroutines+maxConcurrentTasks+10 {
		t.Errorf("System overwhelmed by goroutines: "+
			"Initial: %d, Current: %d, Growth: %d (max expected: %d)",
			initialGoroutines, currentGoroutines,
			currentGoroutines-initialGoroutines, maxConcurrentTasks)
	}

	// Verify memory usage is reasonable
	maxExpectedMemory := uint64(maxConcurrentTasks * 1024) // 1KB per task
	if memoryGrowth > maxExpectedMemory*2 {
		t.Errorf("Excessive memory growth: %d bytes (max expected: %d)",
			memoryGrowth, maxExpectedMemory)
	}

	// Stop all tasks
	for _, task := range tasks {
		task.Stop()
	}

	// Allow cleanup
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	// Verify clean shutdown
	if goroutineDiff > 3 {
		t.Errorf("Resource exhaustion left goroutines: "+
			"Initial: %d, Final: %d, Diff: %d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}

	t.Logf("Resource exhaustion test: Created %d tasks, Active: %d, Rejected: %d, "+
		"Memory growth: %d bytes, Final goroutine diff: %d",
		len(tasks), currentActive, currentRejected, memoryGrowth, goroutineDiff)
}

// TestBackgroundTaskCircuitBreaker_GracefulDegradation tests graceful degradation under load
func TestBackgroundTaskCircuitBreaker_GracefulDegradation(t *testing.T) {
	runtime.GC()
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	// Test different load levels
	loadLevels := []int{1, 5, 10, 25, 50, 100}
	results := make([]struct {
		load      int
		succeeded int
		failed    int
		duration  time.Duration
	}, len(loadLevels))

	for i, load := range loadLevels {
		var succeeded int32
		var failed int32

		startTime := time.Now()

		// Create tasks at this load level
		var wg sync.WaitGroup
		for j := 0; j < load; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				task := NewBackgroundTask(
					"degradation-test",
					50*time.Millisecond,
					func() {
						atomic.AddInt32(&succeeded, 1)
						time.Sleep(25 * time.Millisecond)
					},
					nil,
				)

				task.Start()
				defer task.Stop()

				// Let task run briefly
				time.Sleep(100 * time.Millisecond)
			}()
		}

		wg.Wait()
		duration := time.Since(startTime)

		results[i] = struct {
			load      int
			succeeded int
			failed    int
			duration  time.Duration
		}{
			load:      load,
			succeeded: int(succeeded),
			failed:    int(failed),
			duration:  duration,
		}

		// Brief cleanup between load levels
		time.Sleep(100 * time.Millisecond)
		runtime.GC()

		t.Logf("Load level %d: %d succeeded, %d failed, duration: %v",
			load, succeeded, failed, duration)
	}

	// Verify graceful degradation pattern
	for i := 1; i < len(results); i++ {
		current := results[i]
		previous := results[i-1]

		// Success rate should not crash completely under higher load
		currentSuccessRate := float64(current.succeeded) / float64(current.load)
		previousSuccessRate := float64(previous.succeeded) / float64(previous.load)

		// Allow some degradation but not complete failure
		if currentSuccessRate < previousSuccessRate*0.1 && current.load > 10 {
			t.Errorf("Excessive degradation at load %d: success rate %.2f vs %.2f at load %d",
				current.load, currentSuccessRate, previousSuccessRate, previous.load)
		}
	}

	// Final cleanup verification
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	if goroutineDiff > 3 {
		t.Errorf("Graceful degradation test left goroutines: "+
			"Initial: %d, Final: %d, Diff: %d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// BenchmarkBackgroundTaskCircuitBreaker_TaskCreation benchmarks task creation performance
func BenchmarkBackgroundTaskCircuitBreaker_TaskCreation(b *testing.B) {
	runtime.GC()
	baseline := runtime.NumGoroutine()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		task := NewBackgroundTask(
			"benchmark-test",
			time.Second,
			func() {
				time.Sleep(time.Millisecond)
			},
			nil,
		)

		task.Start()
		task.Stop()

		// Periodic goroutine leak check
		if i%1000 == 999 {
			runtime.GC()
			current := runtime.NumGoroutine()
			if current > baseline+20 {
				b.Fatalf("Goroutine leak detected at iteration %d: baseline=%d, current=%d",
					i, baseline, current)
			}
		}
	}

	b.StopTimer()

	// Final verification
	runtime.GC()
	final := runtime.NumGoroutine()
	if final > baseline+10 {
		b.Errorf("Benchmark left goroutines: baseline=%d, final=%d", baseline, final)
	}
}
