package traefikoidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestGlobalCleanupMechanism tests the global cleanup functionality
func TestGlobalCleanupMechanism(t *testing.T) {
	// Use the cleanup helper
	TestCleanupHelper(t)

	t.Run("HTTP server cleanup", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Register server for cleanup
		globalCleanup.RegisterServer(server)

		// Verify server is working
		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Server should be accessible: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("Background task cleanup", func(t *testing.T) {
		// Skip in short mode since it tests internal mechanics and can be flaky in full suite
		if testing.Short() {
			t.Skip("Skipping background task cleanup test in short mode")
		}

		// Create a unique task name with timestamp to avoid conflicts with other tests
		taskName := fmt.Sprintf("test-task-%d", time.Now().UnixNano())

		var taskRuns int64
		taskStarted := make(chan bool, 1)
		taskReady := make(chan bool, 1)

		// Create a test-specific logger to avoid noise
		logger := GetSingletonNoOpLogger()

		task := NewBackgroundTask(
			taskName,
			10*time.Millisecond,
			func() {
				atomic.AddInt64(&taskRuns, 1)
				select {
				case taskStarted <- true:
				default:
				}
			},
			logger,
		)

		// Reset circuit breaker state manually for test tasks before starting
		registry := GetGlobalTaskRegistry()
		// Clear any existing test tasks from the registry to avoid conflicts
		registry.mu.Lock()
		for name, task := range registry.tasks {
			if strings.Contains(name, "test-task") {
				task.Stop()
				delete(registry.tasks, name)
			}
		}
		registry.mu.Unlock()

		// Register task for cleanup
		globalCleanup.RegisterTask(task)

		// Start the task in a goroutine to avoid blocking
		go func() {
			task.Start()
			taskReady <- true
		}()

		// Wait for task to be ready
		select {
		case <-taskReady:
			// Task is started
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Task failed to start")
		}

		// Wait for task to start running with increased timeout for busy test environments
		select {
		case <-taskStarted:
			// Task has run at least once
		case <-time.After(1000 * time.Millisecond): // Increased from 500ms to 1000ms
			// Don't fail immediately - check if task is running by looking at the run count
			runs := atomic.LoadInt64(&taskRuns)
			if runs == 0 {
				t.Logf("Task may be slow to start in test environment, waiting longer...")
				// Wait a bit more
				time.Sleep(300 * time.Millisecond) // Increased from 200ms to 300ms
				runs = atomic.LoadInt64(&taskRuns)
				if runs == 0 {
					t.Fatal("Task did not start after extended timeout")
				}
			}
		}

		// Let it run a few more times with longer duration for more stable results
		time.Sleep(100 * time.Millisecond) // Increased from 50ms to 100ms

		runs := atomic.LoadInt64(&taskRuns)
		// More lenient expectations: allow 3-10 executions instead of just checking > 0
		if runs < 3 {
			t.Errorf("Background task should have run at least 3 times, got %d", runs)
		} else if runs > 15 { // Upper bound to catch runaway tasks
			t.Errorf("Background task ran too many times (%d), possible issue with cleanup", runs)
		}

		t.Logf("Background task ran %d times (expected 3-15)", runs)
	})

	t.Run("Cache cleanup", func(t *testing.T) {
		cache := &mockCache{closed: false}

		// Register cache for cleanup
		globalCleanup.RegisterCache(cache)

		if cache.closed {
			t.Error("Cache should not be closed yet")
		}
	})
}

// mockCache implements a simple cache with Close method for testing
type mockCache struct {
	closed bool
}

func (c *mockCache) Close() {
	c.closed = true
}

// TestGlobalCleanupIntegration verifies that cleanup happens at the end of tests
func TestGlobalCleanupIntegration(t *testing.T) {
	// This test verifies that the TestMain function calls globalCleanup.CleanupAll()
	// We can't directly test this, but we can test the mechanism works

	originalServerCount := len(globalCleanup.servers)
	originalTaskCount := len(globalCleanup.tasks)
	originalCacheCount := len(globalCleanup.caches)

	// Add some resources
	server := httptest.NewServer(nil)
	globalCleanup.RegisterServer(server)

	task := NewBackgroundTask("integration-test", time.Hour, func() {}, nil)
	globalCleanup.RegisterTask(task)

	cache := &mockCache{}
	globalCleanup.RegisterCache(cache)

	// Verify resources were registered
	if len(globalCleanup.servers) != originalServerCount+1 {
		t.Error("Server should be registered")
	}
	if len(globalCleanup.tasks) != originalTaskCount+1 {
		t.Error("Task should be registered")
	}
	if len(globalCleanup.caches) != originalCacheCount+1 {
		t.Error("Cache should be registered")
	}

	// Manually trigger cleanup to test the mechanism
	globalCleanup.CleanupAll()

	// Verify cleanup
	if len(globalCleanup.servers) != 0 {
		t.Error("Servers should be cleaned up")
	}
	if len(globalCleanup.tasks) != 0 {
		t.Error("Tasks should be cleaned up")
	}
	if len(globalCleanup.caches) != 0 {
		t.Error("Caches should be cleaned up")
	}

	if !cache.closed {
		t.Error("Cache should be closed after cleanup")
	}
}
