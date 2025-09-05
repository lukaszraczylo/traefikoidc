package traefikoidc

import (
	"net/http"
	"net/http/httptest"
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
		var taskRuns int64

		task := NewBackgroundTask(
			"test-task",
			10*time.Millisecond,
			func() { atomic.AddInt64(&taskRuns, 1) },
			nil,
		)

		// Register task for cleanup
		globalCleanup.RegisterTask(task)

		// Start the task
		task.Start()

		// Let it run a few times
		time.Sleep(50 * time.Millisecond)

		runs := atomic.LoadInt64(&taskRuns)
		if runs == 0 {
			t.Error("Background task should have run at least once")
		}

		t.Logf("Background task ran %d times", runs)
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
