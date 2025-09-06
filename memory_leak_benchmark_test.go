package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// MemoryTestSnapshot captures memory statistics at a point in time (renamed to avoid conflict)
type MemoryTestSnapshot struct {
	Timestamp   time.Time
	Alloc       uint64
	TotalAlloc  uint64
	Sys         uint64
	NumGC       uint32
	Goroutines  int
	Description string
}

// TakeMemorySnapshot captures current memory state
func TakeMemorySnapshot(description string) MemoryTestSnapshot {
	runtime.GC()
	runtime.GC() // Double GC for accuracy
	debug.FreeOSMemory()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MemoryTestSnapshot{
		Timestamp:   time.Now(),
		Alloc:       m.Alloc,
		TotalAlloc:  m.TotalAlloc,
		Sys:         m.Sys,
		NumGC:       m.NumGC,
		Goroutines:  runtime.NumGoroutine(),
		Description: description,
	}
}

// MemoryDiff calculates the difference between two memory snapshots
type MemoryDiff struct {
	AllocDiff      int64
	TotalAllocDiff int64
	SysDiff        int64
	GCDiff         int32
	GoroutineDiff  int
	Duration       time.Duration
}

func (before MemoryTestSnapshot) Diff(after MemoryTestSnapshot) MemoryDiff {
	return MemoryDiff{
		AllocDiff:      int64(after.Alloc) - int64(before.Alloc),
		TotalAllocDiff: int64(after.TotalAlloc) - int64(before.TotalAlloc),
		SysDiff:        int64(after.Sys) - int64(before.Sys),
		GCDiff:         int32(after.NumGC) - int32(before.NumGC),
		GoroutineDiff:  after.Goroutines - before.Goroutines,
		Duration:       after.Timestamp.Sub(before.Timestamp),
	}
}

// BenchmarkMemoryLeaks_FullPluginLifecycle benchmarks memory usage across full plugin lifecycle
func BenchmarkMemoryLeaks_FullPluginLifecycle(b *testing.B) {
	baseline := TakeMemorySnapshot("baseline")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create plugin instance
		ctx := context.Background()
		config := CreateConfig()
		config.ProviderURL = "https://accounts.google.com"
		config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
		config.ClientID = "test-client-id"
		config.ClientSecret = "test-client-secret"

		handler, err := New(ctx, nil, config, "benchmark")
		if err != nil {
			b.Fatalf("Failed to create plugin: %v", err)
		}
		plugin := handler.(*TraefikOidc)

		// Simulate plugin usage
		// (In real scenarios, this would process HTTP requests)
		time.Sleep(time.Millisecond) // Brief usage simulation

		// Proper cleanup using Close() method
		if err := plugin.Close(); err != nil {
			b.Logf("Plugin cleanup error at iteration %d: %v", i, err)
		}

		// Take periodic snapshots
		if i%100 == 99 || i == b.N-1 {
			snapshot := TakeMemorySnapshot(fmt.Sprintf("iteration_%d", i))

			// Check for significant memory growth
			diff := baseline.Diff(snapshot)
			maxExpectedGrowth := int64(1024 * 1024) // 1MB tolerance

			if diff.AllocDiff > maxExpectedGrowth {
				b.Fatalf("Memory leak detected at iteration %d: %d bytes growth",
					i, diff.AllocDiff)
			}
		}
	}

	b.StopTimer()

	// Final analysis
	final := TakeMemorySnapshot("final")
	finalDiff := baseline.Diff(final)

	b.Logf("Plugin lifecycle benchmark completed:")
	b.Logf("  Iterations: %d", b.N)
	b.Logf("  Final memory growth: %d bytes", finalDiff.AllocDiff)
	b.Logf("  Goroutine growth: %d", finalDiff.GoroutineDiff)
	b.Logf("  GC cycles: %d", finalDiff.GCDiff)
	b.Logf("  Memory per operation: %.2f bytes", float64(finalDiff.AllocDiff)/float64(b.N))

	// Verify acceptable memory usage
	if finalDiff.GoroutineDiff > 5 {
		b.Errorf("Goroutine leak: %d excess goroutines", finalDiff.GoroutineDiff)
	}
}

// BenchmarkMemoryLeaks_SessionChunkManager benchmarks session chunk manager memory usage
func BenchmarkMemoryLeaks_SessionChunkManager(b *testing.B) {
	cm := NewChunkManager(nil)
	baseline := TakeMemorySnapshot("chunk_manager_baseline")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create and process token chunks
		chunks := make(map[int]*sessions.Session)
		chunkCount := i%5 + 1 // Vary chunk count

		for c := 0; c < chunkCount; c++ {
			session := &sessions.Session{
				Values: map[interface{}]interface{}{
					"token_chunk": fmt.Sprintf("chunk_%d_data_%s", c, generateTestToken(100)),
				},
			}
			chunks[c] = session
		}

		// Process token retrieval
		result := cm.GetToken("", false, chunks, AccessTokenConfig)
		if result.Error != nil && i%1000 == 0 {
			b.Logf("Token processing error at iteration %d: %v", i, result.Error)
		}

		// Simulate session cleanup
		if i%100 == 99 {
			cm.CleanupExpiredSessions()
		}

		// Periodic memory check
		if i%10000 == 9999 {
			current := TakeMemorySnapshot("chunk_manager_periodic")
			diff := baseline.Diff(current)

			maxExpected := int64(cm.maxSessions * 1024) // 1KB per session
			if diff.AllocDiff > maxExpected*2 {
				b.Fatalf("Session chunk manager memory leak at iteration %d: %d bytes",
					i, diff.AllocDiff)
			}
		}
	}

	b.StopTimer()

	final := TakeMemorySnapshot("chunk_manager_final")
	diff := baseline.Diff(final)

	b.Logf("Session chunk manager benchmark:")
	b.Logf("  Memory growth: %d bytes", diff.AllocDiff)
	b.Logf("  Sessions in manager: %d", len(cm.sessionMap))
	b.Logf("  Memory per operation: %.2f bytes", float64(diff.AllocDiff)/float64(b.N))
}

// BenchmarkMemoryLeaks_BackgroundTasks benchmarks background task memory usage
func BenchmarkMemoryLeaks_BackgroundTasks(b *testing.B) {
	baseline := TakeMemorySnapshot("background_tasks_baseline")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create short-lived background task
		task := NewBackgroundTask(
			"benchmark-task",
			10*time.Millisecond,
			func() {
				// Minimal work to avoid affecting benchmark
				time.Sleep(time.Microsecond)
			},
			nil,
		)

		task.Start()
		time.Sleep(25 * time.Millisecond) // Let task run briefly
		task.Stop()

		// Periodic memory validation
		if i%1000 == 999 {
			current := TakeMemorySnapshot("background_tasks_periodic")
			diff := baseline.Diff(current)

			// Background tasks should not accumulate memory
			maxExpected := int64(1024 * 100) // 100KB tolerance
			if diff.AllocDiff > maxExpected {
				b.Fatalf("Background task memory leak at iteration %d: %d bytes",
					i, diff.AllocDiff)
			}

			// Should not accumulate goroutines
			if diff.GoroutineDiff > 10 {
				b.Fatalf("Background task goroutine leak at iteration %d: %d goroutines",
					i, diff.GoroutineDiff)
			}
		}
	}

	b.StopTimer()

	final := TakeMemorySnapshot("background_tasks_final")
	diff := baseline.Diff(final)

	b.Logf("Background tasks benchmark:")
	b.Logf("  Memory growth: %d bytes", diff.AllocDiff)
	b.Logf("  Goroutine growth: %d", diff.GoroutineDiff)
	b.Logf("  Tasks created/destroyed: %d", b.N)
}

// BenchmarkMemoryLeaks_HTTPClientPool benchmarks HTTP client connection pool memory
func BenchmarkMemoryLeaks_HTTPClientPool(b *testing.B) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	factory := NewHTTPClientFactory()
	config := HTTPClientConfig{
		Timeout:             5 * time.Second,
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 25,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     30 * time.Second,
		KeepAlive:           30 * time.Second,
		DisableKeepAlives:   false,
	}

	baseline := TakeMemorySnapshot("http_client_baseline")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client := factory.CreateHTTPClient(config)

		// Make request
		resp, err := client.Get(server.URL)
		if err != nil {
			if i%1000 == 0 {
				b.Logf("HTTP request error at iteration %d: %v", i, err)
			}
			continue
		}
		resp.Body.Close()

		// Periodic memory check
		if i%5000 == 4999 {
			current := TakeMemorySnapshot("http_client_periodic")
			diff := baseline.Diff(current)

			// HTTP client pool should not grow unboundedly
			maxExpected := int64(config.MaxIdleConns * 10240) // 10KB per connection
			if diff.AllocDiff > maxExpected*2 {
				b.Fatalf("HTTP client pool memory leak at iteration %d: %d bytes",
					i, diff.AllocDiff)
			}
		}
	}

	b.StopTimer()

	final := TakeMemorySnapshot("http_client_final")
	diff := baseline.Diff(final)

	b.Logf("HTTP client pool benchmark:")
	b.Logf("  Memory growth: %d bytes", diff.AllocDiff)
	b.Logf("  Requests made: %d", b.N)
	b.Logf("  Memory per request: %.2f bytes", float64(diff.AllocDiff)/float64(b.N))
}

// BenchmarkMemoryLeaks_CacheOperations benchmarks unified cache memory usage
func BenchmarkMemoryLeaks_CacheOperations(b *testing.B) {
	config := DefaultUnifiedCacheConfig()
	config.MaxSize = 1000
	config.Strategy = NewLRUStrategy(1000)

	cache := NewUnifiedCache(config)
	defer cache.Close()

	baseline := TakeMemorySnapshot("cache_baseline")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("cache_key_%d", i)
		value := fmt.Sprintf("cache_value_%d_%s", i, generateTestToken(50))

		// Cache operations
		switch i % 4 {
		case 0:
			cache.Set(key, value, time.Hour)
		case 1:
			cache.Get(key)
		case 2:
			cache.Delete(key)
		case 3:
			cache.Cleanup()
		}

		// Periodic memory validation
		if i%10000 == 9999 {
			current := TakeMemorySnapshot("cache_periodic")
			diff := baseline.Diff(current)

			// Cache memory should be bounded by max size
			maxExpected := int64(config.MaxSize * 2048) // 2KB per item
			if diff.AllocDiff > maxExpected*2 {
				b.Fatalf("Cache memory leak at iteration %d: %d bytes", i, diff.AllocDiff)
			}
		}
	}

	b.StopTimer()

	final := TakeMemorySnapshot("cache_final")
	diff := baseline.Diff(final)

	metrics := cache.GetMetrics()

	b.Logf("Cache operations benchmark:")
	b.Logf("  Memory growth: %d bytes", diff.AllocDiff)
	b.Logf("  Cache size: %v", metrics["item_count"])
	b.Logf("  Operations performed: %d", b.N)
}

// BenchmarkMemoryLeaks_ConcurrentOperations benchmarks memory under concurrent load
func BenchmarkMemoryLeaks_ConcurrentOperations(b *testing.B) {
	baseline := TakeMemorySnapshot("concurrent_baseline")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Mix of operations that could cause memory leaks
			switch i % 6 {
			case 0:
				// Plugin creation/destruction
				testConcurrentPluginOps()
			case 1:
				// Session chunk operations
				testConcurrentSessionOps()
			case 2:
				// Background task operations
				testConcurrentBackgroundTaskOps()
			case 3:
				// HTTP client operations
				testConcurrentHTTPClientOps()
			case 4:
				// Cache operations
				testConcurrentCacheOps()
			case 5:
				// Memory validation
				if i%10000 == 9999 {
					current := TakeMemorySnapshot("concurrent_check")
					diff := baseline.Diff(current)

					// Under concurrent load, allow more memory growth but detect leaks
					maxExpected := int64(10 * 1024 * 1024) // 10MB tolerance
					if diff.AllocDiff > maxExpected {
						b.Fatalf("Concurrent operations memory leak: %d bytes", diff.AllocDiff)
					}
				}
			}
			i++
		}
	})

	b.StopTimer()

	final := TakeMemorySnapshot("concurrent_final")
	diff := baseline.Diff(final)

	b.Logf("Concurrent operations benchmark:")
	b.Logf("  Memory growth: %d bytes", diff.AllocDiff)
	b.Logf("  Goroutine growth: %d", diff.GoroutineDiff)
	b.Logf("  Operations completed: %d", b.N)
}

// Helper functions for concurrent testing

func testConcurrentPluginOps() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	config := CreateConfig()
	config.ProviderURL = "https://accounts.google.com"
	config.SessionEncryptionKey = "test-key-12345678901234567890123"
	config.ClientID = "test"
	config.ClientSecret = "test"

	handler, err := New(ctx, nil, config, "concurrent")
	if err == nil && handler != nil {
		plugin := handler.(*TraefikOidc)
		// Proper cleanup using Close() method
		plugin.Close()
	}
}

func testConcurrentSessionOps() {
	cm := NewChunkManager(nil)
	chunks := map[int]*sessions.Session{
		0: {Values: map[interface{}]interface{}{"token_chunk": generateTestToken(50)}},
	}
	cm.GetToken("", false, chunks, AccessTokenConfig)
	cm.CleanupExpiredSessions()
}

func testConcurrentBackgroundTaskOps() {
	task := NewBackgroundTask("concurrent-test", time.Millisecond, func() {}, nil)
	task.Start()
	time.Sleep(2 * time.Millisecond)
	task.Stop()
}

func testConcurrentHTTPClientOps() {
	factory := NewHTTPClientFactory()
	config := DefaultHTTPClientConfig()
	client := factory.CreateHTTPClient(config)
	_ = client // Use the client reference to prevent optimization
}

func testConcurrentCacheOps() {
	cache := NewUnifiedCacheSimple()
	defer cache.Close()

	key := generateTestToken(10)
	value := generateTestToken(20)

	cache.Set(key, value, time.Minute)
	cache.Get(key)
	cache.Delete(key)
}

// generateTestToken creates a test token string of specified length
func generateTestToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[i%len(charset)]
	}
	return string(result)
}

// TestMemoryLeakDetection_Integration runs integration tests to detect memory leaks
func TestMemoryLeakDetection_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak integration test in short mode")
	}

	tests := []struct {
		name          string
		testFunc      func(*testing.T) MemoryDiff
		maxMemory     int64 // Maximum acceptable memory growth in bytes
		maxGoroutines int   // Maximum acceptable goroutine growth
	}{
		{
			name:          "plugin_lifecycle",
			testFunc:      testPluginLifecycleMemory,
			maxMemory:     2 * 1024 * 1024, // 2MB - increased for plugin lifecycle overhead
			maxGoroutines: 5,               // Allow for background tasks
		},
		{
			name:          "session_management",
			testFunc:      testSessionManagementMemory,
			maxMemory:     512 * 1024, // 512KB
			maxGoroutines: 2,
		},
		{
			name:          "background_tasks",
			testFunc:      testBackgroundTasksMemory,
			maxMemory:     256 * 1024, // 256KB
			maxGoroutines: 1,
		},
		{
			name:          "cache_operations",
			testFunc:      testCacheOperationsMemory,
			maxMemory:     2 * 1024 * 1024, // 2MB
			maxGoroutines: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := tt.testFunc(t)

			if diff.AllocDiff > tt.maxMemory {
				t.Errorf("Memory leak detected in %s: %d bytes growth (max: %d)",
					tt.name, diff.AllocDiff, tt.maxMemory)
			}

			if diff.GoroutineDiff > tt.maxGoroutines {
				t.Errorf("Goroutine leak detected in %s: %d goroutines (max: %d)",
					tt.name, diff.GoroutineDiff, tt.maxGoroutines)
			}

			t.Logf("%s: Memory growth: %d bytes, Goroutine growth: %d",
				tt.name, diff.AllocDiff, diff.GoroutineDiff)
		})
	}
}

func testPluginLifecycleMemory(t *testing.T) MemoryDiff {
	baseline := TakeMemorySnapshot("plugin_lifecycle_baseline")

	for i := 0; i < 50; i++ {
		ctx := context.Background()
		config := CreateConfig()
		config.ProviderURL = "https://accounts.google.com"
		config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
		config.ClientID = "test"
		config.ClientSecret = "test"

		handler, err := New(ctx, nil, config, "test")
		if err != nil {
			t.Logf("Plugin creation error: %v", err)
			continue
		}

		if handler != nil {
			plugin := handler.(*TraefikOidc)
			// Proper cleanup using Close() method
			if err := plugin.Close(); err != nil {
				t.Logf("Plugin close error: %v", err)
			}
		}

		// Allow time for cleanup
		if i%10 == 9 {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Final cleanup before measurement
	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	final := TakeMemorySnapshot("plugin_lifecycle_final")
	return baseline.Diff(final)
}

func testSessionManagementMemory(t *testing.T) MemoryDiff {
	baseline := TakeMemorySnapshot("session_management_baseline")

	cm := NewChunkManager(nil)

	for i := 0; i < 1000; i++ {
		chunks := map[int]*sessions.Session{
			0: {Values: map[interface{}]interface{}{"token_chunk": generateTestToken(100)}},
		}
		cm.GetToken("", false, chunks, AccessTokenConfig)

		if i%100 == 99 {
			cm.CleanupExpiredSessions()
		}
	}

	final := TakeMemorySnapshot("session_management_final")
	return baseline.Diff(final)
}

func testBackgroundTasksMemory(t *testing.T) MemoryDiff {
	baseline := TakeMemorySnapshot("background_tasks_baseline")

	for i := 0; i < 100; i++ {
		task := NewBackgroundTask("test", 5*time.Millisecond, func() {}, nil)
		task.Start()
		time.Sleep(10 * time.Millisecond)
		task.Stop()
	}

	final := TakeMemorySnapshot("background_tasks_final")
	return baseline.Diff(final)
}

func testCacheOperationsMemory(t *testing.T) MemoryDiff {
	baseline := TakeMemorySnapshot("cache_operations_baseline")

	config := DefaultUnifiedCacheConfig()
	config.MaxSize = 100
	cache := NewUnifiedCache(config)
	defer cache.Close()

	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key_%d", i)
		value := generateTestToken(100)
		cache.Set(key, value, time.Hour)

		if i%10 == 5 {
			cache.Get(fmt.Sprintf("key_%d", i-5))
		}

		if i%50 == 49 {
			cache.Cleanup()
		}
	}

	final := TakeMemorySnapshot("cache_operations_final")
	return baseline.Diff(final)
}
