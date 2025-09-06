package traefikoidc

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestGoroutineLeakPrevention_ContextCancellation tests that goroutines are properly cleaned up
// when the context is cancelled during middleware initialization and operation
func TestGoroutineLeakPrevention_ContextCancellation(t *testing.T) {
	tests := []struct {
		name          string
		cancelAfter   time.Duration
		expectedLeaks int // Maximum expected goroutines after cleanup
		description   string
	}{
		{
			name:          "immediate_cancellation",
			cancelAfter:   1 * time.Millisecond,
			expectedLeaks: 10, // Allow for background tasks (replay-cache-cleanup, health-check, etc.)
			description:   "Context cancelled immediately during initialization",
		},
		{
			name:          "quick_cancellation",
			cancelAfter:   50 * time.Millisecond,
			expectedLeaks: 5, // Allow for some background task leaks during cancellation
			description:   "Context cancelled during metadata initialization",
		},
		{
			name:          "delayed_cancellation",
			cancelAfter:   200 * time.Millisecond,
			expectedLeaks: 5, // Allow for some background task leaks during cancellation
			description:   "Context cancelled after partial initialization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record initial goroutine count
			runtime.GC()
			runtime.GC() // Double GC to ensure cleanup
			time.Sleep(10 * time.Millisecond)
			initialGoroutines := runtime.NumGoroutine()

			// Create cancellable context
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Create plugin config
			config := CreateConfig()
			config.ProviderURL = "https://accounts.google.com"
			config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
			config.ClientID = "test-client-id"
			config.ClientSecret = "test-client-secret"

			// Start goroutine leak test
			var plugin *TraefikOidc
			var wg sync.WaitGroup

			// Initialize plugin in separate goroutine to simulate real usage
			wg.Add(1)
			go func() {
				defer wg.Done()
				handler, _ := New(ctx, nil, config, "test")
				if handler != nil {
					plugin = handler.(*TraefikOidc)
				}
			}()

			// Cancel context after specified delay
			time.Sleep(tt.cancelAfter)
			cancel()

			// Wait for initialization to complete or timeout
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				// Initialization completed (or was cancelled)
			case <-time.After(5 * time.Second):
				t.Fatal("Plugin initialization did not complete within timeout")
			}

			// Clean up plugin if it was created
			if plugin != nil {
				// Use proper Close() method for cleanup
				if err := plugin.Close(); err != nil {
					t.Logf("Plugin close error: %v", err)
				}
			}

			// Allow time for goroutine cleanup
			time.Sleep(100 * time.Millisecond)
			runtime.GC()
			runtime.GC()
			time.Sleep(50 * time.Millisecond)

			// Check final goroutine count
			finalGoroutines := runtime.NumGoroutine()
			goroutineDiff := finalGoroutines - initialGoroutines

			if goroutineDiff > tt.expectedLeaks {
				t.Errorf("Goroutine leak detected: %s\n"+
					"Initial goroutines: %d\n"+
					"Final goroutines: %d\n"+
					"Difference: %d (expected max: %d)",
					tt.description, initialGoroutines, finalGoroutines,
					goroutineDiff, tt.expectedLeaks)
			}

			t.Logf("Test %s: Initial: %d, Final: %d, Diff: %d",
				tt.name, initialGoroutines, finalGoroutines, goroutineDiff)
		})
	}
}

// TestGoroutineLeakPrevention_PanicRecovery tests that goroutines are cleaned up
// even when panics occur during initialization
func TestGoroutineLeakPrevention_PanicRecovery(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create context that will be valid but cause initialization issues
	ctx := context.Background()

	// Create invalid config to potentially cause panics
	config := CreateConfig()
	config.ProviderURL = "://invalid-url"     // Invalid URL format
	config.SessionEncryptionKey = "too-short" // Invalid key length
	config.ClientID = ""
	config.ClientSecret = ""

	// Attempt to create plugin - should handle errors gracefully
	handler, err := New(ctx, nil, config, "test")
	var plugin *TraefikOidc
	if handler != nil {
		plugin = handler.(*TraefikOidc)
	}

	// Verify error is handled gracefully (no panic)
	if err == nil {
		t.Log("Plugin creation succeeded despite invalid config")
		if plugin != nil {
			// Clean up if somehow created using proper Close() method
			if err := plugin.Close(); err != nil {
				t.Logf("Plugin close error: %v", err)
			}
		}
	} else {
		t.Logf("Plugin creation failed as expected: %v", err)
	}

	// Allow cleanup time
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	if goroutineDiff > 5 { // Allow more tolerance for background tasks
		t.Errorf("Goroutine leak after panic recovery: "+
			"Initial: %d, Final: %d, Diff: %d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestGoroutineLeakPrevention_MultipleInstances tests that multiple middleware instances
// don't cause goroutine leaks
func TestGoroutineLeakPrevention_MultipleInstances(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	ctx := context.Background()
	const numInstances = 5
	plugins := make([]*TraefikOidc, 0, numInstances)

	// Create multiple plugin instances
	for i := 0; i < numInstances; i++ {
		config := CreateConfig()
		config.ProviderURL = "https://accounts.google.com"
		config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
		config.ClientID = "test-client-id"
		config.ClientSecret = "test-client-secret"

		handler, err := New(ctx, nil, config, "test")
		if err != nil {
			t.Fatalf("Failed to create plugin instance %d: %v", i, err)
		}
		if handler != nil {
			plugin := handler.(*TraefikOidc)
			plugins = append(plugins, plugin)
		}
	}

	// Allow initialization to complete
	time.Sleep(100 * time.Millisecond)

	// Clean up all plugins
	var wg sync.WaitGroup
	for i, plugin := range plugins {
		wg.Add(1)
		go func(p *TraefikOidc, idx int) {
			defer wg.Done()
			// Use proper Close() method for cleanup
			if err := p.Close(); err != nil {
				t.Logf("Plugin %d close error: %v", idx, err)
			}
		}(plugin, i)
	}

	// Wait for all cleanups with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All cleanups completed
	case <-time.After(10 * time.Second):
		t.Fatal("Plugin cleanup did not complete within timeout")
	}

	// Allow final cleanup
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	// Allow for reasonable tolerance due to background tasks and test infrastructure
	maxExpectedLeaks := 10 // Increased to account for background tasks from multiple instances
	if goroutineDiff > maxExpectedLeaks {
		t.Errorf("Excessive goroutine leaks with multiple instances: "+
			"Initial: %d, Final: %d, Diff: %d (max expected: %d)",
			initialGoroutines, finalGoroutines, goroutineDiff, maxExpectedLeaks)
	}

	t.Logf("Multiple instances test: Created %d instances, "+
		"Initial goroutines: %d, Final: %d, Diff: %d",
		numInstances, initialGoroutines, finalGoroutines, goroutineDiff)
}

// TestGoroutineLeakPrevention_TimeoutCleanup tests that stuck goroutines are cleaned up
// within reasonable timeouts
func TestGoroutineLeakPrevention_TimeoutCleanup(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := CreateConfig()
	config.ProviderURL = "https://httpbin.org/delay/10" // Slow endpoint to trigger timeout
	config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
	config.ClientID = "test-client-id"
	config.ClientSecret = "test-client-secret"

	// Create plugin - initialization may timeout
	handler, err := New(ctx, nil, config, "test")
	var plugin *TraefikOidc
	if handler != nil {
		plugin = handler.(*TraefikOidc)
	}

	// Wait for context timeout
	<-ctx.Done()

	if plugin != nil {
		// Clean up if plugin was created using proper Close() method
		if err := plugin.Close(); err != nil {
			t.Logf("Plugin close error: %v", err)
		}
	}

	// Allow extended cleanup time for timeout scenarios
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	if goroutineDiff > 5 { // Allow more tolerance for timeout scenarios
		t.Errorf("Goroutines not cleaned up after timeout: "+
			"Initial: %d, Final: %d, Diff: %d, Error: %v",
			initialGoroutines, finalGoroutines, goroutineDiff, err)
	}
}

// TestGoroutineLeakPrevention_BackgroundTaskCleanup tests that background metadata refresh
// goroutines are properly stopped and cleaned up
func TestGoroutineLeakPrevention_BackgroundTaskCleanup(t *testing.T) {
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	ctx := context.Background()
	config := CreateConfig()
	config.ProviderURL = "https://accounts.google.com"
	config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
	config.ClientID = "test-client-id"
	config.ClientSecret = "test-client-secret"

	handler, err := New(ctx, nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	plugin := handler.(*TraefikOidc)

	// Allow initialization and background task startup
	time.Sleep(200 * time.Millisecond)

	// Check that we have more goroutines (background tasks started)
	midGoroutines := runtime.NumGoroutine()
	if midGoroutines <= initialGoroutines {
		t.Log("Warning: No additional goroutines detected for background tasks")
	}

	// Stop all background tasks properly
	err = plugin.Close()
	if err != nil {
		t.Logf("Warning: Error closing plugin: %v", err)
	}

	// Allow cleanup time
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines

	if goroutineDiff > 5 { // Allow tolerance for background task cleanup timing
		t.Errorf("Background tasks not properly cleaned up: "+
			"Initial: %d, Mid: %d, Final: %d, Diff: %d",
			initialGoroutines, midGoroutines, finalGoroutines, goroutineDiff)
	}

	t.Logf("Background task cleanup: Initial: %d, Mid: %d, Final: %d",
		initialGoroutines, midGoroutines, finalGoroutines)
}

// BenchmarkGoroutineLeakPrevention_CreationDestruction benchmarks goroutine usage
// during plugin creation and destruction cycles
func BenchmarkGoroutineLeakPrevention_CreationDestruction(b *testing.B) {
	ctx := context.Background()

	// Record baseline
	runtime.GC()
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config := CreateConfig()
		config.ProviderURL = "https://accounts.google.com"
		config.SessionEncryptionKey = "test-encryption-key-32-bytes-long"
		config.ClientID = "test-client-id"
		config.ClientSecret = "test-client-secret"

		handler, err := New(ctx, nil, config, "test")
		if err != nil {
			b.Fatalf("Failed to create plugin: %v", err)
		}
		plugin := handler.(*TraefikOidc)

		// Clean up immediately using proper Close() method
		if err := plugin.Close(); err != nil {
			b.Logf("Plugin close error at iteration %d: %v", i, err)
		}

		// Periodic goroutine count check
		if i%100 == 99 {
			runtime.GC()
			current := runtime.NumGoroutine()
			if current > baselineGoroutines+10 {
				b.Fatalf("Goroutine leak detected at iteration %d: baseline=%d, current=%d",
					i, baselineGoroutines, current)
			}
		}
	}

	b.StopTimer()

	// Final cleanup and verification
	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	if finalGoroutines > baselineGoroutines+5 {
		b.Errorf("Potential goroutine leak after benchmark: baseline=%d, final=%d",
			baselineGoroutines, finalGoroutines)
	}
}
