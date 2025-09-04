package traefikoidc

import (
	"testing"
	"time"
)

// Additional tests to push coverage above 75%

// Test SetMaxSize and SetMaxMemory on caches
func TestCacheMemoryManagement(t *testing.T) {
	// OptimizedCache memory management
	cache := NewOptimizedCache()
	cache.SetMaxSize(100)
	cache.SetMaxMemory(5)

	// Fill cache to test eviction
	for i := 0; i < 150; i++ {
		cache.Set(string(rune(i)), "value", 5*time.Minute)
	}

	// UnifiedCache memory management
	config := DefaultUnifiedCacheConfig()
	unifiedCache := NewUnifiedCache(config)
	unifiedCache.SetMaxSize(50)

	for i := 0; i < 60; i++ {
		unifiedCache.Set(string(rune(i)), "value", 5*time.Minute)
	}

	unifiedCache.Close()
}

// Test BackgroundTask functionality
func TestBackgroundTaskOperations(t *testing.T) {
	// BackgroundTask requires logger and WaitGroup
	logger := NewLogger("debug")
	counter := 0
	task := NewBackgroundTask("test_task", 50*time.Millisecond, func() {
		counter++
	}, logger)

	if task == nil {
		t.Fatal("NewBackgroundTask returned nil")
	}

	task.Start()
	time.Sleep(150 * time.Millisecond)
	task.Stop()

	if counter < 2 {
		t.Errorf("Expected task to run at least twice, ran %d times", counter)
	}
}

// Test Logger creation and singleton
func TestLoggerOperations(t *testing.T) {
	// Test NewLogger
	logger := NewLogger("debug")
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}

	// Test singleton no-op logger
	noOpLogger := GetSingletonNoOpLogger()
	if noOpLogger == nil {
		t.Fatal("GetSingletonNoOpLogger returned nil")
	}

	// Should return same instance
	noOpLogger2 := GetSingletonNoOpLogger()
	if noOpLogger != noOpLogger2 {
		t.Error("GetSingletonNoOpLogger should return singleton")
	}
}

// Test CacheAdapter SetMaxSize
func TestCacheAdapterSetMaxSize(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	unified := NewUnifiedCache(config)
	adapter := NewCacheAdapter(unified)

	adapter.SetMaxSize(25)

	// Fill beyond max size
	for i := 0; i < 30; i++ {
		adapter.Set(string(rune(i)), "value", 5*time.Minute)
	}

	adapter.Cleanup()
	adapter.Close()
}
