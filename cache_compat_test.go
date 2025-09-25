package traefikoidc

import (
	"testing"
	"time"
)

// TestNewBoundedCache tests creation of bounded cache
func TestNewBoundedCache(t *testing.T) {
	maxSize := 500
	cache := NewBoundedCache(maxSize)

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	// Verify we can use basic operations
	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

// TestDefaultUnifiedCacheConfig tests default configuration
func TestDefaultUnifiedCacheConfig(t *testing.T) {
	config := DefaultUnifiedCacheConfig()

	if config.Type != CacheTypeGeneral {
		t.Errorf("Expected CacheTypeGeneral, got %v", config.Type)
	}

	if config.MaxSize != 500 {
		t.Errorf("Expected MaxSize 500, got %d", config.MaxSize)
	}

	if config.MaxMemoryBytes != 64*1024*1024 {
		t.Errorf("Expected MaxMemoryBytes 64MB, got %d", config.MaxMemoryBytes)
	}

	if config.CleanupInterval != 2*time.Minute {
		t.Errorf("Expected CleanupInterval 2 minutes, got %v", config.CleanupInterval)
	}

	if config.Logger == nil {
		t.Error("Expected Logger to be set")
	}
}

// TestNewUnifiedCache tests unified cache creation
func TestNewUnifiedCache(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	cache := NewUnifiedCache(config)

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	if cache.UniversalCache == nil {
		t.Error("Expected UniversalCache to be set")
	}

	// Test basic operations
	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

// TestUnifiedCache_SetMaxSize tests SetMaxSize method
func TestUnifiedCache_SetMaxSize(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	cache := NewUnifiedCache(config)

	// Test setting max size
	newSize := 1000
	cache.SetMaxSize(newSize)

	// We can't easily verify the size was set without exposing internal fields,
	// but we can ensure the method doesn't panic
}

// TestNewCacheAdapter tests cache adapter creation
func TestNewCacheAdapter(t *testing.T) {
	tests := []struct {
		name        string
		cache       interface{}
		expectNil   bool
		description string
	}{
		{
			name:        "UniversalCache",
			cache:       NewUniversalCache(DefaultUnifiedCacheConfig()),
			expectNil:   false,
			description: "Should create adapter for UniversalCache",
		},
		{
			name:        "UnifiedCache",
			cache:       NewUnifiedCache(DefaultUnifiedCacheConfig()),
			expectNil:   false,
			description: "Should create adapter for UnifiedCache",
		},
		{
			name:        "Invalid cache type",
			cache:       "not-a-cache",
			expectNil:   true,
			description: "Should return nil for invalid cache type",
		},
		{
			name:        "Nil cache",
			cache:       nil,
			expectNil:   true,
			description: "Should return nil for nil cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewCacheAdapter(tt.cache)

			if tt.expectNil {
				if adapter != nil {
					t.Errorf("Expected nil adapter, got %v", adapter)
				}
			} else {
				if adapter == nil {
					t.Error("Expected non-nil adapter")
				}
				// Test basic operations
				adapter.Set("test", "value", time.Hour)
				value, found := adapter.Get("test")
				if !found {
					t.Error("Expected key to be found")
				}
				if value != "value" {
					t.Errorf("Expected 'value', got %v", value)
				}
			}
		})
	}
}

// TestNewOptimizedCache tests optimized cache creation
func TestNewOptimizedCache(t *testing.T) {
	cache := NewOptimizedCache()

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	// Verify it works with basic operations
	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

// TestNewLRUStrategy tests LRU strategy creation
func TestNewLRUStrategy(t *testing.T) {
	maxSize := 100
	strategy := NewLRUStrategy(maxSize)

	if strategy == nil {
		t.Fatal("Expected strategy to be created, got nil")
	}

	lruStrategy, ok := strategy.(*LRUStrategy)
	if !ok {
		t.Fatal("Expected LRUStrategy type")
	}

	if lruStrategy.maxSize != maxSize {
		t.Errorf("Expected maxSize %d, got %d", maxSize, lruStrategy.maxSize)
	}

	if lruStrategy.order == nil {
		t.Error("Expected order list to be initialized")
	}

	if lruStrategy.elements == nil {
		t.Error("Expected elements map to be initialized")
	}
}

// TestLRUStrategy_Name tests strategy name
func TestLRUStrategy_Name(t *testing.T) {
	strategy := NewLRUStrategy(100)

	name := strategy.Name()
	if name != "LRU" {
		t.Errorf("Expected 'LRU', got %s", name)
	}
}

// TestLRUStrategy_ShouldEvict tests eviction logic
func TestLRUStrategy_ShouldEvict(t *testing.T) {
	strategy := NewLRUStrategy(100)

	// LRU strategy always returns false for ShouldEvict
	result := strategy.ShouldEvict("test-item", time.Now())
	if result != false {
		t.Error("Expected ShouldEvict to return false")
	}
}

// TestLRUStrategy_OnAccess tests access callback
func TestLRUStrategy_OnAccess(t *testing.T) {
	strategy := NewLRUStrategy(100)

	// OnAccess should not panic
	strategy.OnAccess("test-key", "test-value")
}

// TestLRUStrategy_OnRemove tests removal callback
func TestLRUStrategy_OnRemove(t *testing.T) {
	strategy := NewLRUStrategy(100)

	// OnRemove should not panic
	strategy.OnRemove("test-key")
}

// TestLRUStrategy_EstimateSize tests size estimation
func TestLRUStrategy_EstimateSize(t *testing.T) {
	strategy := NewLRUStrategy(100)

	size := strategy.EstimateSize("test-item")
	if size != 64 {
		t.Errorf("Expected size 64, got %d", size)
	}
}

// TestLRUStrategy_GetEvictionCandidate tests eviction candidate retrieval
func TestLRUStrategy_GetEvictionCandidate(t *testing.T) {
	strategy := NewLRUStrategy(100)

	key, found := strategy.GetEvictionCandidate()
	if found {
		t.Error("Expected no eviction candidate to be found")
	}
	if key != "" {
		t.Errorf("Expected empty key, got %s", key)
	}
}

// TestNewOptimizedCacheWithConfig tests optimized cache with custom config
func TestNewOptimizedCacheWithConfig(t *testing.T) {
	config := UniversalCacheConfig{
		Type:           CacheTypeGeneral,
		MaxSize:        1000,
		MaxMemoryBytes: 128 * 1024 * 1024,
		EnableMetrics:  true,
		Logger:         GetSingletonNoOpLogger(),
	}

	cache := NewOptimizedCacheWithConfig(config)

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	// Verify it works with basic operations
	cache.Set("test-key", "test-value", time.Hour)
	value, found := cache.Get("test-key")
	if !found {
		t.Error("Expected key to be found in cache")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

// TestNewFixedMetadataCache tests fixed metadata cache creation
func TestNewFixedMetadataCache(t *testing.T) {
	cache := NewFixedMetadataCache()

	if cache == nil {
		t.Fatal("Expected cache to be created, got nil")
	}

	// Verify it works with proper metadata operations
	metadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
		JWKSURL:  "https://example.com/jwks",
	}

	err := cache.Set("test-provider", metadata, time.Hour)
	if err != nil {
		t.Errorf("Unexpected error setting metadata: %v", err)
	}

	// Test that the cache was created (basic verification)
	// Note: We can't easily test Get without more complex setup
}

// TestNewDoublyLinkedList tests doubly linked list creation
func TestNewDoublyLinkedList(t *testing.T) {
	list := NewDoublyLinkedList()

	if list == nil {
		t.Fatal("Expected list to be created, got nil")
	}

	// Test it's a proper list structure
	if list.Len() != 0 {
		t.Error("Expected empty list initially")
	}
}

// TestDoublyLinkedList_PopFront tests front element removal
func TestDoublyLinkedList_PopFront(t *testing.T) {
	list := NewDoublyLinkedList()

	// Test popping from empty list
	element := list.PopFront()
	if element != nil {
		t.Error("Expected nil when popping from empty list")
	}

	// Add an element and test popping
	added := list.PushBack("test-value")
	if added == nil {
		t.Fatal("Expected element to be added")
	}

	popped := list.PopFront()
	if popped == nil {
		t.Error("Expected element to be popped")
	}

	if list.Len() != 0 {
		t.Error("Expected list to be empty after popping")
	}
}

// Benchmark tests for performance
func BenchmarkNewBoundedCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewBoundedCache(1000)
	}
}

func BenchmarkNewOptimizedCache(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewOptimizedCache()
	}
}

func BenchmarkLRUStrategy_EstimateSize(b *testing.B) {
	strategy := NewLRUStrategy(1000)
	item := "test-item"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.EstimateSize(item)
	}
}
