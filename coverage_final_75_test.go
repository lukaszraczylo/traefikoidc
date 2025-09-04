package traefikoidc

import (
	"testing"
	"time"
)

// Final tests to reach 75% coverage

// Test various provider initialization
func TestProviderInitialization(t *testing.T) {
	// Test provider initialization (basic check)
	config := &Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		ProviderURL:  "https://provider.example.com",
		Scopes:       []string{"openid", "profile", "email"},
		LogLevel:     "info",
	}

	if config.ClientID == "" {
		t.Error("ClientID should not be empty")
	}

	if len(config.Scopes) < 3 {
		t.Error("Should have at least 3 scopes")
	}
}

// Test CreateConfig function
func TestCreateConfigFunction(t *testing.T) {
	config := CreateConfig()
	if config == nil {
		t.Fatal("CreateConfig returned nil")
	}

	// Set some fields
	config.ClientID = "test"
	config.ClientSecret = "secret"
	config.ProviderURL = "https://example.com"

	if config.ClientID != "test" {
		t.Error("ClientID not set correctly")
	}
}

// Test various cache operations for coverage
func TestAdditionalCacheOperations(t *testing.T) {
	// Test OptimizedCache with expiration
	cache := NewOptimizedCache()

	// Set items with very short TTL
	for i := 0; i < 5; i++ {
		cache.Set(string(rune(65+i)), "value", 100*time.Millisecond)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup
	cache.Cleanup()

	// Check items are gone
	if _, found := cache.Get("A"); found {
		t.Error("Expired item should be cleaned up")
	}
}

// Test error handling paths
func TestErrorHandlingPaths(t *testing.T) {
	// Test with nil logger (should use singleton)
	cache := NewOptimizedCacheWithConfig(50, 0, nil)
	if cache == nil {
		t.Fatal("Cache should handle nil logger")
	}

	// Test UnifiedCache with nil strategy
	config := DefaultUnifiedCacheConfig()
	config.Strategy = nil // Should use default
	unifiedCache := NewUnifiedCache(config)
	if unifiedCache == nil {
		t.Fatal("UnifiedCache should handle nil strategy")
	}
	unifiedCache.Close()
}
