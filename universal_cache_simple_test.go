package traefikoidc

import (
	"testing"
	"time"
)

func TestUniversalCacheSimple(t *testing.T) {
	// Create a simple cache
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 10,
		Logger:  GetSingletonNoOpLogger(),
	}

	cache := NewUniversalCache(config)
	defer cache.Close()

	// Test Set and Get
	cache.Set("key1", "value1", 1*time.Hour)

	value, exists := cache.Get("key1")
	if !exists {
		t.Error("Expected key1 to exist")
	}
	if value != "value1" {
		t.Errorf("Expected value1, got %v", value)
	}

	t.Log("Universal cache basic test passed")
}
