package cache

import (
	"sync"
	"testing"
	"time"
)

func TestCacheBasicOperations(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Test Set and Get
	key := "test-key"
	value := "test-value"
	ttl := 1 * time.Hour

	err := cache.Set(key, value, ttl)
	if err != nil {
		t.Fatalf("Failed to set cache value: %v", err)
	}

	retrieved, exists := cache.Get(key)
	if !exists {
		t.Fatal("Expected value to exist in cache")
	}

	if retrieved != value {
		t.Fatalf("Expected %s, got %v", value, retrieved)
	}

	// Test Delete
	cache.Delete(key)
	_, exists = cache.Get(key)
	if exists {
		t.Fatal("Expected value to be deleted from cache")
	}
}

func TestCacheConcurrency(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 100

	// Concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key"
				value := id*numOperations + j
				_ = cache.Set(key, value, 1*time.Hour)
			}
		}(i)
	}

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				cache.Get("key")
			}
		}()
	}

	wg.Wait()
}

func TestTypedCache(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	// Test TokenCache
	tokenCache := NewTokenCache(baseCache)

	token := "test-token"
	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	err := tokenCache.Set(token, claims, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set token: %v", err)
	}

	retrievedClaims, exists := tokenCache.Get(token)
	if !exists {
		t.Fatal("Expected token to exist in cache")
	}

	if retrievedClaims["sub"] != claims["sub"] {
		t.Fatalf("Claims mismatch: expected %v, got %v", claims["sub"], retrievedClaims["sub"])
	}

	// Test blacklist
	err = tokenCache.SetBlacklisted(token, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to blacklist token: %v", err)
	}

	if !tokenCache.IsBlacklisted(token) {
		t.Fatal("Expected token to be blacklisted")
	}
}

func TestCacheManager(t *testing.T) {
	manager := NewManager(nil)
	defer manager.Close()

	// Test getting different cache types
	tokenCache := manager.GetTokenCache()
	if tokenCache == nil {
		t.Fatal("Expected token cache to be initialized")
	}

	metadataCache := manager.GetMetadataCache()
	if metadataCache == nil {
		t.Fatal("Expected metadata cache to be initialized")
	}

	jwkCache := manager.GetJWKCache()
	if jwkCache == nil {
		t.Fatal("Expected JWK cache to be initialized")
	}

	sessionCache := manager.GetSessionCache()
	if sessionCache == nil {
		t.Fatal("Expected session cache to be initialized")
	}

	// Test stats
	stats := manager.GetStats()
	if len(stats) != 5 {
		t.Fatalf("Expected 5 cache stats, got %d", len(stats))
	}
}

func TestCacheEviction(t *testing.T) {
	config := DefaultConfig()
	config.MaxSize = 3
	cache := New(config)
	defer cache.Close()

	// Add items to fill the cache
	_ = cache.Set("key1", "value1", 1*time.Hour)
	_ = cache.Set("key2", "value2", 1*time.Hour)
	_ = cache.Set("key3", "value3", 1*time.Hour)

	// Verify all items exist
	for i := 1; i <= 3; i++ {
		key := "key" + string(rune('0'+i))
		if _, exists := cache.Get(key); !exists {
			t.Fatalf("Expected %s to exist", key)
		}
	}

	// Add another item to trigger eviction
	_ = cache.Set("key4", "value4", 1*time.Hour)

	// Check that we still have only 3 items
	if cache.Size() != 3 {
		t.Fatalf("Expected cache size to be 3, got %d", cache.Size())
	}

	// The least recently used item (key1) should be evicted
	if _, exists := cache.Get("key1"); exists {
		t.Fatal("Expected key1 to be evicted")
	}

	// Other items should still exist
	if _, exists := cache.Get("key4"); !exists {
		t.Fatal("Expected key4 to exist")
	}
}

func TestCacheExpiration(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Set item with short TTL
	_ = cache.Set("short-ttl", "value", 100*time.Millisecond)

	// Item should exist immediately
	if _, exists := cache.Get("short-ttl"); !exists {
		t.Fatal("Expected item to exist immediately after setting")
	}

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Item should be expired
	if _, exists := cache.Get("short-ttl"); exists {
		t.Fatal("Expected item to be expired")
	}
}

func BenchmarkCacheSet(b *testing.B) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := "key"
			_ = cache.Set(key, i, 1*time.Hour)
			i++
		}
	})
}

func BenchmarkCacheGet(b *testing.B) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := "key"
		_ = cache.Set(key, i, 1*time.Hour)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Get("key")
		}
	})
}
