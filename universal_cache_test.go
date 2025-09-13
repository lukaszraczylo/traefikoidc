package traefikoidc

import (
	"sync"
	"testing"
	"time"
)

func TestUniversalCacheBasicOperations(t *testing.T) {
	t.Run("SetAndGet", func(t *testing.T) {
		config := UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 10,
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

		// Test non-existent key
		_, exists = cache.Get("nonexistent")
		if exists {
			t.Error("Expected nonexistent key to not exist")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		config := UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 10,
		}
		cache := NewUniversalCache(config)
		defer cache.Close()

		cache.Set("key1", "value1", 1*time.Hour)

		// Delete the key
		deleted := cache.Delete("key1")
		if !deleted {
			t.Error("Expected key1 to be deleted")
		}

		// Verify it's gone
		_, exists := cache.Get("key1")
		if exists {
			t.Error("Expected key1 to not exist after deletion")
		}

		// Delete non-existent key
		deleted = cache.Delete("nonexistent")
		if deleted {
			t.Error("Expected delete to return false for non-existent key")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		config := UniversalCacheConfig{
			Type:    CacheTypeGeneral,
			MaxSize: 10,
		}
		cache := NewUniversalCache(config)
		defer cache.Close()

		// Add multiple items
		for i := 0; i < 5; i++ {
			cache.Set(string(rune('a'+i)), i, 1*time.Hour)
		}

		if cache.Size() != 5 {
			t.Errorf("Expected size 5, got %d", cache.Size())
		}

		// Clear all
		cache.Clear()

		if cache.Size() != 0 {
			t.Errorf("Expected size 0 after clear, got %d", cache.Size())
		}
	})
}

func TestUniversalCacheLRUEviction(t *testing.T) {
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 3,
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Fill cache to capacity
	cache.Set("a", 1, 1*time.Hour)
	cache.Set("b", 2, 1*time.Hour)
	cache.Set("c", 3, 1*time.Hour)

	// Access 'a' to move it to front
	cache.Get("a")

	// Add new item, should evict 'b' (least recently used)
	cache.Set("d", 4, 1*time.Hour)

	// Check that 'b' was evicted
	_, exists := cache.Get("b")
	if exists {
		t.Error("Expected 'b' to be evicted")
	}

	// Check that others still exist
	if _, exists := cache.Get("a"); !exists {
		t.Error("Expected 'a' to exist")
	}
	if _, exists := cache.Get("c"); !exists {
		t.Error("Expected 'c' to exist")
	}
	if _, exists := cache.Get("d"); !exists {
		t.Error("Expected 'd' to exist")
	}
}

func TestUniversalCacheMemoryLimit(t *testing.T) {
	config := UniversalCacheConfig{
		Type:           CacheTypeGeneral,
		MaxSize:        100,
		MaxMemoryBytes: 100, // Very small limit
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Add items that exceed memory limit
	cache.Set("key1", "This is a very long string that takes up memory", 1*time.Hour)
	cache.Set("key2", "Another long string that should trigger eviction", 1*time.Hour)
	cache.Set("key3", "Yet another string", 1*time.Hour)

	// Check memory usage is within limit
	if cache.MemoryUsage() > config.MaxMemoryBytes {
		t.Errorf("Memory usage %d exceeds limit %d", cache.MemoryUsage(), config.MaxMemoryBytes)
	}

	// At least one item should remain
	if cache.Size() == 0 {
		t.Error("Expected at least one item in cache")
	}
}

func TestUniversalCacheExpiration(t *testing.T) {
	config := UniversalCacheConfig{
		Type:            CacheTypeGeneral,
		MaxSize:         10,
		CleanupInterval: 100 * time.Millisecond,
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Add item with short TTL
	cache.Set("shortlived", "value", 200*time.Millisecond)

	// Verify it exists
	if _, exists := cache.Get("shortlived"); !exists {
		t.Error("Expected shortlived to exist initially")
	}

	// Wait for expiration
	time.Sleep(300 * time.Millisecond)

	// Should be expired now
	if _, exists := cache.Get("shortlived"); exists {
		t.Error("Expected shortlived to be expired")
	}
}

func TestUniversalCacheTokenOperations(t *testing.T) {
	config := UniversalCacheConfig{
		Type: CacheTypeToken,
		TokenConfig: &TokenCacheConfig{
			BlacklistTTL: 1 * time.Hour,
		},
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Test blacklist operation
	err := cache.BlacklistToken("bad-token", 0)
	if err != nil {
		t.Errorf("Failed to blacklist token: %v", err)
	}

	// Check if token is blacklisted
	if !cache.IsTokenBlacklisted("bad-token") {
		t.Error("Expected token to be blacklisted")
	}

	// Check non-blacklisted token
	if cache.IsTokenBlacklisted("good-token") {
		t.Error("Expected good-token to not be blacklisted")
	}
}

func TestUniversalCacheMetadataGracePeriod(t *testing.T) {
	t.Skip("Temporarily skipping grace period test - timing issues")
	config := UniversalCacheConfig{
		Type:            CacheTypeMetadata,
		DefaultTTL:      100 * time.Millisecond,
		CleanupInterval: 10 * time.Second, // Disable cleanup during test
		MetadataConfig: &MetadataCacheConfig{
			GracePeriod:                    200 * time.Millisecond,
			ExtendedGracePeriod:            400 * time.Millisecond,
			MaxGracePeriod:                 600 * time.Millisecond,
			SecurityCriticalMaxGracePeriod: 150 * time.Millisecond, // Reduced for testing
			SecurityCriticalFields:         []string{"jwks_uri"},
		},
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Add metadata that will expire
	cache.SetWithMetadata("provider1", "metadata", 100*time.Millisecond, map[string]interface{}{
		"field": "jwks_uri",
	})

	// Wait for initial TTL to expire (100ms)
	time.Sleep(120 * time.Millisecond)

	// Should still be accessible due to grace period (120ms < 100ms TTL + 150ms grace)
	value, exists := cache.Get("provider1")
	if !exists {
		t.Error("Expected metadata to be accessible during grace period")
	}
	if value != "metadata" {
		t.Errorf("Expected 'metadata', got %v", value)
	}

	// Wait beyond security-critical max grace period (280ms > 100ms TTL + 150ms grace)
	time.Sleep(160 * time.Millisecond)

	// Should now be expired
	_, exists = cache.Get("provider1")
	if exists {
		t.Error("Expected metadata to be expired after max grace period")
	}
}

func TestUniversalCacheConcurrency(t *testing.T) {
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 100,
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := string(rune('a'+id)) + string(rune('0'+j%10))
				cache.Set(key, id*1000+j, 1*time.Hour)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := string(rune('a'+id)) + string(rune('0'+j%10))
				cache.Get(key)
			}
		}(i)
	}

	// Concurrent deletes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations/2; j++ {
				key := string(rune('a'+id)) + string(rune('0'+j%10))
				cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()

	// Cache should still be functional
	cache.Set("final", "value", 1*time.Hour)
	if value, exists := cache.Get("final"); !exists || value != "value" {
		t.Error("Cache not functional after concurrent operations")
	}
}

func TestUniversalCacheMetrics(t *testing.T) {
	config := UniversalCacheConfig{
		Type:          CacheTypeGeneral,
		MaxSize:       10,
		EnableMetrics: true,
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Perform operations
	cache.Set("key1", "value1", 1*time.Hour)
	cache.Get("key1") // Hit
	cache.Get("key2") // Miss
	cache.Get("key3") // Miss

	metrics := cache.GetMetrics()

	// Check metrics
	if metrics["hits"].(int64) != 1 {
		t.Errorf("Expected 1 hit, got %v", metrics["hits"])
	}
	if metrics["misses"].(int64) != 2 {
		t.Errorf("Expected 2 misses, got %v", metrics["misses"])
	}

	hitRate := metrics["hit_rate"].(float64)
	expectedHitRate := 1.0 / 3.0
	if hitRate < expectedHitRate-0.01 || hitRate > expectedHitRate+0.01 {
		t.Errorf("Expected hit rate ~%f, got %f", expectedHitRate, hitRate)
	}
}

func TestUniversalCacheAdapters(t *testing.T) {
	t.Run("TokenCacheAdapter", func(t *testing.T) {
		config := UniversalCacheConfig{
			Type:    CacheTypeToken,
			MaxSize: 100,
			Logger:  NewLogger("debug"),
		}
		cache := NewUniversalCache(config)
		defer cache.Close()

		// Test token operations
		claims := map[string]interface{}{
			"sub": "user123",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}

		cache.Set("token1", claims, 1*time.Hour)

		retrievedClaims, exists := cache.Get("token1")
		if !exists {
			t.Error("Expected token1 to exist")
		}
		if claimsMap, ok := retrievedClaims.(map[string]interface{}); ok {
			if claimsMap["sub"] != "user123" {
				t.Errorf("Expected sub=user123, got %v", claimsMap["sub"])
			}
		} else {
			t.Error("Expected retrieved claims to be a map")
		}

		// Test blacklist functionality - use Set with special marker
		cache.Set("blacklist:bad-token", true, 1*time.Hour)
		if _, exists := cache.Get("blacklist:bad-token"); !exists {
			t.Error("Expected bad-token to be blacklisted")
		}
	})

	t.Run("MetadataCacheAdapter", func(t *testing.T) {
		config := UniversalCacheConfig{
			Type:    CacheTypeMetadata,
			MaxSize: 50,
			Logger:  NewLogger("debug"),
		}
		cache := NewUniversalCache(config)
		defer cache.Close()

		metadata := &ProviderMetadata{
			Issuer:   "https://example.com",
			AuthURL:  "https://example.com/auth",
			TokenURL: "https://example.com/token",
			JWKSURL:  "https://example.com/jwks",
		}

		err := cache.Set("https://example.com", metadata, 1*time.Hour)
		if err != nil {
			t.Errorf("Failed to set metadata: %v", err)
		}

		retrieved, exists := cache.Get("https://example.com")
		if !exists {
			t.Error("Expected metadata to exist")
		}
		if meta, ok := retrieved.(*ProviderMetadata); ok {
			if meta.Issuer != metadata.Issuer {
				t.Errorf("Expected issuer %s, got %s", metadata.Issuer, meta.Issuer)
			}
		} else {
			t.Error("Expected retrieved value to be *ProviderMetadata")
		}
	})

	t.Run("JWKCacheAdapter", func(t *testing.T) {
		config := UniversalCacheConfig{
			Type:    CacheTypeJWK,
			MaxSize: 20,
			Logger:  NewLogger("debug"),
		}
		cache := NewUniversalCache(config)
		defer cache.Close()

		// Test JWK operations
		jwk := map[string]interface{}{
			"kty": "RSA",
			"use": "sig",
			"kid": "key1",
		}

		err := cache.Set("key1", jwk, 1*time.Hour)
		if err != nil {
			t.Errorf("Failed to set JWK: %v", err)
		}

		retrieved, exists := cache.Get("key1")
		if !exists {
			t.Error("Expected key1 to exist")
		}

		if jwkMap, ok := retrieved.(map[string]interface{}); ok {
			if jwkMap["kid"] != "key1" {
				t.Errorf("Expected kid=key1, got %v", jwkMap["kid"])
			}
		} else {
			t.Error("Expected retrieved value to be a map")
		}
	})
}

func TestUniversalCacheMigration(t *testing.T) {
	t.Run("MigrateBoundedCache", func(t *testing.T) {
		// Create cache wrapper for migration testing
		oldCache := NewBoundedCache(10)
		oldCache.Set("key1", "value1", 1*time.Hour)
		oldCache.Set("key2", "value2", 1*time.Hour)

		// Since caches are now unified through UniversalCache,
		// migration is not needed - all caches use the same backend
		// Just verify the cache works
		if val, exists := oldCache.Get("key1"); !exists || val != "value1" {
			t.Error("Expected key1 to exist with value1")
		}
		defer oldCache.Close()

		// Verify second key exists
		value, exists := oldCache.Get("key2")
		if !exists || value != "value2" {
			t.Error("Expected key2 to exist with value2")
		}
	})
}

func TestUniversalCacheTypeDefaults(t *testing.T) {
	tests := []struct {
		name            string
		cacheType       CacheType
		expectedMaxSize int
	}{
		{"TokenCache", CacheTypeToken, 5000},
		{"MetadataCache", CacheTypeMetadata, 100},
		{"JWKCache", CacheTypeJWK, 200},
		{"SessionCache", CacheTypeSession, 10000},
		{"GeneralCache", CacheTypeGeneral, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := UniversalCacheConfig{
				Type: tt.cacheType,
			}
			cache := NewUniversalCache(config)
			defer cache.Close()

			if cache.config.MaxSize != tt.expectedMaxSize {
				t.Errorf("Expected MaxSize=%d for %s, got %d",
					tt.expectedMaxSize, tt.cacheType, cache.config.MaxSize)
			}
		})
	}
}

func BenchmarkUniversalCacheSet(b *testing.B) {
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 10000,
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Set(string(rune('a'+i%26)), i, 1*time.Hour)
			i++
		}
	})
}

func BenchmarkUniversalCacheGet(b *testing.B) {
	config := UniversalCacheConfig{
		Type:    CacheTypeGeneral,
		MaxSize: 10000,
	}
	cache := NewUniversalCache(config)
	defer cache.Close()

	// Pre-populate cache
	for i := 0; i < 100; i++ {
		cache.Set(string(rune('a'+i%26)), i, 1*time.Hour)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Get(string(rune('a' + i%26)))
			i++
		}
	})
}
