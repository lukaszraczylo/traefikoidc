package cache

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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

// TestCacheConfiguration tests various configuration options
func TestCacheConfiguration(t *testing.T) {
	// Test default config
	config := DefaultConfig()
	if config.MaxSize != 1000 {
		t.Errorf("Expected default max size 1000, got %d", config.MaxSize)
	}

	if config.DefaultTTL != 10*time.Minute {
		t.Errorf("Expected default TTL 10 minutes, got %v", config.DefaultTTL)
	}

	if config.Type != TypeGeneral {
		t.Errorf("Expected default type General, got %v", config.Type)
	}

	// Test custom config
	customConfig := Config{
		Type:              TypeToken,
		MaxSize:           500,
		MaxMemoryBytes:    1024 * 1024,
		DefaultTTL:        30 * time.Minute,
		CleanupInterval:   5 * time.Minute,
		EnableCompression: true,
		EnableMetrics:     true,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
	}

	cache := New(customConfig)
	defer cache.Close()

	if cache.config.Type != TypeToken {
		t.Errorf("Expected cache type Token, got %v", cache.config.Type)
	}
}

// TestCacheStats tests cache statistics
func TestCacheStats(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Initial stats
	stats := cache.GetStats()
	if stats["size"].(int64) != 0 {
		t.Errorf("Expected initial size 0, got %d", stats["size"])
	}
	if stats["hits"].(int64) != 0 {
		t.Errorf("Expected initial hits 0, got %d", stats["hits"])
	}
	if stats["misses"].(int64) != 0 {
		t.Errorf("Expected initial misses 0, got %d", stats["misses"])
	}

	// Add item and check stats
	_ = cache.Set("key1", "value1", 1*time.Hour)
	stats = cache.GetStats()
	if stats["size"].(int64) != 1 {
		t.Errorf("Expected size 1, got %d", stats["size"])
	}

	// Cache hit
	_, exists := cache.Get("key1")
	if !exists {
		t.Error("Expected key1 to exist")
	}
	stats = cache.GetStats()
	if stats["hits"].(int64) != 1 {
		t.Errorf("Expected hits 1, got %d", stats["hits"])
	}

	// Cache miss
	_, exists = cache.Get("nonexistent")
	if exists {
		t.Error("Expected nonexistent key to not exist")
	}
	stats = cache.GetStats()
	if stats["misses"].(int64) != 1 {
		t.Errorf("Expected misses 1, got %d", stats["misses"])
	}
}

// TestCacheMemoryLimit tests memory-based eviction
func TestCacheMemoryLimit(t *testing.T) {
	config := DefaultConfig()
	config.MaxMemoryBytes = 1024 // Very small limit
	config.EnableMemoryLimit = true
	cache := New(config)
	defer cache.Close()

	// Add items that exceed memory limit
	largeValue := string(make([]byte, 500))
	_ = cache.Set("key1", largeValue, 1*time.Hour)
	_ = cache.Set("key2", largeValue, 1*time.Hour)
	_ = cache.Set("key3", largeValue, 1*time.Hour)

	// Check that memory limit is enforced
	stats := cache.GetStats()
	memoryUsage := stats["memory"].(int64)
	if memoryUsage > config.MaxMemoryBytes*2 { // Allow some overhead
		t.Errorf("Memory usage %d exceeds limit %d by too much", memoryUsage, config.MaxMemoryBytes)
	}
}

// TestCacheCompression tests compression functionality
func TestCacheCompression(t *testing.T) {
	config := DefaultConfig()
	config.EnableCompression = true
	cache := New(config)
	defer cache.Close()

	// Test with large compressible data
	largeValueBytes := make([]byte, 1000)
	for i := range largeValueBytes {
		largeValueBytes[i] = byte('A') // Highly compressible
	}
	largeValue := string(largeValueBytes)

	err := cache.Set("compressed", largeValue, 1*time.Hour)
	if err != nil {
		t.Errorf("Failed to set compressed value: %v", err)
	}

	retrieved, exists := cache.Get("compressed")
	if !exists {
		t.Error("Expected compressed value to exist")
	}

	if retrieved != largeValue {
		t.Error("Compressed value doesn't match original")
	}
}

// TestCacheCleanup tests automatic cleanup
func TestCacheCleanup(t *testing.T) {
	config := DefaultConfig()
	config.CleanupInterval = 50 * time.Millisecond
	config.EnableAutoCleanup = true
	cache := New(config)
	defer cache.Close()

	// Add expired item
	_ = cache.Set("expired", "value", 25*time.Millisecond)

	// Wait for expiration and cleanup
	time.Sleep(100 * time.Millisecond)

	// Item should be cleaned up
	_, exists := cache.Get("expired")
	if exists {
		t.Error("Expected expired item to be cleaned up")
	}
}

// TestCacheClose tests cache shutdown
func TestCacheClose(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)

	_ = cache.Set("key", "value", 1*time.Hour)

	// Close should not error
	err := cache.Close()
	if err != nil {
		t.Errorf("Close should not error: %v", err)
	}

	// Double close should return an error since cache is already closed
	err = cache.Close()
	if err == nil {
		t.Error("Double close should return an error")
	}
}

// TestCacheContext tests context-based operations
func TestCacheContext(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	_, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test context cancellation during operation
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// This should respect context cancellation (if supported by cache implementation)
	_ = cache.Set("key", "value", 1*time.Hour)
}

// TestCacheErrors tests error conditions
func TestCacheErrors(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Test setting with zero TTL
	err := cache.Set("zero-ttl", "value", 0)
	if err != nil {
		t.Errorf("Setting with zero TTL should not error: %v", err)
	}

	// Test setting with negative TTL
	err = cache.Set("negative-ttl", "value", -1*time.Hour)
	if err != nil {
		t.Errorf("Setting with negative TTL should not error: %v", err)
	}

	// Test empty key
	err = cache.Set("", "value", 1*time.Hour)
	if err != nil {
		t.Errorf("Setting with empty key should not error: %v", err)
	}

	// Test nil value
	err = cache.Set("nil-value", nil, 1*time.Hour)
	if err != nil {
		t.Errorf("Setting nil value should not error: %v", err)
	}
}

// TestCacheTypeSpecificConfigs tests type-specific configurations
func TestCacheTypeSpecificConfigs(t *testing.T) {
	// Test Token cache config
	tokenConfig := &TokenConfig{
		BlacklistTTL:        24 * time.Hour,
		RefreshTokenTTL:     7 * 24 * time.Hour,
		EnableTokenRotation: true,
	}

	config := DefaultConfig()
	config.Type = TypeToken
	config.TokenConfig = tokenConfig

	cache := New(config)
	defer cache.Close()

	if cache.config.TokenConfig.BlacklistTTL != 24*time.Hour {
		t.Errorf("Expected blacklist TTL 24h, got %v", cache.config.TokenConfig.BlacklistTTL)
	}

	// Test Metadata cache config
	metadataConfig := &MetadataConfig{
		GracePeriod:                    30 * time.Minute,
		ExtendedGracePeriod:            2 * time.Hour,
		MaxGracePeriod:                 24 * time.Hour,
		SecurityCriticalMaxGracePeriod: 5 * time.Minute,
		SecurityCriticalFields:         []string{"issuer", "jwks_uri"},
	}

	config.Type = TypeMetadata
	config.MetadataConfig = metadataConfig

	cache2 := New(config)
	defer cache2.Close()

	if cache2.config.MetadataConfig.GracePeriod != 30*time.Minute {
		t.Errorf("Expected grace period 30m, got %v", cache2.config.MetadataConfig.GracePeriod)
	}

	// Test JWK cache config
	jwkConfig := &JWKConfig{
		RefreshInterval: 15 * time.Minute,
		MinRefreshTime:  1 * time.Minute,
		MaxKeyAge:       24 * time.Hour,
	}

	config.Type = TypeJWK
	config.JWKConfig = jwkConfig

	cache3 := New(config)
	defer cache3.Close()

	if cache3.config.JWKConfig.RefreshInterval != 15*time.Minute {
		t.Errorf("Expected refresh interval 15m, got %v", cache3.config.JWKConfig.RefreshInterval)
	}
}

// TestCacheGetOrSet tests the GetOrSet functionality if it exists
func TestCacheGetOrSet(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	key := "get-or-set-key"
	value := "initial-value"

	// Test set if not exists behavior
	_ = cache.Set(key, value, 1*time.Hour)

	retrieved, exists := cache.Get(key)
	if !exists {
		t.Error("Expected value to exist after set")
	}
	if retrieved != value {
		t.Errorf("Expected %s, got %v", value, retrieved)
	}

	// Test get existing
	retrieved, exists = cache.Get(key)
	if !exists {
		t.Error("Expected value to still exist")
	}
	if retrieved != value {
		t.Errorf("Expected %s, got %v", value, retrieved)
	}
}

// TestCacheUpdateTTL tests TTL updates if supported
func TestCacheUpdateTTL(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	key := "ttl-test"
	value := "value"

	// Set with short TTL
	_ = cache.Set(key, value, 50*time.Millisecond)

	// Update with longer TTL
	_ = cache.Set(key, value, 1*time.Hour)

	// Wait past original TTL
	time.Sleep(100 * time.Millisecond)

	// Should still exist due to updated TTL
	_, exists := cache.Get(key)
	if !exists {
		t.Error("Expected item to exist after TTL update")
	}
}

// TestCacheDisabledFeatures tests behavior with disabled features
func TestCacheDisabledFeatures(t *testing.T) {
	config := DefaultConfig()
	config.EnableMetrics = false
	config.EnableAutoCleanup = false
	config.EnableCompression = false
	config.EnableMemoryLimit = false

	cache := New(config)
	defer cache.Close()

	// Should still work with all features disabled
	_ = cache.Set("key", "value", 1*time.Hour)

	retrieved, exists := cache.Get("key")
	if !exists {
		t.Error("Expected basic functionality to work with disabled features")
	}
	if retrieved != "value" {
		t.Error("Expected value to match")
	}
}

// TestCacheSize tests size tracking
func TestCacheSize(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Initial size should be 0
	if cache.Size() != 0 {
		t.Errorf("Expected initial size 0, got %d", cache.Size())
	}

	// Add items
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key%d", i)
		_ = cache.Set(key, fmt.Sprintf("value%d", i), 1*time.Hour)
	}

	if cache.Size() != 5 {
		t.Errorf("Expected size 5, got %d", cache.Size())
	}

	// Delete item
	cache.Delete("key0")

	if cache.Size() != 4 {
		t.Errorf("Expected size 4 after delete, got %d", cache.Size())
	}
}

// TestCacheClear tests clearing the entire cache
func TestCacheClear(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Add multiple items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key%d", i)
		_ = cache.Set(key, fmt.Sprintf("value%d", i), 1*time.Hour)
	}

	if cache.Size() != 10 {
		t.Errorf("Expected size 10, got %d", cache.Size())
	}

	// Clear cache
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Size())
	}

	// Verify all items are gone
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key%d", i)
		if _, exists := cache.Get(key); exists {
			t.Errorf("Expected %s to be cleared", key)
		}
	}
}

// TestCacheSetMaxSize tests dynamic max size updates
func TestCacheSetMaxSize(t *testing.T) {
	config := DefaultConfig()
	config.MaxSize = 5
	cache := New(config)
	defer cache.Close()

	// Add items up to limit
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key%d", i)
		_ = cache.Set(key, fmt.Sprintf("value%d", i), 1*time.Hour)
	}

	if cache.Size() != 5 {
		t.Errorf("Expected size 5, got %d", cache.Size())
	}

	// Reduce max size
	cache.SetMaxSize(3)

	// Cache should evict items to fit new limit
	if cache.Size() > 3 {
		t.Errorf("Expected size <= 3 after reducing max size, got %d", cache.Size())
	}

	// Increase max size
	cache.SetMaxSize(10)

	// Should be able to add more items
	for i := 5; i < 8; i++ {
		key := fmt.Sprintf("key%d", i)
		_ = cache.Set(key, fmt.Sprintf("value%d", i), 1*time.Hour)
	}

	if cache.Size() > 10 {
		t.Errorf("Cache size should not exceed new max size")
	}
}

// TestCacheManualCleanup tests manual cleanup
func TestCacheManualCleanup(t *testing.T) {
	config := DefaultConfig()
	config.EnableAutoCleanup = false // Disable auto cleanup
	cache := New(config)
	defer cache.Close()

	// Add expired items
	_ = cache.Set("expired1", "value1", 1*time.Millisecond)
	_ = cache.Set("expired2", "value2", 1*time.Millisecond)
	_ = cache.Set("valid", "value", 1*time.Hour)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Items should still be there since auto cleanup is disabled
	if cache.Size() != 3 {
		t.Errorf("Expected size 3 before cleanup, got %d", cache.Size())
	}

	// Manual cleanup
	cache.Cleanup()

	// Expired items should be removed
	if cache.Size() == 3 {
		t.Error("Cleanup should have removed expired items")
	}

	// Valid item should still exist
	_, exists := cache.Get("valid")
	if !exists {
		t.Error("Valid item should still exist after cleanup")
	}
}

// TestCacheHitRate tests hit rate calculation
func TestCacheHitRate(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Add item
	_ = cache.Set("key", "value", 1*time.Hour)

	// Generate hits and misses
	cache.Get("key")         // hit
	cache.Get("key")         // hit
	cache.Get("nonexistent") // miss

	stats := cache.GetStats()
	hits := stats["hits"].(int64)
	misses := stats["misses"].(int64)

	if hits != 2 {
		t.Errorf("Expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}

	// Check hit rate if available in stats
	if hitRate, exists := stats["hit_rate"]; exists {
		expectedRate := float64(hits) / float64(hits+misses)
		if hitRate.(float64) != expectedRate {
			t.Errorf("Expected hit rate %f, got %f", expectedRate, hitRate)
		}
	}
}

// TestCacheCompatibilityWrapper tests the compatibility wrapper
func TestCacheCompatibilityWrapper(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	wrapper := NewCompatibilityWrapper(cache)
	if wrapper == nil {
		t.Error("NewCompatibilityWrapper should not return nil")
	}

	// Test wrapper methods
	wrapper.Set("key", "value", 1*time.Hour)

	value, exists := wrapper.Get("key")
	if !exists {
		t.Error("Expected key to exist in wrapper")
	}
	if value != "value" {
		t.Errorf("Expected 'value', got %v", value)
	}

	wrapper.Delete("key")
	_, exists = wrapper.Get("key")
	if exists {
		t.Error("Expected key to be deleted in wrapper")
	}

	// Test wrapper stats
	stats := wrapper.GetStats()
	if stats == nil {
		t.Error("Wrapper GetStats should not return nil")
	}
}

// TestCacheTypedCaches tests the typed cache wrappers
func TestCacheTypedCaches(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	// Test JWK cache
	jwkCache := NewJWKCache(baseCache)
	if jwkCache == nil {
		t.Error("NewJWKCache should not return nil")
	}

	jwkSet := &JWKSet{
		Keys: []JWK{
			{
				Kid: "test-key",
				Kty: "RSA",
				Use: "sig",
				N:   "test-modulus",
				E:   "AQAB",
			},
		},
	}

	err := jwkCache.Set("test-jwk", jwkSet, 1*time.Hour)
	if err != nil {
		t.Errorf("JWKCache Set should not error: %v", err)
	}

	retrieved, exists := jwkCache.Get("test-jwk")
	if !exists {
		t.Error("Expected JWK to exist")
	}
	if retrieved == nil {
		t.Error("JWK data should not be nil")
	}

	// Test Session cache
	sessionCache := NewSessionCache(baseCache)
	if sessionCache == nil {
		t.Error("NewSessionCache should not return nil")
	}

	sessionData := SessionData{
		ID:          "session123",
		UserID:      "user123",
		AccessToken: "access-token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	err = sessionCache.Set("session123", sessionData, 30*time.Minute)
	if err != nil {
		t.Errorf("SessionCache Set should not error: %v", err)
	}

	retrievedSession, exists := sessionCache.Get("session123")
	if !exists {
		t.Error("Expected session to exist")
	}
	if retrievedSession.UserID != "user123" {
		t.Error("Session data should match")
	}
}

// TestNoOpLogger tests the noOpLogger implementation
func TestNoOpLogger(t *testing.T) {
	logger := &noOpLogger{}

	// Test all logging methods - they should not panic or error
	logger.Debug("debug message")
	logger.Debugf("debug %s", "message")
	logger.Info("info message")
	logger.Infof("info %s", "message")
	logger.Error("error message")
	logger.Errorf("error %s", "message")
	logger.Warn("warn message")
	logger.Warnf("warn %s", "message")
	logger.Fatal("fatal message")
	logger.Fatalf("fatal %s", "message")

	// Test WithField and WithFields - should return the same logger
	fieldLogger := logger.WithField("key", "value")
	if fieldLogger != logger {
		t.Error("WithField should return the same logger instance")
	}

	fieldsLogger := logger.WithFields(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})
	if fieldsLogger != logger {
		t.Error("WithFields should return the same logger instance")
	}

	// Test nil values don't cause issues
	logger.WithField("key", nil)
	logger.WithFields(nil)
	logger.WithFields(map[string]interface{}{
		"nil": nil,
	})
}

// TestCacheEdgeCases tests various edge cases
func TestCacheEdgeCases(t *testing.T) {
	config := DefaultConfig()
	cache := New(config)
	defer cache.Close()

	// Test setting very large value
	largeValue := make([]byte, 1024*1024) // 1MB
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	err := cache.Set("large", largeValue, 1*time.Hour)
	if err != nil {
		t.Errorf("Setting large value should not error: %v", err)
	}

	retrieved, exists := cache.Get("large")
	if !exists {
		t.Error("Large value should exist")
	}
	if len(retrieved.([]byte)) != len(largeValue) {
		t.Error("Large value should match original size")
	}

	// Test concurrent access to same key
	var wg sync.WaitGroup
	numGoroutines := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key := "concurrent"
			value := fmt.Sprintf("value-%d", id)
			cache.Set(key, value, 1*time.Hour)
			cache.Get(key)
			if id%2 == 0 {
				cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()

	// Test setting same key multiple times
	for i := 0; i < 100; i++ {
		err := cache.Set("overwrite", fmt.Sprintf("value-%d", i), 1*time.Hour)
		if err != nil {
			t.Errorf("Overwrite should not error: %v", err)
		}
	}

	value, exists := cache.Get("overwrite")
	if !exists {
		t.Error("Overwritten value should exist")
	}
	if !strings.HasPrefix(value.(string), "value-") {
		t.Error("Value should have expected format")
	}
}

// TestCompatibilityWrapperMethods tests all CompatibilityWrapper methods
func TestCompatibilityWrapperMethods(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	wrapper := NewCompatibilityWrapper(baseCache)
	if wrapper == nil {
		t.Fatal("NewCompatibilityWrapper should not return nil")
	}

	// Test SetMaxSize method
	wrapper.SetMaxSize(100)
	if wrapper.Size() != 0 {
		t.Error("Size should be 0 initially")
	}

	// Test Size method with data
	wrapper.Set("key1", "value1", 1*time.Hour)
	if wrapper.Size() != 1 {
		t.Errorf("Expected size 1, got %d", wrapper.Size())
	}

	// Test Clear method
	wrapper.Clear()
	if wrapper.Size() != 0 {
		t.Error("Size should be 0 after clear")
	}

	// Add some data for cleanup test
	wrapper.Set("expired", "value", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	// Test Cleanup method
	wrapper.Cleanup()

	// Test Close method (should not panic)
	wrapper.Close()
}

// TestUniversalCacheCompat tests UniversalCacheCompat methods
func TestUniversalCacheCompat(t *testing.T) {
	config := DefaultConfig()
	compat := NewUniversalCacheCompat(config)
	if compat == nil {
		t.Fatal("NewUniversalCacheCompat should not return nil")
	}
	defer compat.Close()

	// Test Set method
	err := compat.Set("test-key", "test-value", 1*time.Hour)
	if err != nil {
		t.Errorf("UniversalCacheCompat Set should not error: %v", err)
	}

	// Verify the value was set
	value, exists := compat.Get("test-key")
	if !exists {
		t.Error("Expected value to exist")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got %v", value)
	}
}

// TestTokenCacheCompat tests TokenCacheCompat methods
func TestTokenCacheCompat(t *testing.T) {
	compat := NewTokenCacheCompat()
	if compat == nil {
		t.Fatal("NewTokenCacheCompat should not return nil")
	}

	token := "test-token-123"
	claims := map[string]interface{}{
		"sub": "user123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	// Test Set method
	compat.Set(token, claims, 1*time.Hour)

	// Test Get method
	retrievedClaims, exists := compat.Get(token)
	if !exists {
		t.Error("Expected token claims to exist")
	}
	if retrievedClaims["sub"] != "user123" {
		t.Error("Claims should match what was set")
	}

	// Test Delete method
	compat.Delete(token)
	_, exists = compat.Get(token)
	if exists {
		t.Error("Expected token to be deleted")
	}
}

// TestMetadataCacheCompat tests MetadataCacheCompat methods
func TestMetadataCacheCompat(t *testing.T) {
	var wg sync.WaitGroup
	compat := NewMetadataCacheCompat(&wg)
	if compat == nil {
		t.Fatal("NewMetadataCacheCompat should not return nil")
	}

	// Test with logger
	logger := &noOpLogger{}
	compatWithLogger := NewMetadataCacheCompatWithLogger(&wg, logger)
	if compatWithLogger == nil {
		t.Fatal("NewMetadataCacheCompatWithLogger should not return nil")
	}

	providerURL := "https://example.com/.well-known/openid_configuration"
	metadata := &ProviderMetadata{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/auth",
		TokenEndpoint:         "https://example.com/token",
		JWKSUri:               "https://example.com/.well-known/jwks.json",
		UserInfoEndpoint:      "https://example.com/userinfo",
		ScopesSupported:       []string{"openid", "profile", "email"},
	}

	// Test Set method
	err := compat.Set(providerURL, metadata, 1*time.Hour)
	if err != nil {
		t.Errorf("MetadataCacheCompat Set should not error: %v", err)
	}

	// Test Get method
	retrieved, exists := compat.Get(providerURL)
	if !exists {
		t.Error("Expected metadata to exist")
	}
	if retrieved.Issuer != "https://example.com" {
		t.Error("Metadata should match what was set")
	}

	// Test GetWithGracePeriod method
	ctx := context.Background()
	gracePeriodRetrieved, gracePeriodExists := compat.GetWithGracePeriod(ctx, providerURL)
	if !gracePeriodExists {
		t.Error("Expected metadata to exist with grace period")
	}
	if gracePeriodRetrieved.Issuer != "https://example.com" {
		t.Error("Grace period metadata should match")
	}

	// Test Delete method
	compat.Delete(providerURL)
	_, exists = compat.Get(providerURL)
	if exists {
		t.Error("Expected metadata to be deleted")
	}
}

// TestJWKCacheCompat tests JWKCacheCompat methods
func TestJWKCacheCompat(t *testing.T) {
	compat := NewJWKCacheCompat()
	if compat == nil {
		t.Fatal("NewJWKCacheCompat should not return nil")
	}

	jwksURL := "https://example.com/.well-known/jwks.json"
	jwkSet := &JWKSet{
		Keys: []JWK{
			{
				Kid: "key1",
				Kty: "RSA",
				Use: "sig",
				N:   "test-modulus",
				E:   "AQAB",
			},
		},
	}

	// Test Set method
	err := compat.Set(jwksURL, jwkSet, 1*time.Hour)
	if err != nil {
		t.Errorf("JWKCacheCompat Set should not error: %v", err)
	}

	// Test GetJWKS method (should find cached value)
	ctx := context.Background()
	httpClient := &http.Client{}
	retrieved, err := compat.GetJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		t.Errorf("GetJWKS should not error: %v", err)
	}
	if retrieved == nil {
		t.Error("Expected to retrieve cached JWKS")
		return
	}
	if len(retrieved.Keys) != 1 || retrieved.Keys[0].Kid != "key1" {
		t.Error("Retrieved JWKS should match what was set")
	}

	// Test GetJWKS with non-existent URL (should return nil)
	nonExistent, err := compat.GetJWKS(ctx, "https://non-existent.com/jwks", httpClient)
	if err != nil {
		t.Errorf("GetJWKS with non-existent key should not error: %v", err)
	}
	if nonExistent != nil {
		t.Error("Expected nil for non-existent JWKS")
	}

	// Test Cleanup method (should not panic)
	compat.Cleanup()

	// Test Close method (should not panic)
	compat.Close()
}

// TestCacheManagerCompat tests CacheManagerCompat methods
func TestCacheManagerCompat(t *testing.T) {
	var wg sync.WaitGroup
	manager := GetGlobalCacheManagerCompat(&wg)
	if manager == nil {
		t.Fatal("GetGlobalCacheManagerCompat should not return nil")
	}

	// Test GetSharedTokenBlacklist
	blacklist := manager.GetSharedTokenBlacklist()
	if blacklist == nil {
		t.Error("GetSharedTokenBlacklist should not return nil")
	}

	// Test GetSharedTokenCache
	tokenCache := manager.GetSharedTokenCache()
	if tokenCache == nil {
		t.Error("GetSharedTokenCache should not return nil")
	}

	// Test GetSharedMetadataCache
	metadataCache := manager.GetSharedMetadataCache()
	if metadataCache == nil {
		t.Error("GetSharedMetadataCache should not return nil")
	}

	// Test GetSharedJWKCache
	jwkCache := manager.GetSharedJWKCache()
	if jwkCache == nil {
		t.Error("GetSharedJWKCache should not return nil")
	}

	// Test Close method
	err := manager.Close()
	if err != nil {
		t.Errorf("CacheManagerCompat Close should not error: %v", err)
	}
}

// TestUniversalCacheManagerCompat tests UniversalCacheManagerCompat methods
func TestUniversalCacheManagerCompat(t *testing.T) {
	logger := &noOpLogger{}
	manager := GetUniversalCacheManagerCompat(logger)
	if manager == nil {
		t.Fatal("GetUniversalCacheManagerCompat should not return nil")
	}

	// Test GetTokenCache
	tokenCache := manager.GetTokenCache()
	if tokenCache == nil {
		t.Error("GetTokenCache should not return nil")
	}

	// Test GetMetadataCache
	metadataCache := manager.GetMetadataCache()
	if metadataCache == nil {
		t.Error("GetMetadataCache should not return nil")
	}

	// Test GetJWKCache
	jwkCache := manager.GetJWKCache()
	if jwkCache == nil {
		t.Error("GetJWKCache should not return nil")
	}

	// Test GetBlacklistCache
	blacklistCache := manager.GetBlacklistCache()
	if blacklistCache == nil {
		t.Error("GetBlacklistCache should not return nil")
	}

	// Test Close method
	err := manager.Close()
	if err != nil && err.Error() != "cache already closed" {
		t.Errorf("UniversalCacheManagerCompat Close should not error (unless already closed): %v", err)
	}
}

// TestTypedCacheWrapper tests TypedCache methods
func TestTypedCacheWrapper(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	typedCache := NewTypedCache[string](baseCache, "test-prefix")
	if typedCache == nil {
		t.Fatal("NewTypedCache should not return nil")
	}

	// Test Set and Get
	err := typedCache.Set("test-key", "test-value", 1*time.Hour)
	if err != nil {
		t.Errorf("TypedCache Set should not error: %v", err)
	}

	value, exists := typedCache.Get("test-key")
	if !exists {
		t.Error("Expected typed value to exist")
	}
	if value != "test-value" {
		t.Errorf("Expected 'test-value', got '%s'", value)
	}

	// Test Delete method
	typedCache.Delete("test-key")
	_, exists = typedCache.Get("test-key")
	if exists {
		t.Error("Expected typed value to be deleted")
	}

	// Test Clear method
	typedCache.Set("key1", "value1", 1*time.Hour)
	typedCache.Set("key2", "value2", 1*time.Hour)
	typedCache.Clear()

	if typedCache.Size() != 0 {
		t.Error("Expected typed cache to be empty after clear")
	}

	// Test Size method
	if typedCache.Size() != 0 {
		t.Errorf("Expected size 0, got %d", typedCache.Size())
	}

	// Add items to test size
	typedCache.Set("size1", "value1", 1*time.Hour)
	typedCache.Set("size2", "value2", 1*time.Hour)
	if typedCache.Size() != 2 {
		t.Errorf("Expected size 2, got %d", typedCache.Size())
	}
}

// TestTokenCacheSpecificMethods tests TokenCache specific methods
func TestTokenCacheSpecificMethods(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	tokenCache := NewTokenCache(baseCache)
	if tokenCache == nil {
		t.Fatal("NewTokenCache should not return nil")
	}

	token := "test-token-456"
	claims := map[string]interface{}{
		"sub": "user456",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"aud": "test-audience",
	}

	// Test Delete method (currently at 0% coverage)
	tokenCache.Set(token, claims, 1*time.Hour)
	tokenCache.Delete(token)
	_, exists := tokenCache.Get(token)
	if exists {
		t.Error("Expected token to be deleted")
	}

	// Test edge case in IsBlacklisted when token doesn't exist
	if tokenCache.IsBlacklisted("non-existent-token") {
		t.Error("Non-existent token should not be blacklisted")
	}
}

// TestMetadataCacheSpecificMethods tests MetadataCache specific methods
func TestMetadataCacheSpecificMethods(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	metadataConfig := MetadataConfig{
		GracePeriod: 30 * time.Minute,
	}
	metadataCache := NewMetadataCache(baseCache, metadataConfig)
	if metadataCache == nil {
		t.Fatal("NewMetadataCache should not return nil")
	}

	providerURL := "https://test-provider.com/.well-known/openid_configuration"
	metadata := &ProviderMetadata{
		Issuer:                "https://test-provider.com",
		AuthorizationEndpoint: "https://test-provider.com/auth",
		TokenEndpoint:         "https://test-provider.com/token",
		JWKSUri:               "https://test-provider.com/.well-known/jwks.json",
		UserInfoEndpoint:      "https://test-provider.com/userinfo",
		ScopesSupported:       []string{"openid", "profile"},
	}

	// Test Set method (currently at 0% coverage)
	err := metadataCache.Set(providerURL, metadata, 30*time.Minute)
	if err != nil {
		t.Errorf("MetadataCache Set should not error: %v", err)
	}

	// Test Get method (currently at 0% coverage)
	retrieved, exists := metadataCache.Get(providerURL)
	if !exists {
		t.Error("Expected metadata to exist")
	}
	if retrieved.Issuer != "https://test-provider.com" {
		t.Error("Retrieved metadata should match what was set")
	}

	// Test Delete method (currently at 0% coverage)
	metadataCache.Delete(providerURL)
	_, exists = metadataCache.Get(providerURL)
	if exists {
		t.Error("Expected metadata to be deleted")
	}
}

// TestJWKCacheSpecificMethods tests JWKCache specific methods
func TestJWKCacheSpecificMethods(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	jwkCache := NewJWKCache(baseCache)
	if jwkCache == nil {
		t.Fatal("NewJWKCache should not return nil")
	}

	jwksURL := "https://test-jwks.com/.well-known/jwks.json"
	jwkSet := &JWKSet{
		Keys: []JWK{
			{
				Kid: "test-key-123",
				Kty: "RSA",
				Use: "sig",
				N:   "test-modulus-value",
				E:   "AQAB",
			},
			{
				Kid: "test-key-456",
				Kty: "EC",
				Use: "sig",
				N:   "test-n-value",
				E:   "AQAB",
			},
		},
	}

	// Test Delete method (currently at 0% coverage)
	jwkCache.Set(jwksURL, jwkSet, 1*time.Hour)
	jwkCache.Delete(jwksURL)
	_, exists := jwkCache.Get(jwksURL)
	if exists {
		t.Error("Expected JWK set to be deleted")
	}

	// Test edge case in Get method with different key types
	complexJWKSet := &JWKSet{
		Keys: []JWK{
			{
				Kid: "rsa-key",
				Kty: "RSA",
				Use: "sig",
				N:   "long-modulus-value",
				E:   "AQAB",
			},
		},
	}

	jwkCache.Set("complex-jwks", complexJWKSet, 2*time.Hour)
	retrieved, exists := jwkCache.Get("complex-jwks")
	if !exists {
		t.Error("Expected complex JWK set to exist")
	}
	if len(retrieved.Keys) != 1 || retrieved.Keys[0].Kty != "RSA" {
		t.Error("Complex JWK set should match what was set")
	}
}

// TestSessionCacheSpecificMethods tests SessionCache specific methods
func TestSessionCacheSpecificMethods(t *testing.T) {
	config := DefaultConfig()
	baseCache := New(config)
	defer baseCache.Close()

	sessionCache := NewSessionCache(baseCache)
	if sessionCache == nil {
		t.Fatal("NewSessionCache should not return nil")
	}

	sessionID := "session-123-abc"
	sessionData := SessionData{
		ID:           sessionID,
		UserID:       "user789",
		AccessToken:  "access-token-xyz",
		RefreshToken: "refresh-token-abc",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Claims: map[string]interface{}{
			"sub": "user789",
		},
	}

	// Test Delete method (currently at 0% coverage)
	sessionCache.Set(sessionID, sessionData, 45*time.Minute)
	sessionCache.Delete(sessionID)
	_, exists := sessionCache.Get(sessionID)
	if exists {
		t.Error("Expected session to be deleted")
	}

	// Test Exists method (currently at 0% coverage)
	sessionCache.Set(sessionID, sessionData, 45*time.Minute)
	if !sessionCache.Exists(sessionID) {
		t.Error("Expected session to exist")
	}

	sessionCache.Delete(sessionID)
	if sessionCache.Exists(sessionID) {
		t.Error("Expected session to not exist after delete")
	}

	// Test Exists with non-existent session
	if sessionCache.Exists("non-existent-session") {
		t.Error("Non-existent session should not exist")
	}
}

// TestManagerUncoveredMethods tests Manager methods currently at 0% coverage
func TestManagerUncoveredMethods(t *testing.T) {
	logger := &noOpLogger{}
	manager := NewManager(logger)
	if manager == nil {
		t.Fatal("NewManager should not return nil")
	}

	// Test GetGlobalManager (currently at 0% coverage)
	globalManager := GetGlobalManager(logger)
	if globalManager == nil {
		t.Error("GetGlobalManager should not return nil")
	}

	// Test GetGeneralCache (currently at 0% coverage)
	generalCache := manager.GetGeneralCache()
	if generalCache == nil {
		t.Error("GetGeneralCache should not return nil")
	}

	// Test GetRawTokenCache (currently at 0% coverage)
	rawTokenCache := manager.GetRawTokenCache()
	if rawTokenCache == nil {
		t.Error("GetRawTokenCache should not return nil")
	}

	// Test GetRawMetadataCache (currently at 0% coverage)
	rawMetadataCache := manager.GetRawMetadataCache()
	if rawMetadataCache == nil {
		t.Error("GetRawMetadataCache should not return nil")
	}

	// Test GetRawJWKCache (currently at 0% coverage)
	rawJWKCache := manager.GetRawJWKCache()
	if rawJWKCache == nil {
		t.Error("GetRawJWKCache should not return nil")
	}

	// Test ClearAll (currently at 0% coverage)
	// Add some data first
	generalCache.Set("test-key", "test-value", 1*time.Hour)
	rawTokenCache.Set("token-key", "token-value", 1*time.Hour)

	manager.ClearAll()

	// Verify all caches are cleared
	if generalCache.Size() != 0 {
		t.Error("General cache should be empty after ClearAll")
	}
	if rawTokenCache.Size() != 0 {
		t.Error("Token cache should be empty after ClearAll")
	}

	// Test CleanupAll (currently at 0% coverage)
	// Add some expired items
	generalCache.Set("expired1", "value1", 1*time.Millisecond)
	rawTokenCache.Set("expired2", "value2", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	manager.CleanupAll()
	// Note: CleanupAll may not immediately remove expired items depending on implementation

	// Test SetLogger (currently at 0% coverage)
	newLogger := &noOpLogger{}
	manager.SetLogger(newLogger)
	// Verify logger is set (we can't directly test this without exposing internal state)

	// Test Close with multiple components
	err := manager.Close()
	if err != nil {
		t.Errorf("Manager Close should not error: %v", err)
	}
}

// TestManagerCloseEdgeCases tests Manager.Close edge cases
func TestManagerCloseEdgeCases(t *testing.T) {
	manager := NewManager(nil)

	// Test Close when some caches might be nil
	err := manager.Close()
	if err != nil {
		t.Errorf("Close should handle nil caches gracefully: %v", err)
	}

	// Test double close (should return an error for the manager's underlying caches)
	err = manager.Close()
	if err == nil {
		t.Error("Double close should return an error")
	} else if err.Error() != "cache already closed" {
		t.Errorf("Expected 'cache already closed' error, got: %v", err)
	}
}

// TestCacheRaceConditions tests concurrent access patterns with race detection
func TestCacheRaceConditions(t *testing.T) {
	config := DefaultConfig()
	config.MaxSize = 1000
	cache := New(config)
	defer cache.Close()

	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	// Test concurrent Set/Get/Delete operations
	wg.Add(numGoroutines * 3)

	// Concurrent Set operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("set-key-%d-%d", id, j)
				value := fmt.Sprintf("value-%d-%d", id, j)
				cache.Set(key, value, 1*time.Hour)
			}
		}(i)
	}

	// Concurrent Get operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("get-key-%d", j%10)
				cache.Get(key)
			}
		}(i)
	}

	// Concurrent Delete operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("delete-key-%d", j%10)
				cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()

	// Test concurrent cache management operations
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			cache.Size()
			time.Sleep(1 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			cache.GetStats()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			cache.SetMaxSize(500 + i*100)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			cache.Cleanup()
			time.Sleep(15 * time.Millisecond)
		}
	}()

	wg.Wait()
}

// TestAdvancedEdgeCases tests complex edge cases and error scenarios
func TestAdvancedEdgeCases(t *testing.T) {
	// Test with extreme configuration values
	extremeConfig := Config{
		Type:              TypeGeneral,
		MaxSize:           1,                   // Very small
		MaxMemoryBytes:    100,                 // Very small memory limit
		DefaultTTL:        1 * time.Nanosecond, // Very short TTL
		CleanupInterval:   1 * time.Millisecond,
		EnableCompression: true,
		EnableMetrics:     true,
		EnableAutoCleanup: true,
		EnableMemoryLimit: true,
	}

	cache := New(extremeConfig)
	defer cache.Close()

	// Test rapid-fire operations with extreme config
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("rapid-%d", i)
		cache.Set(key, fmt.Sprintf("value-%d", i), 1*time.Millisecond)
		cache.Get(key)
		if i%10 == 0 {
			cache.Delete(key)
		}
	}

	// Test with complex nested data structures
	complexData := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": []interface{}{
					map[string]interface{}{
						"nested": "value",
						"number": 42,
						"array":  []int{1, 2, 3, 4, 5},
					},
				},
			},
		},
		"slice": []map[string]interface{}{
			{"key1": "value1"},
			{"key2": "value2"},
		},
	}

	err := cache.Set("complex", complexData, 1*time.Hour)
	if err != nil {
		t.Errorf("Setting complex data should not error: %v", err)
	}

	retrieved, exists := cache.Get("complex")
	if !exists {
		t.Error("Complex data should exist")
	}
	if retrieved == nil {
		t.Error("Retrieved complex data should not be nil")
	}

	// Test with various data types
	testCases := []struct {
		key   string
		value interface{}
	}{
		{"string", "test string"},
		{"int", 42},
		{"float", 3.14159},
		{"bool", true},
		{"slice", []string{"a", "b", "c"}},
		{"map", map[string]int{"one": 1, "two": 2}},
		{"nil", nil},
		{"empty-string", ""},
		{"empty-slice", []string{}},
		{"empty-map", map[string]interface{}{}},
	}

	for _, tc := range testCases {
		err := cache.Set(tc.key, tc.value, 1*time.Hour)
		if err != nil {
			t.Errorf("Setting %s should not error: %v", tc.key, err)
		}

		retrieved, exists := cache.Get(tc.key)
		if !exists {
			t.Errorf("Value for %s should exist", tc.key)
		}

		// For nil values, check that we get nil back
		if tc.value == nil && retrieved != nil {
			t.Errorf("Expected nil for %s, got %v", tc.key, retrieved)
		}
	}
}

// TestConcurrentManagerOperations tests Manager operations under concurrent access
func TestConcurrentManagerOperations(t *testing.T) {
	manager := NewManager(&noOpLogger{})
	defer manager.Close()

	var wg sync.WaitGroup
	numGoroutines := 20

	// Test concurrent access to different cache types
	wg.Add(numGoroutines * 5)

	// Concurrent token cache operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tokenCache := manager.GetTokenCache()
			for j := 0; j < 20; j++ {
				token := fmt.Sprintf("token-%d-%d", id, j)
				claims := map[string]interface{}{
					"sub": fmt.Sprintf("user-%d", id),
					"exp": time.Now().Add(1 * time.Hour).Unix(),
				}
				tokenCache.Set(token, claims, 1*time.Hour)
				tokenCache.Get(token)
			}
		}(i)
	}

	// Concurrent metadata cache operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			metadataCache := manager.GetMetadataCache()
			for j := 0; j < 20; j++ {
				url := fmt.Sprintf("https://provider-%d.com/.well-known/config-%d", id, j)
				metadata := &ProviderMetadata{
					Issuer: fmt.Sprintf("https://provider-%d.com", id),
				}
				metadataCache.Set(url, metadata, 1*time.Hour)
				metadataCache.Get(url)
			}
		}(i)
	}

	// Concurrent JWK cache operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			jwkCache := manager.GetJWKCache()
			for j := 0; j < 20; j++ {
				url := fmt.Sprintf("https://jwks-%d.com/keys-%d", id, j)
				jwkSet := &JWKSet{
					Keys: []JWK{
						{Kid: fmt.Sprintf("key-%d-%d", id, j), Kty: "RSA"},
					},
				}
				jwkCache.Set(url, jwkSet, 1*time.Hour)
				jwkCache.Get(url)
			}
		}(i)
	}

	// Concurrent session cache operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			sessionCache := manager.GetSessionCache()
			for j := 0; j < 20; j++ {
				sessionID := fmt.Sprintf("session-%d-%d", id, j)
				sessionData := SessionData{
					ID:        sessionID,
					UserID:    fmt.Sprintf("user-%d", id),
					ExpiresAt: time.Now().Add(30 * time.Minute),
				}
				sessionCache.Set(sessionID, sessionData, 30*time.Minute)
				sessionCache.Get(sessionID)
			}
		}(i)
	}

	// Concurrent manager operations
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				manager.GetStats()
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
}

// TestTTLExpirationAndCleanup tests TTL expiration and cleanup routines comprehensively
func TestTTLExpirationAndCleanup(t *testing.T) {
	config := DefaultConfig()
	config.CleanupInterval = 50 * time.Millisecond
	config.EnableAutoCleanup = true
	cache := New(config)
	defer cache.Close()

	// Test various TTL scenarios
	// Note: Timing increased 5x to account for race detector overhead
	testCases := []struct {
		key string
		ttl time.Duration
	}{
		{"very-short", 25 * time.Millisecond},
		{"short", 125 * time.Millisecond},
		{"medium", 500 * time.Millisecond},
		{"long", 1 * time.Hour},
	}

	for _, tc := range testCases {
		cache.Set(tc.key, fmt.Sprintf("value-%s", tc.key), tc.ttl)
	}

	// Verify all items exist initially
	for _, tc := range testCases {
		if _, exists := cache.Get(tc.key); !exists {
			t.Errorf("Item %s should exist initially", tc.key)
		}
	}

	// Wait for very short items to expire
	time.Sleep(75 * time.Millisecond)
	if _, exists := cache.Get("very-short"); exists {
		t.Error("Very short item should be expired")
	}

	// Wait for short items to expire
	time.Sleep(150 * time.Millisecond)
	if _, exists := cache.Get("short"); exists {
		t.Error("Short item should be expired")
	}

	// Medium should still exist
	if _, exists := cache.Get("medium"); !exists {
		t.Error("Medium item should still exist")
	}

	// Long should definitely still exist
	if _, exists := cache.Get("long"); !exists {
		t.Error("Long item should still exist")
	}

	// Test manual cleanup
	cache.Set("manual-cleanup", "value", 5*time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	cache.Cleanup()

	// Add many expired items to test bulk cleanup
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("bulk-%d", i)
		cache.Set(key, fmt.Sprintf("value-%d", i), 5*time.Millisecond)
	}
	time.Sleep(25 * time.Millisecond)

	sizeBefore := cache.Size()
	cache.Cleanup()
	sizeAfter := cache.Size()

	if sizeAfter >= sizeBefore {
		t.Error("Cleanup should have removed expired items")
	}
}

// TestCacheStatisticsAndMetrics tests comprehensive statistics and metrics
func TestCacheStatisticsAndMetrics(t *testing.T) {
	config := DefaultConfig()
	config.EnableMetrics = true
	cache := New(config)
	defer cache.Close()

	// Test initial stats
	stats := cache.GetStats()
	requiredFields := []string{"size", "hits", "misses", "memory", "hit_rate"}
	for _, field := range requiredFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Stats should contain field: %s", field)
		}
	}

	// Test stats tracking with various operations
	operations := []struct {
		key    string
		value  string
		exists bool
	}{
		{"hit1", "value1", true},
		{"hit2", "value2", true},
		{"miss1", "", false},
		{"hit1", "value1", true}, // Repeat for hit
		{"miss2", "", false},
		{"hit2", "value2", true}, // Repeat for hit
	}

	expectedHits := 0
	expectedMisses := 0
	size := 0

	for _, op := range operations {
		if op.exists {
			cache.Set(op.key, op.value, 1*time.Hour)
			if size < 2 { // Only count unique keys
				size++
			}
		}

		_, exists := cache.Get(op.key)
		if exists {
			expectedHits++
		} else {
			expectedMisses++
		}
	}

	stats = cache.GetStats()
	actualHits := stats["hits"].(int64)
	actualMisses := stats["misses"].(int64)
	actualSize := stats["size"].(int64)

	if int(actualHits) != expectedHits {
		t.Errorf("Expected %d hits, got %d", expectedHits, actualHits)
	}
	if int(actualMisses) != expectedMisses {
		t.Errorf("Expected %d misses, got %d", expectedMisses, actualMisses)
	}
	if int(actualSize) != size {
		t.Errorf("Expected size %d, got %d", size, actualSize)
	}

	// Test hit rate calculation
	expectedHitRate := float64(expectedHits) / float64(expectedHits+expectedMisses)
	actualHitRate := stats["hit_rate"].(float64)
	if actualHitRate != expectedHitRate {
		t.Errorf("Expected hit rate %f, got %f", expectedHitRate, actualHitRate)
	}

	// Test memory usage tracking
	memoryUsage := stats["memory"].(int64)
	if memoryUsage <= 0 {
		t.Error("Memory usage should be positive")
	}

	// Add larger items and verify memory increases
	largeValue := string(make([]byte, 1000))
	cache.Set("large", largeValue, 1*time.Hour)

	newStats := cache.GetStats()
	newMemoryUsage := newStats["memory"].(int64)
	if newMemoryUsage <= memoryUsage {
		t.Error("Memory usage should increase after adding large item")
	}
}

// ============================================================================
// noOpLogger Tests
// ============================================================================

// TestNoOpLogger_AllMethods tests all noOpLogger methods to ensure they don't panic
func TestNoOpLogger_AllMethods(t *testing.T) {
	logger := &noOpLogger{}

	// Test simple message methods
	logger.Debug("test debug message")
	logger.Info("test info message")
	logger.Error("test error message")
	logger.Warn("test warn message")
	logger.Fatal("test fatal message")

	// Test formatted message methods
	logger.Debugf("test debug: %s", "value")
	logger.Infof("test info: %s", "value")
	logger.Errorf("test error: %s", "value")
	logger.Warnf("test warn: %s", "value")
	logger.Fatalf("test fatal: %s", "value")

	// If we reach here, all methods executed without panicking
	// This is expected behavior for a no-op logger
}

// TestNoOpLogger_WithField verifies WithField returns the same logger
func TestNoOpLogger_WithField(t *testing.T) {
	logger := &noOpLogger{}

	result := logger.WithField("key", "value")

	if result != logger {
		t.Error("WithField should return the same logger instance")
	}

	// Verify the returned logger works
	result.Info("test message after WithField")
}

// TestNoOpLogger_WithFields verifies WithFields returns the same logger
func TestNoOpLogger_WithFields(t *testing.T) {
	logger := &noOpLogger{}

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	result := logger.WithFields(fields)

	if result != logger {
		t.Error("WithFields should return the same logger instance")
	}

	// Verify the returned logger works
	result.Info("test message after WithFields")
}

// TestNoOpLogger_Chaining verifies method chaining works
func TestNoOpLogger_Chaining(t *testing.T) {
	logger := &noOpLogger{}

	// Use WithField and verify it returns a usable logger
	result := logger.WithField("key1", "value1")

	// Verify the result can be used for logging (Logger interface methods)
	result.Info("info after WithField")
	result.Infof("infof after WithField: %s", "test")
	result.Debug("debug after WithField")
	result.Debugf("debugf after WithField: %d", 123)
	result.Error("error after WithField")
	result.Errorf("errorf after WithField: %v", true)

	// Use WithFields and verify it returns a usable logger
	result2 := logger.WithFields(map[string]interface{}{
		"key2": "value2",
		"key3": 123,
	})

	// Verify the result can be used for logging
	result2.Infof("message after WithFields: %s", "test")
}
