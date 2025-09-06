package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test the core OptimizedCache functionality that's not covered
func TestOptimizedCacheBasic(t *testing.T) {
	cache := NewOptimizedCache()
	if cache == nil {
		t.Fatal("NewOptimizedCache returned nil")
	}

	// Basic set and get
	cache.Set("test_key", "test_value", 5*time.Minute)
	if val, found := cache.Get("test_key"); !found || val != "test_value" {
		t.Errorf("Failed to get cached value: %v, %v", val, found)
	}

	// Delete
	cache.Delete("test_key")
	if _, found := cache.Get("test_key"); found {
		t.Error("Value should be deleted")
	}

	// Test with config
	logger := NewLogger("debug")
	config := OptimizedCacheConfig{
		MaxSize:           50,
		MaxMemoryBytes:    10,
		Logger:            logger,
		EnableMemoryLimit: true,
	}
	cache2 := NewOptimizedCacheWithConfig(config)
	if cache2 == nil {
		t.Fatal("NewOptimizedCacheWithConfig returned nil")
	}

	// Test cleanup
	cache2.Set("expire", "value", 100*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cache2.Cleanup()
	if _, found := cache2.Get("expire"); found {
		t.Error("Expired item should be cleaned up")
	}

	// Test close
	cache2.Close()
}

// Test UnifiedCache basic functionality
func TestUnifiedCacheBasic(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	if config.MaxSize <= 0 {
		t.Error("Default config should have positive MaxSize")
	}

	cache := NewUnifiedCache(config)
	if cache == nil {
		t.Fatal("NewUnifiedCache returned nil")
	}

	// Basic operations
	cache.Set("key1", "value1", 5*time.Minute)
	if val, found := cache.Get("key1"); !found || val != "value1" {
		t.Errorf("Failed to get cached value: %v", val)
	}

	cache.Delete("key1")
	if _, found := cache.Get("key1"); found {
		t.Error("Value should be deleted")
	}

	// Cleanup
	cache.Set("expired", "value", 1*time.Nanosecond)
	time.Sleep(10 * time.Millisecond)
	cache.Cleanup()

	// GetMetrics
	metrics := cache.GetMetrics()
	if metrics == nil {
		t.Error("GetMetrics should not return nil")
	}

	cache.Close()
}

// Test memory pool functionality
func TestMemoryPoolBasic(t *testing.T) {
	manager := NewMemoryPoolManager()
	if manager == nil {
		t.Fatal("NewMemoryPoolManager returned nil")
	}

	// Test compression buffer
	buf := manager.GetCompressionBuffer()
	if buf == nil {
		t.Fatal("GetCompressionBuffer returned nil")
	}
	buf.WriteString("test")
	manager.PutCompressionBuffer(buf)

	// Test JWT parsing buffer
	jwtBuf := manager.GetJWTParsingBuffer()
	if jwtBuf == nil {
		t.Fatal("GetJWTParsingBuffer returned nil")
	}
	manager.PutJWTParsingBuffer(jwtBuf)

	// Test HTTP response buffer
	httpBuf := manager.GetHTTPResponseBuffer()
	if httpBuf == nil {
		t.Fatal("GetHTTPResponseBuffer returned nil")
	}
	manager.PutHTTPResponseBuffer(httpBuf)

	// Test string builder
	sb := manager.GetStringBuilder()
	if sb == nil {
		t.Fatal("GetStringBuilder returned nil")
	}
	manager.PutStringBuilder(sb)
}

// Test global memory pools
func TestGlobalPools(t *testing.T) {
	pools := GetGlobalMemoryPools()
	if pools == nil {
		t.Fatal("GetGlobalMemoryPools returned nil")
	}

	// Should be singleton
	pools2 := GetGlobalMemoryPools()
	if pools != pools2 {
		t.Error("GetGlobalMemoryPools should return singleton")
	}

	// Cleanup should not panic
	CleanupGlobalMemoryPools()
}

// Test TokenCompressionPool
func TestTokenCompression(t *testing.T) {
	pool := NewTokenCompressionPool()
	if pool == nil {
		t.Fatal("NewTokenCompressionPool returned nil")
	}

	compBuf := pool.GetCompressionBuffer()
	if compBuf == nil {
		t.Fatal("GetCompressionBuffer returned nil")
	}
	pool.PutCompressionBuffer(compBuf)

	decompBuf := pool.GetDecompressionBuffer()
	if decompBuf == nil {
		t.Fatal("GetDecompressionBuffer returned nil")
	}
	pool.PutDecompressionBuffer(decompBuf)
}

// Test error recovery base functionality
func TestErrorRecoveryBasic(t *testing.T) {
	logger := NewLogger("debug")

	// Test BaseRecoveryMechanism
	base := NewBaseRecoveryMechanism("test", logger)
	base.RecordRequest()
	base.RecordSuccess()
	base.RecordFailure()

	metrics := base.GetBaseMetrics()
	if metrics == nil {
		t.Fatal("GetBaseMetrics returned nil")
	}

	// Test CircuitBreaker
	cbConfig := CircuitBreakerConfig{
		MaxFailures:  3,
		ResetTimeout: 100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cbConfig, logger)

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Initial state should be closed")
	}

	// Trip the circuit
	for i := 0; i < 3; i++ {
		cb.Execute(func() error {
			return fmt.Errorf("error")
		})
	}

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit should be open after max failures")
	}

	cb.Reset()
	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Circuit should be closed after reset")
	}

	// Test RetryExecutor
	retryConfig := RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
	}
	re := NewRetryExecutor(retryConfig, logger)

	if re != nil && !re.IsAvailable() {
		t.Error("RetryExecutor should be available")
	}
}

// Test profiling components
func TestProfilingBasic(t *testing.T) {
	logger := NewLogger("debug")

	// Test ProfilingManager
	pm := NewProfilingManager(logger)
	if pm == nil {
		t.Fatal("NewProfilingManager returned nil")
	}

	// Take snapshot - may fail if profiling is disabled
	snapshot, _ := pm.TakeSnapshot()
	if snapshot != nil {
		t.Log("Snapshot taken successfully")
	}

	// Test global singletons
	globalPM := GetGlobalProfilingManager()
	if globalPM == nil {
		t.Fatal("GetGlobalProfilingManager returned nil")
	}

	globalMTO := GetGlobalTestOrchestrator()
	if globalMTO == nil {
		t.Fatal("GetGlobalTestOrchestrator returned nil")
	}
}

// Test cache strategies
func TestCacheStrategies(t *testing.T) {
	// Test LRU strategy
	lru := NewLRUStrategy(10)
	if lru.Name() != "LRU" {
		t.Errorf("Expected LRU name, got %s", lru.Name())
	}

	// Test doubly linked list
	list := NewDoublyLinkedList()
	node1 := list.PushBack("key1")
	if node1 == nil || node1.Key != "key1" {
		t.Error("PushBack failed")
	}

	list.PushBack("key2")
	list.PushBack("key3")

	list.MoveToBack(node1)

	popped := list.PopFront()
	if popped == nil || popped.Key != "key2" {
		t.Errorf("Expected key2, got %v", popped)
	}
}

// Test CacheAdapter
func TestCacheAdapterBasic(t *testing.T) {
	config := DefaultUnifiedCacheConfig()
	unified := NewUnifiedCache(config)
	adapter := NewCacheAdapter(unified)

	adapter.Set("key", "value", 5*time.Minute)
	if val, found := adapter.Get("key"); !found || val != "value" {
		t.Errorf("CacheAdapter get failed: %v", val)
	}

	adapter.Delete("key")
	adapter.Cleanup()
	adapter.Close()
}

// Test JWT validation edge cases
func TestJWTValidationCases(t *testing.T) {
	validator := NewTokenValidator(NewLogger("debug"))

	// Test valid JWT
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	token := header + "." + payload + "." + signature

	result := validator.ValidateToken(token, true)
	if !result.Valid {
		t.Errorf("Expected valid token, got error: %v", result.Error)
	}

	// Test expired JWT
	expiredClaims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}
	expiredJSON, _ := json.Marshal(expiredClaims)
	expiredPayload := base64.RawURLEncoding.EncodeToString(expiredJSON)
	expiredToken := header + "." + expiredPayload + "." + signature

	expiredResult := validator.ValidateToken(expiredToken, true)
	if expiredResult.Valid {
		t.Error("Expired token should be invalid")
	}

	// Test opaque token
	opaqueToken := "abcdefghijklmnopqrstuvwxyz1234567890"
	opaqueResult := validator.ValidateToken(opaqueToken, false)
	if !opaqueResult.Valid {
		t.Errorf("Valid opaque token rejected: %v", opaqueResult.Error)
	}

	// Test ExtractClaims
	extractedClaims, err := validator.ExtractClaims(token)
	if err != nil || extractedClaims["sub"] != "user123" {
		t.Errorf("ExtractClaims failed: %v", err)
	}

	// Test CompareTokens
	if !validator.CompareTokens("token123", "token123") {
		t.Error("Identical tokens should match")
	}
	if validator.CompareTokens("token123", "token456") {
		t.Error("Different tokens should not match")
	}

	// Test ValidateTokenSize
	if err := validator.ValidateTokenSize("small", 100); err != nil {
		t.Errorf("Small token should be valid: %v", err)
	}
	if err := validator.ValidateTokenSize(strings.Repeat("a", 200), 100); err == nil {
		t.Error("Large token should be invalid")
	}
}

// Test replay cache
func TestReplayCacheBasic(t *testing.T) {
	// Test getReplayCacheStats
	size, maxSize := getReplayCacheStats()
	if size < 0 || maxSize <= 0 {
		t.Errorf("Invalid replay cache stats: size=%d, maxSize=%d", size, maxSize)
	}

	// Test cleanupReplayCache (should not panic)
	cleanupReplayCache()
}

// Test audience verification
func TestAudienceVerify(t *testing.T) {
	// Exact match
	if err := verifyAudience("my-client", "my-client"); err != nil {
		t.Errorf("Exact match should succeed: %v", err)
	}

	// Array contains
	audArray := []interface{}{"client1", "my-client", "client2"}
	if err := verifyAudience(audArray, "my-client"); err != nil {
		t.Errorf("Array contains should succeed: %v", err)
	}

	// Mismatch
	if err := verifyAudience("other-client", "my-client"); err == nil {
		t.Error("Mismatch should fail")
	}

	// Missing/nil audience
	if err := verifyAudience(nil, "my-client"); err == nil {
		t.Error("Nil aud should fail")
	}
}

// Test helper functions
func TestHelpers(t *testing.T) {
	// Test nonce generation
	nonce1, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce failed: %v", err)
	}
	if len(nonce1) == 0 {
		t.Error("Nonce should not be empty")
	}

	nonce2, _ := generateNonce()
	if nonce1 == nonce2 {
		t.Error("Nonces should be unique")
	}

	// Test code verifier generation
	verifier1, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier failed: %v", err)
	}
	if len(verifier1) == 0 {
		t.Error("Code verifier should not be empty")
	}

	verifier2, _ := generateCodeVerifier()
	if verifier1 == verifier2 {
		t.Error("Code verifiers should be unique")
	}
}

// Test HTTP client factory
func TestHTTPClientCreation(t *testing.T) {
	// Default client
	client1 := CreateDefaultHTTPClient()
	if client1 == nil {
		t.Fatal("CreateDefaultHTTPClient returned nil")
	}
	// Default client should have 30s timeout
	if client1.Timeout != 30*time.Second {
		t.Errorf("Expected 30s timeout, got %v", client1.Timeout)
	}

	// Token client
	client2 := CreateTokenHTTPClient()
	if client2 == nil {
		t.Fatal("CreateTokenHTTPClient returned nil")
	}
	if client2.Timeout != 10*time.Second {
		t.Errorf("Expected 10s timeout, got %v", client2.Timeout)
	}

	// Custom config client
	config := HTTPClientConfig{
		Timeout:            5 * time.Second,
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	client3 := CreateHTTPClientWithConfig(config)
	if client3 == nil {
		t.Fatal("CreateHTTPClientWithConfig returned nil")
	}
	// Custom config client should have 5s timeout as configured
	if client3.Timeout != 5*time.Second {
		t.Errorf("Expected 5s timeout, got %v", client3.Timeout)
	}
}

// Test metadata cache
func TestMetadataCaching(t *testing.T) {
	var wg sync.WaitGroup
	logger := NewLogger("debug")
	cache := NewMetadataCacheWithLogger(&wg, logger)
	if cache == nil {
		t.Fatal("NewMetadataCache returned nil")
	}
	// Basic test that cache was created
}

// Test JWT parsing
func TestJWTParsing(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	token := header + "." + payload + "." + signature

	parsedJWT, err := parseJWT(token)
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if parsedJWT.Claims["sub"] != "user123" {
		t.Errorf("Expected sub=user123, got %v", parsedJWT.Claims["sub"])
	}
}
