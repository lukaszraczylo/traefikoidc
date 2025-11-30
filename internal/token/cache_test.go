//go:build !yaegi

package token

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock implementations
type mockCache struct {
	data map[string]map[string]interface{}
	mu   sync.RWMutex
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string]map[string]interface{}),
	}
}

func (m *mockCache) Get(key string) (map[string]interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, exists := m.data[key]
	return val, exists
}

func (m *mockCache) Set(key string, value map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
}

func (m *mockCache) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

type mockLogger struct{}

func (m *mockLogger) Logf(format string, args ...interface{})      {}
func (m *mockLogger) ErrorLogf(format string, args ...interface{}) {}

type mockMetrics struct{}

func (m *mockMetrics) RecordTokenRefresh()      {}
func (m *mockMetrics) RecordTokenRefreshError() {}

// TokenCache tests
func TestNewTokenCache(t *testing.T) {
	cache := newMockCache()
	blacklist := newMockCache()
	logger := &mockLogger{}
	metrics := &mockMetrics{}

	tokenCache := NewTokenCache(cache, blacklist, logger, metrics, 5*time.Minute)

	if tokenCache == nil {
		t.Fatal("Expected NewTokenCache to return non-nil")
	}

	if tokenCache.cache == nil {
		t.Error("Expected cache to be set")
	}

	if tokenCache.maxTTL != 5*time.Minute {
		t.Error("Expected maxTTL to be 5 minutes")
	}
}

func TestTokenCache_CacheToken(t *testing.T) {
	cache := newMockCache()
	blacklist := newMockCache()
	logger := &mockLogger{}
	metrics := &mockMetrics{}
	tokenCache := NewTokenCache(cache, blacklist, logger, metrics, 5*time.Minute)

	claims := map[string]interface{}{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	tokenCache.CacheToken("test-token", claims)

	// Verify it was cached with metadata
	stored, exists := cache.Get("test-token")
	if !exists {
		t.Error("Expected token to be cached")
	}

	if stored["sub"] != "user123" {
		t.Error("Expected sub claim to be preserved")
	}

	if _, ok := stored["_cached_at"]; !ok {
		t.Error("Expected _cached_at metadata to be added")
	}
}

func TestTokenCache_CacheToken_EmptyToken(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	claims := map[string]interface{}{"sub": "user"}

	// Should not cache empty token
	tokenCache.CacheToken("", claims)

	if len(cache.data) != 0 {
		t.Error("Expected empty token not to be cached")
	}
}

func TestTokenCache_CacheToken_EmptyClaims(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	// Should not cache with empty claims
	tokenCache.CacheToken("test-token", map[string]interface{}{})

	if len(cache.data) != 0 {
		t.Error("Expected token with empty claims not to be cached")
	}
}

func TestTokenCache_GetCachedToken(t *testing.T) {
	cache := newMockCache()
	blacklist := newMockCache()
	tokenCache := NewTokenCache(cache, blacklist, &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	claims := map[string]interface{}{
		"sub": "user123",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	tokenCache.CacheToken("test-token", claims)

	// Retrieve token
	retrieved, exists := tokenCache.GetCachedToken("test-token")
	if !exists {
		t.Error("Expected cached token to be found")
	}

	if retrieved["sub"] != "user123" {
		t.Error("Expected sub claim to match")
	}
}

func TestTokenCache_GetCachedToken_Expired(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	// Add expired token
	expiredClaims := map[string]interface{}{
		"sub": "user",
		"exp": float64(time.Now().Add(-1 * time.Hour).Unix()),
	}

	tokenCache.CacheToken("expired-token", expiredClaims)

	// Should not return expired token
	_, exists := tokenCache.GetCachedToken("expired-token")
	if exists {
		t.Error("Expected expired token not to be returned")
	}
}

func TestTokenCache_GetCachedToken_ExceedsMaxTTL(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 1*time.Millisecond)

	claims := map[string]interface{}{
		"sub":        "user",
		"exp":        float64(time.Now().Add(1 * time.Hour).Unix()),
		"_cached_at": time.Now().Add(-10 * time.Minute).Unix(),
	}

	cache.Set("old-token", claims)

	// Should not return token that exceeds maxTTL
	_, exists := tokenCache.GetCachedToken("old-token")
	if exists {
		t.Error("Expected token exceeding maxTTL not to be returned")
	}
}

func TestTokenCache_GetCachedToken_Blacklisted(t *testing.T) {
	cache := newMockCache()
	blacklist := newMockCache()
	tokenCache := NewTokenCache(cache, blacklist, &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	claims := map[string]interface{}{
		"sub": "user",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	tokenCache.CacheToken("token", claims)

	// Blacklist the token
	blacklist.Set("token", map[string]interface{}{"reason": "test"})

	// Should not return blacklisted token
	_, exists := tokenCache.GetCachedToken("token")
	if exists {
		t.Error("Expected blacklisted token not to be returned")
	}
}

func TestTokenCache_InvalidateToken(t *testing.T) {
	cache := newMockCache()
	blacklist := newMockCache()
	tokenCache := NewTokenCache(cache, blacklist, &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	claims := map[string]interface{}{
		"sub": "user",
	}

	tokenCache.CacheToken("token", claims)

	// Invalidate
	tokenCache.InvalidateToken("token")

	// Should be removed from cache
	_, exists := cache.Get("token")
	if exists {
		t.Error("Expected token to be removed from cache")
	}

	// Should be in blacklist
	_, blacklisted := blacklist.Get("token")
	if !blacklisted {
		t.Error("Expected token to be blacklisted")
	}
}

func TestTokenCache_StartStopCleanup(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	// Start cleanup
	tokenCache.StartCleanup(100 * time.Millisecond)

	// Verify ticker is set
	if tokenCache.cleanupTicker == nil {
		t.Error("Expected cleanup ticker to be started")
	}

	// Stop cleanup
	tokenCache.StopCleanup()

	// Wait briefly for cleanup to stop
	time.Sleep(50 * time.Millisecond)

	// Ticker should be nil after stop
	if tokenCache.cleanupTicker != nil {
		t.Error("Expected cleanup ticker to be stopped")
	}
}

func TestTokenCache_StartCleanup_AlreadyRunning(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	// Start cleanup
	tokenCache.StartCleanup(100 * time.Millisecond)
	ticker1 := tokenCache.cleanupTicker

	// Start again (should not create new ticker)
	tokenCache.StartCleanup(100 * time.Millisecond)
	ticker2 := tokenCache.cleanupTicker

	if ticker1 != ticker2 {
		t.Error("Expected same ticker when starting cleanup while already running")
	}

	tokenCache.StopCleanup()
}

// TokenBlacklist tests
func TestNewTokenBlacklist(t *testing.T) {
	blacklist := newMockCache()
	logger := &mockLogger{}

	tb := NewTokenBlacklist(blacklist, logger)

	if tb == nil {
		t.Fatal("Expected NewTokenBlacklist to return non-nil")
	}

	if tb.blacklist == nil {
		t.Error("Expected blacklist to be set")
	}
}

func TestTokenBlacklist_Add(t *testing.T) {
	blacklist := newMockCache()
	tb := NewTokenBlacklist(blacklist, &mockLogger{})

	tb.Add("test-token", "test_reason")

	// Verify token was blacklisted
	data, exists := blacklist.Get("test-token")
	if !exists {
		t.Error("Expected token to be blacklisted")
	}

	if data["reason"] != "test_reason" {
		t.Error("Expected reason to be stored")
	}
}

func TestTokenBlacklist_AddJTI(t *testing.T) {
	blacklist := newMockCache()
	tb := NewTokenBlacklist(blacklist, &mockLogger{})

	tb.AddJTI("jti-123")

	// Verify JTI was blacklisted
	data, exists := blacklist.Get("jti-123")
	if !exists {
		t.Error("Expected JTI to be blacklisted")
	}

	if data["reason"] != "jti_replay_detection" {
		t.Error("Expected replay detection reason")
	}
}

func TestTokenBlacklist_IsBlacklisted(t *testing.T) {
	blacklist := newMockCache()
	tb := NewTokenBlacklist(blacklist, &mockLogger{})

	tb.Add("blacklisted-token", "test")

	if !tb.IsBlacklisted("blacklisted-token") {
		t.Error("Expected token to be blacklisted")
	}

	if tb.IsBlacklisted("not-blacklisted") {
		t.Error("Expected token not to be blacklisted")
	}
}

func TestTokenBlacklist_IsJTIBlacklisted(t *testing.T) {
	blacklist := newMockCache()
	tb := NewTokenBlacklist(blacklist, &mockLogger{})

	tb.AddJTI("jti-123")

	if !tb.IsJTIBlacklisted("jti-123") {
		t.Error("Expected JTI to be blacklisted")
	}

	if tb.IsJTIBlacklisted("jti-456") {
		t.Error("Expected JTI not to be blacklisted")
	}
}

// TokenRevocationManager tests
func TestNewTokenRevocationManager(t *testing.T) {
	blacklist := NewTokenBlacklist(newMockCache(), &mockLogger{})
	httpClient := &http.Client{}

	trm := NewTokenRevocationManager("client-id", "secret", "https://revoke.url", httpClient, &mockLogger{}, blacklist)

	if trm == nil {
		t.Fatal("Expected NewTokenRevocationManager to return non-nil")
	}

	if trm.clientID != "client-id" {
		t.Error("Expected clientID to be set")
	}
}

func TestTokenRevocationManager_RevokeToken(t *testing.T) {
	blacklist := NewTokenBlacklist(newMockCache(), &mockLogger{})
	trm := NewTokenRevocationManager("client-id", "secret", "https://revoke.url", &http.Client{}, &mockLogger{}, blacklist)

	err := trm.RevokeToken("test-token", "access_token", false)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Token should be in blacklist
	if !blacklist.IsBlacklisted("test-token") {
		t.Error("Expected token to be blacklisted")
	}
}

// Race condition tests
func TestTokenCache_ConcurrentAccess(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent cache operations
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			claims := map[string]interface{}{
				"sub": idx,
				"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			}
			token := string(rune('A' + idx%26))
			tokenCache.CacheToken(token, claims)
		}(i)
	}

	// Concurrent retrieve operations
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := string(rune('A' + idx%26))
			_, _ = tokenCache.GetCachedToken(token)
		}(i)
	}

	// Concurrent invalidations
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := string(rune('A' + idx%26))
			tokenCache.InvalidateToken(token)
		}(i)
	}

	wg.Wait()
}

func TestTokenBlacklist_ConcurrentAccess(t *testing.T) {
	blacklist := newMockCache()
	tb := NewTokenBlacklist(blacklist, &mockLogger{})

	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tb.Add(string(rune('A'+idx%26)), "test")
		}(i)
	}

	// Concurrent checks
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = tb.IsBlacklisted(string(rune('A' + idx%26)))
		}(i)
	}

	wg.Wait()
}

func TestTokenCache_CleanupWithConcurrentOperations(t *testing.T) {
	cache := newMockCache()
	tokenCache := NewTokenCache(cache, newMockCache(), &mockLogger{}, &mockMetrics{}, 5*time.Minute)

	var wg sync.WaitGroup
	stopFlag := atomic.Bool{}

	// Start cleanup
	tokenCache.StartCleanup(50 * time.Millisecond)

	// Goroutine adding tokens
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stopFlag.Load() && i < 50; i++ {
			claims := map[string]interface{}{
				"sub": i,
				"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
			}
			tokenCache.CacheToken(string(rune('A'+i%26)), claims)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine invalidating tokens
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stopFlag.Load() && i < 30; i++ {
			tokenCache.InvalidateToken(string(rune('A' + i%26)))
			time.Sleep(15 * time.Millisecond)
		}
	}()

	// Let it run for a bit
	time.Sleep(300 * time.Millisecond)
	stopFlag.Store(true)

	wg.Wait()

	// Stop cleanup
	tokenCache.StopCleanup()

	// Should not have panicked
}
