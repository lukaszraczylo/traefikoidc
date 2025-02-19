package traefikoidc

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestTokenBlacklistSizeLimit(t *testing.T) {
	tb := NewTokenBlacklist()

	// Add tokens up to maxSize
	for i := 0; i < 1000; i++ {
		tb.Add(fmt.Sprintf("token%d", i), time.Now().Add(time.Hour))
	}

	// Verify size is at max
	if tb.Count() != 1000 {
		t.Errorf("Expected blacklist size to be 1000, got %d", tb.Count())
	}

	// Add one more token, should trigger cleanup/eviction
	tb.Add("newtoken", time.Now().Add(time.Hour))

	// Size should still be at max
	if tb.Count() > 1000 {
		t.Errorf("Blacklist exceeded max size: %d", tb.Count())
	}
}

func TestTokenBlacklistExpiredCleanup(t *testing.T) {
	tb := NewTokenBlacklist()

	// Add some expired tokens
	for i := 0; i < 500; i++ {
		tb.Add(fmt.Sprintf("expired%d", i), time.Now().Add(-time.Hour))
	}

	// Add some valid tokens
	for i := 0; i < 500; i++ {
		tb.Add(fmt.Sprintf("valid%d", i), time.Now().Add(time.Hour))
	}

	// Force cleanup
	tb.Cleanup()

	// Only valid tokens should remain
	if tb.Count() != 500 {
		t.Errorf("Expected 500 valid tokens after cleanup, got %d", tb.Count())
	}

	// Verify only valid tokens remain
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	for token, expiry := range tb.tokens {
		if time.Now().After(expiry) {
			t.Errorf("Found expired token after cleanup: %s", token)
		}
	}
}

func TestTokenBlacklistOldestEviction(t *testing.T) {
	tb := NewTokenBlacklist()

	// Add tokens at capacity with different expiration times
	baseTime := time.Now()
	oldestToken := "oldest"

	// Add oldest token first
	tb.Add(oldestToken, baseTime.Add(time.Hour))

	// Fill up to capacity with newer tokens
	for i := 0; i < 999; i++ {
		tb.Add(fmt.Sprintf("token%d", i), baseTime.Add(time.Hour*2))
	}

	// Add a new token that should evict the oldest
	newToken := "newest"
	tb.Add(newToken, baseTime.Add(time.Hour*3))

	// Verify oldest token was evicted
	if tb.IsBlacklisted(oldestToken) {
		t.Error("Oldest token should have been evicted")
	}

	// Verify newest token is present
	if !tb.IsBlacklisted(newToken) {
		t.Error("Newest token should be present")
	}
}

func TestTokenBlacklistMemoryUsage(t *testing.T) {
	tb := NewTokenBlacklist()
	iterations := 10000

	// Force initial GC
	runtime.GC()

	// Record initial memory stats
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Simulate heavy usage
	for i := 0; i < iterations; i++ {
		// Add new token
		tb.Add(fmt.Sprintf("token%d", i), time.Now().Add(time.Hour))

		// Periodically check blacklisted status
		if i%100 == 0 {
			tb.IsBlacklisted(fmt.Sprintf("token%d", i-50))
		}

		// Periodically cleanup
		if i%1000 == 0 {
			tb.Cleanup()
		}
	}

	// Force GC and wait for it to complete
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.ReadMemStats(&m2)

	// Check memory growth (using HeapAlloc for more accurate measurement)
	memoryGrowth := int64(m2.HeapAlloc - m1.HeapAlloc)
	maxAllowedGrowth := int64(2 * 1024 * 1024) // 2MB max growth

	if memoryGrowth > maxAllowedGrowth {
		t.Logf("Initial HeapAlloc: %d, Final HeapAlloc: %d", m1.HeapAlloc, m2.HeapAlloc)
		t.Errorf("Excessive memory growth: %d bytes", memoryGrowth)
	}

	// Verify size stayed within limits
	if tb.Count() > 1000 {
		t.Errorf("Blacklist exceeded max size: %d", tb.Count())
	}
}

func TestConcurrentTokenBlacklistOperations(t *testing.T) {
	tb := NewTokenBlacklist()
	iterations := 1000
	concurrency := 10
	done := make(chan bool)

	// Start multiple goroutines performing operations
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				// Add tokens
				token := fmt.Sprintf("token%d-%d", id, j)
				tb.Add(token, time.Now().Add(time.Hour))

				// Check blacklist status
				tb.IsBlacklisted(token)

				// Periodic cleanup
				if j%100 == 0 {
					tb.Cleanup()
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Verify size constraints were maintained
	if tb.Count() > 1000 {
		t.Errorf("Blacklist exceeded max size under concurrent operations: %d", tb.Count())
	}
}

func TestTokenCacheMemoryUsage(t *testing.T) {
	tc := NewTokenCache()
	iterations := 10000

	// Force initial GC
	runtime.GC()

	// Record initial memory stats
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Simulate heavy cache usage
	for i := 0; i < iterations; i++ {
		claims := map[string]interface{}{
			"sub": fmt.Sprintf("user%d", i),
			"exp": time.Now().Add(time.Hour).Unix(),
		}

		// Add to cache
		tc.Set(fmt.Sprintf("token%d", i), claims, time.Hour)

		// Periodically retrieve
		if i%100 == 0 {
			tc.Get(fmt.Sprintf("token%d", i-50))
		}

		// Periodically cleanup
		if i%1000 == 0 {
			tc.Cleanup()
		}
	}

	// Force GC and wait for it to complete
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.ReadMemStats(&m2)

	// Check memory growth (using HeapAlloc for more accurate measurement)
	memoryGrowth := int64(m2.HeapAlloc - m1.HeapAlloc)
	maxAllowedGrowth := int64(2 * 1024 * 1024) // 2MB max growth

	if memoryGrowth > maxAllowedGrowth {
		t.Logf("Initial HeapAlloc: %d, Final HeapAlloc: %d", m1.HeapAlloc, m2.HeapAlloc)
		t.Errorf("Excessive cache memory growth: %d bytes", memoryGrowth)
	}

	// Verify cache size stayed within limits
	if len(tc.cache.items) > tc.cache.maxSize {
		t.Errorf("Cache exceeded max size: %d", len(tc.cache.items))
	}
}
