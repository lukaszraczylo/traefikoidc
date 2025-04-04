package traefikoidc

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// Removed tests related to the old TokenBlacklist implementation:
// - TestTokenBlacklistSizeLimit
// - TestTokenBlacklistExpiredCleanup
// - TestTokenBlacklistOldestEviction
// - TestTokenBlacklistMemoryUsage
// - TestConcurrentTokenBlacklistOperations

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
