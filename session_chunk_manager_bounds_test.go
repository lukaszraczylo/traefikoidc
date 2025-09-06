package traefikoidc

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// TestSessionMapBounds_HardLimitEnforcement tests that the session map enforces hard limits
// and prevents unbounded memory growth
func TestSessionMapBounds_HardLimitEnforcement(t *testing.T) {
	tests := []struct {
		name           string
		maxSessions    int
		sessionCount   int
		expectEviction bool
		description    string
	}{
		{
			name:           "within_limit",
			maxSessions:    100,
			sessionCount:   50,
			expectEviction: false,
			description:    "Sessions within limit should not trigger eviction",
		},
		{
			name:           "at_limit",
			maxSessions:    100,
			sessionCount:   100,
			expectEviction: false,
			description:    "Sessions at exact limit should not trigger eviction",
		},
		{
			name:           "exceeds_limit",
			maxSessions:    100,
			sessionCount:   150,
			expectEviction: true,
			description:    "Sessions exceeding limit should trigger eviction",
		},
		{
			name:           "small_limit",
			maxSessions:    10,
			sessionCount:   20,
			expectEviction: true,
			description:    "Small limit should be strictly enforced",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create chunk manager with custom limits
			cm := NewChunkManager(nil)
			cm.maxSessions = tt.maxSessions

			// Record initial memory
			runtime.GC()
			var m1 runtime.MemStats
			runtime.ReadMemStats(&m1)

			// Create sessions by storing them in the session map
			for i := 0; i < tt.sessionCount; i++ {
				sessionKey := generateSessionKey(i)

				// Create a mock session entry
				cm.mutex.Lock()
				cm.sessionMap[sessionKey] = &SessionEntry{
					Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
					ExpiresAt: time.Now().Add(24 * time.Hour),
					LastUsed:  time.Now(),
				}
				cm.mutex.Unlock()

				// Trigger cleanup every 10 sessions to test enforcement
				if i%10 == 9 {
					cm.CleanupExpiredSessions()
				}
			}

			// Force final cleanup to enforce limits
			cm.CleanupExpiredSessions()

			// Check final session count
			cm.mutex.RLock()
			finalSessionCount := len(cm.sessionMap)
			cm.mutex.RUnlock()

			// Verify hard limit enforcement
			if finalSessionCount > tt.maxSessions {
				t.Errorf("Hard limit not enforced: %s\n"+
					"Max sessions: %d\n"+
					"Final session count: %d\n"+
					"Expected eviction: %v",
					tt.description, tt.maxSessions, finalSessionCount, tt.expectEviction)
			}

			// Verify eviction occurred if expected
			if tt.expectEviction && finalSessionCount >= tt.sessionCount {
				t.Errorf("Expected eviction did not occur: %s\n"+
					"Created sessions: %d\n"+
					"Final sessions: %d",
					tt.description, tt.sessionCount, finalSessionCount)
			}

			// Record final memory
			runtime.GC()
			var m2 runtime.MemStats
			runtime.ReadMemStats(&m2)
			memoryGrowth := m2.Alloc - m1.Alloc

			t.Logf("Test %s: Created %d sessions, Final count: %d, Memory growth: %d bytes",
				tt.name, tt.sessionCount, finalSessionCount, memoryGrowth)

			// Verify memory growth is bounded
			maxExpectedMemoryPerSession := int64(1024) // 1KB per session
			maxExpectedMemory := int64(tt.maxSessions) * maxExpectedMemoryPerSession
			if int64(memoryGrowth) > maxExpectedMemory*2 { // Allow 2x tolerance
				t.Errorf("Memory growth exceeds expected bounds: %d bytes (max expected: %d)",
					memoryGrowth, maxExpectedMemory)
			}
		})
	}
}

// TestSessionMapBounds_EmergencyCleanup tests that emergency cleanup triggers when approaching limits
func TestSessionMapBounds_EmergencyCleanup(t *testing.T) {
	cm := NewChunkManager(nil)
	cm.maxSessions = 50

	// Fill sessions to near capacity
	nearCapacity := cm.maxSessions - 5
	for i := 0; i < nearCapacity; i++ {
		sessionKey := generateSessionKey(i)
		cm.mutex.Lock()
		cm.sessionMap[sessionKey] = &SessionEntry{
			Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now().Add(time.Duration(-i) * time.Hour), // Vary ages for LRU
		}
		cm.mutex.Unlock()
	}

	// Add some expired sessions that should be cleaned up
	expiredCount := 10
	for i := 0; i < expiredCount; i++ {
		sessionKey := generateExpiredSessionKey(i)
		cm.mutex.Lock()
		cm.sessionMap[sessionKey] = &SessionEntry{
			Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
			ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
			LastUsed:  time.Now().Add(-48 * time.Hour),
		}
		cm.mutex.Unlock()
	}

	// Record state before emergency cleanup
	cm.mutex.RLock()
	beforeCleanup := len(cm.sessionMap)
	cm.mutex.RUnlock()

	// Trigger emergency cleanup
	cm.CleanupExpiredSessions()

	// Check that expired sessions were removed
	cm.mutex.RLock()
	afterCleanup := len(cm.sessionMap)
	cm.mutex.RUnlock()

	cleanedUp := beforeCleanup - afterCleanup
	if cleanedUp < expiredCount {
		t.Errorf("Emergency cleanup insufficient: cleaned %d sessions, expected at least %d",
			cleanedUp, expiredCount)
	}

	// Verify we're still within limits
	if afterCleanup > cm.maxSessions {
		t.Errorf("Emergency cleanup failed to enforce limits: %d sessions > %d max",
			afterCleanup, cm.maxSessions)
	}

	t.Logf("Emergency cleanup: Before: %d, After: %d, Cleaned: %d",
		beforeCleanup, afterCleanup, cleanedUp)
}

// TestSessionMapBounds_EvictionUnderHighLoad tests session eviction under high concurrent load
func TestSessionMapBounds_EvictionUnderHighLoad(t *testing.T) {
	cm := NewChunkManager(nil)
	cm.maxSessions = 100

	// Record initial memory
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const numGoroutines = 10
	const sessionsPerGoroutine = 50
	var wg sync.WaitGroup

	// Create sessions concurrently to simulate high load
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < sessionsPerGoroutine; i++ {
				sessionKey := generateConcurrentSessionKey(goroutineID, i)

				cm.mutex.Lock()
				cm.sessionMap[sessionKey] = &SessionEntry{
					Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
					ExpiresAt: time.Now().Add(24 * time.Hour),
					LastUsed:  time.Now(),
				}

				// Randomly trigger cleanup to test concurrent access
				if i%10 == goroutineID%10 {
					cm.mutex.Unlock()
					cm.CleanupExpiredSessions()
				} else {
					cm.mutex.Unlock()
				}

				// Small delay to increase concurrency contention
				time.Sleep(time.Microsecond)
			}
		}(g)
	}

	wg.Wait()

	// Final cleanup
	cm.CleanupExpiredSessions()

	// Verify limits are still enforced
	cm.mutex.RLock()
	finalCount := len(cm.sessionMap)
	cm.mutex.RUnlock()

	if finalCount > cm.maxSessions {
		t.Errorf("High load caused limit breach: %d sessions > %d max", finalCount, cm.maxSessions)
	}

	// Check memory usage
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	memoryGrowth := m2.Alloc - m1.Alloc

	t.Logf("High load test: Created %d total sessions, Final count: %d, Memory growth: %d bytes",
		numGoroutines*sessionsPerGoroutine, finalCount, memoryGrowth)

	// Verify memory is bounded
	maxExpectedMemory := int64(cm.maxSessions * 2048) // 2KB per session
	if int64(memoryGrowth) > maxExpectedMemory {
		t.Errorf("Memory growth under high load: %d bytes > %d expected max",
			memoryGrowth, maxExpectedMemory)
	}
}

// TestSessionMapBounds_NoMemoryGrowthBeyondLimits tests that memory doesn't grow beyond configured limits
func TestSessionMapBounds_NoMemoryGrowthBeyondLimits(t *testing.T) {
	const maxSessions = 200
	const testIterations = 1000 // Create way more sessions than limit

	cm := NewChunkManager(nil)
	cm.maxSessions = maxSessions

	// Record baseline memory
	runtime.GC()
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	// Create sessions in waves, exceeding limits
	for wave := 0; wave < 5; wave++ {
		// Create burst of sessions
		for i := 0; i < testIterations/5; i++ {
			sessionKey := generateWaveSessionKey(wave, i)

			cm.mutex.Lock()
			cm.sessionMap[sessionKey] = &SessionEntry{
				Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
				ExpiresAt: time.Now().Add(24 * time.Hour),
				LastUsed:  time.Now(),
			}
			cm.mutex.Unlock()

			// Periodic cleanup
			if i%50 == 49 {
				cm.CleanupExpiredSessions()
			}
		}

		// Force cleanup after each wave
		cm.CleanupExpiredSessions()

		// Check session count doesn't exceed limits
		cm.mutex.RLock()
		currentCount := len(cm.sessionMap)
		cm.mutex.RUnlock()

		if currentCount > maxSessions {
			t.Errorf("Session count exceeded limit in wave %d: %d > %d",
				wave, currentCount, maxSessions)
		}

		// Check memory growth is bounded
		runtime.GC()
		var current runtime.MemStats
		runtime.ReadMemStats(&current)
		memoryGrowth := current.Alloc - baseline.Alloc

		// Memory should not grow linearly with total sessions created
		maxExpectedMemory := uint64(maxSessions * 3072) // 3KB per session with overhead
		if memoryGrowth > maxExpectedMemory {
			t.Errorf("Memory growth exceeded bounds in wave %d: %d bytes > %d expected",
				wave, memoryGrowth, maxExpectedMemory)
		}

		t.Logf("Wave %d: Sessions: %d, Memory growth: %d bytes",
			wave, currentCount, memoryGrowth)
	}
}

// TestSessionMapBounds_LRUEvictionOrder tests that LRU eviction maintains correct order
func TestSessionMapBounds_LRUEvictionOrder(t *testing.T) {
	cm := NewChunkManager(nil)
	cm.maxSessions = 10

	// Create sessions with known access patterns
	sessionOrder := make([]string, 0, 15)

	// Create initial sessions
	for i := 0; i < 15; i++ {
		sessionKey := generateOrderedSessionKey(i)
		sessionOrder = append(sessionOrder, sessionKey)

		cm.mutex.Lock()
		cm.sessionMap[sessionKey] = &SessionEntry{
			Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now().Add(time.Duration(-i) * time.Minute), // Older sessions have earlier LastUsed
		}
		cm.mutex.Unlock()
	}

	// Force eviction
	cm.CleanupExpiredSessions()

	// Check that oldest sessions were evicted
	cm.mutex.RLock()
	remainingSessions := make([]string, 0, len(cm.sessionMap))
	for key := range cm.sessionMap {
		remainingSessions = append(remainingSessions, key)
	}
	cm.mutex.RUnlock()

	// Should have exactly maxSessions remaining
	if len(remainingSessions) != cm.maxSessions {
		t.Errorf("Incorrect number of sessions after eviction: got %d, expected %d",
			len(remainingSessions), cm.maxSessions)
	}

	// Check that the most recently used sessions remain
	// (sessions with lower indices have more recent LastUsed times)
	expectedRemaining := sessionOrder[:cm.maxSessions]
	for _, expectedKey := range expectedRemaining {
		found := false
		for _, remainingKey := range remainingSessions {
			if remainingKey == expectedKey {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected session %s to remain after LRU eviction", expectedKey)
		}
	}
}

// Helper functions for generating unique session keys

func generateSessionKey(id int) string {
	return "session_" + strings.Repeat("0", 5-len(string(rune(id)))) + string(rune('0'+id%10))
}

func generateExpiredSessionKey(id int) string {
	return "expired_session_" + strings.Repeat("0", 5-len(string(rune(id)))) + string(rune('0'+id%10))
}

func generateConcurrentSessionKey(goroutineID, sessionID int) string {
	return generateSessionKey(goroutineID*1000 + sessionID)
}

func generateWaveSessionKey(wave, id int) string {
	return "wave_" + string(rune('0'+wave)) + "_" + generateSessionKey(id)
}

func generateOrderedSessionKey(id int) string {
	return "ordered_" + strings.Repeat("0", 5-len(string(rune(id)))) + string(rune('0'+id%10))
}

// BenchmarkSessionMapBounds_EvictionPerformance benchmarks the performance of session eviction
func BenchmarkSessionMapBounds_EvictionPerformance(b *testing.B) {
	cm := NewChunkManager(nil)
	cm.maxSessions = 1000

	// Pre-populate with sessions at capacity
	for i := 0; i < cm.maxSessions; i++ {
		sessionKey := generateSessionKey(i)
		cm.mutex.Lock()
		cm.sessionMap[sessionKey] = &SessionEntry{
			Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now().Add(time.Duration(-i) * time.Minute),
		}
		cm.mutex.Unlock()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Add session that will trigger eviction
		sessionKey := generateSessionKey(cm.maxSessions + i)
		cm.mutex.Lock()
		cm.sessionMap[sessionKey] = &SessionEntry{
			Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now(),
		}
		cm.mutex.Unlock()

		// Force eviction
		cm.CleanupExpiredSessions()
	}
}

// BenchmarkSessionMapBounds_ConcurrentAccess benchmarks concurrent session access with bounds checking
func BenchmarkSessionMapBounds_ConcurrentAccess(b *testing.B) {
	cm := NewChunkManager(nil)
	cm.maxSessions = 500

	// Pre-populate sessions
	for i := 0; i < cm.maxSessions/2; i++ {
		sessionKey := generateSessionKey(i)
		cm.mutex.Lock()
		cm.sessionMap[sessionKey] = &SessionEntry{
			Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
			ExpiresAt: time.Now().Add(24 * time.Hour),
			LastUsed:  time.Now(),
		}
		cm.mutex.Unlock()
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sessionKey := generateSessionKey(i)

			// Mix of operations: create, cleanup, access
			switch i % 3 {
			case 0:
				cm.mutex.Lock()
				cm.sessionMap[sessionKey] = &SessionEntry{
					Session:   &sessions.Session{Values: make(map[interface{}]interface{})},
					ExpiresAt: time.Now().Add(24 * time.Hour),
					LastUsed:  time.Now(),
				}
				cm.mutex.Unlock()
			case 1:
				cm.CleanupExpiredSessions()
			case 2:
				cm.mutex.RLock()
				_ = len(cm.sessionMap)
				cm.mutex.RUnlock()
			}
			i++
		}
	})
}
