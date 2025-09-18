package chunking

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// TestTokenValidatorJWT tests JWT validation using TokenValidator
func TestTokenValidatorJWT(t *testing.T) {
	validator := NewTokenValidator()

	// Test valid JWT format (using base64url encoded parts that are long enough)
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	err := validator.ValidateJWTFormat(validJWT, "test")
	if err != nil {
		t.Errorf("Expected valid JWT to pass, got error: %v", err)
	}

	// Test invalid JWT format - too few parts
	invalidJWT := "header.payload"
	err = validator.ValidateJWTFormat(invalidJWT, "test")
	if err == nil {
		t.Error("Expected invalid JWT to fail validation")
	}

	// Test invalid JWT format - too many parts
	invalidJWT2 := "header.payload.signature.extra"
	err = validator.ValidateJWTFormat(invalidJWT2, "test")
	if err == nil {
		t.Error("Expected invalid JWT with extra parts to fail validation")
	}

	// Test empty JWT
	err = validator.ValidateJWTFormat("", "test")
	if err != nil {
		t.Error("Expected empty JWT to pass validation (empty is allowed)")
	}
}

// TestTokenValidatorOpaqueToken tests opaque token validation using TokenValidator
func TestTokenValidatorOpaqueToken(t *testing.T) {
	validator := NewTokenValidator()
	config := AccessTokenConfig

	// Test valid opaque token with more entropy
	validOpaque := "z8Bx5mP9qK3nL4wR7tY2uI0oE6cV1aS"
	err := validator.ValidateTokenContent(validOpaque, config)
	if err != nil {
		t.Errorf("Expected valid opaque token to pass, got error: %v", err)
	}

	// Test too short opaque token
	shortOpaque := "short"
	err = validator.ValidateTokenContent(shortOpaque, config)
	if err == nil {
		t.Error("Expected short opaque token to fail validation")
	}

	// Test empty opaque token
	err = validator.ValidateTokenContent("", config)
	if err != nil {
		t.Error("Expected empty opaque token to pass validation (empty is allowed)")
	}
}

// TestTokenValidatorTokenSize tests token size validation using TokenValidator
func TestTokenValidatorTokenSize(t *testing.T) {
	validator := NewTokenValidator()

	// Test normal token size
	normalToken := strings.Repeat("a", 1000)
	err := validator.ValidateTokenSize(normalToken, AccessTokenConfig)
	if err != nil {
		t.Errorf("Expected normal token to pass size validation, got error: %v", err)
	}

	// Test oversized token
	oversizedToken := strings.Repeat("a", AccessTokenConfig.MaxLength+1)
	err = validator.ValidateTokenSize(oversizedToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected oversized token to fail validation")
	}

	// Test undersized token
	undersizedToken := "ab"
	err = validator.ValidateTokenSize(undersizedToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected undersized token to fail validation")
	}
}

// TestTokenValidatorTokenContent tests token content validation using TokenValidator
func TestTokenValidatorTokenContent(t *testing.T) {
	validator := NewTokenValidator()

	// Test normal token content with good entropy
	normalToken := "A9zZ8yX7wV6uT5sR4qP3oN2mL1kJ0iH"
	err := validator.ValidateTokenContent(normalToken, AccessTokenConfig)
	if err != nil {
		t.Errorf("Expected normal token to pass content validation, got error: %v", err)
	}

	// Test token with null bytes
	nullByteToken := "token_with\x00null_byte"
	err = validator.ValidateTokenContent(nullByteToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected token with null bytes to fail validation")
	}

	// Test token with control characters
	controlCharToken := "token_with\x01control"
	err = validator.ValidateTokenContent(controlCharToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected token with control characters to fail validation")
	}
}

// TestChunkManagerSingleTokenValidation tests single token validation path
func TestChunkManagerSingleTokenValidation(t *testing.T) {
	cm := NewChunkManager(nil)

	// Create a valid opaque token with good entropy
	validToken := "oP8qW7rE6tY5uI4oP3aS2dF1gH9jK0lZ3xC6vB5nM4"

	// Test valid token processing
	result := cm.processSingleToken(validToken, false, AccessTokenConfig)
	if result.Error != nil {
		t.Errorf("Expected valid token to process successfully, got error: %v", result.Error)
	}
	if result.Token != validToken {
		t.Error("Expected token to be returned unchanged")
	}

	// Test invalid token processing
	invalidToken := "invalid.token"
	result = cm.processSingleToken(invalidToken, false, IDTokenConfig) // ID tokens require JWT format
	if result.Error == nil {
		t.Error("Expected invalid token to fail processing")
	}
}

// TestTokenConfigValidation tests different token configurations
func TestTokenConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config TokenConfig
	}{
		{
			name:   "AccessTokenConfig",
			config: AccessTokenConfig,
		},
		{
			name:   "RefreshTokenConfig",
			config: RefreshTokenConfig,
		},
		{
			name:   "IDTokenConfig",
			config: IDTokenConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify config has expected fields
			if tt.config.Type == "" {
				t.Error("Expected config to have Type set")
			}
			if tt.config.MaxLength <= 0 {
				t.Error("Expected config to have positive MaxLength")
			}
			if tt.config.MinLength <= 0 {
				t.Error("Expected config to have positive MinLength")
			}
		})
	}
}

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
				t.Errorf("Hard limit not enforced: %s\nMax sessions: %d\nFinal session count: %d\nExpected eviction: %v",
					tt.description, tt.maxSessions, finalSessionCount, tt.expectEviction)
			}

			// Verify eviction occurred if expected
			if tt.expectEviction && finalSessionCount >= tt.sessionCount {
				t.Errorf("Expected eviction did not occur: %s\nCreated sessions: %d\nFinal sessions: %d",
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

	// Force lastCleanup to be old so cleanup will run
	cm.lastCleanup = time.Now().Add(-2 * time.Hour)

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

// TestEstimateChunkCount tests the EstimateChunkCount function
func TestEstimateChunkCount(t *testing.T) {
	cs := NewChunkSerializer(nil)

	tests := []struct {
		name        string
		tokenLength int
		chunkSize   int
		expected    int
	}{
		{
			name:        "Single chunk",
			tokenLength: 1000,
			chunkSize:   1200,
			expected:    1,
		},
		{
			name:        "Exactly two chunks",
			tokenLength: 2400,
			chunkSize:   1200,
			expected:    2,
		},
		{
			name:        "Three chunks with remainder",
			tokenLength: 2500,
			chunkSize:   1200,
			expected:    3,
		},
		{
			name:        "Zero chunk size defaults to maxCookieSize",
			tokenLength: 1300,
			chunkSize:   0,
			expected:    2, // 1300 / 1200 = 1.083... = 2 chunks
		},
		{
			name:        "Large token many chunks",
			tokenLength: 10000,
			chunkSize:   800,
			expected:    13, // 10000 / 800 = 12.5 = 13 chunks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.EstimateChunkCount(tt.tokenLength, tt.chunkSize)
			if result != tt.expected {
				t.Errorf("EstimateChunkCount(%d, %d) = %d; expected %d",
					tt.tokenLength, tt.chunkSize, result, tt.expected)
			}
		})
	}
}

// TestMaxTokenSizeForChunks tests the MaxTokenSizeForChunks function
func TestMaxTokenSizeForChunks(t *testing.T) {
	cs := NewChunkSerializer(nil)

	tests := []struct {
		name      string
		maxChunks int
		chunkSize int
		expected  int
	}{
		{
			name:      "Single chunk",
			maxChunks: 1,
			chunkSize: 1200,
			expected:  1200,
		},
		{
			name:      "Multiple chunks",
			maxChunks: 5,
			chunkSize: 1000,
			expected:  5000,
		},
		{
			name:      "Zero chunk size defaults to maxCookieSize",
			maxChunks: 3,
			chunkSize: 0,
			expected:  3600, // 3 * 1200
		},
		{
			name:      "Large configuration",
			maxChunks: 25,
			chunkSize: 1200,
			expected:  30000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.MaxTokenSizeForChunks(tt.maxChunks, tt.chunkSize)
			if result != tt.expected {
				t.Errorf("MaxTokenSizeForChunks(%d, %d) = %d; expected %d",
					tt.maxChunks, tt.chunkSize, result, tt.expected)
			}
		})
	}
}

// TestValidateJWTContent tests JWT content validation
func TestValidateJWTContent(t *testing.T) {
	validator := NewTokenValidator()
	config := IDTokenConfig

	tests := []struct {
		name        string
		token       string
		expectError bool
		description string
	}{
		{
			name:        "Valid JWT with required ID token claims",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6ImNsaWVudElkIiwiZXhwIjoxNjQ2MDY0MDAwLCJpYXQiOjE2NDYwNjA0MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectError: false,
			description: "JWT with all required ID token claims should pass",
		},
		{
			name:        "JWT missing required claims",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectError: true,
			description: "JWT missing required claims should fail",
		},
		{
			name:        "JWT with invalid structure",
			token:       "invalid.token",
			expectError: true,
			description: "JWT with wrong number of parts should fail",
		},
		{
			name:        "Empty JWT",
			token:       "",
			expectError: true,
			description: "Empty JWT should fail at JWT content level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateJWTContent(tt.token, config)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestValidateJWTHeader tests JWT header validation
func TestValidateJWTHeader(t *testing.T) {
	validator := NewTokenValidator()
	config := IDTokenConfig

	tests := []struct {
		name        string
		header      string
		expectError bool
		description string
	}{
		{
			name:        "Valid JWT header",
			header:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9", // {"alg":"RS256","typ":"JWT"}
			expectError: false,
			description: "Valid JWT header with alg and typ",
		},
		{
			name:        "Header missing alg",
			header:      "eyJ0eXAiOiJKV1QifQ", // {"typ":"JWT"}
			expectError: true,
			description: "Header missing algorithm should fail",
		},
		{
			name:        "Header missing typ",
			header:      "eyJhbGciOiJSUzI1NiJ9", // {"alg":"RS256"}
			expectError: true,
			description: "Header missing type should fail",
		},
		{
			name:        "Invalid base64 header",
			header:      "invalid_base64!",
			expectError: true,
			description: "Invalid base64 should fail",
		},
		{
			name:        "Invalid JSON header",
			header:      "aW52YWxpZCBqc29u", // "invalid json"
			expectError: true,
			description: "Invalid JSON should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateJWTHeader(tt.header, config)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestValidateJWTPayload tests JWT payload validation
func TestValidateJWTPayload(t *testing.T) {
	validator := NewTokenValidator()

	tests := []struct {
		name        string
		payload     string
		config      TokenConfig
		expectError bool
		description string
	}{
		{
			name:        "Valid ID token payload",
			payload:     "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6ImNsaWVudElkIiwiZXhwIjoxNjQ2MDY0MDAwLCJpYXQiOjE2NDYwNjA0MDB9", // Required ID token claims
			config:      IDTokenConfig,
			expectError: false,
			description: "Valid ID token with required claims",
		},
		{
			name:        "ID token missing required claims",
			payload:     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", // {"sub":"1234567890","name":"John Doe"}
			config:      IDTokenConfig,
			expectError: true,
			description: "ID token missing required claims should fail",
		},
		{
			name:        "Access token payload",
			payload:     "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", // {"sub":"1234567890","name":"John Doe"}
			config:      AccessTokenConfig,
			expectError: false,
			description: "Access token doesn't require specific claims",
		},
		{
			name:        "Invalid base64 payload",
			payload:     "invalid_base64!",
			config:      IDTokenConfig,
			expectError: true,
			description: "Invalid base64 should fail",
		},
		{
			name:        "Invalid JSON payload",
			payload:     "aW52YWxpZCBqc29u", // "invalid json"
			config:      IDTokenConfig,
			expectError: true,
			description: "Invalid JSON should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateJWTPayload(tt.payload, tt.config)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestValidateJWTSignature tests JWT signature validation
func TestValidateJWTSignature(t *testing.T) {
	validator := NewTokenValidator()
	config := IDTokenConfig

	tests := []struct {
		name        string
		signature   string
		expectError bool
		description string
	}{
		{
			name:        "Valid signature",
			signature:   "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectError: false,
			description: "Valid base64URL signature",
		},
		{
			name:        "Empty signature",
			signature:   "",
			expectError: true,
			description: "Empty signature should fail",
		},
		{
			name:        "Invalid base64URL signature",
			signature:   "invalid_base64!@#",
			expectError: true,
			description: "Invalid base64URL should fail",
		},
		{
			name:        "Valid signature with padding",
			signature:   "dGVzdA==",
			expectError: false,
			description: "Base64 with padding should work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateJWTSignature(tt.signature, config)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestValidateChunkStructure tests chunk structure validation
func TestValidateChunkStructure(t *testing.T) {
	validator := NewTokenValidator()
	config := AccessTokenConfig

	tests := []struct {
		name        string
		chunks      []ChunkData
		expectError bool
		description string
	}{
		{
			name: "Valid chunk structure",
			chunks: []ChunkData{
				{Index: 0, Total: 2, Content: "part1", Checksum: "checksum1"},
				{Index: 1, Total: 2, Content: "part2", Checksum: "checksum2"},
			},
			expectError: false,
			description: "Valid ordered chunks",
		},
		{
			name:        "Empty chunks",
			chunks:      []ChunkData{},
			expectError: true,
			description: "Empty chunk list should fail",
		},
		{
			name: "Too many chunks",
			chunks: func() []ChunkData {
				chunks := make([]ChunkData, AccessTokenConfig.MaxChunks+1)
				for i := range chunks {
					chunks[i] = ChunkData{Index: i, Total: len(chunks), Content: "content", Checksum: "checksum"}
				}
				return chunks
			}(),
			expectError: true,
			description: "Too many chunks should fail",
		},
		{
			name: "Duplicate chunk indices",
			chunks: []ChunkData{
				{Index: 0, Total: 2, Content: "part1", Checksum: "checksum1"},
				{Index: 0, Total: 2, Content: "part2", Checksum: "checksum2"},
			},
			expectError: true,
			description: "Duplicate indices should fail",
		},
		{
			name: "Missing chunk index",
			chunks: []ChunkData{
				{Index: 0, Total: 3, Content: "part1", Checksum: "checksum1"},
				{Index: 2, Total: 3, Content: "part3", Checksum: "checksum3"},
			},
			expectError: true,
			description: "Missing chunk index should fail",
		},
		{
			name: "Inconsistent total count",
			chunks: []ChunkData{
				{Index: 0, Total: 2, Content: "part1", Checksum: "checksum1"},
				{Index: 1, Total: 3, Content: "part2", Checksum: "checksum2"},
			},
			expectError: true,
			description: "Inconsistent total should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateChunkStructure(tt.chunks, config)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestValidateChunkData tests individual chunk data validation
func TestValidateChunkData(t *testing.T) {
	validator := NewTokenValidator()
	config := AccessTokenConfig

	tests := []struct {
		name          string
		chunk         ChunkData
		expectedTotal int
		expectError   bool
		description   string
	}{
		{
			name:          "Valid chunk data",
			chunk:         ChunkData{Index: 0, Total: 2, Content: "content", Checksum: "checksum"},
			expectedTotal: 2,
			expectError:   false,
			description:   "Valid chunk should pass",
		},
		{
			name:          "Negative index",
			chunk:         ChunkData{Index: -1, Total: 2, Content: "content", Checksum: "checksum"},
			expectedTotal: 2,
			expectError:   true,
			description:   "Negative index should fail",
		},
		{
			name:          "Inconsistent total",
			chunk:         ChunkData{Index: 0, Total: 3, Content: "content", Checksum: "checksum"},
			expectedTotal: 2,
			expectError:   true,
			description:   "Inconsistent total should fail",
		},
		{
			name:          "Index exceeds total",
			chunk:         ChunkData{Index: 2, Total: 2, Content: "content", Checksum: "checksum"},
			expectedTotal: 2,
			expectError:   true,
			description:   "Index exceeding total should fail",
		},
		{
			name:          "Empty content",
			chunk:         ChunkData{Index: 0, Total: 2, Content: "", Checksum: "checksum"},
			expectedTotal: 2,
			expectError:   true,
			description:   "Empty content should fail",
		},
		{
			name:          "Empty checksum",
			chunk:         ChunkData{Index: 0, Total: 2, Content: "content", Checksum: ""},
			expectedTotal: 2,
			expectError:   true,
			description:   "Empty checksum should fail",
		},
		{
			name: "Chunk too large",
			chunk: ChunkData{
				Index:    0,
				Total:    2,
				Content:  strings.Repeat("x", config.MaxChunkSize+1),
				Checksum: "checksum",
			},
			expectedTotal: 2,
			expectError:   true,
			description:   "Oversized chunk should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateChunkData(tt.chunk, tt.expectedTotal, config)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestChunkErrorMethod tests the Error method of ChunkError
func TestChunkErrorMethod(t *testing.T) {
	tests := []struct {
		name     string
		error    *ChunkError
		expected string
	}{
		{
			name: "Basic chunk error",
			error: &ChunkError{
				Type:    "access",
				Reason:  "too large",
				Details: "chunk exceeds maximum size",
			},
			expected: "access chunk error: too large - chunk exceeds maximum size",
		},
		{
			name: "Validation chunk error",
			error: &ChunkError{
				Type:    "id",
				Reason:  "missing chunk",
				Details: "chunk 2 is missing from sequence",
			},
			expected: "id chunk error: missing chunk - chunk 2 is missing from sequence",
		},
		{
			name: "Empty fields",
			error: &ChunkError{
				Type:    "",
				Reason:  "",
				Details: "",
			},
			expected: " chunk error:  - ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.error.Error()
			if result != tt.expected {
				t.Errorf("ChunkError.Error() = %q; expected %q", result, tt.expected)
			}
		})
	}
}

// TestValidationErrorMethod tests the Error method of ValidationError
func TestValidationErrorMethod(t *testing.T) {
	tests := []struct {
		name     string
		error    *ValidationError
		expected string
	}{
		{
			name: "Token validation error",
			error: &ValidationError{
				Type:    "access",
				Reason:  "invalid format",
				Details: "token must be valid JWT",
			},
			expected: "access validation error: invalid format - token must be valid JWT",
		},
		{
			name: "Size validation error",
			error: &ValidationError{
				Type:    "refresh",
				Reason:  "too large",
				Details: "token size exceeds 50KB limit",
			},
			expected: "refresh validation error: too large - token size exceeds 50KB limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.error.Error()
			if result != tt.expected {
				t.Errorf("ValidationError.Error() = %q; expected %q", result, tt.expected)
			}
		})
	}
}

// TestGetToken tests the main GetToken function
func TestGetToken(t *testing.T) {
	cm := NewChunkManager(nil)

	tests := []struct {
		name          string
		mainSession   *sessions.Session
		chunks        map[int]*sessions.Session
		config        TokenConfig
		expectedToken string
		expectError   bool
		description   string
	}{
		{
			name: "Token from main session",
			mainSession: &sessions.Session{
				Values: map[interface{}]interface{}{
					"access_token": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
				},
			},
			chunks:        nil,
			config:        AccessTokenConfig,
			expectedToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			expectError:   false,
			description:   "Should retrieve token from main session",
		},
		{
			name:          "No token in main session, no chunks",
			mainSession:   &sessions.Session{Values: map[interface{}]interface{}{}},
			chunks:        map[int]*sessions.Session{},
			config:        AccessTokenConfig,
			expectedToken: "",
			expectError:   false,
			description:   "Should return empty token when no data available",
		},
		{
			name:        "Token from chunks",
			mainSession: &sessions.Session{Values: map[interface{}]interface{}{}},
			chunks: map[int]*sessions.Session{
				0: {Values: map[interface{}]interface{}{"value": "abcdefghijklmnopqrstuvwxyz"}},
				1: {Values: map[interface{}]interface{}{"value": "0123456789ABCDEFGHIJKLMNOP"}},
			},
			config:        AccessTokenConfig,
			expectedToken: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
			expectError:   false,
			description:   "Should reconstruct token from chunks",
		},
		{
			name:        "Too many chunks",
			mainSession: &sessions.Session{Values: map[interface{}]interface{}{}},
			chunks: func() map[int]*sessions.Session {
				chunks := make(map[int]*sessions.Session)
				for i := 0; i <= AccessTokenConfig.MaxChunks; i++ {
					chunks[i] = &sessions.Session{Values: map[interface{}]interface{}{"value": "chunk"}}
				}
				return chunks
			}(),
			config:        AccessTokenConfig,
			expectedToken: "",
			expectError:   true,
			description:   "Should fail with too many chunks",
		},
	}

	// Mock compressor
	compressor := &mockTokenCompressor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cm.GetToken(tt.mainSession, tt.chunks, tt.config, compressor)

			if tt.expectError && result.Error == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && result.Error != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, result.Error)
			}
			if result.Token != tt.expectedToken {
				t.Errorf("Expected token %q, got %q for %s", tt.expectedToken, result.Token, tt.description)
			}
		})
	}
}

// TestStoreSessionGetSession tests session storage and retrieval
func TestStoreSessionGetSession(t *testing.T) {
	cm := NewChunkManager(nil)

	// Test storing and retrieving a session
	key := "test_session_key"
	session := &sessions.Session{Values: map[interface{}]interface{}{"test": "value"}}

	// Store session
	cm.StoreSession(key, session)

	// Retrieve session
	retrieved := cm.GetSession(key)
	if retrieved == nil {
		t.Error("Expected to retrieve stored session, but got nil")
	}

	if retrieved != session {
		t.Error("Retrieved session does not match stored session")
	}

	// Test retrieving non-existent session
	nonExistent := cm.GetSession("non_existent_key")
	if nonExistent != nil {
		t.Error("Expected nil for non-existent session, but got a session")
	}

	// Test session limit enforcement
	cm.maxSessions = 2
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("session_%d", i)
		session := &sessions.Session{Values: map[interface{}]interface{}{"id": i}}
		cm.StoreSession(key, session)
	}

	cm.mutex.RLock()
	sessionCount := len(cm.sessionMap)
	cm.mutex.RUnlock()

	if sessionCount > cm.maxSessions {
		t.Errorf("Session count %d exceeds limit %d", sessionCount, cm.maxSessions)
	}
}

// TestNoOpLogger tests the no-op logger implementation
func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()

	// Test all methods (they should not panic or error)
	logger.Debug("test message")
	logger.Debugf("test format %s", "message")
	logger.Error("test error")
	logger.Errorf("test error %s", "formatted")

	// Since these are no-op methods, we mainly test that they don't panic
	// The fact that the test completes successfully indicates they work
}

// TestSerializeTokenToChunks tests token serialization
func TestSerializeTokenToChunks(t *testing.T) {
	cs := NewChunkSerializer(NewNoOpLogger())
	config := AccessTokenConfig

	tests := []struct {
		name        string
		token       string
		expectError bool
		description string
	}{
		{
			name:        "Valid token serialization",
			token:       strings.Repeat("a", 2500), // Larger than single chunk
			expectError: false,
			description: "Should serialize large token into chunks",
		},
		{
			name:        "Empty token",
			token:       "",
			expectError: true,
			description: "Should fail with empty token",
		},
		{
			name:        "Token too short",
			token:       "abc", // Less than config.MinLength
			expectError: true,
			description: "Should fail with too short token",
		},
		{
			name:        "Token too long",
			token:       strings.Repeat("x", config.MaxLength+1),
			expectError: true,
			description: "Should fail with oversized token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks, err := cs.SerializeTokenToChunks(tt.token, config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}

			if !tt.expectError && len(chunks) > 0 {
				// Verify chunk structure
				expectedChunks := len(chunks)
				for _, chunk := range chunks {
					if chunk.Total != expectedChunks {
						t.Errorf("Chunk total mismatch: got %d, expected %d", chunk.Total, expectedChunks)
					}
					if chunk.Content == "" {
						t.Error("Chunk content should not be empty")
					}
					if chunk.Checksum == "" {
						t.Error("Chunk checksum should not be empty")
					}
				}
			}
		})
	}
}

// TestDeserializeTokenFromChunks tests token deserialization
func TestDeserializeTokenFromChunks(t *testing.T) {
	cs := NewChunkSerializer(NewNoOpLogger())
	config := AccessTokenConfig

	// First serialize a token to get valid chunks
	originalToken := strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP", 40) // Make it large enough for multiple chunks
	chunks, err := cs.SerializeTokenToChunks(originalToken, config)
	if err != nil {
		t.Fatalf("Failed to serialize token for test: %v", err)
	}

	tests := []struct {
		name          string
		chunks        []ChunkData
		expectedToken string
		expectError   bool
		description   string
	}{
		{
			name:          "Valid chunks deserialization",
			chunks:        chunks,
			expectedToken: originalToken,
			expectError:   false,
			description:   "Should deserialize chunks back to original token",
		},
		{
			name:          "Empty chunks",
			chunks:        []ChunkData{},
			expectedToken: "",
			expectError:   true,
			description:   "Should fail with empty chunks",
		},
		{
			name: "Too many chunks",
			chunks: func() []ChunkData {
				many := make([]ChunkData, config.MaxChunks+1)
				for i := range many {
					many[i] = ChunkData{Index: i, Total: len(many), Content: "content", Checksum: "checksum"}
				}
				return many
			}(),
			expectedToken: "",
			expectError:   true,
			description:   "Should fail with too many chunks",
		},
		{
			name: "Inconsistent chunk totals",
			chunks: []ChunkData{
				{Index: 0, Total: 2, Content: "part1", Checksum: cs.calculateChecksum("part1")},
				{Index: 1, Total: 3, Content: "part2", Checksum: cs.calculateChecksum("part2")}, // Different total
			},
			expectedToken: "",
			expectError:   true,
			description:   "Should fail with inconsistent totals",
		},
		{
			name: "Missing chunk",
			chunks: []ChunkData{
				{Index: 0, Total: 3, Content: "part1", Checksum: cs.calculateChecksum("part1")},
				{Index: 2, Total: 3, Content: "part3", Checksum: cs.calculateChecksum("part3")}, // Missing index 1
			},
			expectedToken: "",
			expectError:   true,
			description:   "Should fail with missing chunk",
		},
		{
			name: "Invalid checksum",
			chunks: []ChunkData{
				{Index: 0, Total: 2, Content: "part1", Checksum: "invalid_checksum"},
				{Index: 1, Total: 2, Content: "part2", Checksum: cs.calculateChecksum("part2")},
			},
			expectedToken: "",
			expectError:   true,
			description:   "Should fail with invalid checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := cs.DeserializeTokenFromChunks(tt.chunks, config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
			if token != tt.expectedToken {
				t.Errorf("Expected token length %d, got %d for %s", len(tt.expectedToken), len(token), tt.description)
			}
		})
	}
}

// TestEncodeDecodeChunk tests chunk encoding and decoding
func TestEncodeDecodeChunk(t *testing.T) {
	cs := NewChunkSerializer(NewNoOpLogger())

	tests := []struct {
		name        string
		chunk       ChunkData
		expectError bool
		description string
	}{
		{
			name: "Valid chunk encoding/decoding",
			chunk: ChunkData{
				Index:    0,
				Total:    2,
				Content:  "test_content",
				Checksum: "test_checksum",
			},
			expectError: false,
			description: "Should encode and decode chunk successfully",
		},
		{
			name: "Chunk with special characters",
			chunk: ChunkData{
				Index:    1,
				Total:    3,
				Content:  "content:with:colons",
				Checksum: "checksum_123",
			},
			expectError: false,
			description: "Should handle special characters in content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode chunk
			encoded, err := cs.EncodeChunk(tt.chunk)
			if tt.expectError && err == nil {
				t.Errorf("Expected encoding error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no encoding error for %s, but got: %v", tt.description, err)
			}

			if !tt.expectError && encoded != "" {
				// Decode chunk
				decoded, err := cs.DecodeChunk(encoded)
				if err != nil {
					t.Errorf("Expected no decoding error for %s, but got: %v", tt.description, err)
				}

				// Verify decoded chunk matches original
				if decoded.Index != tt.chunk.Index {
					t.Errorf("Index mismatch: got %d, expected %d", decoded.Index, tt.chunk.Index)
				}
				if decoded.Total != tt.chunk.Total {
					t.Errorf("Total mismatch: got %d, expected %d", decoded.Total, tt.chunk.Total)
				}
				if decoded.Content != tt.chunk.Content {
					t.Errorf("Content mismatch: got %q, expected %q", decoded.Content, tt.chunk.Content)
				}
				if decoded.Checksum != tt.chunk.Checksum {
					t.Errorf("Checksum mismatch: got %q, expected %q", decoded.Checksum, tt.chunk.Checksum)
				}
			}
		})
	}

	// Test decoding invalid data
	invalidTests := []struct {
		name        string
		encoded     string
		description string
	}{
		{
			name:        "Invalid base64",
			encoded:     "invalid_base64!",
			description: "Should fail with invalid base64",
		},
		{
			name:        "Wrong format",
			encoded:     "dGVzdA==", // "test" in base64, but wrong format
			description: "Should fail with wrong format",
		},
	}

	for _, tt := range invalidTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cs.DecodeChunk(tt.encoded)
			if err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
		})
	}
}

// TestValidateChunkIntegrity tests chunk integrity validation
func TestValidateChunkIntegrity(t *testing.T) {
	cs := NewChunkSerializer(NewNoOpLogger())

	tests := []struct {
		name        string
		chunk       ChunkData
		expectError bool
		description string
	}{
		{
			name: "Valid chunk integrity",
			chunk: ChunkData{
				Index:    0,
				Total:    2,
				Content:  "test_content",
				Checksum: cs.calculateChecksum("test_content"),
			},
			expectError: false,
			description: "Should pass integrity check",
		},
		{
			name: "Negative index",
			chunk: ChunkData{
				Index:    -1,
				Total:    2,
				Content:  "test_content",
				Checksum: cs.calculateChecksum("test_content"),
			},
			expectError: true,
			description: "Should fail with negative index",
		},
		{
			name: "Invalid total",
			chunk: ChunkData{
				Index:    0,
				Total:    0,
				Content:  "test_content",
				Checksum: cs.calculateChecksum("test_content"),
			},
			expectError: true,
			description: "Should fail with zero total",
		},
		{
			name: "Index exceeds total",
			chunk: ChunkData{
				Index:    2,
				Total:    2,
				Content:  "test_content",
				Checksum: cs.calculateChecksum("test_content"),
			},
			expectError: true,
			description: "Should fail with index >= total",
		},
		{
			name: "Empty content",
			chunk: ChunkData{
				Index:    0,
				Total:    2,
				Content:  "",
				Checksum: cs.calculateChecksum(""),
			},
			expectError: true,
			description: "Should fail with empty content",
		},
		{
			name: "Empty checksum",
			chunk: ChunkData{
				Index:    0,
				Total:    2,
				Content:  "test_content",
				Checksum: "",
			},
			expectError: true,
			description: "Should fail with empty checksum",
		},
		{
			name: "Invalid checksum",
			chunk: ChunkData{
				Index:    0,
				Total:    2,
				Content:  "test_content",
				Checksum: "invalid_checksum",
			},
			expectError: true,
			description: "Should fail with wrong checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cs.ValidateChunkIntegrity(tt.chunk)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCalculateChecksum tests checksum calculation
func TestCalculateChecksum(t *testing.T) {
	cs := NewChunkSerializer(NewNoOpLogger())

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "Empty content",
			content:  "",
			expected: "empty",
		},
		{
			name:     "Single character",
			content:  "a",
			expected: "len1_first97",
		},
		{
			name:     "Two characters",
			content:  "ab",
			expected: "len2_first97_last98",
		},
		{
			name:     "Longer content",
			content:  "test_content",
			expected: "len12_first116_last116",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.calculateChecksum(tt.content)
			if result != tt.expected {
				t.Errorf("calculateChecksum(%q) = %q; expected %q", tt.content, result, tt.expected)
			}
		})
	}
}

// Mock token compressor for testing
type mockTokenCompressor struct{}

func (m *mockTokenCompressor) CompressToken(token string) string {
	// Simple mock - just return the original token
	return token
}

func (m *mockTokenCompressor) DecompressToken(compressed string) string {
	// Simple mock - just return the original token
	return compressed
}
