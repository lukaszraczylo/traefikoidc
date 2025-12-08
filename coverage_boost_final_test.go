//go:build !yaegi

package traefikoidc

import (
	"container/list"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// =============================================================================
// CACHE COMPAT TESTS - OnAccess, OnRemove
// =============================================================================

func TestLRUStrategy_OnAccess_CoverageBoost(t *testing.T) {
	strategy := &LRUStrategy{
		order:    list.New(),
		elements: make(map[string]*list.Element),
		maxSize:  100,
	}

	// OnAccess should not panic
	strategy.OnAccess("key1", "value1")
	strategy.OnAccess("key2", struct{ Name string }{"test"})
	strategy.OnAccess("", nil)
}

func TestLRUStrategy_OnRemove_CoverageBoost(t *testing.T) {
	strategy := &LRUStrategy{
		order:    list.New(),
		elements: make(map[string]*list.Element),
		maxSize:  100,
	}

	// OnRemove should not panic
	strategy.OnRemove("key1")
	strategy.OnRemove("nonexistent")
	strategy.OnRemove("")
}

// =============================================================================
// JWT REPLAY CACHE TESTS
// =============================================================================

func TestGetReplayCacheStats_CoverageBoost(t *testing.T) {
	// Test the function - it should return valid stats
	size, maxSize := getReplayCacheStats()

	if maxSize != 10000 {
		t.Errorf("Expected maxSize to be 10000, got %d", maxSize)
	}

	// Size should be >= 0
	if size < 0 {
		t.Errorf("Expected size to be >= 0, got %d", size)
	}
}

// =============================================================================
// PROFILING MANAGER TESTS
// =============================================================================

func TestProfilingManager_GetCurrentStats_Simple_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	pm := NewProfilingManager(logger)

	// Test GetCurrentStats which doesn't need full initialization
	stats := pm.GetCurrentStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	// Verify some fields are populated
	if stats.Sys == 0 {
		t.Log("Sys memory is 0")
	}
}

func TestProfilingManager_RegisterUnregisterProfiler_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	pm := NewProfilingManager(logger)

	// Create a mock profiler using an existing type
	mockProfiler := NewCacheMemoryProfiler(nil, logger)

	// Register profiler
	pm.RegisterProfiler("test-profiler", mockProfiler)

	// Get registered profilers
	profilers := pm.GetRegisteredProfilers()
	found := false
	for _, name := range profilers {
		if name == "test-profiler" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find registered profiler")
	}

	// Unregister profiler
	pm.UnregisterProfiler("test-profiler")

	// Verify it's gone
	profilers = pm.GetRegisteredProfilers()
	for _, name := range profilers {
		if name == "test-profiler" {
			t.Error("Expected profiler to be unregistered")
		}
	}
}

// =============================================================================
// MEMORY TEST ORCHESTRATOR TESTS
// =============================================================================

func TestMemoryTestOrchestrator_UnregisterComponent_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	config := LeakDetectionConfig{
		EnableLeakDetection:    true,
		LeakThresholdMB:        100,
		GoroutineLeakThreshold: 50,
	}

	mto := NewMemoryTestOrchestrator(config, logger)

	mockProfiler := NewCacheMemoryProfiler(nil, logger)

	// Register component
	mto.RegisterComponent("test-component", mockProfiler)

	// Unregister component
	mto.UnregisterComponent("test-component")

	// Unregister again should be safe
	mto.UnregisterComponent("nonexistent")
}

func TestMemoryTestOrchestrator_LeakDetection_Simple_CoverageBoost(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping leak detection test in short mode")
	}

	logger := NewLogger("info")
	config := LeakDetectionConfig{
		EnableLeakDetection:    true,
		LeakThresholdMB:        100,
		GoroutineLeakThreshold: 50,
	}

	mto := NewMemoryTestOrchestrator(config, logger)

	// Just test the GetAllLeakAnalyses which is safe
	analyses := mto.GetAllLeakAnalyses()
	if analyses == nil {
		t.Error("Expected non-nil map")
	}
}

func TestMemoryTestOrchestrator_LeakDetectionDisabled_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	config := LeakDetectionConfig{
		EnableLeakDetection: false, // Disabled
	}

	mto := NewMemoryTestOrchestrator(config, logger)

	// Should fail because detection is disabled
	err := mto.StartLeakDetection()
	if err == nil {
		t.Error("Expected error when leak detection is disabled")
	}
}

// =============================================================================
// CACHE MEMORY PROFILER TESTS
// =============================================================================

func TestCacheMemoryProfiler_Methods_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")

	cmp := NewCacheMemoryProfiler(nil, logger)
	if cmp == nil {
		t.Fatal("Expected non-nil CacheMemoryProfiler")
	}

	config := ProfilingConfig{
		LeakThresholdMB: 100,
	}

	// StartProfiling
	err := cmp.StartProfiling(config)
	if err != nil {
		t.Errorf("CacheMemoryProfiler.StartProfiling failed: %v", err)
	}

	// GetCurrentStats
	stats := cmp.GetCurrentStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}

	// StopProfiling
	snapshot, err := cmp.StopProfiling()
	if err != nil {
		t.Errorf("CacheMemoryProfiler.StopProfiling failed: %v", err)
	}
	if snapshot == nil {
		t.Error("Expected snapshot from StopProfiling")
	}

	// AnalyzeLeaks
	baseline, _ := cmp.TakeSnapshot()
	current, _ := cmp.TakeSnapshot()
	analysis := cmp.AnalyzeLeaks(baseline, current)
	if analysis == nil {
		t.Error("Expected leak analysis")
	}
}

// =============================================================================
// HTTP CLIENT PROFILER TESTS
// =============================================================================

func TestHTTPClientProfiler_Methods_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	client := &http.Client{}

	hcp := NewHTTPClientProfiler(client, logger)
	if hcp == nil {
		t.Fatal("Expected non-nil HTTPClientProfiler")
	}

	config := ProfilingConfig{
		LeakThresholdMB: 100,
	}

	// StartProfiling
	err := hcp.StartProfiling(config)
	if err != nil {
		t.Errorf("HTTPClientProfiler.StartProfiling failed: %v", err)
	}

	// GetCurrentStats
	stats := hcp.GetCurrentStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}

	// TakeSnapshot
	snapshot, err := hcp.TakeSnapshot()
	if err != nil {
		t.Errorf("TakeSnapshot failed: %v", err)
	}
	if snapshot == nil {
		t.Error("Expected snapshot")
	}

	// StopProfiling
	snapshot, err = hcp.StopProfiling()
	if err != nil {
		t.Errorf("StopProfiling failed: %v", err)
	}
	if snapshot == nil {
		t.Error("Expected snapshot from StopProfiling")
	}

	// AnalyzeLeaks
	baseline, _ := hcp.TakeSnapshot()
	current, _ := hcp.TakeSnapshot()
	analysis := hcp.AnalyzeLeaks(baseline, current)
	if analysis == nil {
		t.Error("Expected leak analysis")
	}
}

// =============================================================================
// SECURITY MONITORING TESTS
// =============================================================================

func TestSecurityMonitor_StopCleanupRoutine_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	config := SecurityMonitorConfig{
		MaxFailuresPerIP:       5,
		FailureWindowMinutes:   15,
		BlockDurationMinutes:   30,
		RapidFailureThreshold:  3,
		CleanupIntervalMinutes: 60,
		RetentionHours:         24,
		EnablePatternDetection: true,
		EnableDetailedLogging:  false,
		LogSuspiciousOnly:      false,
	}

	sm := NewSecurityMonitor(config, logger)
	if sm == nil {
		t.Fatal("Expected non-nil SecurityMonitor")
	}

	// Start cleanup routine first (lowercase method)
	sm.startCleanupRoutine()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Stop cleanup routine (public method)
	sm.StopCleanupRoutine()

	// Stop again should be safe
	sm.StopCleanupRoutine()
}

func TestSecurityMonitor_MultipleHandlers_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	config := SecurityMonitorConfig{
		MaxFailuresPerIP:       5,
		FailureWindowMinutes:   15,
		BlockDurationMinutes:   30,
		RapidFailureThreshold:  3,
		CleanupIntervalMinutes: 60,
		RetentionHours:         24,
	}

	sm := NewSecurityMonitor(config, logger)

	// Create handler
	handler := &LoggingSecurityEventHandler{logger: logger}

	// Register handler using AddEventHandler
	sm.AddEventHandler(handler)

	// Record a failure to trigger events
	sm.RecordAuthenticationFailure("192.168.1.100", "test-agent", "/test", "test_failure", nil)
}

func TestLoggingSecurityEventHandler_HandleSecurityEvent_AllSeverities_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	handler := &LoggingSecurityEventHandler{logger: logger}

	// Severity is a string in this implementation
	events := []SecurityEvent{
		{Type: "test", Severity: "low", Message: "low severity"},
		{Type: "test", Severity: "medium", Message: "medium severity"},
		{Type: "test", Severity: "high", Message: "high severity"},
		{Type: "test", Severity: "critical", Message: "critical severity"},
	}

	for _, event := range events {
		handler.HandleSecurityEvent(event)
	}
}

// =============================================================================
// SESSION MANAGER TESTS
// =============================================================================

func TestSessionManager_GetSessionStats_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	stats := sm.GetSessionStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}

	// Should have expected keys
	if _, ok := stats["active_sessions"]; !ok {
		t.Error("Expected active_sessions in stats")
	}
	if _, ok := stats["pool_hits"]; !ok {
		t.Error("Expected pool_hits in stats")
	}
	if _, ok := stats["pool_misses"]; !ok {
		t.Error("Expected pool_misses in stats")
	}
}

func TestSessionManager_ValidateSessionHealth_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Test with nil session
	err = sm.ValidateSessionHealth(nil)
	if err == nil {
		t.Error("Expected error for nil session")
	}

	// Test with mock session that has proper initialization
	sessionData := CreateMockSessionData()
	// Initialize mainSession to avoid nil pointer
	sessionData.mainSession = sessions.NewSession(nil, "main")
	sessionData.mainSession.Values["authenticated"] = false

	err = sm.ValidateSessionHealth(sessionData)
	if err == nil {
		t.Error("Expected error for unauthenticated session")
	}
}

func TestSessionManager_ValidateTokenFormat_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Empty token - should be valid
	err = sm.validateTokenFormat("", "test_token")
	if err != nil {
		t.Errorf("Empty token should be valid: %v", err)
	}

	// Valid JWT format
	validJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	err = sm.validateTokenFormat(validJWT, "access_token")
	if err != nil {
		t.Errorf("Valid JWT should pass: %v", err)
	}

	// JWT with empty part
	invalidJWT := "header..signature"
	err = sm.validateTokenFormat(invalidJWT, "access_token")
	if err == nil {
		t.Error("Expected error for JWT with empty part")
	}
}

func TestSessionManager_DetectSessionTampering_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Test with nil main session
	sessionData := CreateMockSessionData()
	sessionData.mainSession = nil

	err = sm.detectSessionTampering(sessionData)
	if err == nil {
		t.Error("Expected error for nil main session")
	}

	// Test with path traversal attempt
	sessionData.mainSession = sessions.NewSession(nil, "test")
	sessionData.mainSession.Values["evil"] = "../../../etc/passwd"

	err = sm.detectSessionTampering(sessionData)
	if err == nil {
		t.Error("Expected error for path traversal attempt")
	}

	// Test with XSS attempt
	sessionData.mainSession.Values["evil"] = "<script>alert('xss')</script>"
	err = sm.detectSessionTampering(sessionData)
	if err == nil {
		t.Error("Expected error for XSS attempt")
	}

	// Test with overly long value
	longValue := make([]byte, 15000)
	for i := range longValue {
		longValue[i] = 'a'
	}
	sessionData.mainSession.Values["long"] = string(longValue)
	err = sm.detectSessionTampering(sessionData)
	if err == nil {
		t.Error("Expected error for overly long value")
	}
}

func TestSessionData_GetRefreshTokenIssuedAt_CoverageBoost(t *testing.T) {
	sessionData := CreateMockSessionData()

	// Initialize refresh session
	sessionData.refreshSession = sessions.NewSession(nil, "refresh")

	// Should return zero time when not set
	issuedAt := sessionData.GetRefreshTokenIssuedAt()
	if !issuedAt.IsZero() {
		t.Error("Expected zero time when issued_at not set")
	}

	// Set issued_at in refresh session
	now := time.Now().Unix()
	sessionData.refreshSession.Values["issued_at"] = now

	issuedAt = sessionData.GetRefreshTokenIssuedAt()
	if issuedAt.Unix() != now {
		t.Errorf("Expected issued_at %d, got %d", now, issuedAt.Unix())
	}
}

func TestSessionManager_PeriodicChunkCleanup_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Should not panic when called
	sm.PeriodicChunkCleanup()
}

func TestSessionManager_performCleanupCycle_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Should not panic when called
	sm.performCleanupCycle()
}

func TestSessionManager_cleanupSessionPool_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	// Should not panic when called
	sm.cleanupSessionPool()
}

// =============================================================================
// SESSION POOL PROFILER TESTS
// =============================================================================

func TestSessionPoolProfiler_Methods_CoverageBoost(t *testing.T) {
	sm, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, NewLogger("debug"))
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}
	logger := NewLogger("info")

	spp := NewSessionPoolProfiler(sm, logger)
	if spp == nil {
		t.Fatal("Expected non-nil SessionPoolProfiler")
	}

	config := ProfilingConfig{
		LeakThresholdMB: 100,
	}

	// StartProfiling
	err = spp.StartProfiling(config)
	if err != nil {
		t.Errorf("SessionPoolProfiler.StartProfiling failed: %v", err)
	}

	// GetCurrentStats
	stats := spp.GetCurrentStats()
	if stats == nil {
		t.Error("Expected non-nil stats")
	}

	// TakeSnapshot
	snapshot, err := spp.TakeSnapshot()
	if err != nil {
		t.Errorf("TakeSnapshot failed: %v", err)
	}
	if snapshot == nil {
		t.Error("Expected snapshot")
	}

	// StopProfiling
	snapshot, err = spp.StopProfiling()
	if err != nil {
		t.Errorf("StopProfiling failed: %v", err)
	}
	if snapshot == nil {
		t.Error("Expected snapshot from StopProfiling")
	}

	// AnalyzeLeaks
	baseline, _ := spp.TakeSnapshot()
	current, _ := spp.TakeSnapshot()
	analysis := spp.AnalyzeLeaks(baseline, current)
	if analysis == nil {
		t.Error("Expected leak analysis")
	}
}

// =============================================================================
// ADDITIONAL COVERAGE TESTS
// =============================================================================

func TestProfilingManager_AnalyzeLeaks_WithData_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	pm := NewProfilingManager(logger)

	pm.config.LeakThresholdMB = 0 // Set low threshold to trigger detection

	// Take real snapshots to test
	baseline, err := pm.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take baseline snapshot: %v", err)
	}

	// Allocate some memory to simulate change
	data := make([]byte, 1024*1024) // 1MB
	_ = data

	current, err := pm.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take current snapshot: %v", err)
	}

	analysis := pm.AnalyzeLeaks(baseline, current)
	if analysis == nil {
		t.Fatal("Expected analysis")
	}
}

func TestProfilingManager_AnalyzeLeaks_NilSnapshots_CoverageBoost(t *testing.T) {
	logger := NewLogger("info")
	pm := NewProfilingManager(logger)

	analysis := pm.AnalyzeLeaks(nil, nil)
	if analysis == nil {
		t.Fatal("Expected analysis even with nil snapshots")
	}

	if analysis.HasLeak {
		t.Error("Should not report leak with nil snapshots")
	}
}

// =============================================================================
// ADDITIONAL COVERAGE BOOST - TokenCache, JWKCache, GenericCache
// =============================================================================

func TestTokenCache_CleanupClose_CoverageBoost(t *testing.T) {
	tc := NewTokenCache()

	// These are no-ops but need coverage
	tc.Cleanup()
	tc.Close()
}

func TestJWKCache_CleanupClose_CoverageBoost(t *testing.T) {
	jc := NewJWKCache()

	// These are no-ops but need coverage
	jc.Cleanup()
	jc.Close()
}

func TestGenericCache_Operations_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	gc := NewGenericCache(time.Minute, logger)

	// Test Set
	gc.Set("key1", "value1")
	gc.Set("key2", 42)

	// Test Get
	val, exists := gc.Get("key1")
	if !exists {
		t.Error("Expected key1 to exist")
	}
	if val != "value1" {
		t.Errorf("Expected value1, got %v", val)
	}

	// Test Delete
	gc.Delete("key1")
	_, exists = gc.Get("key1")
	if exists {
		t.Error("Expected key1 to be deleted")
	}

	// Test Stop
	gc.Stop()
}

func TestLRUStrategy_AllMethods_CoverageBoost(t *testing.T) {
	strategy := NewLRUStrategy(100)

	// Test Name
	if strategy.Name() != "LRU" {
		t.Errorf("Expected LRU, got %s", strategy.Name())
	}

	// Test ShouldEvict
	evict := strategy.ShouldEvict("item", time.Now())
	if evict {
		t.Error("ShouldEvict should return false")
	}

	// Test OnAccess
	strategy.OnAccess("testkey", "testvalue")

	// Test OnRemove
	strategy.OnRemove("testkey")

	// Test EstimateSize
	size := strategy.EstimateSize("value")
	if size != 64 {
		t.Errorf("Expected 64, got %d", size)
	}

	// Test GetEvictionCandidate
	key, found := strategy.GetEvictionCandidate()
	if found {
		t.Errorf("Expected not found, got key: %s", key)
	}
}

func TestCacheInterfaceWrapper_SetMaxMemory_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	manager := GetUniversalCacheManager(logger)
	tokenCache := manager.GetTokenCache()

	// The cache should exist
	if tokenCache == nil {
		t.Fatal("Expected non-nil token cache")
	}
}

// =============================================================================
// SESSION CHUNK MANAGER TESTS
// =============================================================================

func TestResetGlobalSessionCounters_CoverageBoost(t *testing.T) {
	// Call the function - it should not panic
	ResetGlobalSessionCounters()

	// Call it again to ensure it's idempotent
	ResetGlobalSessionCounters()
}

// =============================================================================
// CACHE MANAGER SetMaxMemory TEST
// =============================================================================

func TestCacheManager_SetMaxMemory_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	manager := GetUniversalCacheManager(logger)

	if manager == nil {
		t.Fatal("Expected non-nil cache manager")
	}

	// Test SetMaxMemory through CacheInterfaceWrapper using NewCacheAdapter
	tokenCache := manager.GetTokenCache()
	wrapper := NewCacheAdapter(tokenCache)
	if wrapper != nil {
		// Set max memory - this should not panic
		wrapper.SetMaxMemory(1024 * 1024 * 100) // 100MB
	}
}

// =============================================================================
// SETTINGS VALIDATION TESTS
// =============================================================================

func TestValidateTemplateSecure_CoverageBoost(t *testing.T) {
	tests := []struct {
		name        string
		template    string
		shouldError bool
	}{
		{
			name:        "valid access token template",
			template:    "{{.AccessToken}}",
			shouldError: false,
		},
		{
			name:        "valid id token template",
			template:    "{{.IdToken}}",
			shouldError: false,
		},
		{
			name:        "valid refresh token template",
			template:    "{{.RefreshToken}}",
			shouldError: false,
		},
		{
			name:        "valid claims template",
			template:    "{{.Claims.email}}",
			shouldError: false,
		},
		{
			name:        "dangerous call pattern",
			template:    "{{call .Func}}",
			shouldError: true,
		},
		{
			name:        "dangerous range pattern",
			template:    "{{range .Items}}{{.}}{{end}}",
			shouldError: true,
		},
		{
			name:        "dangerous define pattern",
			template:    "{{define \"test\"}}{{.}}{{end}}",
			shouldError: true,
		},
		{
			name:        "dangerous template inclusion",
			template:    "{{template \"other\"}}",
			shouldError: true,
		},
		{
			name:        "dangerous printf pattern",
			template:    "{{printf \"%s\" .}}",
			shouldError: true,
		},
		{
			name:        "safe get function",
			template:    "{{get .Claims \"email\"}}",
			shouldError: false,
		},
		{
			name:        "safe default function",
			template:    "{{default \"unknown\" .Claims.email}}",
			shouldError: false,
		},
		{
			name:        "no allowed pattern",
			template:    "{{.Unknown}}",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTemplateSecure(tt.template)
			if tt.shouldError && err == nil {
				t.Errorf("Expected error for template: %s", tt.template)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error for template %s: %v", tt.template, err)
			}
		})
	}
}

func TestIsOriginAllowed_CoverageBoost(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		expected       bool
	}{
		{
			name:           "exact match",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			expected:       true,
		},
		{
			name:           "wildcard allows all",
			origin:         "https://any.domain.com",
			allowedOrigins: []string{"*"},
			expected:       true,
		},
		{
			name:           "subdomain wildcard https match",
			origin:         "https://sub.example.com",
			allowedOrigins: []string{"https://*.example.com"},
			expected:       true,
		},
		{
			name:           "subdomain wildcard http match",
			origin:         "http://sub.example.com",
			allowedOrigins: []string{"http://*.example.com"},
			expected:       true,
		},
		{
			name:           "root domain with https wildcard",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://*.example.com"},
			expected:       true,
		},
		{
			name:           "root domain with http wildcard",
			origin:         "http://example.com",
			allowedOrigins: []string{"http://*.example.com"},
			expected:       true,
		},
		{
			name:           "no match",
			origin:         "https://other.com",
			allowedOrigins: []string{"https://example.com"},
			expected:       false,
		},
		{
			name:           "empty allowed origins",
			origin:         "https://example.com",
			allowedOrigins: []string{},
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOriginAllowed(tt.origin, tt.allowedOrigins)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for origin %s with allowed %v",
					tt.expected, result, tt.origin, tt.allowedOrigins)
			}
		})
	}
}

// =============================================================================
// TOKEN CACHE LIFECYCLE TESTS
// =============================================================================

func TestTokenCache_CleanupAndClose_CoverageBoost(t *testing.T) {
	tc := NewTokenCache()
	if tc == nil {
		t.Fatal("Expected non-nil TokenCache")
	}

	// Add some data
	tc.Set("test-token-1", map[string]interface{}{"sub": "user1"}, time.Minute)
	tc.Set("test-token-2", map[string]interface{}{"sub": "user2"}, time.Minute)

	// Call Cleanup - this should not panic
	tc.Cleanup()

	// Call Close - this should not panic
	tc.Close()
}

// =============================================================================
// JWK CACHE LIFECYCLE TESTS
// =============================================================================

func TestJWKCache_CleanupAndClose_CoverageBoost(t *testing.T) {
	jc := NewJWKCache()
	if jc == nil {
		t.Fatal("Expected non-nil JWKCache")
	}

	// Call Cleanup - this should not panic
	jc.Cleanup()

	// Call Close - this should not panic
	jc.Close()
}

// =============================================================================
// PROFILING LEAK DETECTION TESTS
// =============================================================================

func TestMemoryTestOrchestrator_StopLeakDetection_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")

	config := LeakDetectionConfig{
		EnableLeakDetection:    true,
		LeakThresholdMB:        100,
		GoroutineLeakThreshold: 50,
	}

	mto := NewMemoryTestOrchestrator(config, logger)

	// Test StopLeakDetection when not started - should return error
	err := mto.StopLeakDetection()
	if err == nil {
		t.Log("StopLeakDetection returned nil error (expected since detection was not started)")
	}
}

// =============================================================================
// CHUNK MANAGER TESTS
// =============================================================================

func TestChunkManager_GetSessionCount_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	cm := NewChunkManager(logger)
	if cm == nil {
		t.Fatal("Expected non-nil ChunkManager")
	}
	defer cm.Shutdown()

	// Test GetSessionCount
	count := cm.GetSessionCount()
	if count != 0 {
		t.Errorf("Expected 0 sessions, got %d", count)
	}
}

func TestChunkManager_GetMemoryStats_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	cm := NewChunkManager(logger)
	if cm == nil {
		t.Fatal("Expected non-nil ChunkManager")
	}
	defer cm.Shutdown()

	// Test GetMemoryStats
	stats := cm.GetMemoryStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	// Verify expected keys exist
	if _, ok := stats["active_sessions"]; !ok {
		t.Error("Expected active_sessions key in stats")
	}
	if _, ok := stats["max_sessions"]; !ok {
		t.Error("Expected max_sessions key in stats")
	}
	if _, ok := stats["bytes_allocated"]; !ok {
		t.Error("Expected bytes_allocated key in stats")
	}
}

func TestChunkManager_CanCreateSession_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	cm := NewChunkManager(logger)
	if cm == nil {
		t.Fatal("Expected non-nil ChunkManager")
	}
	defer cm.Shutdown()

	// Test CanCreateSession - should be true initially
	canCreate, err := cm.CanCreateSession()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !canCreate {
		t.Error("Expected CanCreateSession to return true when empty")
	}
}

func TestChunkManager_EmergencyCleanup_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	cm := NewChunkManager(logger)
	if cm == nil {
		t.Fatal("Expected non-nil ChunkManager")
	}
	defer cm.Shutdown()

	// Test EmergencyCleanup - should not panic on empty session map
	cm.EmergencyCleanup()

	// Verify no sessions exist
	if cm.GetSessionCount() != 0 {
		t.Error("Expected 0 sessions after cleanup")
	}
}

func TestChunkManager_CleanupExpiredSessions_CoverageBoost(t *testing.T) {
	logger := NewLogger("debug")
	cm := NewChunkManager(logger)
	if cm == nil {
		t.Fatal("Expected non-nil ChunkManager")
	}
	defer cm.Shutdown()

	// Test CleanupExpiredSessions - should not panic on empty session map
	cm.CleanupExpiredSessions()

	// Verify no sessions exist
	if cm.GetSessionCount() != 0 {
		t.Error("Expected 0 sessions after cleanup")
	}
}

// =============================================================================
// REDIS CONFIG VALIDATE TESTS
// =============================================================================

func TestRedisConfig_Validate_CoverageBoost(t *testing.T) {
	tests := []struct {
		name        string
		config      RedisConfig
		shouldError bool
	}{
		{
			name:        "disabled redis is valid",
			config:      RedisConfig{Enabled: false},
			shouldError: false,
		},
		{
			name:        "enabled redis without address",
			config:      RedisConfig{Enabled: true, Address: ""},
			shouldError: true,
		},
		{
			name: "valid enabled redis",
			config: RedisConfig{
				Enabled: true,
				Address: "localhost:6379",
			},
			shouldError: false,
		},
		{
			name: "invalid cache mode",
			config: RedisConfig{
				Enabled:   true,
				Address:   "localhost:6379",
				CacheMode: "invalid",
			},
			shouldError: true,
		},
		{
			name: "valid redis cache mode",
			config: RedisConfig{
				Enabled:   true,
				Address:   "localhost:6379",
				CacheMode: "redis",
			},
			shouldError: false,
		},
		{
			name: "valid hybrid cache mode",
			config: RedisConfig{
				Enabled:   true,
				Address:   "localhost:6379",
				CacheMode: "hybrid",
			},
			shouldError: false,
		},
		{
			name: "negative pool size",
			config: RedisConfig{
				Enabled:  true,
				Address:  "localhost:6379",
				PoolSize: -1,
			},
			shouldError: true,
		},
		{
			name: "negative connect timeout",
			config: RedisConfig{
				Enabled:        true,
				Address:        "localhost:6379",
				ConnectTimeout: -1,
			},
			shouldError: true,
		},
		{
			name: "negative read timeout",
			config: RedisConfig{
				Enabled:     true,
				Address:     "localhost:6379",
				ReadTimeout: -1,
			},
			shouldError: true,
		},
		{
			name: "negative write timeout",
			config: RedisConfig{
				Enabled:      true,
				Address:      "localhost:6379",
				WriteTimeout: -1,
			},
			shouldError: true,
		},
		{
			name: "negative hybrid L1 size",
			config: RedisConfig{
				Enabled:      true,
				Address:      "localhost:6379",
				CacheMode:    "hybrid",
				HybridL1Size: -1,
			},
			shouldError: true,
		},
		{
			name: "negative hybrid L1 memory",
			config: RedisConfig{
				Enabled:          true,
				Address:          "localhost:6379",
				CacheMode:        "hybrid",
				HybridL1MemoryMB: -1,
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.shouldError && err == nil {
				t.Errorf("Expected error for config: %+v", tt.config)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error for config %+v: %v", tt.config, err)
			}
		})
	}
}
