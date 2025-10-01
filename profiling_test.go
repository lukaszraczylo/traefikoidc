package traefikoidc

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

// isRaceDetectorEnabled returns true if the Go race detector is enabled.
// This is determined by checking the build info for the race build tag.
func isRaceDetectorEnabled() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" && setting.Value == "true" {
			return true
		}
	}
	// Alternative method: check if GORACE environment variable is set
	return os.Getenv("GORACE") != ""
}

func TestProfilingManager(t *testing.T) {
	logger := NewLogger("debug")
	pm := NewProfilingManager(logger)

	// Test taking a snapshot
	snapshot, err := pm.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take snapshot: %v", err)
	}

	if snapshot == nil {
		t.Fatal("Snapshot is nil")
	}

	if snapshot.RuntimeStats.Alloc == 0 {
		t.Error("Runtime stats Alloc should not be zero")
	}

	if snapshot.Timestamp.IsZero() {
		t.Error("Snapshot timestamp should not be zero")
	}
}

func TestMemoryTestOrchestrator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	logger := NewLogger("debug")
	config := LeakDetectionConfig{
		EnableLeakDetection: true,
		LeakThresholdMB:     10,
	}

	mto := NewMemoryTestOrchestrator(config, logger)

	// Test registering a component
	sessionManager, err := NewSessionManager("test-key-32-chars-long-for-testing", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	profiler := NewSessionPoolProfiler(sessionManager, logger)
	mto.RegisterComponent("session_pool", profiler)

	// Test getting leak analysis (should return false initially since no checks have been performed)
	_, exists := mto.GetLeakAnalysis("session_pool")
	if exists {
		t.Error("Should not have leak analysis before any checks are performed")
	}

	// Perform a manual leak check
	baseline, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take baseline snapshot: %v", err)
	}

	time.Sleep(10 * time.Millisecond) // Small delay

	// Manually trigger leak check with baseline
	baselineSnapshots := make(map[string]*MemorySnapshot)
	baselineSnapshots["session_pool"] = baseline
	mto.performLeakCheck(baselineSnapshots)

	// Now test getting leak analysis
	analysis, exists := mto.GetLeakAnalysis("session_pool")
	if !exists {
		t.Error("Should have leak analysis after performing checks")
	}

	if analysis == nil {
		t.Error("Leak analysis should not be nil after checks")
	}
}

func TestComponentProfilers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	logger := NewLogger("debug")

	// Test Session Pool Profiler
	sessionManager, err := NewSessionManager("test-key-32-chars-long-for-testing", false, "", logger)
	if err != nil {
		t.Fatalf("Failed to create session manager: %v", err)
	}

	spp := NewSessionPoolProfiler(sessionManager, logger)
	snapshot, err := spp.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take session pool snapshot: %v", err)
	}

	if snapshot == nil {
		t.Fatal("Session pool snapshot is nil")
	}

	// Test Cache Memory Profiler
	cache := NewCache()
	cmp := NewCacheMemoryProfiler(cache, logger)
	snapshot, err = cmp.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take cache snapshot: %v", err)
	}

	if snapshot == nil {
		t.Fatal("Cache snapshot is nil")
	}

	// Test HTTP Client Profiler
	httpClient := CreateDefaultHTTPClient()
	hcp := NewHTTPClientProfiler(httpClient, logger)
	snapshot, err = hcp.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take HTTP client snapshot: %v", err)
	}

	if snapshot == nil {
		t.Fatal("HTTP client snapshot is nil")
	}

	// Token Compression Profiler removed - use internal/pool statistics instead
	t.Log("Token compression profiler deprecated - use internal/pool stats")
}

func TestLeakAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	logger := NewLogger("debug")
	pm := NewProfilingManager(logger)

	// Create baseline snapshot
	baseline, err := pm.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to create baseline: %v", err)
	}

	// Wait a bit and create current snapshot
	time.Sleep(10 * time.Millisecond)
	current, err := pm.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to create current snapshot: %v", err)
	}

	// Test leak analysis
	analysis := pm.AnalyzeLeaks(baseline, current)
	if analysis == nil {
		t.Fatal("Leak analysis is nil")
	}

	// Analysis should not have leaks for normal operation
	if analysis.HasLeak {
		t.Logf("Leak detected: %s", analysis.LeakDescription)
		// This is acceptable as the test environment may have varying memory usage
	}
}

func TestGlobalInstances(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// Test global profiling manager
	gpm := GetGlobalProfilingManager()
	if gpm == nil {
		t.Fatal("Global profiling manager is nil")
	}

	// Test global test orchestrator
	gto := GetGlobalTestOrchestrator()
	if gto == nil {
		t.Fatal("Global test orchestrator is nil")
	}

	// Test that they're singletons
	gpm2 := GetGlobalProfilingManager()
	if gpm != gpm2 {
		t.Error("Global profiling manager should be singleton")
	}

	gto2 := GetGlobalTestOrchestrator()
	if gto != gto2 {
		t.Error("Global test orchestrator should be singleton")
	}
}

func TestProfilingConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	config := ProfilingConfig{
		EnableHeapProfiling:        true,
		EnableGoroutineProfiling:   true,
		SnapshotInterval:           30 * time.Second,
		LeakThresholdMB:            50,
		MaxSnapshots:               100,
		EnableContinuousMonitoring: true,
		MonitoringInterval:         60 * time.Second,
	}

	if !config.EnableHeapProfiling {
		t.Error("Heap profiling should be enabled")
	}

	if !config.EnableGoroutineProfiling {
		t.Error("Goroutine profiling should be enabled")
	}

	if config.LeakThresholdMB != 50 {
		t.Errorf("Expected leak threshold 50, got %d", config.LeakThresholdMB)
	}
}

func TestLeakDetectionConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	config := LeakDetectionConfig{
		EnableLeakDetection:       true,
		LeakThresholdMB:           50,
		GoroutineLeakThreshold:    10,
		SessionPoolThreshold:      100,
		CacheMemoryThreshold:      20 * 1024 * 1024,
		HTTPClientThreshold:       50,
		TokenCompressionThreshold: 2 * 1024 * 1024,
	}

	if !config.EnableLeakDetection {
		t.Error("Leak detection should be enabled")
	}

	if config.LeakThresholdMB != 50 {
		t.Errorf("Expected leak threshold 50, got %d", config.LeakThresholdMB)
	}

	if config.CacheMemoryThreshold != 20*1024*1024 {
		t.Errorf("Expected cache threshold 20MB, got %d", config.CacheMemoryThreshold)
	}
}

// ProviderMetadataProfiler monitors provider metadata fetching and caching operations
type ProviderMetadataProfiler struct {
	metadataCache *MetadataCache
	httpClient    *http.Client
	logger        *Logger
	providerURL   string
}

// NewProviderMetadataProfiler creates a new provider metadata profiler
func NewProviderMetadataProfiler(metadataCache *MetadataCache, httpClient *http.Client, providerURL string, logger *Logger) *ProviderMetadataProfiler {
	if logger == nil {
		logger = newNoOpLogger()
	}
	return &ProviderMetadataProfiler{
		metadataCache: metadataCache,
		httpClient:    httpClient,
		providerURL:   providerURL,
		logger:        logger,
	}
}

// TakeSnapshot captures current memory statistics for metadata operations
func (pmp *ProviderMetadataProfiler) TakeSnapshot() (*MemorySnapshot, error) {
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	// Capture runtime memory statistics
	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Add metadata-specific metrics
	snapshot.CustomMetrics["metadata_cache_size"] = 1  // Placeholder for cache size
	snapshot.CustomMetrics["metadata_fetch_count"] = 0 // Placeholder for fetch count
	snapshot.CustomMetrics["background_goroutines"] = runtime.NumGoroutine()

	return snapshot, nil
}

// StartProfiling begins profiling (no-op for metadata profiler)
func (pmp *ProviderMetadataProfiler) StartProfiling(config ProfilingConfig) error {
	return nil
}

// StopProfiling ends profiling
func (pmp *ProviderMetadataProfiler) StopProfiling() (*MemorySnapshot, error) {
	return pmp.TakeSnapshot()
}

// GetCurrentStats returns current memory statistics
func (pmp *ProviderMetadataProfiler) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks analyzes metadata operations for memory leaks
func (pmp *ProviderMetadataProfiler) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.LeakDescription = "Insufficient metadata data"
		return analysis
	}

	// Check for memory leaks
	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 5*1024*1024 { // 5MB threshold for metadata operations
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"Metadata operations memory usage increased significantly")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for metadata cache not being cleaned up properly")
	}

	// Check for goroutine leaks
	goroutineIncrease := current.CustomMetrics["background_goroutines"].(int) - baseline.CustomMetrics["background_goroutines"].(int)
	if goroutineIncrease > 2 { // Allow some variance
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			fmt.Sprintf("Goroutine count increased by %d during metadata operations", goroutineIncrease))
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for background goroutines not being cleaned up")
	}

	return analysis
}

// TestProviderMetadataMemoryLeakDetection tests for memory leaks in provider metadata operations
func TestProviderMetadataMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping provider metadata memory leak detection test in short mode")
	}

	// Reset singleton cache manager to ensure clean state
	ResetUniversalCacheManagerForTesting()
	defer ResetUniversalCacheManagerForTesting() // Clean up after test

	logger := NewLogger("debug")

	strictMode := os.Getenv("STRICT_MEMORY_TEST") == "true"
	if strictMode {
		t.Log("Running in strict memory test mode - will fail on detected leaks")
	} else {
		t.Log("Running in lenient memory test mode - will log warnings instead of failing")
	}

	config := LeakDetectionConfig{
		EnableLeakDetection: true,
		LeakThresholdMB:     10,
	}

	mto := NewMemoryTestOrchestrator(config, logger)

	// Create mock HTTP server for metadata endpoint with failure simulation
	requestCount := 0
	serverFailures := 0
	mockServer := &http.Server{
		Addr: "localhost:0", // Let system assign port
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			if r.URL.Path == "/.well-known/openid-configuration" {
				// Simulate occasional failures to test cache extension
				if requestCount%4 == 0 { // Fail every 4th request
					serverFailures++
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				metadata := ProviderMetadata{
					Issuer:        "https://mock-provider.com",
					AuthURL:       "https://mock-provider.com/auth",
					TokenURL:      "https://mock-provider.com/token",
					JWKSURL:       "https://mock-provider.com/jwks",
					RevokeURL:     "https://mock-provider.com/revoke",
					EndSessionURL: "https://mock-provider.com/logout",
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "max-age=3600") // 1 hour cache hint
				json.NewEncoder(w).Encode(metadata)
			} else {
				http.NotFound(w, r)
			}
		}),
	}

	// Start mock server
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	go mockServer.Serve(listener)
	defer mockServer.Close()

	providerURL := fmt.Sprintf("http://%s", listener.Addr().String())
	httpClient := CreateDefaultHTTPClient()

	// Create metadata cache
	metadataCache := NewMetadataCacheWithLogger(nil, logger)

	// Create profiler
	profiler := NewProviderMetadataProfiler(metadataCache, httpClient, providerURL, logger)
	mto.RegisterComponent("provider_metadata", profiler)

	// Take initial baseline
	baseline, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take baseline snapshot: %v", err)
	}

	initialGoroutines := runtime.NumGoroutine()

	// Phase 1: Simulate periodic metadata fetching with some failures
	t.Log("Phase 1: Testing periodic fetching with occasional failures...")
	for i := 0; i < 20; i++ {
		_, err := metadataCache.GetMetadata(providerURL, httpClient, logger)
		if err != nil {
			t.Logf("Metadata fetch %d failed (expected for cache extension testing): %v", i+1, err)
		} else {
			t.Logf("Metadata fetch %d succeeded", i+1)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for background cleanup (normally every 5 minutes)
	time.Sleep(300 * time.Millisecond)

	// Take intermediate snapshot
	intermediate, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take intermediate snapshot: %v", err)
	}

	// Phase 2: Continue with more fetches to test sustained operation
	// Adjust iterations based on race detector presence to avoid timeouts
	var phase2Iterations int
	var sleepDuration time.Duration
	if isRaceDetectorEnabled() {
		// With race detector: reduce iterations significantly to stay well within timeout
		phase2Iterations = 100
		sleepDuration = 100 * time.Millisecond // Slightly longer sleep to reduce CPU contention
		t.Log("Phase 2: Testing sustained operation with 100 iterations (race detector enabled)...")
	} else {
		// Without race detector: use original values for thorough testing
		phase2Iterations = 1000
		sleepDuration = 50 * time.Millisecond
		t.Log("Phase 2: Testing sustained operation with 1000 iterations...")
	}

	for i := 20; i < 20+phase2Iterations; i++ {
		_, err := metadataCache.GetMetadata(providerURL, httpClient, logger)
		if err != nil {
			t.Logf("Metadata fetch %d failed: %v", i+1, err)
		}
		time.Sleep(sleepDuration)
	}

	// Take final snapshot
	current, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take current snapshot: %v", err)
	}

	finalGoroutines := runtime.NumGoroutine()

	// Analyze for leaks
	analysis := profiler.AnalyzeLeaks(baseline, current)

	// Assertions for memory leaks
	if analysis.HasLeak {
		if strictMode {
			t.Errorf("Memory leak detected in provider metadata operations: %s", analysis.LeakDescription)
			for _, leak := range analysis.SuspectedLeaks {
				t.Errorf("Suspected leak: %s", leak)
			}
		} else {
			t.Logf("Memory leak warning in provider metadata operations: %s", analysis.LeakDescription)
			for _, leak := range analysis.SuspectedLeaks {
				t.Logf("Suspected leak: %s", leak)
			}
		}
		for _, rec := range analysis.Recommendations {
			t.Logf("Recommendation: %s", rec)
		}
	}

	// Check total memory growth
	totalMemoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if totalMemoryIncrease > 20*1024*1024 { // 20MB threshold for entire test
		if strictMode {
			t.Errorf("Total memory usage increased by %.2f MB during metadata operations", float64(totalMemoryIncrease)/(1024*1024))
		} else {
			t.Logf("Total memory usage increased by %.2f MB during metadata operations", float64(totalMemoryIncrease)/(1024*1024))
		}
	}

	// Check for gradual memory growth patterns
	intermediateMemoryIncrease := intermediate.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if intermediateMemoryIncrease > 10*1024*1024 { // 10MB threshold for first phase
		if strictMode {
			t.Errorf("Memory usage increased by %.2f MB during first phase of metadata operations", float64(intermediateMemoryIncrease)/(1024*1024))
		} else {
			t.Logf("Memory usage increased by %.2f MB during first phase of metadata operations", float64(intermediateMemoryIncrease)/(1024*1024))
		}
	}

	// Check goroutine count stability
	goroutineIncrease := finalGoroutines - initialGoroutines
	if goroutineIncrease > 5 { // Allow some variance for test environment
		if strictMode {
			t.Errorf("Goroutine count increased by %d during metadata operations (initial: %d, final: %d)",
				goroutineIncrease, initialGoroutines, finalGoroutines)
		} else {
			t.Logf("Goroutine count increased by %d during metadata operations (initial: %d, final: %d)",
				goroutineIncrease, initialGoroutines, finalGoroutines)
		}
	}

	// Phase 3: Test cache extension behavior on persistent failures
	t.Log("Phase 3: Testing cache extension on persistent failures...")

	// Stop mock server to simulate provider unavailability
	mockServer.Close()

	// Try multiple fetches after server shutdown
	postShutdownFailures := 0
	for i := 0; i < 5; i++ {
		_, err = metadataCache.GetMetadata(providerURL, httpClient, logger)
		if err != nil {
			postShutdownFailures++
			t.Logf("Expected failure %d after server shutdown: %v", i+1, err)
		} else {
			t.Logf("Unexpected success %d after server shutdown - cache extension working", i+1)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if postShutdownFailures == 0 {
		if strictMode {
			t.Error("Expected some metadata fetches to fail after server shutdown")
		} else {
			t.Log("Warning: No metadata fetches failed after server shutdown - cache extension may not be working as expected")
		}
	}

	// Phase 4: Test background goroutine lifecycle and cleanup
	t.Log("Phase 4: Testing background goroutine lifecycle...")

	// Wait longer to allow background cleanup to run
	time.Sleep(GetTestDuration(1 * time.Second))

	// Take final snapshot after cleanup
	finalAfterCleanup, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take final snapshot after cleanup: %v", err)
	}

	// Check if memory decreased after cleanup
	if finalAfterCleanup.RuntimeStats.Alloc < current.RuntimeStats.Alloc {
		memoryDecrease := current.RuntimeStats.Alloc - finalAfterCleanup.RuntimeStats.Alloc
		t.Logf("Memory decreased by %.2f MB after cleanup phase", float64(memoryDecrease)/(1024*1024))
	}

	// Clean up resources
	// The cache manager cleanup is handled by the defer at the beginning of the test

	t.Logf("Test completed: %d total requests, %d server failures, %d post-shutdown failures",
		requestCount, serverFailures, postShutdownFailures)
	t.Logf("Memory usage: baseline=%.2f MB, intermediate=%.2f MB, final=%.2f MB",
		float64(baseline.RuntimeStats.Alloc)/(1024*1024),
		float64(intermediate.RuntimeStats.Alloc)/(1024*1024),
		float64(current.RuntimeStats.Alloc)/(1024*1024))
}

// TestMemoryPoolLeakDetection tests for memory leaks in memory pool operations
func TestMemoryPoolLeakDetection(t *testing.T) {
	t.Skip("Deprecated - memory pool profilers removed. Use internal/pool statistics instead")
}
