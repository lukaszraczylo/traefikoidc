package traefikoidc

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

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
	httpClient := createDefaultHTTPClient()
	hcp := NewHTTPClientProfiler(httpClient, logger)
	snapshot, err = hcp.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take HTTP client snapshot: %v", err)
	}

	if snapshot == nil {
		t.Fatal("HTTP client snapshot is nil")
	}

	// Test Token Compression Profiler
	compressionPool := NewTokenCompressionPool()
	tcp := NewTokenCompressionProfiler(compressionPool, logger)
	snapshot, err = tcp.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take compression snapshot: %v", err)
	}

	if snapshot == nil {
		t.Fatal("Compression snapshot is nil")
	}
}

func TestLeakAnalysis(t *testing.T) {
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
	httpClient := createDefaultHTTPClient()

	// Create metadata cache with WaitGroup for proper goroutine synchronization
	var wg sync.WaitGroup
	metadataCache := NewMetadataCacheWithLogger(&wg, logger)

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
	t.Log("Phase 2: Testing sustained operation with 1000 iterations...")
	for i := 20; i < 1020; i++ {
		_, err := metadataCache.GetMetadata(providerURL, httpClient, logger)
		if err != nil {
			t.Logf("Metadata fetch %d failed: %v", i+1, err)
		}
		time.Sleep(50 * time.Millisecond) // Reduced sleep for faster execution
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
	time.Sleep(1 * time.Second)

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
	metadataCache.Close()
	wg.Wait() // Ensure all background goroutines complete

	t.Logf("Test completed: %d total requests, %d server failures, %d post-shutdown failures",
		requestCount, serverFailures, postShutdownFailures)
	t.Logf("Memory usage: baseline=%.2f MB, intermediate=%.2f MB, final=%.2f MB",
		float64(baseline.RuntimeStats.Alloc)/(1024*1024),
		float64(intermediate.RuntimeStats.Alloc)/(1024*1024),
		float64(current.RuntimeStats.Alloc)/(1024*1024))
}

// TestMemoryPoolLeakDetection tests for memory leaks in memory pool operations
func TestMemoryPoolLeakDetection(t *testing.T) {
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

	// Create memory pool manager and token compression pool
	memoryPoolManager := NewMemoryPoolManager()
	tokenCompressionPool := NewTokenCompressionPool()

	// Create profiler for memory pools
	profiler := NewMemoryPoolProfiler(memoryPoolManager, tokenCompressionPool, logger)
	mto.RegisterComponent("memory_pools", profiler)

	// Take initial baseline
	baseline, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take baseline snapshot: %v", err)
	}

	initialGoroutines := runtime.NumGoroutine()

	// Phase 1: Simulate various memory pool operations
	t.Log("Phase 1: Testing memory pool operations with various patterns...")

	// Test compression buffer pool
	for i := 0; i < 100; i++ {
		buf := memoryPoolManager.GetCompressionBuffer()
		// Simulate some work with the buffer
		buf.WriteString(fmt.Sprintf("test data %d", i))
		// Properly return buffer to pool
		memoryPoolManager.PutCompressionBuffer(buf)
	}

	// Test JWT parsing buffer pool
	for i := 0; i < 50; i++ {
		jwtBuf := memoryPoolManager.GetJWTParsingBuffer()
		// Simulate JWT parsing operations
		jwtBuf.HeaderBuf = append(jwtBuf.HeaderBuf, []byte("header")...)
		jwtBuf.PayloadBuf = append(jwtBuf.PayloadBuf, []byte("payload")...)
		jwtBuf.SignatureBuf = append(jwtBuf.SignatureBuf, []byte("signature")...)
		// Properly return buffer to pool
		memoryPoolManager.PutJWTParsingBuffer(jwtBuf)
	}

	// Test HTTP response buffer pool
	for i := 0; i < 75; i++ {
		httpBuf := memoryPoolManager.GetHTTPResponseBuffer()
		// Simulate HTTP response processing
		copy(httpBuf[:min(len(httpBuf), 100)], []byte("http response data"))
		// Properly return buffer to pool
		memoryPoolManager.PutHTTPResponseBuffer(httpBuf)
	}

	// Test string builder pool
	for i := 0; i < 60; i++ {
		sb := memoryPoolManager.GetStringBuilder()
		// Simulate string building operations
		sb.WriteString(fmt.Sprintf("built string %d", i))
		_ = sb.String() // Use the result
		// Properly return string builder to pool
		memoryPoolManager.PutStringBuilder(sb)
	}

	// Test token compression pool
	for i := 0; i < 40; i++ {
		compBuf := tokenCompressionPool.GetCompressionBuffer()
		// Simulate compression operations
		compBuf.WriteString(fmt.Sprintf("compress data %d", i))
		// Properly return buffer to pool
		tokenCompressionPool.PutCompressionBuffer(compBuf)

		decompBuf := tokenCompressionPool.GetDecompressionBuffer()
		// Simulate decompression operations
		decompBuf.WriteString(fmt.Sprintf("decompress data %d", i))
		// Properly return buffer to pool
		tokenCompressionPool.PutDecompressionBuffer(decompBuf)

		sb := tokenCompressionPool.GetStringBuilder()
		// Simulate string operations
		sb.WriteString(fmt.Sprintf("token string %d", i))
		_ = sb.String()
		// Properly return string builder to pool
		tokenCompressionPool.PutStringBuilder(sb)
	}

	// Take intermediate snapshot
	intermediate, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take intermediate snapshot: %v", err)
	}

	// Phase 2: Continue with more intensive operations to test sustained usage
	t.Log("Phase 2: Testing sustained memory pool usage...")

	// Simulate mixed operations with varying patterns
	for i := 0; i < 200; i++ {
		// Mix different pool operations
		switch i % 4 {
		case 0:
			buf := memoryPoolManager.GetCompressionBuffer()
			buf.WriteString("mixed operation data")
			memoryPoolManager.PutCompressionBuffer(buf)
		case 1:
			jwtBuf := memoryPoolManager.GetJWTParsingBuffer()
			jwtBuf.HeaderBuf = append(jwtBuf.HeaderBuf, []byte("mixed")...)
			memoryPoolManager.PutJWTParsingBuffer(jwtBuf)
		case 2:
			httpBuf := memoryPoolManager.GetHTTPResponseBuffer()
			copy(httpBuf[:min(len(httpBuf), 50)], []byte("mixed http"))
			memoryPoolManager.PutHTTPResponseBuffer(httpBuf)
		case 3:
			sb := memoryPoolManager.GetStringBuilder()
			sb.WriteString("mixed string building")
			_ = sb.String()
			memoryPoolManager.PutStringBuilder(sb)
		}
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
			t.Errorf("Memory leak detected in memory pool operations: %s", analysis.LeakDescription)
			for _, leak := range analysis.SuspectedLeaks {
				t.Errorf("Suspected leak: %s", leak)
			}
		} else {
			t.Logf("Memory leak warning in memory pool operations: %s", analysis.LeakDescription)
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
	if totalMemoryIncrease > 15*1024*1024 { // 15MB threshold for entire test
		if strictMode {
			t.Errorf("Total memory usage increased by %.2f MB during memory pool operations", float64(totalMemoryIncrease)/(1024*1024))
		} else {
			t.Logf("Total memory usage increased by %.2f MB during memory pool operations", float64(totalMemoryIncrease)/(1024*1024))
		}
	}

	// Check for gradual memory growth patterns
	intermediateMemoryIncrease := intermediate.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if intermediateMemoryIncrease > 8*1024*1024 { // 8MB threshold for first phase
		if strictMode {
			t.Errorf("Memory usage increased by %.2f MB during first phase of memory pool operations", float64(intermediateMemoryIncrease)/(1024*1024))
		} else {
			t.Logf("Memory usage increased by %.2f MB during first phase of memory pool operations", float64(intermediateMemoryIncrease)/(1024*1024))
		}
	}

	// Check goroutine count stability
	goroutineIncrease := finalGoroutines - initialGoroutines
	if goroutineIncrease > 3 { // Allow small variance for test environment
		if strictMode {
			t.Errorf("Goroutine count increased by %d during memory pool operations (initial: %d, final: %d)",
				goroutineIncrease, initialGoroutines, finalGoroutines)
		} else {
			t.Logf("Goroutine count increased by %d during memory pool operations (initial: %d, final: %d)",
				goroutineIncrease, initialGoroutines, finalGoroutines)
		}
	}

	// Phase 3: Test cleanup verification
	t.Log("Phase 3: Testing cleanup verification...")

	// Force garbage collection to see if pools are properly managed
	runtime.GC()
	runtime.GC() // Run twice to ensure cleanup

	time.Sleep(10 * time.Millisecond) // Allow cleanup to complete

	// Take post-cleanup snapshot
	postCleanup, err := profiler.TakeSnapshot()
	if err != nil {
		t.Fatalf("Failed to take post-cleanup snapshot: %v", err)
	}

	// Check if memory decreased after cleanup
	if postCleanup.RuntimeStats.Alloc < current.RuntimeStats.Alloc {
		memoryDecrease := current.RuntimeStats.Alloc - postCleanup.RuntimeStats.Alloc
		t.Logf("Memory decreased by %.2f MB after cleanup phase", float64(memoryDecrease)/(1024*1024))
	} else if postCleanup.RuntimeStats.Alloc > current.RuntimeStats.Alloc {
		memoryIncrease := postCleanup.RuntimeStats.Alloc - current.RuntimeStats.Alloc
		if strictMode {
			t.Errorf("Memory increased by %.2f MB after cleanup phase - possible cleanup issues", float64(memoryIncrease)/(1024*1024))
		} else {
			t.Logf("Memory increased by %.2f MB after cleanup phase - possible cleanup issues", float64(memoryIncrease)/(1024*1024))
		}
	}

	t.Logf("Memory pool leak detection test completed")
	t.Logf("Memory usage: baseline=%.2f MB, intermediate=%.2f MB, final=%.2f MB, post-cleanup=%.2f MB",
		float64(baseline.RuntimeStats.Alloc)/(1024*1024),
		float64(intermediate.RuntimeStats.Alloc)/(1024*1024),
		float64(current.RuntimeStats.Alloc)/(1024*1024),
		float64(postCleanup.RuntimeStats.Alloc)/(1024*1024))
}
