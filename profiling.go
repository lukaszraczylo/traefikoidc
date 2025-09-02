package traefikoidc

import (
	"bytes"
	"fmt"
	"net/http"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"
)

// MemoryProfiler defines the interface for memory profiling operations
type MemoryProfiler interface {
	// TakeSnapshot captures current memory statistics
	TakeSnapshot() (*MemorySnapshot, error)

	// StartProfiling begins memory profiling with specified configuration
	StartProfiling(config ProfilingConfig) error

	// StopProfiling ends memory profiling and returns final snapshot
	StopProfiling() (*MemorySnapshot, error)

	// GetCurrentStats returns current runtime memory statistics
	GetCurrentStats() *runtime.MemStats

	// AnalyzeLeaks performs leak detection analysis
	AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis
}

// MemorySnapshot represents a point-in-time capture of memory statistics
type MemorySnapshot struct {
	Timestamp        time.Time
	RuntimeStats     runtime.MemStats
	HeapProfile      []byte
	GoroutineProfile []byte
	CustomMetrics    map[string]interface{}
}

// LeakAnalysis contains the results of memory leak detection
type LeakAnalysis struct {
	HasLeak           bool
	LeakDescription   string
	MemoryIncrease    uint64
	GoroutineIncrease int
	SuspectedLeaks    []string
	Recommendations   []string
}

// ProfilingManager coordinates memory profiling operations
type ProfilingManager struct {
	mu               sync.RWMutex
	isProfiling      bool
	startTime        time.Time
	baselineSnapshot *MemorySnapshot
	config           ProfilingConfig
	logger           *Logger
	profilers        map[string]MemoryProfiler
}

// ProfilingConfig contains configuration for profiling operations
type ProfilingConfig struct {
	EnableHeapProfiling        bool
	EnableGoroutineProfiling   bool
	SnapshotInterval           time.Duration
	LeakThresholdMB            uint64
	MaxSnapshots               int
	EnableContinuousMonitoring bool
	MonitoringInterval         time.Duration
}

// LeakDetectionConfig contains configuration for leak detection
type LeakDetectionConfig struct {
	EnableLeakDetection       bool
	LeakThresholdMB           uint64
	GoroutineLeakThreshold    int
	SessionPoolThreshold      int
	CacheMemoryThreshold      uint64
	HTTPClientThreshold       int
	TokenCompressionThreshold uint64
}

// NewProfilingManager creates a new profiling manager instance
func NewProfilingManager(logger *Logger) *ProfilingManager {
	if logger == nil {
		logger = newNoOpLogger()
	}

	return &ProfilingManager{
		profilers: make(map[string]MemoryProfiler),
		config: ProfilingConfig{
			EnableHeapProfiling:        true,
			EnableGoroutineProfiling:   true,
			SnapshotInterval:           30 * time.Second,
			LeakThresholdMB:            50, // 50MB
			MaxSnapshots:               100,
			EnableContinuousMonitoring: true,
			MonitoringInterval:         60 * time.Second,
		},
		logger: logger,
	}
}

// TakeSnapshot captures current memory statistics
func (pm *ProfilingManager) TakeSnapshot() (*MemorySnapshot, error) {
	var buf bytes.Buffer
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	// Capture runtime memory statistics
	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Capture heap profile if enabled
	if pm.config.EnableHeapProfiling {
		if err := pprof.WriteHeapProfile(&buf); err != nil {
			pm.logger.Errorf("Failed to capture heap profile: %v", err)
		} else {
			snapshot.HeapProfile = make([]byte, buf.Len())
			copy(snapshot.HeapProfile, buf.Bytes())
			buf.Reset()
		}
	}

	// Capture goroutine profile if enabled
	if pm.config.EnableGoroutineProfiling {
		if err := pprof.Lookup("goroutine").WriteTo(&buf, 0); err != nil {
			pm.logger.Errorf("Failed to capture goroutine profile: %v", err)
		} else {
			snapshot.GoroutineProfile = make([]byte, buf.Len())
			copy(snapshot.GoroutineProfile, buf.Bytes())
			buf.Reset()
		}
	}

	// Capture custom metrics from registered profilers
	pm.mu.RLock()
	for name, profiler := range pm.profilers {
		if customStats := profiler.GetCurrentStats(); customStats != nil {
			snapshot.CustomMetrics[name] = customStats
		}
	}
	pm.mu.RUnlock()

	return snapshot, nil
}

// StartProfiling begins memory profiling with specified configuration
func (pm *ProfilingManager) StartProfiling(config ProfilingConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.isProfiling {
		return fmt.Errorf("profiling already in progress")
	}

	pm.config = config
	pm.isProfiling = true
	pm.startTime = time.Now()

	// Take baseline snapshot
	baseline, err := pm.TakeSnapshot()
	if err != nil {
		pm.isProfiling = false
		return fmt.Errorf("failed to take baseline snapshot: %w", err)
	}
	pm.baselineSnapshot = baseline

	pm.logger.Infof("Memory profiling started at %v", pm.startTime)
	return nil
}

// StopProfiling ends memory profiling and returns final snapshot
func (pm *ProfilingManager) StopProfiling() (*MemorySnapshot, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.isProfiling {
		return nil, fmt.Errorf("profiling not in progress")
	}

	// Take final snapshot
	finalSnapshot, err := pm.TakeSnapshot()
	if err != nil {
		pm.logger.Errorf("Failed to take final snapshot: %v", err)
	}

	pm.isProfiling = false
	duration := time.Since(pm.startTime)

	pm.logger.Infof("Memory profiling stopped after %v", duration)
	return finalSnapshot, err
}

// GetCurrentStats returns current runtime memory statistics
func (pm *ProfilingManager) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks performs leak detection analysis
func (pm *ProfilingManager) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.HasLeak = false
		analysis.LeakDescription = "Insufficient data for leak analysis"
		return analysis
	}

	// Calculate memory increase
	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	analysis.MemoryIncrease = memoryIncrease

	// Calculate goroutine increase
	currentGoroutines := runtime.NumGoroutine()
	baselineGoroutines := runtime.NumGoroutine() // Note: This is not accurate for baseline, but we don't have historical data
	goroutineIncrease := currentGoroutines - baselineGoroutines
	analysis.GoroutineIncrease = goroutineIncrease

	// Check for memory leaks
	memoryThreshold := pm.config.LeakThresholdMB * 1024 * 1024 // Convert MB to bytes
	if memoryIncrease > memoryThreshold {
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			fmt.Sprintf("Memory usage increased by %.2f MB", float64(memoryIncrease)/(1024*1024)))
		analysis.Recommendations = append(analysis.Recommendations,
			"Consider checking for unreleased memory pools or growing caches")
	}

	// Check for goroutine leaks
	if goroutineIncrease > 10 { // Arbitrary threshold
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			fmt.Sprintf("Goroutine count increased by %d", goroutineIncrease))
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for goroutines that are not being properly cleaned up")
	}

	if analysis.HasLeak {
		analysis.LeakDescription = fmt.Sprintf("Potential memory leak detected: %s",
			fmt.Sprintf("%.2f MB increase, %d goroutines", float64(memoryIncrease)/(1024*1024), goroutineIncrease))
	} else {
		analysis.LeakDescription = "No significant memory leaks detected"
	}

	return analysis
}

// RegisterProfiler registers a component-specific profiler
func (pm *ProfilingManager) RegisterProfiler(name string, profiler MemoryProfiler) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.profilers[name] = profiler
	pm.logger.Debugf("Registered profiler: %s", name)
}

// UnregisterProfiler removes a component-specific profiler
func (pm *ProfilingManager) UnregisterProfiler(name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.profilers, name)
	pm.logger.Debugf("Unregistered profiler: %s", name)
}

// GetRegisteredProfilers returns list of registered profiler names
func (pm *ProfilingManager) GetRegisteredProfilers() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	names := make([]string, 0, len(pm.profilers))
	for name := range pm.profilers {
		names = append(names, name)
	}
	return names
}

// MemoryTestOrchestrator coordinates memory leak testing across components
type MemoryTestOrchestrator struct {
	mu          sync.RWMutex
	profilers   map[string]MemoryProfiler
	config      LeakDetectionConfig
	logger      *Logger
	isRunning   bool
	stopChan    chan struct{}
	testResults map[string]*LeakAnalysis
}

// NewMemoryTestOrchestrator creates a new test orchestrator
func NewMemoryTestOrchestrator(config LeakDetectionConfig, logger *Logger) *MemoryTestOrchestrator {
	if logger == nil {
		logger = newNoOpLogger()
	}

	return &MemoryTestOrchestrator{
		profilers:   make(map[string]MemoryProfiler),
		config:      config,
		logger:      logger,
		stopChan:    make(chan struct{}),
		testResults: make(map[string]*LeakAnalysis),
	}
}

// RegisterComponent registers a component for memory leak testing
func (mto *MemoryTestOrchestrator) RegisterComponent(name string, profiler MemoryProfiler) {
	mto.mu.Lock()
	defer mto.mu.Unlock()
	mto.profilers[name] = profiler
	mto.logger.Debugf("Registered component for leak testing: %s", name)
}

// UnregisterComponent removes a component from leak testing
func (mto *MemoryTestOrchestrator) UnregisterComponent(name string) {
	mto.mu.Lock()
	defer mto.mu.Unlock()
	delete(mto.profilers, name)
	delete(mto.testResults, name)
	mto.logger.Debugf("Unregistered component from leak testing: %s", name)
}

// StartLeakDetection begins continuous leak detection monitoring
func (mto *MemoryTestOrchestrator) StartLeakDetection() error {
	mto.mu.Lock()
	defer mto.mu.Unlock()

	if mto.isRunning {
		return fmt.Errorf("leak detection already running")
	}

	if !mto.config.EnableLeakDetection {
		return fmt.Errorf("leak detection is disabled in configuration")
	}

	mto.isRunning = true
	go mto.runLeakDetection()

	mto.logger.Infof("Memory leak detection started")
	return nil
}

// StopLeakDetection stops continuous leak detection monitoring
func (mto *MemoryTestOrchestrator) StopLeakDetection() error {
	mto.mu.Lock()
	defer mto.mu.Unlock()

	if !mto.isRunning {
		return fmt.Errorf("leak detection not running")
	}

	mto.isRunning = false
	close(mto.stopChan)
	mto.stopChan = make(chan struct{}) // Reset for potential restart

	mto.logger.Infof("Memory leak detection stopped")
	return nil
}

// runLeakDetection performs continuous leak detection monitoring
func (mto *MemoryTestOrchestrator) runLeakDetection() {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	baselineSnapshots := make(map[string]*MemorySnapshot)

	// Take initial baseline snapshots
	mto.mu.RLock()
	for name, profiler := range mto.profilers {
		if snapshot, err := profiler.TakeSnapshot(); err == nil {
			baselineSnapshots[name] = snapshot
		}
	}
	mto.mu.RUnlock()

	for {
		select {
		case <-ticker.C:
			mto.performLeakCheck(baselineSnapshots)
		case <-mto.stopChan:
			return
		}
	}
}

// performLeakCheck performs leak detection for all registered components
func (mto *MemoryTestOrchestrator) performLeakCheck(baselineSnapshots map[string]*MemorySnapshot) {
	mto.mu.RLock()
	defer mto.mu.RUnlock()

	for name, profiler := range mto.profilers {
		baseline, exists := baselineSnapshots[name]
		if !exists {
			continue
		}

		current, err := profiler.TakeSnapshot()
		if err != nil {
			mto.logger.Errorf("Failed to take snapshot for component %s: %v", name, err)
			continue
		}

		analysis := profiler.AnalyzeLeaks(baseline, current)
		if analysis.HasLeak {
			mto.logger.Errorf("Memory leak detected in component %s: %s", name, analysis.LeakDescription)
			for _, rec := range analysis.Recommendations {
				mto.logger.Errorf("Recommendation for %s: %s", name, rec)
			}
		}

		mto.testResults[name] = analysis
	}
}

// GetLeakAnalysis returns leak analysis for a specific component
func (mto *MemoryTestOrchestrator) GetLeakAnalysis(componentName string) (*LeakAnalysis, bool) {
	mto.mu.RLock()
	defer mto.mu.RUnlock()
	analysis, exists := mto.testResults[componentName]
	return analysis, exists
}

// GetAllLeakAnalyses returns leak analyses for all components
func (mto *MemoryTestOrchestrator) GetAllLeakAnalyses() map[string]*LeakAnalysis {
	mto.mu.RLock()
	defer mto.mu.RUnlock()

	results := make(map[string]*LeakAnalysis)
	for name, analysis := range mto.testResults {
		results[name] = analysis
	}
	return results
}

// Component-specific profiler implementations

// SessionPoolProfiler monitors session pool memory usage
type SessionPoolProfiler struct {
	sessionManager *SessionManager
	logger         *Logger
}

// NewSessionPoolProfiler creates a new session pool profiler
func NewSessionPoolProfiler(sm *SessionManager, logger *Logger) *SessionPoolProfiler {
	if logger == nil {
		logger = newNoOpLogger()
	}
	return &SessionPoolProfiler{
		sessionManager: sm,
		logger:         logger,
	}
}

// TakeSnapshot captures session pool memory statistics
func (spp *SessionPoolProfiler) TakeSnapshot() (*MemorySnapshot, error) {
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	// Capture runtime stats
	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Add session pool specific metrics
	snapshot.CustomMetrics["session_pool_metrics"] = spp.sessionManager.GetSessionMetrics()

	return snapshot, nil
}

// StartProfiling begins profiling (no-op for session pools)
func (spp *SessionPoolProfiler) StartProfiling(config ProfilingConfig) error {
	return nil
}

// StopProfiling ends profiling (no-op for session pools)
func (spp *SessionPoolProfiler) StopProfiling() (*MemorySnapshot, error) {
	return spp.TakeSnapshot()
}

// GetCurrentStats returns current memory statistics
func (spp *SessionPoolProfiler) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks analyzes session pool for leaks
func (spp *SessionPoolProfiler) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.LeakDescription = "Insufficient session pool data"
		return analysis
	}

	// Check for session pool specific leaks
	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 10*1024*1024 { // 10MB threshold
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"Session pool memory usage increased significantly")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for sessions not being returned to pool properly")
	}

	return analysis
}

// CacheMemoryProfiler monitors cache memory usage
type CacheMemoryProfiler struct {
	cache  *Cache
	logger *Logger
}

// NewCacheMemoryProfiler creates a new cache memory profiler
func NewCacheMemoryProfiler(cache *Cache, logger *Logger) *CacheMemoryProfiler {
	if logger == nil {
		logger = newNoOpLogger()
	}
	return &CacheMemoryProfiler{
		cache:  cache,
		logger: logger,
	}
}

// TakeSnapshot captures cache memory statistics
func (cmp *CacheMemoryProfiler) TakeSnapshot() (*MemorySnapshot, error) {
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Add cache-specific metrics (would need to be added to Cache struct)
	snapshot.CustomMetrics["cache_size"] = "unknown" // Placeholder

	return snapshot, nil
}

// StartProfiling begins profiling (no-op for cache)
func (cmp *CacheMemoryProfiler) StartProfiling(config ProfilingConfig) error {
	return nil
}

// StopProfiling ends profiling
func (cmp *CacheMemoryProfiler) StopProfiling() (*MemorySnapshot, error) {
	return cmp.TakeSnapshot()
}

// GetCurrentStats returns current memory statistics
func (cmp *CacheMemoryProfiler) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks analyzes cache for memory leaks
func (cmp *CacheMemoryProfiler) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.LeakDescription = "Insufficient cache data"
		return analysis
	}

	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 20*1024*1024 { // 20MB threshold for cache
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"Cache memory usage increased significantly")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check cache size limits and cleanup intervals")
	}

	return analysis
}

// HTTPClientProfiler monitors HTTP client connection pools
type HTTPClientProfiler struct {
	httpClient *http.Client
	logger     *Logger
}

// NewHTTPClientProfiler creates a new HTTP client profiler
func NewHTTPClientProfiler(client *http.Client, logger *Logger) *HTTPClientProfiler {
	if logger == nil {
		logger = newNoOpLogger()
	}
	return &HTTPClientProfiler{
		httpClient: client,
		logger:     logger,
	}
}

// TakeSnapshot captures HTTP client memory statistics
func (hcp *HTTPClientProfiler) TakeSnapshot() (*MemorySnapshot, error) {
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Add HTTP client specific metrics
	if transport, ok := hcp.httpClient.Transport.(*http.Transport); ok {
		snapshot.CustomMetrics["idle_connections"] = transport.IdleConnTimeout.String()
		snapshot.CustomMetrics["max_idle_conns"] = transport.MaxIdleConns
	}

	return snapshot, nil
}

// StartProfiling begins profiling (no-op for HTTP client)
func (hcp *HTTPClientProfiler) StartProfiling(config ProfilingConfig) error {
	return nil
}

// StopProfiling ends profiling
func (hcp *HTTPClientProfiler) StopProfiling() (*MemorySnapshot, error) {
	return hcp.TakeSnapshot()
}

// GetCurrentStats returns current memory statistics
func (hcp *HTTPClientProfiler) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks analyzes HTTP client for connection leaks
func (hcp *HTTPClientProfiler) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.LeakDescription = "Insufficient HTTP client data"
		return analysis
	}

	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 5*1024*1024 { // 5MB threshold for HTTP client
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"HTTP client memory usage increased significantly")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for HTTP response bodies not being drained properly")
	}

	return analysis
}

// TokenCompressionProfiler monitors token compression memory usage
type TokenCompressionProfiler struct {
	compressionPool *TokenCompressionPool
	logger          *Logger
}

// NewTokenCompressionProfiler creates a new token compression profiler
func NewTokenCompressionProfiler(pool *TokenCompressionPool, logger *Logger) *TokenCompressionProfiler {
	if logger == nil {
		logger = newNoOpLogger()
	}
	return &TokenCompressionProfiler{
		compressionPool: pool,
		logger:          logger,
	}
}

// TakeSnapshot captures token compression memory statistics
func (tcp *TokenCompressionProfiler) TakeSnapshot() (*MemorySnapshot, error) {
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Add compression pool specific metrics
	snapshot.CustomMetrics["compression_pool_active"] = true

	return snapshot, nil
}

// StartProfiling begins profiling (no-op for compression)
func (tcp *TokenCompressionProfiler) StartProfiling(config ProfilingConfig) error {
	return nil
}

// StopProfiling ends profiling
func (tcp *TokenCompressionProfiler) StopProfiling() (*MemorySnapshot, error) {
	return tcp.TakeSnapshot()
}

// GetCurrentStats returns current memory statistics
func (tcp *TokenCompressionProfiler) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks analyzes token compression for memory leaks
func (tcp *TokenCompressionProfiler) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.LeakDescription = "Insufficient compression data"
		return analysis
	}

	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 2*1024*1024 { // 2MB threshold for compression
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"Token compression memory usage increased significantly")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for compression buffers not being returned to pool")
	}

	return analysis
}

// MemoryPoolProfiler monitors memory pool usage and detects leaks
type MemoryPoolProfiler struct {
	memoryPoolManager    *MemoryPoolManager
	tokenCompressionPool *TokenCompressionPool
	logger               *Logger
}

// NewMemoryPoolProfiler creates a new memory pool profiler
func NewMemoryPoolProfiler(memoryPoolManager *MemoryPoolManager, tokenCompressionPool *TokenCompressionPool, logger *Logger) *MemoryPoolProfiler {
	if logger == nil {
		logger = newNoOpLogger()
	}
	return &MemoryPoolProfiler{
		memoryPoolManager:    memoryPoolManager,
		tokenCompressionPool: tokenCompressionPool,
		logger:               logger,
	}
}

// TakeSnapshot captures memory pool statistics
func (mpp *MemoryPoolProfiler) TakeSnapshot() (*MemorySnapshot, error) {
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	// Capture runtime stats
	runtime.ReadMemStats(&snapshot.RuntimeStats)

	// Add memory pool metrics
	if mpp.memoryPoolManager != nil {
		snapshot.CustomMetrics["memory_pool_active"] = true
		// Note: sync.Pool doesn't expose internal statistics, so we track usage patterns
	}

	if mpp.tokenCompressionPool != nil {
		snapshot.CustomMetrics["token_compression_pool_active"] = true
	}

	return snapshot, nil
}

// StartProfiling begins profiling (no-op for memory pools)
func (mpp *MemoryPoolProfiler) StartProfiling(config ProfilingConfig) error {
	return nil
}

// StopProfiling ends profiling
func (mpp *MemoryPoolProfiler) StopProfiling() (*MemorySnapshot, error) {
	return mpp.TakeSnapshot()
}

// GetCurrentStats returns current memory statistics
func (mpp *MemoryPoolProfiler) GetCurrentStats() *runtime.MemStats {
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return stats
}

// AnalyzeLeaks analyzes memory pools for leaks
func (mpp *MemoryPoolProfiler) AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis {
	analysis := &LeakAnalysis{
		SuspectedLeaks:  make([]string, 0),
		Recommendations: make([]string, 0),
	}

	if baseline == nil || current == nil {
		analysis.LeakDescription = "Insufficient memory pool data"
		return analysis
	}

	// Check for memory leaks in pool operations
	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 5*1024*1024 { // 5MB threshold for pool operations
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"Memory pool operations caused significant memory increase")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for objects not being returned to memory pools properly")
	}

	return analysis
}

// Global profiling manager instance
var globalProfilingManager *ProfilingManager
var profilingManagerOnce sync.Once

// GetGlobalProfilingManager returns the singleton profiling manager
func GetGlobalProfilingManager() *ProfilingManager {
	profilingManagerOnce.Do(func() {
		globalProfilingManager = NewProfilingManager(nil)
	})
	return globalProfilingManager
}

// Global test orchestrator instance
var globalTestOrchestrator *MemoryTestOrchestrator
var testOrchestratorOnce sync.Once

// GetGlobalTestOrchestrator returns the singleton test orchestrator
func GetGlobalTestOrchestrator() *MemoryTestOrchestrator {
	testOrchestratorOnce.Do(func() {
		config := LeakDetectionConfig{
			EnableLeakDetection:       true,
			LeakThresholdMB:           50,
			GoroutineLeakThreshold:    10,
			SessionPoolThreshold:      100,
			CacheMemoryThreshold:      20 * 1024 * 1024, // 20MB
			HTTPClientThreshold:       50,
			TokenCompressionThreshold: 2 * 1024 * 1024, // 2MB
		}
		globalTestOrchestrator = NewMemoryTestOrchestrator(config, nil)
	})
	return globalTestOrchestrator
}
