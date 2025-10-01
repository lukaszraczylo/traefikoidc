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

// MemoryProfiler defines the interface for memory profiling operations.
// Implementations provide memory monitoring, leak detection, and performance analysis
// capabilities for debugging and optimizing memory usage in production environments.
type MemoryProfiler interface {
	// TakeSnapshot captures current memory state for analysis
	TakeSnapshot() (*MemorySnapshot, error)
	// StartProfiling begins continuous memory monitoring
	StartProfiling(config ProfilingConfig) error
	// StopProfiling ends monitoring and returns final snapshot
	StopProfiling() (*MemorySnapshot, error)
	// GetCurrentStats returns current runtime memory statistics
	GetCurrentStats() *runtime.MemStats
	// AnalyzeLeaks compares snapshots to detect memory leaks
	AnalyzeLeaks(baseline, current *MemorySnapshot) *LeakAnalysis
}

// MemorySnapshot represents a point-in-time capture of memory statistics.
// It provides comprehensive memory profiling data including heap, goroutines,
// and custom metrics for detailed memory usage analysis.
type MemorySnapshot struct {
	Timestamp        time.Time
	CustomMetrics    map[string]interface{}
	HeapProfile      []byte
	GoroutineProfile []byte
	RuntimeStats     runtime.MemStats
}

// LeakAnalysis contains the results of memory leak detection and analysis.
// Provides actionable insights about potential memory leaks and recommendations
// for addressing identified issues.
type LeakAnalysis struct {
	LeakDescription   string
	SuspectedLeaks    []string
	Recommendations   []string
	MemoryIncrease    uint64
	GoroutineIncrease int
	HasLeak           bool
}

// ProfilingManager coordinates memory profiling operations across the application.
// It manages multiple profiler instances, handles configuration, and provides
// centralized access to memory monitoring and leak detection capabilities.
type ProfilingManager struct {
	startTime        time.Time
	baselineSnapshot *MemorySnapshot
	logger           *Logger
	profilers        map[string]MemoryProfiler
	config           ProfilingConfig
	mu               sync.RWMutex
	isProfiling      bool
}

// ProfilingConfig contains configuration parameters for profiling operations.
// Controls what types of profiling are enabled and how frequently they run.
type ProfilingConfig struct {
	SnapshotInterval           time.Duration
	LeakThresholdMB            uint64
	MaxSnapshots               int
	MonitoringInterval         time.Duration
	EnableHeapProfiling        bool
	EnableGoroutineProfiling   bool
	EnableContinuousMonitoring bool
}

// LeakDetectionConfig contains configuration parameters for memory leak detection.
// Defines thresholds and limits for various types of memory leak detection.
type LeakDetectionConfig struct {
	// EnableLeakDetection enables automatic leak detection
	EnableLeakDetection bool
	// LeakThresholdMB sets general memory leak threshold in megabytes
	LeakThresholdMB uint64
	// GoroutineLeakThreshold sets limit for goroutine count increases
	GoroutineLeakThreshold int
	// SessionPoolThreshold sets limit for session pool size
	SessionPoolThreshold int
	// CacheMemoryThreshold sets limit for cache memory usage
	CacheMemoryThreshold uint64
	// HTTPClientThreshold sets limit for HTTP client connections
	HTTPClientThreshold int
	// Deprecated: TokenCompressionThreshold is no longer used
	TokenCompressionThreshold uint64
}

// NewProfilingManager creates a new profiling manager with default configuration.
// Initializes profiling with sensible defaults for production monitoring.
func NewProfilingManager(logger *Logger) *ProfilingManager {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	return &ProfilingManager{
		profilers: make(map[string]MemoryProfiler),
		config: ProfilingConfig{
			EnableHeapProfiling:        true,
			EnableGoroutineProfiling:   true,
			SnapshotInterval:           30 * time.Second,
			LeakThresholdMB:            50,
			MaxSnapshots:               100,
			EnableContinuousMonitoring: true,
			MonitoringInterval:         60 * time.Second,
		},
		logger: logger,
	}
}

// TakeSnapshot captures a comprehensive snapshot of current memory statistics.
// Includes runtime stats, heap profile, goroutine profile, and custom metrics.
func (pm *ProfilingManager) TakeSnapshot() (*MemorySnapshot, error) {
	var buf bytes.Buffer
	snapshot := &MemorySnapshot{
		Timestamp:     time.Now(),
		CustomMetrics: make(map[string]interface{}),
	}

	runtime.ReadMemStats(&snapshot.RuntimeStats)

	if pm.config.EnableHeapProfiling {
		if err := pprof.WriteHeapProfile(&buf); err != nil {
			pm.logger.Errorf("Failed to capture heap profile: %v", err)
		} else {
			snapshot.HeapProfile = make([]byte, buf.Len())
			copy(snapshot.HeapProfile, buf.Bytes())
			buf.Reset()
		}
	}

	if pm.config.EnableGoroutineProfiling {
		if err := pprof.Lookup("goroutine").WriteTo(&buf, 0); err != nil {
			pm.logger.Errorf("Failed to capture goroutine profile: %v", err)
		} else {
			snapshot.GoroutineProfile = make([]byte, buf.Len())
			copy(snapshot.GoroutineProfile, buf.Bytes())
			buf.Reset()
		}
	}

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

	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	analysis.MemoryIncrease = memoryIncrease

	currentGoroutines := runtime.NumGoroutine()
	baselineGoroutines := runtime.NumGoroutine()
	goroutineIncrease := currentGoroutines - baselineGoroutines
	analysis.GoroutineIncrease = goroutineIncrease

	memoryThreshold := pm.config.LeakThresholdMB * 1024 * 1024
	if memoryIncrease > memoryThreshold {
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			fmt.Sprintf("Memory usage increased by %.2f MB", float64(memoryIncrease)/(1024*1024)))
		analysis.Recommendations = append(analysis.Recommendations,
			"Consider checking for unreleased memory pools or growing caches")
	}

	if goroutineIncrease > 10 {
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
	profilers   map[string]MemoryProfiler
	logger      *Logger
	stopChan    chan struct{}
	testResults map[string]*LeakAnalysis
	config      LeakDetectionConfig
	mu          sync.RWMutex
	isRunning   bool
}

// NewMemoryTestOrchestrator creates a new test orchestrator
func NewMemoryTestOrchestrator(config LeakDetectionConfig, logger *Logger) *MemoryTestOrchestrator {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
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
	mto.stopChan = make(chan struct{})

	mto.logger.Infof("Memory leak detection stopped")
	return nil
}

// runLeakDetection performs continuous leak detection monitoring
func (mto *MemoryTestOrchestrator) runLeakDetection() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	baselineSnapshots := make(map[string]*MemorySnapshot)

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

// SessionPoolProfiler monitors session pool memory usage
type SessionPoolProfiler struct {
	sessionManager *SessionManager
	logger         *Logger
}

// NewSessionPoolProfiler creates a new session pool profiler
func NewSessionPoolProfiler(sm *SessionManager, logger *Logger) *SessionPoolProfiler {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
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

	runtime.ReadMemStats(&snapshot.RuntimeStats)

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

	memoryIncrease := current.RuntimeStats.Alloc - baseline.RuntimeStats.Alloc
	if memoryIncrease > 10*1024*1024 {
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
	cache  CacheInterface
	logger *Logger
}

// NewCacheMemoryProfiler creates a new cache memory profiler
func NewCacheMemoryProfiler(cache CacheInterface, logger *Logger) *CacheMemoryProfiler {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
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

	snapshot.CustomMetrics["cache_size"] = "unknown"

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
	if memoryIncrease > 20*1024*1024 {
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
		logger = GetSingletonNoOpLogger()
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
	if memoryIncrease > 5*1024*1024 {
		analysis.HasLeak = true
		analysis.SuspectedLeaks = append(analysis.SuspectedLeaks,
			"HTTP client memory usage increased significantly")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check for HTTP response bodies not being drained properly")
	}

	return analysis
}

// Deprecated profilers removed - use internal/pool statistics instead
// The centralized pool manager in internal/pool provides comprehensive
// statistics tracking that replaces these specialized profilers

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
			CacheMemoryThreshold:      20 * 1024 * 1024,
			HTTPClientThreshold:       50,
			TokenCompressionThreshold: 2 * 1024 * 1024,
		}
		globalTestOrchestrator = NewMemoryTestOrchestrator(config, nil)
	})
	return globalTestOrchestrator
}
