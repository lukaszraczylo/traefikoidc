package traefikoidc

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryStats holds comprehensive memory statistics
type MemoryStats struct {
	LastGCTime        time.Time
	Timestamp         time.Time
	GCSysBytes        uint64
	NumGoroutines     int
	HeapReleasedBytes uint64
	HeapObjects       uint64
	StackInuseBytes   uint64
	StackSysBytes     uint64
	HeapAllocBytes    uint64
	HeapInuseBytes    uint64
	HeapIdleBytes     uint64
	SessionCount      int
	TaskCount         int
	CacheSize         int64
	ConnectionPools   int
	MemoryPressure    MemoryPressureLevel
	GCFrequency       float64
	HeapSysBytes      uint64
}

// MemoryPressureLevel indicates the current memory pressure
type MemoryPressureLevel int

const (
	MemoryPressureNone MemoryPressureLevel = iota
	MemoryPressureLow
	MemoryPressureModerate
	MemoryPressureHigh
	MemoryPressureCritical
)

func (mpl MemoryPressureLevel) String() string {
	switch mpl {
	case MemoryPressureNone:
		return "None"
	case MemoryPressureLow:
		return "Low"
	case MemoryPressureModerate:
		return "Moderate"
	case MemoryPressureHigh:
		return "High"
	case MemoryPressureCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// MemoryMonitor provides comprehensive memory monitoring and alerting.
//
// Memory sampling is expensive: runtime.ReadMemStats is a stop-the-world
// operation. To keep latency predictable the monitor caches the most recent
// sample and only refreshes it when the background ticker fires, when TriggerGC
// is invoked, or when a caller explicitly calls Refresh(). GetCurrentStats is a
// cheap read of that cached sample.
type MemoryMonitor struct {
	lastGCTime         time.Time
	startTime          time.Time
	lastStats          *MemoryStats
	cachedMemStats     runtime.MemStats
	logger             *Logger
	alertThresholds    MemoryAlertThresholds
	config             MemoryMonitorConfig
	baselineGoroutines int
	baselineHeap       uint64
	heapGrowthRate     float64
	maxGoroutines      int64
	mu                 sync.RWMutex
	lastGCCount        uint32
	suspiciousGrowth   bool
	goroutineLeakAlert bool
}

// MemoryAlertThresholds defines when to trigger memory alerts
type MemoryAlertThresholds struct {
	HeapSizeMB          uint64  // Alert when heap exceeds this size in MB
	HeapGrowthRateMB    float64 // Alert when heap grows faster than this MB/sec
	GoroutineCount      int     // Alert when goroutine count exceeds this
	GoroutineGrowthRate float64 // Alert when goroutines grow faster than this per minute
	GCFrequency         float64 // Alert when GC frequency exceeds this per minute
}

// MemoryMonitorConfig configures the memory monitor's scheduling behavior.
// Thresholds are kept separate in MemoryAlertThresholds.
type MemoryMonitorConfig struct {
	// Interval between background samples. Must be >= MinMemoryMonitorInterval
	// (30s). Values below the minimum are clamped when monitoring starts.
	Interval time.Duration
}

// Default and minimum interval values. The minimum exists because
// runtime.ReadMemStats is stop-the-world and hammering it on a hot loop causes
// noticeable latency spikes, especially under yaegi.
const (
	DefaultMemoryMonitorInterval = 60 * time.Second
	MinMemoryMonitorInterval     = 30 * time.Second
)

// DefaultMemoryMonitorConfig returns a config with sensible production
// defaults.
func DefaultMemoryMonitorConfig() MemoryMonitorConfig {
	return MemoryMonitorConfig{
		Interval: DefaultMemoryMonitorInterval,
	}
}

// DefaultMemoryAlertThresholds returns sensible default alert thresholds
func DefaultMemoryAlertThresholds() MemoryAlertThresholds {
	return MemoryAlertThresholds{
		HeapSizeMB:          256,  // 256MB heap size
		HeapGrowthRateMB:    10.0, // 10MB/sec heap growth
		GoroutineCount:      1000, // 1000 goroutines
		GoroutineGrowthRate: 10.0, // 10 goroutines/minute growth
		GCFrequency:         30.0, // 30 GCs/minute
	}
}

// NewMemoryMonitor creates a new memory monitor using default scheduling
// configuration. See NewMemoryMonitorWithConfig for full control.
func NewMemoryMonitor(logger *Logger, thresholds MemoryAlertThresholds) *MemoryMonitor {
	return NewMemoryMonitorWithConfig(logger, thresholds, DefaultMemoryMonitorConfig())
}

// NewMemoryMonitorWithConfig creates a new memory monitor with an explicit
// scheduling config.
//
// NOTE: the constructor performs a single runtime.ReadMemStats call to capture
// baseline heap / goroutine / GC counters used for leak and growth detection.
// This is a one-time stop-the-world cost at startup; all subsequent samples
// only happen on the monitoring ticker or on explicit Refresh() calls.
func NewMemoryMonitorWithConfig(logger *Logger, thresholds MemoryAlertThresholds, config MemoryMonitorConfig) *MemoryMonitor {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	if config.Interval <= 0 {
		config.Interval = DefaultMemoryMonitorInterval
	}

	// One-time initial sample to seed baselines used for growth / leak
	// detection. All subsequent sampling is gated by the monitoring ticker or
	// explicit Refresh() calls.
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	mm := &MemoryMonitor{
		logger:             logger,
		startTime:          time.Now(),
		alertThresholds:    thresholds,
		config:             config,
		baselineHeap:       memStats.HeapAlloc,
		baselineGoroutines: runtime.NumGoroutine(),
		// #nosec G115 -- LastGC nanoseconds fits in int64 for centuries
		lastGCTime:  time.Unix(0, int64(memStats.LastGC)),
		lastGCCount: memStats.NumGC,
	}
	mm.cachedMemStats = memStats
	return mm
}

// GetCurrentStats returns the most recently sampled memory statistics.
//
// This is a cheap cached read: it does NOT call runtime.ReadMemStats. Samples
// are refreshed only by the monitoring ticker or by an explicit call to
// Refresh(). If no sample has been produced yet, stats derived from the
// constructor-time raw sample are returned (with no additional STW cost).
func (mm *MemoryMonitor) GetCurrentStats() *MemoryStats {
	mm.mu.RLock()
	stats := mm.lastStats
	mm.mu.RUnlock()
	if stats != nil {
		return stats
	}
	return mm.buildStatsFromCache()
}

// Refresh synchronously samples current memory statistics via
// runtime.ReadMemStats and updates the cached value. This is the only path
// (other than the monitoring ticker and TriggerGC) that pays the stop-the-world
// cost. Use it in tests or in callers that explicitly need a fresh sample.
func (mm *MemoryMonitor) Refresh() *MemoryStats {
	return mm.sample()
}

// sample performs a stop-the-world ReadMemStats, updates the cached raw stats,
// computes a derived MemoryStats snapshot, and stores it as lastStats.
func (mm *MemoryMonitor) sample() *MemoryStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	now := time.Now()

	// Calculate GC frequency relative to the previous snapshot.
	gcFrequency := 0.0
	mm.mu.RLock()
	lastStats := mm.lastStats
	lastGCCount := mm.lastGCCount
	mm.mu.RUnlock()

	if lastStats != nil {
		timeDiff := now.Sub(lastStats.Timestamp).Minutes()
		if timeDiff > 0 {
			gcDiff := float64(memStats.NumGC - lastGCCount)
			gcFrequency = gcDiff / timeDiff
		}
	}

	stats := &MemoryStats{
		HeapAllocBytes:    memStats.HeapAlloc,
		HeapSysBytes:      memStats.HeapSys,
		HeapIdleBytes:     memStats.HeapIdle,
		HeapInuseBytes:    memStats.HeapInuse,
		HeapReleasedBytes: memStats.HeapReleased,
		HeapObjects:       memStats.HeapObjects,
		StackInuseBytes:   memStats.StackInuse,
		StackSysBytes:     memStats.StackSys,
		GCSysBytes:        memStats.GCSys,
		NumGoroutines:     runtime.NumGoroutine(),
		// #nosec G115 -- LastGC nanoseconds fits in int64 for centuries
		LastGCTime:  time.Unix(0, int64(memStats.LastGC)),
		GCFrequency: gcFrequency,
		Timestamp:   now,
	}

	// Get application-specific stats
	mm.collectApplicationStats(stats)

	// Calculate memory pressure
	stats.MemoryPressure = mm.calculateMemoryPressure(stats)

	// Update goroutine tracking
	mm.updateGoroutineTracking(stats)

	// Update heap growth tracking
	mm.updateHeapGrowthTracking(stats)

	mm.mu.Lock()
	mm.cachedMemStats = memStats
	mm.lastStats = stats
	mm.lastGCCount = memStats.NumGC
	mm.mu.Unlock()

	return stats
}

// buildStatsFromCache constructs a MemoryStats snapshot from the cached raw
// runtime.MemStats without issuing a new ReadMemStats call. Used as a fallback
// when GetCurrentStats is called before the first sample() has completed.
func (mm *MemoryMonitor) buildStatsFromCache() *MemoryStats {
	mm.mu.RLock()
	memStats := mm.cachedMemStats
	mm.mu.RUnlock()

	stats := &MemoryStats{
		HeapAllocBytes:    memStats.HeapAlloc,
		HeapSysBytes:      memStats.HeapSys,
		HeapIdleBytes:     memStats.HeapIdle,
		HeapInuseBytes:    memStats.HeapInuse,
		HeapReleasedBytes: memStats.HeapReleased,
		HeapObjects:       memStats.HeapObjects,
		StackInuseBytes:   memStats.StackInuse,
		StackSysBytes:     memStats.StackSys,
		GCSysBytes:        memStats.GCSys,
		NumGoroutines:     runtime.NumGoroutine(),
		// #nosec G115 -- LastGC nanoseconds fits in int64 for centuries
		LastGCTime:  time.Unix(0, int64(memStats.LastGC)),
		GCFrequency: 0.0,
		Timestamp:   time.Now(),
	}
	mm.collectApplicationStats(stats)
	stats.MemoryPressure = mm.calculateMemoryPressure(stats)
	return stats
}

// collectApplicationStats gathers application-specific memory stats
func (mm *MemoryMonitor) collectApplicationStats(stats *MemoryStats) {
	// Get session count from ChunkManager if available
	// This is a placeholder - real implementation would access actual managers
	stats.SessionCount = 0 // Would be populated from actual session manager

	// Get background task count from TaskRegistry
	registry := GetGlobalTaskRegistry()
	stats.TaskCount = registry.GetTaskCount()

	// Estimate cache size
	stats.CacheSize = 0 // Would be populated from actual cache implementations

	// Count HTTP connection pools
	stats.ConnectionPools = 1 // Would be counted from actual HTTP clients
}

// calculateMemoryPressure determines the current memory pressure level
func (mm *MemoryMonitor) calculateMemoryPressure(stats *MemoryStats) MemoryPressureLevel {
	heapMB := float64(stats.HeapAllocBytes) / (1024 * 1024)

	// Critical: Heap > 512MB or very frequent GC
	if heapMB > 512 || stats.GCFrequency > 60 {
		return MemoryPressureCritical
	}

	// High: Heap > 256MB or frequent GC
	if heapMB > 256 || stats.GCFrequency > 30 {
		return MemoryPressureHigh
	}

	// Moderate: Heap > 128MB or elevated GC
	if heapMB > 128 || stats.GCFrequency > 15 {
		return MemoryPressureModerate
	}

	// Low: Heap > 64MB or some GC activity
	if heapMB > 64 || stats.GCFrequency > 5 {
		return MemoryPressureLow
	}

	return MemoryPressureNone
}

// updateGoroutineTracking monitors goroutine counts for leaks
func (mm *MemoryMonitor) updateGoroutineTracking(stats *MemoryStats) {
	currentCount := int64(stats.NumGoroutines)

	// Update max goroutines
	if currentCount > atomic.LoadInt64(&mm.maxGoroutines) {
		atomic.StoreInt64(&mm.maxGoroutines, currentCount)
	}

	// Check for potential goroutine leak
	if stats.NumGoroutines > mm.baselineGoroutines+mm.alertThresholds.GoroutineCount {
		mm.mu.Lock()
		wasAlert := mm.goroutineLeakAlert
		if !wasAlert {
			mm.goroutineLeakAlert = true
		}
		mm.mu.Unlock()
		if !wasAlert {
			mm.logger.Error("Potential goroutine leak detected: %d goroutines (baseline: %d)",
				stats.NumGoroutines, mm.baselineGoroutines)
		}
	} else {
		mm.mu.Lock()
		mm.goroutineLeakAlert = false
		mm.mu.Unlock()
	}
}

// updateHeapGrowthTracking monitors heap growth rate
func (mm *MemoryMonitor) updateHeapGrowthTracking(stats *MemoryStats) {
	mm.mu.RLock()
	lastStats := mm.lastStats
	mm.mu.RUnlock()

	if lastStats != nil {
		timeDiff := stats.Timestamp.Sub(lastStats.Timestamp).Seconds()
		if timeDiff > 0 {
			heapDiff := float64(stats.HeapAllocBytes) - float64(lastStats.HeapAllocBytes)
			heapGrowthRate := heapDiff / timeDiff // bytes per second

			mm.mu.Lock()
			mm.heapGrowthRate = heapGrowthRate
			mm.mu.Unlock()

			growthRateMB := heapGrowthRate / (1024 * 1024)
			if growthRateMB > mm.alertThresholds.HeapGrowthRateMB {
				mm.mu.Lock()
				wasSuspicious := mm.suspiciousGrowth
				if !wasSuspicious {
					mm.suspiciousGrowth = true
				}
				mm.mu.Unlock()
				if !wasSuspicious {
					mm.logger.Error("Suspicious heap growth rate: %.2f MB/sec", growthRateMB)
				}
			} else {
				mm.mu.Lock()
				mm.suspiciousGrowth = false
				mm.mu.Unlock()
			}
		}
	}
}

// LogMemoryStats logs comprehensive memory statistics
func (mm *MemoryMonitor) LogMemoryStats(stats *MemoryStats) {
	heapMB := float64(stats.HeapAllocBytes) / (1024 * 1024)
	sysMB := float64(stats.HeapSysBytes) / (1024 * 1024)

	mm.logger.Info("Memory Stats - Heap: %.1fMB/%.1fMB, Goroutines: %d, Pressure: %s, GC: %.1f/min",
		heapMB, sysMB, stats.NumGoroutines, stats.MemoryPressure.String(), stats.GCFrequency)

	// Log additional details at debug level
	mm.logger.Debug("Memory Details - Sessions: %d, Tasks: %d, Cache: %dB, Pools: %d",
		stats.SessionCount, stats.TaskCount, stats.CacheSize, stats.ConnectionPools)
}

// Global monitoring state
var (
	globalMonitoringStarted bool
	globalMonitoringMutex   sync.Mutex
)

// StartMonitoring starts continuous memory monitoring as a global singleton.
//
// The effective interval is resolved as follows:
//  1. If the caller passes a positive interval, that is used.
//  2. Otherwise the configured MemoryMonitorConfig.Interval is used.
//  3. Otherwise the built-in default (60s) is used.
//
// The result is then clamped to a minimum of MinMemoryMonitorInterval (30s) to
// avoid stop-the-world ReadMemStats storms. Callers that need rapid updates in
// tests should call Refresh() directly instead of spinning the ticker fast.
func (mm *MemoryMonitor) StartMonitoring(ctx context.Context, interval time.Duration) {
	globalMonitoringMutex.Lock()
	defer globalMonitoringMutex.Unlock()

	// Check if monitoring is already started
	if globalMonitoringStarted {
		if !isTestMode() {
			mm.logger.Debug("Memory monitoring already started, skipping duplicate start")
		}
		return
	}

	if interval <= 0 {
		interval = mm.config.Interval
	}
	if interval <= 0 {
		interval = DefaultMemoryMonitorInterval
	}
	if interval < MinMemoryMonitorInterval {
		if !isTestMode() {
			mm.logger.Debug("Memory monitor interval %v is below minimum %v; clamping",
				interval, MinMemoryMonitorInterval)
		}
		interval = MinMemoryMonitorInterval
	}

	registry := GetGlobalTaskRegistry()

	task, err := registry.CreateSingletonTask(
		"memory-monitor",
		interval,
		func() {
			stats := mm.sample()
			mm.LogMemoryStats(stats)
			mm.checkAlerts(stats)
		},
		mm.logger,
		nil,
	)

	if err != nil {
		mm.logger.Errorf("Failed to create memory monitoring task: %v", err)
		return
	}

	// Only start if task was newly created or we're sure it's not already running
	task.Start()
	globalMonitoringStarted = true

	if !isTestMode() {
		mm.logger.Info("Started global memory monitoring with %v interval", interval)
	}
}

// checkAlerts checks for memory-related alerts
func (mm *MemoryMonitor) checkAlerts(stats *MemoryStats) {
	heapMB := float64(stats.HeapAllocBytes) / (1024 * 1024)

	// Heap size alert
	if heapMB > float64(mm.alertThresholds.HeapSizeMB) {
		mm.logger.Error("Memory Alert: Heap size %.1fMB exceeds threshold %dMB",
			heapMB, mm.alertThresholds.HeapSizeMB)
	}

	// GC frequency alert
	if stats.GCFrequency > mm.alertThresholds.GCFrequency {
		mm.logger.Error("Memory Alert: GC frequency %.1f/min exceeds threshold %.1f/min",
			stats.GCFrequency, mm.alertThresholds.GCFrequency)
	}

	// Critical memory pressure
	if stats.MemoryPressure >= MemoryPressureHigh {
		mm.logger.Error("Memory Alert: %s memory pressure detected", stats.MemoryPressure.String())
	}
}

// TriggerGC forces garbage collection and logs the impact. Both the before and
// after measurements are fresh samples (explicit Refresh() calls) because the
// comparison is meaningless against a stale cached snapshot.
func (mm *MemoryMonitor) TriggerGC() {
	before := mm.Refresh()

	runtime.GC()
	runtime.GC() // Run twice to ensure full collection

	after := mm.Refresh()

	// #nosec G115 -- heap allocation bytes fit in int64 for practical purposes
	freedBytes := int64(before.HeapAllocBytes) - int64(after.HeapAllocBytes)
	freedMB := float64(freedBytes) / (1024 * 1024)

	mm.logger.Info("Manual GC completed - Freed: %.1fMB, Before: %.1fMB, After: %.1fMB",
		freedMB,
		float64(before.HeapAllocBytes)/(1024*1024),
		float64(after.HeapAllocBytes)/(1024*1024))
}

// GetMemoryPressure returns the current memory pressure level
func (mm *MemoryMonitor) GetMemoryPressure() MemoryPressureLevel {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if mm.lastStats != nil {
		return mm.lastStats.MemoryPressure
	}
	return MemoryPressureNone
}

// StopMonitoring stops the global memory monitoring if it's running
func (mm *MemoryMonitor) StopMonitoring() {
	globalMonitoringMutex.Lock()
	defer globalMonitoringMutex.Unlock()

	if !globalMonitoringStarted {
		return
	}

	registry := GetGlobalTaskRegistry()
	if task, exists := registry.GetTask("memory-monitor"); exists {
		task.Stop()
		globalMonitoringStarted = false
		if !isTestMode() {
			mm.logger.Info("Stopped global memory monitoring")
		}
	} else {
		mm.logger.Errorf("Failed to find memory monitoring task to stop")
	}
}

// IsMonitoringActive returns true if global memory monitoring is currently active
func (mm *MemoryMonitor) IsMonitoringActive() bool {
	globalMonitoringMutex.Lock()
	defer globalMonitoringMutex.Unlock()
	return globalMonitoringStarted
}

// Global memory monitor instance
var (
	globalMemoryMonitor     *MemoryMonitor
	globalMemoryMonitorOnce sync.Once
)

// GetGlobalMemoryMonitor returns the singleton memory monitor
func GetGlobalMemoryMonitor() *MemoryMonitor {
	globalMemoryMonitorOnce.Do(func() {
		logger := GetSingletonNoOpLogger()
		thresholds := DefaultMemoryAlertThresholds()
		globalMemoryMonitor = NewMemoryMonitor(logger, thresholds)
	})
	return globalMemoryMonitor
}

// ResetGlobalMemoryMonitor resets the global memory monitor for testing
// This should only be used in tests to prevent state pollution between tests
func ResetGlobalMemoryMonitor() {
	globalMonitoringMutex.Lock()
	defer globalMonitoringMutex.Unlock()

	if globalMemoryMonitor != nil {
		// Stop monitoring if it's active
		if globalMonitoringStarted {
			registry := GetGlobalTaskRegistry()
			if task, exists := registry.GetTask("memory-monitor"); exists {
				task.Stop()
			}
		}
		globalMemoryMonitor = nil
	}

	// Reset the singleton state
	globalMemoryMonitorOnce = sync.Once{}
	globalMonitoringStarted = false
}
