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
	// Go runtime memory stats
	HeapAllocBytes    uint64    // bytes allocated and still in use
	HeapSysBytes      uint64    // bytes obtained from system
	HeapIdleBytes     uint64    // bytes in idle (unused) spans
	HeapInuseBytes    uint64    // bytes in in-use spans
	HeapReleasedBytes uint64    // bytes released to the OS
	HeapObjects       uint64    // total number of allocated objects
	StackInuseBytes   uint64    // bytes in stack spans
	StackSysBytes     uint64    // bytes obtained from system for stack
	GCSysBytes        uint64    // bytes used for garbage collection system metadata
	NumGoroutines     int       // number of goroutines that currently exist
	LastGCTime        time.Time // time of last garbage collection

	// Application-specific memory tracking
	SessionCount    int   // current number of sessions
	TaskCount       int   // current number of background tasks
	CacheSize       int64 // estimated cache memory usage
	ConnectionPools int   // number of HTTP connection pools

	// Memory pressure indicators
	MemoryPressure MemoryPressureLevel // overall memory pressure level
	GCFrequency    float64             // garbage collections per minute

	Timestamp time.Time
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

// MemoryMonitor provides comprehensive memory monitoring and alerting
type MemoryMonitor struct {
	logger          *Logger
	mu              sync.RWMutex
	lastStats       *MemoryStats
	lastGCCount     uint32
	lastGCTime      time.Time
	startTime       time.Time
	alertThresholds MemoryAlertThresholds

	// Memory leak detection
	baselineHeap     uint64
	heapGrowthRate   float64 // bytes per second
	suspiciousGrowth bool

	// Goroutine tracking
	baselineGoroutines int
	maxGoroutines      int64
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

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(logger *Logger, thresholds MemoryAlertThresholds) *MemoryMonitor {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &MemoryMonitor{
		logger:             logger,
		startTime:          time.Now(),
		alertThresholds:    thresholds,
		baselineHeap:       memStats.HeapAlloc,
		baselineGoroutines: runtime.NumGoroutine(),
		// #nosec G115 -- LastGC nanoseconds fits in int64 for centuries
		lastGCTime:  time.Unix(0, int64(memStats.LastGC)),
		lastGCCount: memStats.NumGC,
	}
}

// GetCurrentStats collects current memory statistics
func (mm *MemoryMonitor) GetCurrentStats() *MemoryStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	now := time.Now()

	// Calculate GC frequency
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
	mm.lastStats = stats
	mm.lastGCCount = memStats.NumGC
	mm.mu.Unlock()

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
	if stats.NumGoroutines > mm.baselineGoroutines+int(mm.alertThresholds.GoroutineCount) {
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

// StartMonitoring starts continuous memory monitoring as a global singleton
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
		interval = 30 * time.Second
	}

	registry := GetGlobalTaskRegistry()

	task, err := registry.CreateSingletonTask(
		"memory-monitor",
		interval,
		func() {
			stats := mm.GetCurrentStats()
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

// TriggerGC forces garbage collection and logs the impact
func (mm *MemoryMonitor) TriggerGC() {
	before := mm.GetCurrentStats()

	runtime.GC()
	runtime.GC() // Run twice to ensure full collection

	after := mm.GetCurrentStats()

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
