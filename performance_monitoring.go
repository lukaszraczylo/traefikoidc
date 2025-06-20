package traefikoidc

import (
	"maps"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// PerformanceMetrics tracks various performance-related metrics
type PerformanceMetrics struct {
	startTime               time.Time
	logger                  *Logger
	verificationTimes       []time.Duration
	refreshTimes            []time.Duration
	validationTimes         []time.Duration
	memoryUsage             int64
	heapSize                int64
	successfulVerifications int64
	successfulValidations   int64
	successfulRefreshes     int64
	failedVerifications     int64
	failedValidations       int64
	failedRefreshes         int64
	avgVerificationTime     time.Duration
	avgValidationTime       time.Duration
	avgRefreshTime          time.Duration
	cacheHits               int64
	goroutineCount          int64
	memoryPressure          int64
	gcPauseTime             int64
	tokenRefreshes          int64
	heapInUse               int64
	verificationErrors      int64
	validationErrors        int64
	refreshErrors           int64
	rateLimitedRequests     int64
	activeSessions          int64
	sessionCreations        int64
	sessionDeletions        int64
	cacheMisses             int64
	tokenValidations        int64
	tokenVerifications      int64
	cacheSize               int64
	cacheEvictions          int64
	timingMutex             sync.RWMutex
}

// NewPerformanceMetrics creates a new performance metrics tracker
func NewPerformanceMetrics(logger *Logger) *PerformanceMetrics {
	pm := &PerformanceMetrics{
		startTime:         time.Now(),
		verificationTimes: make([]time.Duration, 0, 1000), // Keep last 1000 measurements
		validationTimes:   make([]time.Duration, 0, 1000),
		refreshTimes:      make([]time.Duration, 0, 1000),
		logger:            logger,
	}

	// Start background metrics collection
	go pm.startMetricsCollection()

	return pm
}

// RecordCacheHit records a cache hit
func (pm *PerformanceMetrics) RecordCacheHit() {
	atomic.AddInt64(&pm.cacheHits, 1)
}

// RecordCacheMiss records a cache miss
func (pm *PerformanceMetrics) RecordCacheMiss() {
	atomic.AddInt64(&pm.cacheMisses, 1)
}

// RecordCacheEviction records a cache eviction
func (pm *PerformanceMetrics) RecordCacheEviction() {
	atomic.AddInt64(&pm.cacheEvictions, 1)
}

// UpdateCacheSize updates the current cache size
func (pm *PerformanceMetrics) UpdateCacheSize(size int64) {
	atomic.StoreInt64(&pm.cacheSize, size)
}

// RecordTokenVerification records a token verification operation
func (pm *PerformanceMetrics) RecordTokenVerification(duration time.Duration, success bool) {
	atomic.AddInt64(&pm.tokenVerifications, 1)

	if success {
		atomic.AddInt64(&pm.successfulVerifications, 1)
		pm.addVerificationTime(duration)
	} else {
		atomic.AddInt64(&pm.failedVerifications, 1)
		atomic.AddInt64(&pm.verificationErrors, 1)
	}
}

// RecordTokenValidation records a token validation operation
func (pm *PerformanceMetrics) RecordTokenValidation(duration time.Duration, success bool) {
	atomic.AddInt64(&pm.tokenValidations, 1)

	if success {
		atomic.AddInt64(&pm.successfulValidations, 1)
		pm.addValidationTime(duration)
	} else {
		atomic.AddInt64(&pm.failedValidations, 1)
		atomic.AddInt64(&pm.validationErrors, 1)
	}
}

// RecordTokenRefresh records a token refresh operation
func (pm *PerformanceMetrics) RecordTokenRefresh(duration time.Duration, success bool) {
	atomic.AddInt64(&pm.tokenRefreshes, 1)

	if success {
		atomic.AddInt64(&pm.successfulRefreshes, 1)
		pm.addRefreshTime(duration)
	} else {
		atomic.AddInt64(&pm.failedRefreshes, 1)
		atomic.AddInt64(&pm.refreshErrors, 1)
	}
}

// RecordRateLimitedRequest records a rate-limited request
func (pm *PerformanceMetrics) RecordRateLimitedRequest() {
	atomic.AddInt64(&pm.rateLimitedRequests, 1)
}

// RecordSessionCreation records a session creation
func (pm *PerformanceMetrics) RecordSessionCreation() {
	atomic.AddInt64(&pm.sessionCreations, 1)
	atomic.AddInt64(&pm.activeSessions, 1)
}

// RecordSessionDeletion records a session deletion
func (pm *PerformanceMetrics) RecordSessionDeletion() {
	atomic.AddInt64(&pm.sessionDeletions, 1)
	atomic.AddInt64(&pm.activeSessions, -1)
}

// addVerificationTime adds a verification time measurement
func (pm *PerformanceMetrics) addVerificationTime(duration time.Duration) {
	pm.timingMutex.Lock()
	defer pm.timingMutex.Unlock()

	pm.verificationTimes = append(pm.verificationTimes, duration)
	if len(pm.verificationTimes) > 1000 {
		pm.verificationTimes = pm.verificationTimes[1:]
	}

	pm.updateAverageVerificationTime()
}

// addValidationTime adds a validation time measurement
func (pm *PerformanceMetrics) addValidationTime(duration time.Duration) {
	pm.timingMutex.Lock()
	defer pm.timingMutex.Unlock()

	pm.validationTimes = append(pm.validationTimes, duration)
	if len(pm.validationTimes) > 1000 {
		pm.validationTimes = pm.validationTimes[1:]
	}

	pm.updateAverageValidationTime()
}

// addRefreshTime adds a refresh time measurement
func (pm *PerformanceMetrics) addRefreshTime(duration time.Duration) {
	pm.timingMutex.Lock()
	defer pm.timingMutex.Unlock()

	pm.refreshTimes = append(pm.refreshTimes, duration)
	if len(pm.refreshTimes) > 1000 {
		pm.refreshTimes = pm.refreshTimes[1:]
	}

	pm.updateAverageRefreshTime()
}

// updateAverageVerificationTime calculates the average verification time
func (pm *PerformanceMetrics) updateAverageVerificationTime() {
	if len(pm.verificationTimes) == 0 {
		pm.avgVerificationTime = 0
		return
	}

	var total time.Duration
	for _, t := range pm.verificationTimes {
		total += t
	}
	pm.avgVerificationTime = total / time.Duration(len(pm.verificationTimes))
}

// updateAverageValidationTime calculates the average validation time
func (pm *PerformanceMetrics) updateAverageValidationTime() {
	if len(pm.validationTimes) == 0 {
		pm.avgValidationTime = 0
		return
	}

	var total time.Duration
	for _, t := range pm.validationTimes {
		total += t
	}
	pm.avgValidationTime = total / time.Duration(len(pm.validationTimes))
}

// updateAverageRefreshTime calculates the average refresh time
func (pm *PerformanceMetrics) updateAverageRefreshTime() {
	if len(pm.refreshTimes) == 0 {
		pm.avgRefreshTime = 0
		return
	}

	var total time.Duration
	for _, t := range pm.refreshTimes {
		total += t
	}
	pm.avgRefreshTime = total / time.Duration(len(pm.refreshTimes))
}

// startMetricsCollection starts background collection of system metrics
func (pm *PerformanceMetrics) startMetricsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pm.collectSystemMetrics()
	}
}

// collectSystemMetrics collects system-level metrics
func (pm *PerformanceMetrics) collectSystemMetrics() {
	// Memory statistics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	atomic.StoreInt64(&pm.memoryUsage, int64(m.Alloc))
	atomic.StoreInt64(&pm.heapSize, int64(m.HeapSys))
	atomic.StoreInt64(&pm.heapInUse, int64(m.HeapInuse))
	atomic.StoreInt64(&pm.gcPauseTime, int64(m.PauseNs[(m.NumGC+255)%256]))

	// Calculate memory pressure (0-100 scale)
	// Based on heap utilization and GC frequency
	heapUtilization := float64(m.HeapInuse) / float64(m.HeapSys)
	gcFrequency := float64(m.NumGC) / time.Since(pm.startTime).Minutes()

	// Memory pressure calculation
	pressure := int64(heapUtilization * 50) // 0-50 based on heap utilization
	if gcFrequency > 10 {                   // High GC frequency indicates pressure
		pressure += int64((gcFrequency - 10) * 2) // Add up to 50 more
	}
	if pressure > 100 {
		pressure = 100
	}
	atomic.StoreInt64(&pm.memoryPressure, pressure)

	// Goroutine count
	atomic.StoreInt64(&pm.goroutineCount, int64(runtime.NumGoroutine()))

	// Log memory pressure warnings
	if pressure > 80 {
		pm.logger.Errorf("High memory pressure detected: %d%% (heap utilization: %.1f%%, GC frequency: %.1f/min)",
			pressure, heapUtilization*100, gcFrequency)
	} else if pressure > 60 {
		pm.logger.Infof("Moderate memory pressure: %d%% (heap utilization: %.1f%%, GC frequency: %.1f/min)",
			pressure, heapUtilization*100, gcFrequency)
	}
}

// GetMetrics returns all current performance metrics
func (pm *PerformanceMetrics) GetMetrics() map[string]any {
	pm.timingMutex.RLock()
	defer pm.timingMutex.RUnlock()

	// Calculate cache hit ratio
	hits := atomic.LoadInt64(&pm.cacheHits)
	misses := atomic.LoadInt64(&pm.cacheMisses)
	var hitRatio float64
	if hits+misses > 0 {
		hitRatio = float64(hits) / float64(hits+misses)
	}

	// Calculate error rates
	verifications := atomic.LoadInt64(&pm.tokenVerifications)
	validations := atomic.LoadInt64(&pm.tokenValidations)
	refreshes := atomic.LoadInt64(&pm.tokenRefreshes)

	var verificationErrorRate, validationErrorRate, refreshErrorRate float64

	if verifications > 0 {
		verificationErrorRate = float64(atomic.LoadInt64(&pm.verificationErrors)) / float64(verifications)
	}
	if validations > 0 {
		validationErrorRate = float64(atomic.LoadInt64(&pm.validationErrors)) / float64(validations)
	}
	if refreshes > 0 {
		refreshErrorRate = float64(atomic.LoadInt64(&pm.refreshErrors)) / float64(refreshes)
	}

	return map[string]any{
		// Cache metrics
		"cache_hits":      hits,
		"cache_misses":    misses,
		"cache_hit_ratio": hitRatio,
		"cache_evictions": atomic.LoadInt64(&pm.cacheEvictions),
		"cache_size":      atomic.LoadInt64(&pm.cacheSize),

		// Token operation metrics
		"token_verifications":     verifications,
		"token_validations":       validations,
		"token_refreshes":         refreshes,
		"verification_error_rate": verificationErrorRate,
		"validation_error_rate":   validationErrorRate,
		"refresh_error_rate":      refreshErrorRate,

		// Success/failure metrics
		"successful_verifications": atomic.LoadInt64(&pm.successfulVerifications),
		"successful_validations":   atomic.LoadInt64(&pm.successfulValidations),
		"successful_refreshes":     atomic.LoadInt64(&pm.successfulRefreshes),
		"failed_verifications":     atomic.LoadInt64(&pm.failedVerifications),
		"failed_validations":       atomic.LoadInt64(&pm.failedValidations),
		"failed_refreshes":         atomic.LoadInt64(&pm.failedRefreshes),

		// Timing metrics
		"avg_verification_time_ms": pm.avgVerificationTime.Milliseconds(),
		"avg_validation_time_ms":   pm.avgValidationTime.Milliseconds(),
		"avg_refresh_time_ms":      pm.avgRefreshTime.Milliseconds(),

		// Resource metrics
		"memory_usage_bytes": atomic.LoadInt64(&pm.memoryUsage),
		"memory_pressure":    atomic.LoadInt64(&pm.memoryPressure),
		"heap_size_bytes":    atomic.LoadInt64(&pm.heapSize),
		"heap_inuse_bytes":   atomic.LoadInt64(&pm.heapInUse),
		"gc_pause_time_ns":   atomic.LoadInt64(&pm.gcPauseTime),
		"goroutine_count":    atomic.LoadInt64(&pm.goroutineCount),

		// Rate limiting metrics
		"rate_limited_requests": atomic.LoadInt64(&pm.rateLimitedRequests),

		// Session metrics
		"active_sessions":   atomic.LoadInt64(&pm.activeSessions),
		"sessions_created":  atomic.LoadInt64(&pm.sessionCreations),
		"sessions_deleted":  atomic.LoadInt64(&pm.sessionDeletions),
		"session_creations": atomic.LoadInt64(&pm.sessionCreations),
		"session_deletions": atomic.LoadInt64(&pm.sessionDeletions),

		// Uptime
		"uptime_seconds": time.Since(pm.startTime).Seconds(),
	}
}

// GetDetailedTimingMetrics returns detailed timing statistics
func (pm *PerformanceMetrics) GetDetailedTimingMetrics() map[string]any {
	pm.timingMutex.RLock()
	defer pm.timingMutex.RUnlock()

	return map[string]any{
		"verification_stats":  pm.calculateTimingStats(pm.verificationTimes),
		"verification_timing": pm.calculateTimingStats(pm.verificationTimes),
		"validation_stats":    pm.calculateTimingStats(pm.validationTimes),
		"validation_timing":   pm.calculateTimingStats(pm.validationTimes),
		"refresh_stats":       pm.calculateTimingStats(pm.refreshTimes),
		"refresh_timing":      pm.calculateTimingStats(pm.refreshTimes),
	}
}

// calculateTimingStats calculates statistical metrics for timing data
func (pm *PerformanceMetrics) calculateTimingStats(times []time.Duration) map[string]any {
	if len(times) == 0 {
		return map[string]any{
			"count":      0,
			"min_ms":     float64(0),
			"max_ms":     float64(0),
			"avg_ms":     float64(0),
			"average_ms": float64(0),
			"median_ms":  float64(0),
			"p95_ms":     float64(0),
			"p99_ms":     float64(0),
		}
	}

	// Sort times for percentile calculations
	sortedTimes := make([]time.Duration, len(times))
	copy(sortedTimes, times)

	// Simple bubble sort for small arrays
	for i := range sortedTimes {
		for j := i + 1; j < len(sortedTimes); j++ {
			if sortedTimes[i] > sortedTimes[j] {
				sortedTimes[i], sortedTimes[j] = sortedTimes[j], sortedTimes[i]
			}
		}
	}

	// Calculate statistics
	min := sortedTimes[0]
	max := sortedTimes[len(sortedTimes)-1]

	var total time.Duration
	for _, t := range sortedTimes {
		total += t
	}
	avg := total / time.Duration(len(sortedTimes))

	median := sortedTimes[len(sortedTimes)/2]
	p95 := sortedTimes[int(float64(len(sortedTimes))*0.95)]
	p99 := sortedTimes[int(float64(len(sortedTimes))*0.99)]

	return map[string]any{
		"count":      len(sortedTimes),
		"min_ms":     float64(min.Nanoseconds()) / 1e6,
		"max_ms":     float64(max.Nanoseconds()) / 1e6,
		"avg_ms":     float64(avg.Nanoseconds()) / 1e6,
		"average_ms": float64(avg.Nanoseconds()) / 1e6,
		"median_ms":  float64(median.Nanoseconds()) / 1e6,
		"p95_ms":     float64(p95.Nanoseconds()) / 1e6,
		"p99_ms":     float64(p99.Nanoseconds()) / 1e6,
	}
}

// ResourceMonitor tracks resource usage and limits
type ResourceMonitor struct {
	cacheSizes      map[string]int64
	alertThresholds map[string]float64
	perfMetrics     *PerformanceMetrics
	logger          *Logger
	alerts          []ResourceAlert
	maxMemoryBytes  int64
	maxCacheSize    int64
	maxSessions     int64
	cacheMutex      sync.RWMutex
	alertsMutex     sync.RWMutex
}

// ResourceAlert represents a resource usage alert
type ResourceAlert struct {
	Timestamp    time.Time `json:"timestamp"`
	Type         string    `json:"type"`
	Message      string    `json:"message"`
	Severity     string    `json:"severity"`
	Threshold    float64   `json:"threshold"`
	CurrentValue float64   `json:"current_value"`
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(perfMetrics *PerformanceMetrics, logger *Logger) *ResourceMonitor {
	rm := &ResourceMonitor{
		maxMemoryBytes: 100 * 1024 * 1024, // 100MB default
		maxCacheSize:   10000,             // 10k items default
		maxSessions:    1000,              // 1k sessions default
		cacheSizes:     make(map[string]int64),
		alertThresholds: map[string]float64{
			"memory_usage":    0.8,  // 80%
			"memory_pressure": 0.7,  // 70%
			"cache_usage":     0.9,  // 90%
			"session_usage":   0.85, // 85%
			"error_rate":      0.1,  // 10%
		},
		alerts:      make([]ResourceAlert, 0),
		perfMetrics: perfMetrics,
		logger:      logger,
	}

	// Start monitoring routine
	go rm.startMonitoring()

	return rm
}

// SetMemoryLimit sets the maximum memory usage limit
func (rm *ResourceMonitor) SetMemoryLimit(bytes int64) {
	rm.maxMemoryBytes = bytes
}

// SetCacheLimit sets the maximum cache size limit
func (rm *ResourceMonitor) SetCacheLimit(size int64) {
	rm.maxCacheSize = size
}

// SetSessionLimit sets the maximum session count limit
func (rm *ResourceMonitor) SetSessionLimit(count int64) {
	rm.maxSessions = count
}

// UpdateCacheSize updates the size of a specific cache
func (rm *ResourceMonitor) UpdateCacheSize(cacheName string, size int64) {
	rm.cacheMutex.Lock()
	defer rm.cacheMutex.Unlock()
	rm.cacheSizes[cacheName] = size
}

// GetCacheSizes returns current cache sizes
func (rm *ResourceMonitor) GetCacheSizes() map[string]int64 {
	rm.cacheMutex.RLock()
	defer rm.cacheMutex.RUnlock()

	sizes := make(map[string]int64)
	maps.Copy(sizes, rm.cacheSizes)
	return sizes
}

// startMonitoring starts the background monitoring routine
func (rm *ResourceMonitor) startMonitoring() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		rm.checkResourceUsage()
	}
}

// checkResourceUsage checks current resource usage against limits
func (rm *ResourceMonitor) checkResourceUsage() {
	metrics := rm.perfMetrics.GetMetrics()

	// Check memory usage
	if memUsage, ok := metrics["memory_usage_bytes"].(int64); ok {
		memUsageRatio := float64(memUsage) / float64(rm.maxMemoryBytes)
		if memUsageRatio > rm.alertThresholds["memory_usage"] {
			rm.addAlert(ResourceAlert{
				Type:         "memory_usage",
				Message:      "Memory usage exceeds threshold",
				Threshold:    rm.alertThresholds["memory_usage"],
				CurrentValue: memUsageRatio,
				Timestamp:    time.Now(),
				Severity:     rm.getSeverity(memUsageRatio, rm.alertThresholds["memory_usage"]),
			})
		}
	}

	// Check memory pressure
	if memPressure, ok := metrics["memory_pressure"].(int64); ok {
		pressureRatio := float64(memPressure) / 100.0 // Convert to 0-1 scale
		if pressureRatio > rm.alertThresholds["memory_pressure"] {
			rm.addAlert(ResourceAlert{
				Type:         "memory_pressure",
				Message:      "Memory pressure exceeds threshold",
				Threshold:    rm.alertThresholds["memory_pressure"],
				CurrentValue: pressureRatio,
				Timestamp:    time.Now(),
				Severity:     rm.getSeverity(pressureRatio, rm.alertThresholds["memory_pressure"]),
			})
		}
	}

	// Check cache usage
	if cacheSize, ok := metrics["cache_size"].(int64); ok {
		cacheUsageRatio := float64(cacheSize) / float64(rm.maxCacheSize)
		if cacheUsageRatio > rm.alertThresholds["cache_usage"] {
			rm.addAlert(ResourceAlert{
				Type:         "cache_usage",
				Message:      "Cache usage exceeds threshold",
				Threshold:    rm.alertThresholds["cache_usage"],
				CurrentValue: cacheUsageRatio,
				Timestamp:    time.Now(),
				Severity:     rm.getSeverity(cacheUsageRatio, rm.alertThresholds["cache_usage"]),
			})
		}
	}

	// Check session usage
	if activeSessions, ok := metrics["active_sessions"].(int64); ok {
		sessionUsageRatio := float64(activeSessions) / float64(rm.maxSessions)
		if sessionUsageRatio > rm.alertThresholds["session_usage"] {
			rm.addAlert(ResourceAlert{
				Type:         "session_usage",
				Message:      "Active session count exceeds threshold",
				Threshold:    rm.alertThresholds["session_usage"],
				CurrentValue: sessionUsageRatio,
				Timestamp:    time.Now(),
				Severity:     rm.getSeverity(sessionUsageRatio, rm.alertThresholds["session_usage"]),
			})
		}
	}

	// Check error rates
	if errorRate, ok := metrics["verification_error_rate"].(float64); ok {
		if errorRate > rm.alertThresholds["error_rate"] {
			rm.addAlert(ResourceAlert{
				Type:         "verification_error_rate",
				Message:      "Token verification error rate exceeds threshold",
				Threshold:    rm.alertThresholds["error_rate"],
				CurrentValue: errorRate,
				Timestamp:    time.Now(),
				Severity:     rm.getSeverity(errorRate, rm.alertThresholds["error_rate"]),
			})
		}
	}
}

// getSeverity determines the severity level based on how much the threshold is exceeded
func (rm *ResourceMonitor) getSeverity(currentValue, threshold float64) string {
	ratio := currentValue / threshold
	if ratio >= 1.5 {
		return "critical"
	} else if ratio >= 1.2 {
		return "high"
	} else if ratio >= 1.0 {
		return "medium"
	}
	return "low"
}

// addAlert adds a new resource alert
func (rm *ResourceMonitor) addAlert(alert ResourceAlert) {
	rm.alertsMutex.Lock()
	defer rm.alertsMutex.Unlock()

	// Add alert
	rm.alerts = append(rm.alerts, alert)

	// Keep only last 100 alerts
	if len(rm.alerts) > 100 {
		rm.alerts = rm.alerts[1:]
	}

	// Log the alert
	rm.logger.Errorf("Resource Alert [%s/%s]: %s (%.2f%% > %.2f%%)",
		alert.Type, alert.Severity, alert.Message,
		alert.CurrentValue*100, alert.Threshold*100)
}

// GetAlerts returns current resource alerts
func (rm *ResourceMonitor) GetAlerts() []ResourceAlert {
	rm.alertsMutex.RLock()
	defer rm.alertsMutex.RUnlock()

	alerts := make([]ResourceAlert, len(rm.alerts))
	copy(alerts, rm.alerts)
	return alerts
}

// GetResourceStatus returns current resource status
func (rm *ResourceMonitor) GetResourceStatus() map[string]any {
	metrics := rm.perfMetrics.GetMetrics()
	cacheSizes := rm.GetCacheSizes()

	status := map[string]any{
		"limits": map[string]any{
			"max_memory_bytes": rm.maxMemoryBytes,
			"max_cache_size":   rm.maxCacheSize,
			"max_sessions":     rm.maxSessions,
		},
		"thresholds":  rm.alertThresholds,
		"current":     metrics,
		"cache_sizes": cacheSizes,
		// Add expected keys for tests
		"memory_limit":  uint64(rm.maxMemoryBytes),
		"cache_limit":   int(rm.maxCacheSize),
		"session_limit": int(rm.maxSessions),
	}

	// Calculate usage ratios
	if memUsage, ok := metrics["memory_usage_bytes"].(int64); ok {
		status["memory_usage_ratio"] = float64(memUsage) / float64(rm.maxMemoryBytes)
	}
	if memPressure, ok := metrics["memory_pressure"].(int64); ok {
		status["memory_pressure_ratio"] = float64(memPressure) / 100.0
	}
	if cacheSize, ok := metrics["cache_size"].(int64); ok {
		status["cache_usage_ratio"] = float64(cacheSize) / float64(rm.maxCacheSize)
	}
	if activeSessions, ok := metrics["active_sessions"].(int64); ok {
		status["session_usage_ratio"] = float64(activeSessions) / float64(rm.maxSessions)
	}

	// Calculate total cache size across all caches
	var totalCacheSize int64
	for _, size := range cacheSizes {
		totalCacheSize += size
	}
	status["total_cache_size"] = totalCacheSize

	return status
}
