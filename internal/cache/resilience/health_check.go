// Package resilience provides resilience patterns for cache backends.
package resilience

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// HealthStatus represents the health status of a backend
type HealthStatus int32

const (
	// HealthUnknown indicates unknown health status
	HealthUnknown HealthStatus = iota

	// HealthHealthy indicates the backend is healthy
	HealthHealthy

	// HealthDegraded indicates the backend is degraded but operational
	HealthDegraded

	// HealthUnhealthy indicates the backend is unhealthy
	HealthUnhealthy
)

// String returns the string representation of the health status
func (h HealthStatus) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthDegraded:
		return "degraded"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// HealthCheckConfig holds configuration for the health checker
type HealthCheckConfig struct {
	OnStatusChange     func(from, to HealthStatus)
	CheckFunc          func(ctx context.Context) error
	CheckInterval      time.Duration
	Timeout            time.Duration
	HealthyThreshold   int
	UnhealthyThreshold int
	DegradedThreshold  time.Duration
}

// DefaultHealthCheckConfig returns default configuration
func DefaultHealthCheckConfig() *HealthCheckConfig {
	return &HealthCheckConfig{
		CheckInterval:      30 * time.Second,
		Timeout:            5 * time.Second,
		HealthyThreshold:   3,
		UnhealthyThreshold: 3,
		DegradedThreshold:  100 * time.Millisecond,
	}
}

// HealthChecker monitors the health of a backend
type HealthChecker struct {
	lastCheckTime        time.Time
	lastSuccessTime      time.Time
	lastFailureTime      time.Time
	config               *HealthCheckConfig
	stopChan             chan struct{}
	ticker               *time.Ticker
	wg                   sync.WaitGroup
	statusChanges        atomic.Int64
	totalChecks          atomic.Int64
	totalSuccesses       atomic.Int64
	totalFailures        atomic.Int64
	averageLatency       atomic.Int64
	timeMu               sync.RWMutex
	consecutiveFailures  atomic.Int32
	consecutiveSuccesses atomic.Int32
	stopped              atomic.Bool
	status               atomic.Int32
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config *HealthCheckConfig) *HealthChecker {
	if config == nil {
		config = DefaultHealthCheckConfig()
	}

	hc := &HealthChecker{
		config:   config,
		stopChan: make(chan struct{}),
	}
	hc.status.Store(int32(HealthUnknown))

	return hc
}

// Start begins health checking
func (hc *HealthChecker) Start() {
	if hc.stopped.Load() {
		return
	}

	hc.ticker = time.NewTicker(hc.config.CheckInterval)
	hc.wg.Add(1)
	go hc.checkLoop()
}

// Stop stops health checking
func (hc *HealthChecker) Stop() {
	if hc.stopped.Swap(true) {
		return // Already stopped
	}

	close(hc.stopChan)
	if hc.ticker != nil {
		hc.ticker.Stop()
	}
	hc.wg.Wait()
}

// checkLoop runs periodic health checks
func (hc *HealthChecker) checkLoop() {
	defer hc.wg.Done()

	// Initial check - log error but continue
	if err := hc.Check(context.Background()); err != nil {
		// Error is already tracked in Check() method, no need to log again
		_ = err
	}

	for {
		select {
		case <-hc.stopChan:
			return
		case <-hc.ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
			if err := hc.Check(ctx); err != nil {
				// Error is already tracked in Check() method, no need to log again
				_ = err
			}
			cancel()
		}
	}
}

// Check performs a health check
func (hc *HealthChecker) Check(ctx context.Context) error {
	if hc.config.CheckFunc == nil {
		return nil
	}

	hc.totalChecks.Add(1)
	start := time.Now()

	// Create timeout context if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hc.config.Timeout)
		defer cancel()
	}

	// Perform health check
	err := hc.config.CheckFunc(ctx)
	latency := time.Since(start)

	hc.timeMu.Lock()
	hc.lastCheckTime = time.Now()
	hc.timeMu.Unlock()

	// Update average latency
	hc.updateAverageLatency(latency)

	if err != nil {
		hc.recordFailure()
	} else {
		hc.recordSuccess(latency)
	}

	return err
}

// recordSuccess records a successful health check
func (hc *HealthChecker) recordSuccess(latency time.Duration) {
	hc.totalSuccesses.Add(1)
	successes := hc.consecutiveSuccesses.Add(1)
	hc.consecutiveFailures.Store(0)

	hc.timeMu.Lock()
	hc.lastSuccessTime = time.Now()
	hc.timeMu.Unlock()

	currentStatus := hc.GetStatus()
	newStatus := currentStatus

	// Check if we should become healthy
	// #nosec G115 -- HealthyThreshold is a small config value that fits in int32
	if successes >= int32(hc.config.HealthyThreshold) {
		if latency > hc.config.DegradedThreshold {
			newStatus = HealthDegraded
		} else {
			newStatus = HealthHealthy
		}
	}

	if newStatus != currentStatus {
		hc.setStatus(newStatus)
	}
}

// recordFailure records a failed health check
func (hc *HealthChecker) recordFailure() {
	hc.totalFailures.Add(1)
	failures := hc.consecutiveFailures.Add(1)
	hc.consecutiveSuccesses.Store(0)

	hc.timeMu.Lock()
	hc.lastFailureTime = time.Now()
	hc.timeMu.Unlock()

	// Check if we should become unhealthy
	// #nosec G115 -- UnhealthyThreshold is a small config value that fits in int32
	if failures >= int32(hc.config.UnhealthyThreshold) {
		hc.setStatus(HealthUnhealthy)
	}
}

// updateAverageLatency updates the rolling average latency
func (hc *HealthChecker) updateAverageLatency(latency time.Duration) {
	// Simple exponential moving average
	currentAvg := time.Duration(hc.averageLatency.Load())
	if currentAvg == 0 {
		hc.averageLatency.Store(int64(latency))
	} else {
		// Weight: 0.2 for new value, 0.8 for old average
		newAvg := (currentAvg*4 + latency) / 5
		hc.averageLatency.Store(int64(newAvg))
	}
}

// GetStatus returns the current health status
func (hc *HealthChecker) GetStatus() HealthStatus {
	return HealthStatus(hc.status.Load())
}

// setStatus changes the health status
func (hc *HealthChecker) setStatus(newStatus HealthStatus) {
	oldStatus := HealthStatus(hc.status.Swap(int32(newStatus)))

	if oldStatus != newStatus {
		hc.statusChanges.Add(1)
		if hc.config.OnStatusChange != nil {
			hc.config.OnStatusChange(oldStatus, newStatus)
		}
	}
}

// IsHealthy returns true if the backend is healthy or degraded
func (hc *HealthChecker) IsHealthy() bool {
	status := hc.GetStatus()
	return status == HealthHealthy || status == HealthDegraded
}

// LastCheckTime returns the time of the last health check
func (hc *HealthChecker) LastCheckTime() time.Time {
	hc.timeMu.RLock()
	defer hc.timeMu.RUnlock()
	return hc.lastCheckTime
}

// HealthScore returns a health score between 0.0 (unhealthy) and 1.0 (healthy)
func (hc *HealthChecker) HealthScore() float64 {
	status := hc.GetStatus()
	switch status {
	case HealthHealthy:
		return 1.0
	case HealthDegraded:
		return 0.7
	case HealthUnhealthy:
		return 0.0
	default:
		return 0.5
	}
}

// Stats returns health checker statistics
func (hc *HealthChecker) Stats() HealthCheckerStats {
	hc.timeMu.RLock()
	lastCheck := hc.lastCheckTime
	lastSuccess := hc.lastSuccessTime
	lastFailure := hc.lastFailureTime
	hc.timeMu.RUnlock()

	totalChecks := hc.totalChecks.Load()
	totalSuccesses := hc.totalSuccesses.Load()
	totalFailures := hc.totalFailures.Load()

	successRate := float64(0)
	if totalChecks > 0 {
		successRate = float64(totalSuccesses) / float64(totalChecks)
	}

	return HealthCheckerStats{
		Status:               hc.GetStatus(),
		ConsecutiveSuccesses: hc.consecutiveSuccesses.Load(),
		ConsecutiveFailures:  hc.consecutiveFailures.Load(),
		TotalChecks:          totalChecks,
		TotalSuccesses:       totalSuccesses,
		TotalFailures:        totalFailures,
		SuccessRate:          successRate,
		AverageLatency:       time.Duration(hc.averageLatency.Load()),
		StatusChanges:        hc.statusChanges.Load(),
		LastCheckTime:        lastCheck,
		LastSuccessTime:      lastSuccess,
		LastFailureTime:      lastFailure,
		HealthScore:          hc.HealthScore(),
	}
}

// HealthCheckerStats holds statistics for the health checker
type HealthCheckerStats struct {
	LastCheckTime        time.Time
	LastFailureTime      time.Time
	LastSuccessTime      time.Time
	TotalChecks          int64
	TotalSuccesses       int64
	TotalFailures        int64
	SuccessRate          float64
	AverageLatency       time.Duration
	StatusChanges        int64
	HealthScore          float64
	Status               HealthStatus
	ConsecutiveFailures  int32
	ConsecutiveSuccesses int32
}

// Reset resets the health checker statistics
func (hc *HealthChecker) Reset() {
	hc.status.Store(int32(HealthUnknown))
	hc.consecutiveSuccesses.Store(0)
	hc.consecutiveFailures.Store(0)
	hc.totalChecks.Store(0)
	hc.totalSuccesses.Store(0)
	hc.totalFailures.Store(0)
	hc.statusChanges.Store(0)
	hc.averageLatency.Store(0)

	now := time.Now()
	hc.timeMu.Lock()
	hc.lastCheckTime = now
	hc.lastSuccessTime = now
	hc.lastFailureTime = now
	hc.timeMu.Unlock()
}
