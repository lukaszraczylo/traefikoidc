package backends

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// HealthMonitor continuously monitors Redis connection health and triggers reconnections
type HealthMonitor struct {
	pool                *ConnectionPool
	config              *HealthMonitorConfig
	stopChan            chan struct{}
	wg                  sync.WaitGroup
	lastCheckTime       atomic.Int64
	consecutiveFailures atomic.Int64
	totalChecks         atomic.Int64
	totalFailures       atomic.Int64
	healthy             atomic.Bool
	running             atomic.Bool
}

// HealthMonitorConfig configures the health monitor
type HealthMonitorConfig struct {
	OnHealthChange     func(healthy bool)
	CheckInterval      time.Duration
	Timeout            time.Duration
	UnhealthyThreshold int
}

// DefaultHealthMonitorConfig returns default health monitor configuration
func DefaultHealthMonitorConfig() *HealthMonitorConfig {
	return &HealthMonitorConfig{
		CheckInterval:      5 * time.Second,
		Timeout:            3 * time.Second,
		UnhealthyThreshold: 3,
	}
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(pool *ConnectionPool, config *HealthMonitorConfig) *HealthMonitor {
	if config == nil {
		config = DefaultHealthMonitorConfig()
	}

	hm := &HealthMonitor{
		pool:     pool,
		config:   config,
		stopChan: make(chan struct{}),
	}

	hm.healthy.Store(true) // Assume healthy initially
	return hm
}

// Start begins health monitoring
func (hm *HealthMonitor) Start() {
	if hm.running.Swap(true) {
		return // Already running
	}

	hm.wg.Add(1)
	go hm.monitorLoop()
}

// Stop stops health monitoring
func (hm *HealthMonitor) Stop() {
	if !hm.running.Swap(false) {
		return // Not running
	}

	close(hm.stopChan)
	hm.wg.Wait()
}

// IsHealthy returns the current health status
func (hm *HealthMonitor) IsHealthy() bool {
	return hm.healthy.Load()
}

// GetStats returns health monitor statistics
func (hm *HealthMonitor) GetStats() map[string]interface{} {
	lastCheck := time.Unix(hm.lastCheckTime.Load(), 0)

	return map[string]interface{}{
		"healthy":              hm.healthy.Load(),
		"consecutive_failures": hm.consecutiveFailures.Load(),
		"total_checks":         hm.totalChecks.Load(),
		"total_failures":       hm.totalFailures.Load(),
		"last_check":           lastCheck,
	}
}

// monitorLoop runs the health check loop
func (hm *HealthMonitor) monitorLoop() {
	defer hm.wg.Done()

	ticker := time.NewTicker(hm.config.CheckInterval)
	defer ticker.Stop()

	// Perform initial check immediately
	hm.performHealthCheck()

	for {
		select {
		case <-hm.stopChan:
			return
		case <-ticker.C:
			hm.performHealthCheck()
		}
	}
}

// performHealthCheck executes a health check
func (hm *HealthMonitor) performHealthCheck() {
	hm.totalChecks.Add(1)
	hm.lastCheckTime.Store(time.Now().Unix())

	ctx, cancel := context.WithTimeout(context.Background(), hm.config.Timeout)
	defer cancel()

	// Try to get a connection and ping Redis
	conn, err := hm.pool.Get(ctx)
	if err != nil {
		hm.recordFailure()
		return
	}
	defer hm.pool.Put(conn)

	// Ping Redis
	_, err = conn.Do("PING")
	if err != nil {
		hm.recordFailure()
		return
	}

	// Success!
	hm.recordSuccess()
}

// recordSuccess records a successful health check
func (hm *HealthMonitor) recordSuccess() {
	wasHealthy := hm.healthy.Load()
	hm.consecutiveFailures.Store(0)
	hm.healthy.Store(true)

	// Trigger callback if health changed
	if !wasHealthy && hm.config.OnHealthChange != nil {
		hm.config.OnHealthChange(true)
	}
}

// recordFailure records a failed health check
func (hm *HealthMonitor) recordFailure() {
	hm.totalFailures.Add(1)
	failures := hm.consecutiveFailures.Add(1)

	wasHealthy := hm.healthy.Load()

	// Mark unhealthy if threshold exceeded
	if failures >= int64(hm.config.UnhealthyThreshold) {
		hm.healthy.Store(false)

		// Trigger callback if health changed
		if wasHealthy && hm.config.OnHealthChange != nil {
			hm.config.OnHealthChange(false)
		}
	}
}
