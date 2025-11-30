// Package resilience provides resilience patterns for cache backends.
package resilience

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// HealthCheckBackend wraps a cache backend with health checking
type HealthCheckBackend struct {
	backend backends.CacheBackend
	config  *HealthCheckConfig

	// Health tracking
	status           atomic.Int32
	consecutiveFails atomic.Int32
	consecutiveOK    atomic.Int32
	lastCheck        time.Time
	checkMutex       sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewHealthCheckBackend creates a new health check wrapped backend
func NewHealthCheckBackend(b backends.CacheBackend, config *HealthCheckConfig) backends.CacheBackend {
	if config == nil {
		config = DefaultHealthCheckConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	hc := &HealthCheckBackend{
		backend: b,
		config:  config,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Set initial status to healthy (optimistic)
	hc.status.Store(int32(HealthHealthy))

	// Start health check routine
	hc.wg.Add(1)
	go hc.healthCheckLoop()

	return hc
}

// Set stores a value and tracks health
func (h *HealthCheckBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	// Allow operations even if unhealthy (may recover)
	err := h.backend.Set(ctx, key, value, ttl)
	h.recordResult(err == nil)
	return err
}

// Get retrieves a value and tracks health
func (h *HealthCheckBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	value, ttl, exists, err := h.backend.Get(ctx, key)
	h.recordResult(err == nil)
	return value, ttl, exists, err
}

// Delete removes a key and tracks health
func (h *HealthCheckBackend) Delete(ctx context.Context, key string) (bool, error) {
	deleted, err := h.backend.Delete(ctx, key)
	h.recordResult(err == nil)
	return deleted, err
}

// Exists checks if a key exists and tracks health
func (h *HealthCheckBackend) Exists(ctx context.Context, key string) (bool, error) {
	exists, err := h.backend.Exists(ctx, key)
	h.recordResult(err == nil)
	return exists, err
}

// Clear removes all keys and tracks health
func (h *HealthCheckBackend) Clear(ctx context.Context) error {
	err := h.backend.Clear(ctx)
	h.recordResult(err == nil)
	return err
}

// GetStats returns statistics including health status
func (h *HealthCheckBackend) GetStats() map[string]interface{} {
	stats := h.backend.GetStats()
	if stats == nil {
		stats = make(map[string]interface{})
	}

	h.checkMutex.RLock()
	lastCheck := h.lastCheck
	h.checkMutex.RUnlock()

	status := HealthStatus(h.status.Load())
	stats["health"] = map[string]interface{}{
		"status":             status.String(),
		"consecutive_fails":  h.consecutiveFails.Load(),
		"consecutive_ok":     h.consecutiveOK.Load(),
		"last_check":         lastCheck.Format(time.RFC3339),
		"time_since_check":   time.Since(lastCheck).Seconds(),
		"check_interval_sec": h.config.CheckInterval.Seconds(),
	}

	return stats
}

// Ping checks backend health
func (h *HealthCheckBackend) Ping(ctx context.Context) error {
	err := h.backend.Ping(ctx)
	h.recordResult(err == nil)
	return err
}

// Close shuts down the health checker and backend
func (h *HealthCheckBackend) Close() error {
	// Stop health check routine
	h.cancel()

	// Wait for routine to finish
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Finished normally
	case <-time.After(2 * time.Second):
		// Timeout
	}

	return h.backend.Close()
}

// IsHealthy returns true if the backend is healthy
func (h *HealthCheckBackend) IsHealthy() bool {
	status := HealthStatus(h.status.Load())
	return status == HealthHealthy || status == HealthDegraded
}

// recordResult records the result of an operation for health tracking
func (h *HealthCheckBackend) recordResult(success bool) {
	if success {
		fails := h.consecutiveFails.Swap(0)
		oks := h.consecutiveOK.Add(1)

		// Check if we should transition to healthy
		if fails > 0 && oks >= int32(h.config.HealthyThreshold) {
			oldStatus := HealthStatus(h.status.Swap(int32(HealthHealthy)))
			if oldStatus != HealthHealthy && h.config.OnStatusChange != nil {
				h.config.OnStatusChange(oldStatus, HealthHealthy)
			}
		}
	} else {
		oks := h.consecutiveOK.Swap(0)
		fails := h.consecutiveFails.Add(1)

		// Check if we should transition to unhealthy
		if oks > 0 && fails >= int32(h.config.UnhealthyThreshold) {
			oldStatus := HealthStatus(h.status.Swap(int32(HealthUnhealthy)))
			if oldStatus != HealthUnhealthy && h.config.OnStatusChange != nil {
				h.config.OnStatusChange(oldStatus, HealthUnhealthy)
			}
		} else if fails >= int32(h.config.UnhealthyThreshold)*2 {
			// Severely degraded
			h.status.Store(int32(HealthUnhealthy))
		} else if fails >= int32(h.config.UnhealthyThreshold) {
			// Degraded but still trying
			h.status.Store(int32(HealthDegraded))
		}
	}
}

// healthCheckLoop runs periodic health checks
func (h *HealthCheckBackend) healthCheckLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.CheckInterval)
	defer ticker.Stop()

	// Do initial check
	h.performHealthCheck()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.performHealthCheck()
		}
	}
}

// performHealthCheck performs a single health check
func (h *HealthCheckBackend) performHealthCheck() {
	h.checkMutex.Lock()
	h.lastCheck = time.Now()
	h.checkMutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
	defer cancel()

	err := h.backend.Ping(ctx)
	h.recordResult(err == nil)
}
