// Package resilience provides resilience patterns for cache backends.
package resilience

import (
	"context"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
)

// CircuitBreakerBackend wraps a cache backend with circuit breaker protection
type CircuitBreakerBackend struct {
	backend backends.CacheBackend
	cb      *CircuitBreaker
}

// NewCircuitBreakerBackend creates a new circuit breaker wrapped backend
func NewCircuitBreakerBackend(b backends.CacheBackend, config *CircuitBreakerConfig) backends.CacheBackend {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	return &CircuitBreakerBackend{
		backend: b,
		cb:      NewCircuitBreaker(config),
	}
}

// Set stores a value with circuit breaker protection
func (c *CircuitBreakerBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if !c.cb.AllowRequest() {
		return backends.ErrCircuitOpen
	}

	err := c.backend.Set(ctx, key, value, ttl)
	if err == nil {
		c.cb.RecordSuccess()
	} else {
		c.cb.RecordFailure()
	}
	return err
}

// Get retrieves a value with circuit breaker protection
func (c *CircuitBreakerBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	if !c.cb.AllowRequest() {
		return nil, 0, false, backends.ErrCircuitOpen
	}

	value, ttl, exists, err := c.backend.Get(ctx, key)
	if err == nil {
		c.cb.RecordSuccess()
	} else {
		c.cb.RecordFailure()
	}
	return value, ttl, exists, err
}

// Delete removes a key with circuit breaker protection
func (c *CircuitBreakerBackend) Delete(ctx context.Context, key string) (bool, error) {
	if !c.cb.AllowRequest() {
		return false, backends.ErrCircuitOpen
	}

	deleted, err := c.backend.Delete(ctx, key)
	if err == nil {
		c.cb.RecordSuccess()
	} else {
		c.cb.RecordFailure()
	}
	return deleted, err
}

// Exists checks if a key exists with circuit breaker protection
func (c *CircuitBreakerBackend) Exists(ctx context.Context, key string) (bool, error) {
	if !c.cb.AllowRequest() {
		return false, backends.ErrCircuitOpen
	}

	exists, err := c.backend.Exists(ctx, key)
	if err == nil {
		c.cb.RecordSuccess()
	} else {
		c.cb.RecordFailure()
	}
	return exists, err
}

// Clear removes all keys with circuit breaker protection
func (c *CircuitBreakerBackend) Clear(ctx context.Context) error {
	if !c.cb.AllowRequest() {
		return backends.ErrCircuitOpen
	}

	err := c.backend.Clear(ctx)
	if err == nil {
		c.cb.RecordSuccess()
	} else {
		c.cb.RecordFailure()
	}
	return err
}

// GetStats returns statistics including circuit breaker state
func (c *CircuitBreakerBackend) GetStats() map[string]interface{} {
	stats := c.backend.GetStats()
	if stats == nil {
		stats = make(map[string]interface{})
	}

	cbStats := c.cb.Stats()
	stats["circuit_breaker"] = map[string]interface{}{
		"state":                cbStats.State.String(),
		"consecutive_failures": cbStats.ConsecutiveFailures,
		"total_requests":       cbStats.TotalRequests,
		"total_failures":       cbStats.TotalFailures,
		"success_rate":         cbStats.SuccessRate,
	}

	return stats
}

// Ping checks backend health with circuit breaker protection
func (c *CircuitBreakerBackend) Ping(ctx context.Context) error {
	if !c.cb.AllowRequest() {
		return backends.ErrCircuitOpen
	}

	err := c.backend.Ping(ctx)
	if err == nil {
		c.cb.RecordSuccess()
	} else {
		c.cb.RecordFailure()
	}
	return err
}

// Close shuts down the backend
func (c *CircuitBreakerBackend) Close() error {
	return c.backend.Close()
}
