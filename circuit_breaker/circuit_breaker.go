// Package circuit_breaker provides circuit breaker implementation for resilience
package circuit_breaker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreakerState represents the current state of a circuit breaker.
// The circuit breaker pattern prevents cascading failures by monitoring
// error rates and temporarily blocking requests to failing services.
type CircuitBreakerState int

// Circuit breaker states following the standard pattern:
// Closed: Normal operation, requests flow through
// Open: Circuit is tripped, requests are blocked
// HalfOpen: Testing state, limited requests allowed to test recovery
const (
	// CircuitBreakerClosed allows all requests through (normal operation)
	CircuitBreakerClosed CircuitBreakerState = iota
	// CircuitBreakerOpen blocks all requests (service is failing)
	CircuitBreakerOpen
	// CircuitBreakerHalfOpen allows limited requests to test service recovery
	CircuitBreakerHalfOpen
)

// String returns a string representation of the circuit breaker state
func (s CircuitBreakerState) String() string {
	switch s {
	case CircuitBreakerClosed:
		return "closed"
	case CircuitBreakerOpen:
		return "open"
	case CircuitBreakerHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Logger interface for dependency injection
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// BaseRecoveryMechanism interface for common functionality
type BaseRecoveryMechanism interface {
	RecordRequest()
	RecordSuccess()
	RecordFailure()
	GetBaseMetrics() map[string]interface{}
	LogInfo(format string, args ...interface{})
	LogError(format string, args ...interface{})
	LogDebug(format string, args ...interface{})
}

// CircuitBreaker implements the circuit breaker pattern for external service calls.
// It monitors failure rates and automatically opens the circuit when failures
// exceed the threshold, preventing further requests until the service recovers.
type CircuitBreaker struct {
	// baseRecovery provides common functionality
	baseRecovery BaseRecoveryMechanism
	// maxFailures is the threshold for opening the circuit
	maxFailures int
	// timeout is how long to wait before allowing requests in half-open state
	timeout time.Duration
	// resetTimeout is how long to wait before transitioning from open to half-open
	resetTimeout time.Duration
	// state tracks the current circuit breaker state
	state CircuitBreakerState
	// failures counts consecutive failures
	failures int64
	// lastFailureTime records when the last failure occurred
	lastFailureTime time.Time
	// mutex protects shared state
	mutex sync.RWMutex
	// logger for debugging and monitoring
	logger Logger
}

// CircuitBreakerConfig holds configuration parameters for circuit breakers.
// These settings control when the circuit opens and how it recovers.
type CircuitBreakerConfig struct {
	// MaxFailures is the number of failures before opening the circuit
	MaxFailures int `json:"max_failures"`
	// Timeout is how long to wait before trying to recover (open -> half-open)
	Timeout time.Duration `json:"timeout"`
	// ResetTimeout is how long to wait before fully closing the circuit
	ResetTimeout time.Duration `json:"reset_timeout"`
}

// DefaultCircuitBreakerConfig returns sensible default configuration for circuit breakers.
// Configured for typical web service scenarios with moderate tolerance for failures.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      60 * time.Second,
		ResetTimeout: 30 * time.Second,
	}
}

// NewCircuitBreaker creates a new circuit breaker with the specified configuration.
// The circuit breaker starts in the closed state, allowing all requests through.
func NewCircuitBreaker(config CircuitBreakerConfig, logger Logger, baseRecovery BaseRecoveryMechanism) *CircuitBreaker {
	return &CircuitBreaker{
		baseRecovery: baseRecovery,
		maxFailures:  config.MaxFailures,
		timeout:      config.Timeout,
		resetTimeout: config.ResetTimeout,
		state:        CircuitBreakerClosed,
		logger:       logger,
	}
}

// ExecuteWithContext executes a function through the circuit breaker with context.
// It checks if requests are allowed, executes the function, and updates the circuit state
// based on the result. Implements the ErrorRecoveryMechanism interface.
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func() error) error {
	if cb.baseRecovery != nil {
		cb.baseRecovery.RecordRequest()
	}

	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}

	err := fn()
	if err != nil {
		cb.recordFailure()
		if cb.baseRecovery != nil {
			cb.baseRecovery.RecordFailure()
		}
		return err
	}

	cb.recordSuccess()
	if cb.baseRecovery != nil {
		cb.baseRecovery.RecordSuccess()
	}
	return nil
}

// Execute executes a function through the circuit breaker without context.
// This is provided for backward compatibility with existing code.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	return cb.ExecuteWithContext(context.Background(), fn)
}

// allowRequest determines whether to allow a request based on the circuit state.
// Handles state transitions from open to half-open based on timeout.
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		return true

	case CircuitBreakerOpen:
		if now.Sub(cb.lastFailureTime) > cb.timeout {
			cb.state = CircuitBreakerHalfOpen
			if cb.logger != nil {
				cb.logger.Infof("Circuit breaker transitioning to half-open state")
			}
			return true
		}
		return false

	case CircuitBreakerHalfOpen:
		return true

	default:
		return false
	}
}

// recordFailure records a failure and potentially opens the circuit.
// Updates failure count and triggers state transitions when thresholds are exceeded.
func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		if cb.failures >= int64(cb.maxFailures) {
			cb.state = CircuitBreakerOpen
			if cb.baseRecovery != nil {
				cb.baseRecovery.LogError("Circuit breaker opened after %d failures", cb.failures)
			}
		}

	case CircuitBreakerHalfOpen:
		cb.state = CircuitBreakerOpen
		if cb.baseRecovery != nil {
			cb.baseRecovery.LogError("Circuit breaker returned to open state after failure in half-open")
		}
	}
}

// recordSuccess records a successful request and potentially closes the circuit.
// Resets failure count and transitions from half-open to closed state on success.
func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	switch cb.state {
	case CircuitBreakerHalfOpen:
		cb.failures = 0
		cb.state = CircuitBreakerClosed
		if cb.baseRecovery != nil {
			cb.baseRecovery.LogInfo("Circuit breaker closed after successful request in half-open state")
		}

	case CircuitBreakerClosed:
		cb.failures = 0
	}
}

// GetState returns the current state of the circuit breaker.
// Thread-safe method for monitoring circuit breaker status.
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// Reset resets the circuit breaker to its initial closed state.
// Clears failure count and state, effectively recovering from any open state.
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.state = CircuitBreakerClosed
	atomic.StoreInt64(&cb.failures, 0)
	if cb.baseRecovery != nil {
		cb.baseRecovery.LogInfo("Circuit breaker has been reset")
	}
}

// IsAvailable returns whether the circuit breaker is currently allowing requests.
// This provides a quick way to check if the service is available.
func (cb *CircuitBreaker) IsAvailable() bool {
	return cb.allowRequest()
}

// GetMetrics returns comprehensive metrics about the circuit breaker.
// Includes state information, failure counts, configuration, and base metrics.
func (cb *CircuitBreaker) GetMetrics() map[string]interface{} {
	cb.mutex.RLock()
	state := cb.state
	failures := cb.failures
	lastFailureTime := cb.lastFailureTime
	cb.mutex.RUnlock()

	var metrics map[string]interface{}
	if cb.baseRecovery != nil {
		metrics = cb.baseRecovery.GetBaseMetrics()
	} else {
		metrics = make(map[string]interface{})
	}

	metrics["state"] = state.String()
	metrics["current_failures"] = failures
	metrics["max_failures"] = cb.maxFailures
	metrics["timeout"] = cb.timeout.String()
	metrics["reset_timeout"] = cb.resetTimeout.String()

	if !lastFailureTime.IsZero() {
		metrics["last_failure_time"] = lastFailureTime
		metrics["time_since_last_failure"] = time.Since(lastFailureTime).String()
	}

	return metrics
}

// GetFailureCount returns the current failure count
func (cb *CircuitBreaker) GetFailureCount() int64 {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.failures
}

// GetLastFailureTime returns the time of the last failure
func (cb *CircuitBreaker) GetLastFailureTime() time.Time {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.lastFailureTime
}

// IsOpen returns true if the circuit breaker is in open state
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state == CircuitBreakerOpen
}

// IsClosed returns true if the circuit breaker is in closed state
func (cb *CircuitBreaker) IsClosed() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state == CircuitBreakerClosed
}

// IsHalfOpen returns true if the circuit breaker is in half-open state
func (cb *CircuitBreaker) IsHalfOpen() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state == CircuitBreakerHalfOpen
}
