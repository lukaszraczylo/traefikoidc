// Package recovery provides error recovery and resilience mechanisms for OIDC authentication.
package recovery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreakerState represents the current state of the circuit breaker
type CircuitBreakerState int

const (
	// CircuitBreakerClosed allows all requests to pass through
	CircuitBreakerClosed CircuitBreakerState = iota
	// CircuitBreakerOpen blocks all requests
	CircuitBreakerOpen
	// CircuitBreakerHalfOpen allows limited requests for testing
	CircuitBreakerHalfOpen
)

// String returns the string representation of the circuit breaker state
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

// CircuitBreakerConfig defines configuration for the circuit breaker
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of failures before opening the circuit
	FailureThreshold int
	// SuccessThreshold is the number of successes in half-open state before closing
	SuccessThreshold int
	// Timeout is the duration to wait before transitioning from open to half-open
	Timeout time.Duration
	// MaxRequests is the maximum number of requests allowed in half-open state
	MaxRequests int
}

// DefaultCircuitBreakerConfig returns sensible default configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
		MaxRequests:      3,
	}
}

// CircuitBreaker implements the circuit breaker pattern for fault tolerance.
// It prevents cascading failures by temporarily blocking requests to a failing service.
type CircuitBreaker struct {
	lastStateChange time.Time
	*BaseRecoveryMechanism
	config               CircuitBreakerConfig
	stateMutex           sync.RWMutex
	state                int32
	consecutiveFailures  int32
	consecutiveSuccesses int32
	halfOpenRequests     int32
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig, logger Logger) *CircuitBreaker {
	return &CircuitBreaker{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("CircuitBreaker", logger),
		config:                config,
		state:                 int32(CircuitBreakerClosed),
		lastStateChange:       time.Now(),
		consecutiveFailures:   0,
		consecutiveSuccesses:  0,
		halfOpenRequests:      0,
	}
}

// ExecuteWithContext executes a function with circuit breaker protection
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func() error) error {
	cb.RecordRequest()

	// Check if request is allowed
	if !cb.allowRequest() {
		cb.RecordFailure()
		return fmt.Errorf("circuit breaker is open")
	}

	// Execute the function
	err := fn()

	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// Execute executes a function with circuit breaker protection (legacy method)
func (cb *CircuitBreaker) Execute(fn func() error) error {
	return cb.ExecuteWithContext(context.Background(), fn)
}

// allowRequest determines if a request should be allowed based on the circuit state
func (cb *CircuitBreaker) allowRequest() bool {
	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))

	switch state {
	case CircuitBreakerClosed:
		return true

	case CircuitBreakerOpen:
		// Check if timeout has elapsed
		cb.stateMutex.RLock()
		lastChange := cb.lastStateChange
		cb.stateMutex.RUnlock()

		if time.Since(lastChange) > cb.config.Timeout {
			// Transition to half-open
			cb.transitionToHalfOpen()
			return cb.allowHalfOpenRequest()
		}
		return false

	case CircuitBreakerHalfOpen:
		return cb.allowHalfOpenRequest()

	default:
		return false
	}
}

// allowHalfOpenRequest checks if a request is allowed in half-open state
func (cb *CircuitBreaker) allowHalfOpenRequest() bool {
	current := atomic.AddInt32(&cb.halfOpenRequests, 1)
	// #nosec G115 -- MaxRequests is a small config value that fits in int32
	if current <= int32(cb.config.MaxRequests) {
		return true
	}
	atomic.AddInt32(&cb.halfOpenRequests, -1)
	return false
}

// recordFailure records a failure and potentially opens the circuit
func (cb *CircuitBreaker) recordFailure() {
	cb.RecordFailure()

	failures := atomic.AddInt32(&cb.consecutiveFailures, 1)
	atomic.StoreInt32(&cb.consecutiveSuccesses, 0)

	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))

	// #nosec G115 -- FailureThreshold is a small config value that fits in int32
	if state == CircuitBreakerClosed && failures >= int32(cb.config.FailureThreshold) {
		cb.transitionToOpen()
	} else if state == CircuitBreakerHalfOpen {
		cb.transitionToOpen()
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *CircuitBreaker) recordSuccess() {
	cb.RecordSuccess()

	successes := atomic.AddInt32(&cb.consecutiveSuccesses, 1)
	atomic.StoreInt32(&cb.consecutiveFailures, 0)

	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))

	// #nosec G115 -- SuccessThreshold is a small config value that fits in int32
	if state == CircuitBreakerHalfOpen && successes >= int32(cb.config.SuccessThreshold) {
		cb.transitionToClosed()
	}
}

// transitionToClosed transitions the circuit to closed state
func (cb *CircuitBreaker) transitionToClosed() {
	if atomic.CompareAndSwapInt32(&cb.state, int32(CircuitBreakerHalfOpen), int32(CircuitBreakerClosed)) {
		cb.stateMutex.Lock()
		cb.lastStateChange = time.Now()
		cb.stateMutex.Unlock()

		atomic.StoreInt32(&cb.consecutiveFailures, 0)
		atomic.StoreInt32(&cb.consecutiveSuccesses, 0)
		atomic.StoreInt32(&cb.halfOpenRequests, 0)

		cb.LogInfo("Circuit breaker closed")
	}
}

// transitionToOpen transitions the circuit to open state
func (cb *CircuitBreaker) transitionToOpen() {
	oldState := atomic.SwapInt32(&cb.state, int32(CircuitBreakerOpen))
	if oldState != int32(CircuitBreakerOpen) {
		cb.stateMutex.Lock()
		cb.lastStateChange = time.Now()
		cb.stateMutex.Unlock()

		atomic.StoreInt32(&cb.consecutiveFailures, 0)
		atomic.StoreInt32(&cb.consecutiveSuccesses, 0)
		atomic.StoreInt32(&cb.halfOpenRequests, 0)

		cb.LogError("Circuit breaker opened due to failures")
	}
}

// transitionToHalfOpen transitions the circuit to half-open state
func (cb *CircuitBreaker) transitionToHalfOpen() {
	if atomic.CompareAndSwapInt32(&cb.state, int32(CircuitBreakerOpen), int32(CircuitBreakerHalfOpen)) {
		cb.stateMutex.Lock()
		cb.lastStateChange = time.Now()
		cb.stateMutex.Unlock()

		atomic.StoreInt32(&cb.consecutiveFailures, 0)
		atomic.StoreInt32(&cb.consecutiveSuccesses, 0)
		atomic.StoreInt32(&cb.halfOpenRequests, 0)

		cb.LogInfo("Circuit breaker half-open, testing recovery")
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(atomic.LoadInt32(&cb.state))
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	atomic.StoreInt32(&cb.state, int32(CircuitBreakerClosed))

	cb.stateMutex.Lock()
	cb.lastStateChange = time.Now()
	cb.stateMutex.Unlock()

	atomic.StoreInt32(&cb.consecutiveFailures, 0)
	atomic.StoreInt32(&cb.consecutiveSuccesses, 0)
	atomic.StoreInt32(&cb.halfOpenRequests, 0)

	// Reset base metrics
	atomic.StoreInt64(&cb.totalRequests, 0)
	atomic.StoreInt64(&cb.successCount, 0)
	atomic.StoreInt64(&cb.failureCount, 0)

	cb.LogInfo("Circuit breaker reset to closed state")
}

// IsAvailable returns true if the circuit breaker is not fully open
func (cb *CircuitBreaker) IsAvailable() bool {
	state := cb.GetState()
	return state != CircuitBreakerOpen || time.Since(cb.getLastStateChange()) > cb.config.Timeout
}

// getLastStateChange returns the last state change time safely
func (cb *CircuitBreaker) getLastStateChange() time.Time {
	cb.stateMutex.RLock()
	defer cb.stateMutex.RUnlock()
	return cb.lastStateChange
}

// GetMetrics returns comprehensive metrics about the circuit breaker
func (cb *CircuitBreaker) GetMetrics() map[string]interface{} {
	metrics := cb.GetBaseMetrics()

	state := cb.GetState()
	metrics["state"] = state.String()
	metrics["consecutiveFailures"] = atomic.LoadInt32(&cb.consecutiveFailures)
	metrics["consecutiveSuccesses"] = atomic.LoadInt32(&cb.consecutiveSuccesses)
	metrics["halfOpenRequests"] = atomic.LoadInt32(&cb.halfOpenRequests)

	cb.stateMutex.RLock()
	metrics["lastStateChange"] = cb.lastStateChange.Format(time.RFC3339)
	metrics["timeSinceLastChange"] = time.Since(cb.lastStateChange).String()
	cb.stateMutex.RUnlock()

	// Configuration
	metrics["config"] = map[string]interface{}{
		"failureThreshold": cb.config.FailureThreshold,
		"successThreshold": cb.config.SuccessThreshold,
		"timeout":          cb.config.Timeout.String(),
		"maxRequests":      cb.config.MaxRequests,
	}

	// Health indicator
	switch state {
	case CircuitBreakerClosed:
		metrics["health"] = "healthy"
	case CircuitBreakerHalfOpen:
		metrics["health"] = "recovering"
	case CircuitBreakerOpen:
		if time.Since(cb.getLastStateChange()) > cb.config.Timeout {
			metrics["health"] = "ready-to-recover"
		} else {
			metrics["health"] = "unhealthy"
		}
	}

	return metrics
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen() {
	atomic.StoreInt32(&cb.state, int32(CircuitBreakerOpen))

	cb.stateMutex.Lock()
	cb.lastStateChange = time.Now()
	cb.stateMutex.Unlock()

	cb.LogInfo("Circuit breaker forced open")
}

// ForceClosed forces the circuit breaker to closed state
func (cb *CircuitBreaker) ForceClosed() {
	atomic.StoreInt32(&cb.state, int32(CircuitBreakerClosed))

	cb.stateMutex.Lock()
	cb.lastStateChange = time.Now()
	cb.stateMutex.Unlock()

	atomic.StoreInt32(&cb.consecutiveFailures, 0)
	atomic.StoreInt32(&cb.consecutiveSuccesses, 0)
	atomic.StoreInt32(&cb.halfOpenRequests, 0)

	cb.LogInfo("Circuit breaker forced closed")
}
