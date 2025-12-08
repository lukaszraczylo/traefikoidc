// Package resilience provides resilience patterns for cache backends.
package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Common errors
var (
	// ErrCircuitOpen is returned when the circuit breaker is open
	ErrCircuitOpen = errors.New("circuit breaker is open")

	// ErrTooManyRequests is returned when too many requests are made in half-open state
	ErrTooManyRequests = errors.New("too many requests in half-open state")
)

// State represents the state of the circuit breaker
type State int32

const (
	// StateClosed allows all operations to pass through
	StateClosed State = iota

	// StateOpen blocks all operations
	StateOpen

	// StateHalfOpen allows a limited number of operations to test recovery
	StateHalfOpen
)

// String returns the string representation of the state
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	// MaxFailures is the number of consecutive failures before opening the circuit
	MaxFailures int

	// FailureThreshold is the failure rate threshold (0.0 to 1.0)
	FailureThreshold float64

	// Timeout is how long the circuit stays open before trying half-open
	Timeout time.Duration

	// HalfOpenMaxRequests is the number of requests allowed in half-open state
	HalfOpenMaxRequests int

	// ResetTimeout is how long to wait before resetting counters in closed state
	ResetTimeout time.Duration

	// OnStateChange is called when the circuit breaker changes state
	OnStateChange func(from, to State)
}

// DefaultCircuitBreakerConfig returns default configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		MaxFailures:         5,
		FailureThreshold:    0.6,
		Timeout:             30 * time.Second,
		HalfOpenMaxRequests: 3,
		ResetTimeout:        60 * time.Second,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config *CircuitBreakerConfig

	// State management
	state           atomic.Int32
	lastStateChange time.Time
	stateMu         sync.RWMutex

	// Failure tracking
	consecutiveFailures atomic.Int32
	totalRequests       atomic.Int64
	totalFailures       atomic.Int64
	halfOpenRequests    atomic.Int32

	// Timing
	lastFailureTime time.Time
	lastSuccessTime time.Time
	nextRetryTime   time.Time
	timeMu          sync.RWMutex

	// Metrics
	stateTransitions atomic.Int64
	rejectedRequests atomic.Int64
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	return &CircuitBreaker{
		config:          config,
		lastStateChange: time.Now(),
	}
}

// Execute runs a function through the circuit breaker
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	if !cb.AllowRequest() {
		cb.rejectedRequests.Add(1)
		return ErrCircuitOpen
	}

	cb.totalRequests.Add(1)

	err := fn()
	if err != nil {
		cb.RecordFailure()
	} else {
		cb.RecordSuccess()
	}

	return err
}

// AllowRequest checks if a request is allowed to proceed
func (cb *CircuitBreaker) AllowRequest() bool {
	state := cb.GetState()

	switch state {
	case StateClosed:
		return true

	case StateOpen:
		// Check if timeout has passed and we should try half-open
		cb.timeMu.RLock()
		shouldRetry := time.Now().After(cb.nextRetryTime)
		cb.timeMu.RUnlock()

		if shouldRetry {
			cb.setState(StateHalfOpen)
			return true
		}
		return false

	case StateHalfOpen:
		// Allow limited requests in half-open state
		current := cb.halfOpenRequests.Add(1)
		// #nosec G115 -- HalfOpenMaxRequests is a small config value that fits in int32
		return current <= int32(cb.config.HalfOpenMaxRequests)

	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.timeMu.Lock()
	cb.lastSuccessTime = time.Now()
	cb.timeMu.Unlock()

	state := cb.GetState()

	switch state {
	case StateClosed:
		// Reset consecutive failures
		cb.consecutiveFailures.Store(0)

	case StateHalfOpen:
		// If we've had enough successful requests, close the circuit
		successfulRequests := cb.halfOpenRequests.Load()
		// #nosec G115 -- HalfOpenMaxRequests is a small config value that fits in int32
		if successfulRequests >= int32(cb.config.HalfOpenMaxRequests) {
			cb.setState(StateClosed)
			cb.consecutiveFailures.Store(0)
			cb.halfOpenRequests.Store(0)
		}
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.totalFailures.Add(1)
	failures := cb.consecutiveFailures.Add(1)

	cb.timeMu.Lock()
	cb.lastFailureTime = time.Now()
	cb.timeMu.Unlock()

	state := cb.GetState()

	switch state {
	case StateClosed:
		// Check if we should open the circuit
		// #nosec G115 -- MaxFailures is a small config value that fits in int32
		if failures >= int32(cb.config.MaxFailures) {
			cb.openCircuit()
		} else if cb.config.FailureThreshold > 0 {
			// Check failure rate
			total := cb.totalRequests.Load()
			failureCount := cb.totalFailures.Load()
			if total > 10 && float64(failureCount)/float64(total) > cb.config.FailureThreshold {
				cb.openCircuit()
			}
		}

	case StateHalfOpen:
		// Any failure in half-open state reopens the circuit
		cb.openCircuit()
	}
}

// openCircuit transitions to open state
func (cb *CircuitBreaker) openCircuit() {
	cb.setState(StateOpen)
	cb.halfOpenRequests.Store(0)

	cb.timeMu.Lock()
	cb.nextRetryTime = time.Now().Add(cb.config.Timeout)
	cb.timeMu.Unlock()
}

// GetState returns the current state
func (cb *CircuitBreaker) GetState() State {
	return State(cb.state.Load())
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(newState State) {
	oldState := State(cb.state.Swap(int32(newState)))

	if oldState != newState {
		cb.stateTransitions.Add(1)

		cb.stateMu.Lock()
		cb.lastStateChange = time.Now()
		cb.stateMu.Unlock()

		if cb.config.OnStateChange != nil {
			cb.config.OnStateChange(oldState, newState)
		}
	}
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.setState(StateClosed)
	cb.consecutiveFailures.Store(0)
	cb.totalRequests.Store(0)
	cb.totalFailures.Store(0)
	cb.halfOpenRequests.Store(0)
	cb.rejectedRequests.Store(0)
	cb.stateTransitions.Store(0)

	now := time.Now()
	cb.timeMu.Lock()
	cb.lastFailureTime = now
	cb.lastSuccessTime = now
	cb.nextRetryTime = now
	cb.timeMu.Unlock()

	cb.stateMu.Lock()
	cb.lastStateChange = now
	cb.stateMu.Unlock()
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.timeMu.RLock()
	lastFailure := cb.lastFailureTime
	lastSuccess := cb.lastSuccessTime
	nextRetry := cb.nextRetryTime
	cb.timeMu.RUnlock()

	cb.stateMu.RLock()
	lastChange := cb.lastStateChange
	cb.stateMu.RUnlock()

	totalReq := cb.totalRequests.Load()
	totalFail := cb.totalFailures.Load()
	successRate := float64(0)
	if totalReq > 0 {
		successRate = float64(totalReq-totalFail) / float64(totalReq)
	}

	return CircuitBreakerStats{
		State:               cb.GetState(),
		ConsecutiveFailures: cb.consecutiveFailures.Load(),
		TotalRequests:       totalReq,
		TotalFailures:       totalFail,
		SuccessRate:         successRate,
		RejectedRequests:    cb.rejectedRequests.Load(),
		StateTransitions:    cb.stateTransitions.Load(),
		LastFailureTime:     lastFailure,
		LastSuccessTime:     lastSuccess,
		LastStateChange:     lastChange,
		NextRetryTime:       nextRetry,
	}
}

// CircuitBreakerStats holds statistics for the circuit breaker
type CircuitBreakerStats struct {
	State               State
	ConsecutiveFailures int32
	TotalRequests       int64
	TotalFailures       int64
	SuccessRate         float64
	RejectedRequests    int64
	StateTransitions    int64
	LastFailureTime     time.Time
	LastSuccessTime     time.Time
	LastStateChange     time.Time
	NextRetryTime       time.Time
}

// IsHealthy returns true if the circuit breaker is in a healthy state
func (cb *CircuitBreaker) IsHealthy() bool {
	return cb.GetState() != StateOpen
}
