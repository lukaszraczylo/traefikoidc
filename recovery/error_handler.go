// Package recovery provides error recovery and resilience mechanisms
package recovery

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// ErrorRecoveryMechanism defines the interface for error recovery strategies.
// It provides a common contract for implementing various resilience patterns
// (circuit breaker, retry, graceful degradation) to handle transient failures
// and protect downstream services from cascading failures.
type ErrorRecoveryMechanism interface {
	// ExecuteWithContext executes a function with error recovery mechanisms
	ExecuteWithContext(ctx context.Context, fn func() error) error
	// GetMetrics returns metrics about the recovery mechanism's performance
	GetMetrics() map[string]interface{}
	// Reset resets the mechanism to its initial state
	Reset()
	// IsAvailable returns whether the mechanism is available for requests
	IsAvailable() bool
}

// Logger interface for dependency injection
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// BaseRecoveryMechanism provides common functionality and metrics tracking
// for all error recovery mechanisms. It handles request/failure/success counting,
// timing information, and logging capabilities for derived recovery mechanisms.
type BaseRecoveryMechanism struct {
	// startTime tracks when the mechanism was created
	startTime time.Time
	// lastFailureTime records the most recent failure timestamp
	lastFailureTime time.Time
	// lastSuccessTime records the most recent success timestamp
	lastSuccessTime time.Time
	// logger for debugging and monitoring
	logger Logger
	// name identifies this recovery mechanism instance
	name string
	// totalRequests counts all requests processed
	totalRequests int64
	// totalFailures counts failed requests
	totalFailures int64
	// totalSuccesses counts successful requests
	totalSuccesses int64
	// mutex protects shared state access
	mutex sync.RWMutex
}

// NewBaseRecoveryMechanism creates a new base recovery mechanism with the given name and logger.
// This serves as the foundation for specific recovery mechanism implementations.
func NewBaseRecoveryMechanism(name string, logger Logger) *BaseRecoveryMechanism {
	if logger == nil {
		logger = NewNoOpLogger()
	}

	return &BaseRecoveryMechanism{
		name:      name,
		logger:    logger,
		startTime: time.Now(),
	}
}

// RecordRequest increments the total request counter.
// This method is thread-safe using atomic operations.
func (b *BaseRecoveryMechanism) RecordRequest() {
	atomic.AddInt64(&b.totalRequests, 1)
}

// RecordSuccess increments the success counter and updates the last success timestamp.
// This method is thread-safe using atomic operations for counters
// and mutex protection for timestamp updates.
func (b *BaseRecoveryMechanism) RecordSuccess() {
	atomic.AddInt64(&b.totalSuccesses, 1)

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.lastSuccessTime = time.Now()
}

// RecordFailure increments the failure counter and updates the last failure timestamp.
// This method is thread-safe using atomic operations for counters
// and mutex protection for timestamp updates.
func (b *BaseRecoveryMechanism) RecordFailure() {
	atomic.AddInt64(&b.totalFailures, 1)

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.lastFailureTime = time.Now()
}

// GetBaseMetrics returns basic metrics collected by the base recovery mechanism.
// This includes request counts, success/failure rates, and timing information.
func (b *BaseRecoveryMechanism) GetBaseMetrics() map[string]interface{} {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	totalReqs := atomic.LoadInt64(&b.totalRequests)
	totalSucc := atomic.LoadInt64(&b.totalSuccesses)
	totalFail := atomic.LoadInt64(&b.totalFailures)

	metrics := map[string]interface{}{
		"name":            b.name,
		"total_requests":  totalReqs,
		"total_successes": totalSucc,
		"total_failures":  totalFail,
		"start_time":      b.startTime,
	}

	if totalReqs > 0 {
		metrics["success_rate"] = float64(totalSucc) / float64(totalReqs)
		metrics["failure_rate"] = float64(totalFail) / float64(totalReqs)
	}

	if !b.lastSuccessTime.IsZero() {
		metrics["last_success_time"] = b.lastSuccessTime
		metrics["time_since_last_success"] = time.Since(b.lastSuccessTime)
	}

	if !b.lastFailureTime.IsZero() {
		metrics["last_failure_time"] = b.lastFailureTime
		metrics["time_since_last_failure"] = time.Since(b.lastFailureTime)
	}

	metrics["uptime"] = time.Since(b.startTime)

	return metrics
}

// LogInfo logs an info message if a logger is available
func (b *BaseRecoveryMechanism) LogInfo(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Infof(format, args...)
	}
}

// LogError logs an error message if a logger is available
func (b *BaseRecoveryMechanism) LogError(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Errorf(format, args...)
	}
}

// LogDebug logs a debug message if a logger is available
func (b *BaseRecoveryMechanism) LogDebug(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Debugf(format, args...)
	}
}

// ErrorHandler provides centralized error handling and recovery coordination
type ErrorHandler struct {
	mechanisms []ErrorRecoveryMechanism
	logger     Logger
	mutex      sync.RWMutex
}

// NewErrorHandler creates a new error handler with the given mechanisms
func NewErrorHandler(logger Logger, mechanisms ...ErrorRecoveryMechanism) *ErrorHandler {
	return &ErrorHandler{
		mechanisms: mechanisms,
		logger:     logger,
	}
}

// AddMechanism adds a recovery mechanism to the handler
func (eh *ErrorHandler) AddMechanism(mechanism ErrorRecoveryMechanism) {
	eh.mutex.Lock()
	defer eh.mutex.Unlock()
	eh.mechanisms = append(eh.mechanisms, mechanism)
}

// ExecuteWithRecovery executes a function with all configured recovery mechanisms
func (eh *ErrorHandler) ExecuteWithRecovery(ctx context.Context, fn func() error) error {
	eh.mutex.RLock()
	mechanisms := make([]ErrorRecoveryMechanism, len(eh.mechanisms))
	copy(mechanisms, eh.mechanisms)
	eh.mutex.RUnlock()

	// If no mechanisms are configured, execute directly
	if len(mechanisms) == 0 {
		return fn()
	}

	// Chain the mechanisms - each wraps the next
	var wrappedFn func() error = fn
	for i := len(mechanisms) - 1; i >= 0; i-- {
		mechanism := mechanisms[i]
		currentFn := wrappedFn
		wrappedFn = func() error {
			return mechanism.ExecuteWithContext(ctx, currentFn)
		}
	}

	return wrappedFn()
}

// GetAllMetrics returns metrics from all configured mechanisms
func (eh *ErrorHandler) GetAllMetrics() map[string]interface{} {
	eh.mutex.RLock()
	defer eh.mutex.RUnlock()

	allMetrics := make(map[string]interface{})
	for i, mechanism := range eh.mechanisms {
		mechanismKey := "mechanism_" + string(rune(i))
		allMetrics[mechanismKey] = mechanism.GetMetrics()
	}

	return allMetrics
}

// ResetAll resets all configured mechanisms
func (eh *ErrorHandler) ResetAll() {
	eh.mutex.RLock()
	defer eh.mutex.RUnlock()

	for _, mechanism := range eh.mechanisms {
		mechanism.Reset()
	}
}

// IsHealthy returns true if all mechanisms are available
func (eh *ErrorHandler) IsHealthy() bool {
	eh.mutex.RLock()
	defer eh.mutex.RUnlock()

	for _, mechanism := range eh.mechanisms {
		if !mechanism.IsAvailable() {
			return false
		}
	}

	return true
}

// NoOpLogger provides a logger that does nothing
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-op logger
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// Infof does nothing
func (l *NoOpLogger) Infof(format string, args ...interface{}) {}

// Errorf does nothing
func (l *NoOpLogger) Errorf(format string, args ...interface{}) {}

// Debugf does nothing
func (l *NoOpLogger) Debugf(format string, args ...interface{}) {}
