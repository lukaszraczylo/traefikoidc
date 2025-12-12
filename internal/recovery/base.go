// Package recovery provides error recovery and resilience mechanisms for OIDC authentication.
package recovery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ErrorRecoveryMechanism defines the interface for error recovery strategies.
// It provides a common contract for implementing various resilience patterns
// such as circuit breakers, retry mechanisms, and fallback strategies.
type ErrorRecoveryMechanism interface {
	// ExecuteWithContext runs a function with error recovery using the provided context
	ExecuteWithContext(ctx context.Context, fn func() error) error
	// Reset resets the recovery mechanism state
	Reset()
	// IsAvailable checks if the mechanism is currently available for use
	IsAvailable() bool
	// GetMetrics returns metrics about the recovery mechanism's performance
	GetMetrics() map[string]interface{}
}

// Logger defines the logging interface
type Logger interface {
	Logf(format string, args ...interface{})
	ErrorLogf(format string, args ...interface{})
	DebugLogf(format string, args ...interface{})
}

// BaseRecoveryMechanism provides common functionality and metrics tracking
// for all recovery mechanism implementations. It handles request counting,
// success/failure tracking, and timestamp management in a thread-safe manner.
type BaseRecoveryMechanism struct {
	logger         Logger
	name           string
	lastSuccessStr string
	lastFailureStr string
	totalRequests  int64
	successCount   int64
	failureCount   int64
	successMutex   sync.RWMutex
	failureMutex   sync.RWMutex
}

// NewBaseRecoveryMechanism creates a new base recovery mechanism with the given name and logger.
// This serves as the foundation for specific recovery mechanism implementations.
// Parameters:
//   - name: Identifier for this recovery mechanism instance
//   - logger: Logger instance for outputting diagnostic information
//
// Returns:
//   - A new BaseRecoveryMechanism instance with initialized metrics
func NewBaseRecoveryMechanism(name string, logger Logger) *BaseRecoveryMechanism {
	return &BaseRecoveryMechanism{
		name:           name,
		logger:         logger,
		totalRequests:  0,
		successCount:   0,
		failureCount:   0,
		lastSuccessStr: "never",
		lastFailureStr: "never",
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
	atomic.AddInt64(&b.successCount, 1)
	b.successMutex.Lock()
	b.lastSuccessStr = time.Now().Format(time.RFC3339)
	b.successMutex.Unlock()
}

// RecordFailure increments the failure counter and updates the last failure timestamp.
// This method is thread-safe using atomic operations for counters
// and mutex protection for timestamp updates.
func (b *BaseRecoveryMechanism) RecordFailure() {
	atomic.AddInt64(&b.failureCount, 1)
	b.failureMutex.Lock()
	b.lastFailureStr = time.Now().Format(time.RFC3339)
	b.failureMutex.Unlock()
}

// GetBaseMetrics returns comprehensive metrics about the recovery mechanism.
// Includes request counts, success/failure rates, timing information,
// and calculated percentages. All access is thread-safe.
func (b *BaseRecoveryMechanism) GetBaseMetrics() map[string]interface{} {
	total := atomic.LoadInt64(&b.totalRequests)
	success := atomic.LoadInt64(&b.successCount)
	failure := atomic.LoadInt64(&b.failureCount)

	b.successMutex.RLock()
	lastSuccess := b.lastSuccessStr
	b.successMutex.RUnlock()

	b.failureMutex.RLock()
	lastFailure := b.lastFailureStr
	b.failureMutex.RUnlock()

	metrics := map[string]interface{}{
		"name":          b.name,
		"totalRequests": total,
		"successCount":  success,
		"failureCount":  failure,
		"lastSuccess":   lastSuccess,
		"lastFailure":   lastFailure,
	}

	// Calculate success and failure rates
	if total > 0 {
		successRate := float64(success) / float64(total) * 100
		failureRate := float64(failure) / float64(total) * 100
		metrics["successRate"] = fmt.Sprintf("%.2f%%", successRate)
		metrics["failureRate"] = fmt.Sprintf("%.2f%%", failureRate)
	} else {
		metrics["successRate"] = "0.00%"
		metrics["failureRate"] = "0.00%"
	}

	return metrics
}

// LogInfo logs an informational message with the mechanism name as prefix.
// Provides consistent logging format across all recovery mechanisms.
func (b *BaseRecoveryMechanism) LogInfo(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Logf("[%s] %s", b.name, fmt.Sprintf(format, args...))
	}
}

// LogError logs an error message with the mechanism name as prefix.
// Used for reporting failures and error conditions in recovery mechanisms.
func (b *BaseRecoveryMechanism) LogError(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.ErrorLogf("[%s] %s", b.name, fmt.Sprintf(format, args...))
	}
}

// LogDebug logs a debug message with the mechanism name as prefix.
// Useful for detailed troubleshooting of recovery mechanism behavior.
func (b *BaseRecoveryMechanism) LogDebug(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.DebugLogf("[%s] %s", b.name, fmt.Sprintf(format, args...))
	}
}

// ErrorType represents different categories of errors
type ErrorType int

const (
	// ErrorTypeUnknown represents an unknown error type
	ErrorTypeUnknown ErrorType = iota
	// ErrorTypeNetwork represents network-related errors
	ErrorTypeNetwork
	// ErrorTypeTimeout represents timeout errors
	ErrorTypeTimeout
	// ErrorTypeAuthentication represents authentication errors
	ErrorTypeAuthentication
	// ErrorTypeRateLimit represents rate limiting errors
	ErrorTypeRateLimit
	// ErrorTypeServerError represents server errors (5xx)
	ErrorTypeServerError
	// ErrorTypeClientError represents client errors (4xx)
	ErrorTypeClientError
)

// HTTPError represents an HTTP error with status code and message
type HTTPError struct {
	Headers    map[string]string
	Message    string
	Body       []byte
	StatusCode int
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// IsRetryable checks if the HTTP error is retryable
func (e *HTTPError) IsRetryable() bool {
	// Retry on 5xx errors and specific 4xx errors
	return e.StatusCode >= 500 || e.StatusCode == 429 || e.StatusCode == 408
}

// OIDCError represents an OIDC-specific error
type OIDCError struct {
	Code        string
	Description string
	URI         string
	State       string
}

// Error implements the error interface
func (e *OIDCError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("OIDC error %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("OIDC error: %s", e.Code)
}

// IsRetryable checks if the OIDC error is retryable
func (e *OIDCError) IsRetryable() bool {
	// Some OIDC errors are retryable
	switch e.Code {
	case "temporarily_unavailable", "server_error":
		return true
	default:
		return false
	}
}

// FallbackMechanism provides a simple fallback recovery strategy
type FallbackMechanism struct {
	*BaseRecoveryMechanism
	fallbackFunc func() error
}

// NewFallbackMechanism creates a new fallback mechanism
func NewFallbackMechanism(name string, logger Logger, fallbackFunc func() error) *FallbackMechanism {
	return &FallbackMechanism{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism(name, logger),
		fallbackFunc:          fallbackFunc,
	}
}

// ExecuteWithContext executes the primary function and falls back on error
func (f *FallbackMechanism) ExecuteWithContext(ctx context.Context, fn func() error) error {
	f.RecordRequest()

	// Check context first
	select {
	case <-ctx.Done():
		f.RecordFailure()
		return ctx.Err()
	default:
	}

	// Try primary function
	if err := fn(); err != nil {
		f.LogInfo("Primary function failed: %v, trying fallback", err)

		// Try fallback
		if f.fallbackFunc != nil {
			if fallbackErr := f.fallbackFunc(); fallbackErr == nil {
				f.RecordSuccess()
				return nil
			} else {
				f.LogError("Fallback also failed: %v", fallbackErr)
				f.RecordFailure()
				return fmt.Errorf("both primary and fallback failed: primary=%v, fallback=%v", err, fallbackErr)
			}
		}

		f.RecordFailure()
		return err
	}

	f.RecordSuccess()
	return nil
}

// Reset resets the fallback mechanism state
func (f *FallbackMechanism) Reset() {
	// Reset metrics
	atomic.StoreInt64(&f.totalRequests, 0)
	atomic.StoreInt64(&f.successCount, 0)
	atomic.StoreInt64(&f.failureCount, 0)

	f.successMutex.Lock()
	f.lastSuccessStr = "never"
	f.successMutex.Unlock()

	f.failureMutex.Lock()
	f.lastFailureStr = "never"
	f.failureMutex.Unlock()
}

// IsAvailable checks if the fallback mechanism is available
func (f *FallbackMechanism) IsAvailable() bool {
	// Fallback is always available
	return true
}

// GetMetrics returns metrics about the fallback mechanism
func (f *FallbackMechanism) GetMetrics() map[string]interface{} {
	metrics := f.GetBaseMetrics()
	metrics["type"] = "fallback"
	metrics["hasFallback"] = f.fallbackFunc != nil
	return metrics
}
