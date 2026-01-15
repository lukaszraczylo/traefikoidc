package traefikoidc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"strings"
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
	logger *Logger
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
// Parameters:
//   - name: Identifier for this recovery mechanism instance
//   - logger: Logger for debugging and monitoring (nil creates no-op logger)
//
// Returns:
//   - A configured BaseRecoveryMechanism instance
func NewBaseRecoveryMechanism(name string, logger *Logger) *BaseRecoveryMechanism {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
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

// GetBaseMetrics returns comprehensive metrics about the recovery mechanism.
// Includes request counts, success/failure rates, timing information,
// and uptime statistics that are common to all recovery mechanisms.
func (b *BaseRecoveryMechanism) GetBaseMetrics() map[string]interface{} {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	metrics := map[string]interface{}{
		"total_requests":  atomic.LoadInt64(&b.totalRequests),
		"total_failures":  atomic.LoadInt64(&b.totalFailures),
		"total_successes": atomic.LoadInt64(&b.totalSuccesses),
		"uptime_seconds":  time.Since(b.startTime).Seconds(),
		"name":            b.name,
	}

	if !b.lastFailureTime.IsZero() {
		metrics["last_failure_time"] = b.lastFailureTime.Format(time.RFC3339)
		metrics["seconds_since_last_failure"] = time.Since(b.lastFailureTime).Seconds()
	}

	if !b.lastSuccessTime.IsZero() {
		metrics["last_success_time"] = b.lastSuccessTime.Format(time.RFC3339)
		metrics["seconds_since_last_success"] = time.Since(b.lastSuccessTime).Seconds()
	}

	totalReq, _ := metrics["total_requests"].(int64)   // Safe to ignore: type assertion with fallback
	totalSucc, _ := metrics["total_successes"].(int64) // Safe to ignore: type assertion with fallback
	if totalReq > 0 {
		successRate := float64(totalSucc) / float64(totalReq)
		metrics["success_rate"] = successRate
	} else {
		metrics["success_rate"] = 1.0
	}

	return metrics
}

// LogInfo logs an informational message with the mechanism name as prefix.
// Provides consistent logging format across all recovery mechanisms.
func (b *BaseRecoveryMechanism) LogInfo(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Infof("%s: "+format, append([]interface{}{b.name}, args...)...)
	}
}

// LogError logs an error message with the mechanism name as prefix.
// Used for reporting failures and error conditions in recovery mechanisms.
func (b *BaseRecoveryMechanism) LogError(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Errorf("%s: "+format, append([]interface{}{b.name}, args...)...)
	}
}

// LogDebug logs a debug message with the mechanism name as prefix.
// Used for detailed debugging information about recovery mechanism operations.
func (b *BaseRecoveryMechanism) LogDebug(format string, args ...interface{}) {
	if b.logger != nil {
		b.logger.Debugf("%s: "+format, append([]interface{}{b.name}, args...)...)
	}
}

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

// CircuitBreaker implements the circuit breaker pattern for external service calls.
// It monitors failure rates and automatically opens the circuit when failures
// exceed the threshold, preventing further requests until the service recovers.
type CircuitBreaker struct {
	// BaseRecoveryMechanism provides common functionality
	*BaseRecoveryMechanism
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
func NewCircuitBreaker(config CircuitBreakerConfig, logger *Logger) *CircuitBreaker {
	return &CircuitBreaker{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("circuit-breaker", logger),
		maxFailures:           config.MaxFailures,
		timeout:               config.Timeout,
		resetTimeout:          config.ResetTimeout,
		state:                 CircuitBreakerClosed,
	}
}

// ExecuteWithContext executes a function through the circuit breaker with context.
// It checks if requests are allowed, executes the function, and updates the circuit state
// based on the result. Implements the ErrorRecoveryMechanism interface.
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func() error) error {
	cb.RecordRequest()

	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}

	err := fn()
	if err != nil {
		cb.recordFailure()
		cb.RecordFailure()
		return err
	}

	cb.recordSuccess()
	cb.RecordSuccess()
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
			cb.logger.Infof("Circuit breaker transitioning to half-open state")
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

	switch cb.state {
	case CircuitBreakerClosed:
		if cb.failures >= int64(cb.maxFailures) {
			cb.state = CircuitBreakerOpen
			cb.LogError("Circuit breaker opened after %d failures", cb.failures)
		}

	case CircuitBreakerHalfOpen:
		cb.state = CircuitBreakerOpen
		cb.LogError("Circuit breaker returned to open state after failure in half-open")
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
		cb.LogInfo("Circuit breaker closed after successful request in half-open state")

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
	cb.LogInfo("Circuit breaker has been reset")
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
	cb.mutex.RUnlock()

	metrics := cb.GetBaseMetrics()

	stateStr := "unknown"
	switch state {
	case CircuitBreakerClosed:
		stateStr = "closed"
	case CircuitBreakerOpen:
		stateStr = "open"
	case CircuitBreakerHalfOpen:
		stateStr = "half-open"
	}

	metrics["state"] = stateStr
	metrics["max_failures"] = cb.maxFailures
	metrics["current_failures"] = failures
	metrics["timeout_ms"] = cb.timeout.Milliseconds()
	metrics["reset_timeout_ms"] = cb.resetTimeout.Milliseconds()

	return metrics
}

// RetryConfig holds configuration parameters for retry mechanisms.
// Controls retry behavior including which errors to retry, timing, and backoff strategy.
type RetryConfig struct {
	// RetryableErrors defines error patterns that should trigger retries
	RetryableErrors []string `json:"retryable_errors"`
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int `json:"max_attempts"`
	// InitialDelay is the delay before the first retry
	InitialDelay time.Duration `json:"initial_delay"`
	// MaxDelay caps the maximum delay between retries
	MaxDelay time.Duration `json:"max_delay"`
	// BackoffFactor multiplies delay between attempts (exponential backoff)
	BackoffFactor float64 `json:"backoff_factor"`
	// EnableJitter adds randomness to delays to prevent thundering herd
	EnableJitter bool `json:"enable_jitter"`
}

// DefaultRetryConfig returns sensible default configuration for retry mechanisms.
// Configured with exponential backoff, jitter, and common retryable error patterns.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		EnableJitter:  true,
		RetryableErrors: []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"network unreachable",
		},
	}
}

// MetadataFetchRetryConfig returns retry configuration optimized for OIDC metadata
// fetching during startup. Uses more aggressive retry settings to handle the race
// condition where Traefik initializes the plugin before routes are fully established,
// or before TLS certificates are properly loaded.
// See: https://github.com/lukaszraczylo/traefikoidc/issues/90
func MetadataFetchRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   10,               // More attempts for startup scenarios
		InitialDelay:  1 * time.Second,  // 1 second between attempts as suggested
		MaxDelay:      10 * time.Second, // Cap at 10 seconds
		BackoffFactor: 1.5,              // Gentler backoff for startup
		EnableJitter:  true,             // Prevent thundering herd
		RetryableErrors: []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"network unreachable",
			"EOF",
			"certificate",
			"x509",
			"tls",
		},
	}
}

// RetryExecutor implements retry logic with exponential backoff and jitter.
// It automatically retries failed operations based on configurable error patterns
// and uses exponential backoff to avoid overwhelming failing services.
type RetryExecutor struct {
	// BaseRecoveryMechanism provides common functionality
	*BaseRecoveryMechanism
	// config contains retry behavior configuration
	config RetryConfig
}

// NewRetryExecutor creates a new retry executor with the specified configuration.
// The executor will retry operations according to the provided configuration.
func NewRetryExecutor(config RetryConfig, logger *Logger) *RetryExecutor {
	return &RetryExecutor{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("retry-executor", logger),
		config:                config,
	}
}

// ExecuteWithContext executes a function with retry logic and exponential backoff.
// Retries failed operations based on error patterns and respects context cancellation.
// Implements the ErrorRecoveryMechanism interface.
func (re *RetryExecutor) ExecuteWithContext(ctx context.Context, fn func() error) error {
	re.RecordRequest()
	var lastErr error

	for attempt := 1; attempt <= re.config.MaxAttempts; attempt++ {
		err := fn()
		if err == nil {
			if attempt > 1 {
				re.LogInfo("Operation succeeded after %d attempts", attempt)
			}
			re.RecordSuccess()
			return nil
		}

		lastErr = err

		if !re.isRetryableError(err) {
			re.RecordFailure()
			return err
		}

		if attempt == re.config.MaxAttempts {
			re.RecordFailure()
			break
		}

		delay := re.calculateDelay(attempt)
		if attempt == 1 || attempt%3 == 0 {
			re.LogDebug("Retrying operation after %v (attempt %d/%d): %v",
				delay, attempt, re.config.MaxAttempts, err)
		}

		select {
		case <-ctx.Done():
			re.RecordFailure()
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	finalErr := fmt.Errorf("operation failed after %d attempts: %w", re.config.MaxAttempts, lastErr)
	return finalErr
}

// Execute runs the given function with retry logic (for backward compatibility)
// Execute executes a function with retry logic (backward compatibility).
// This method provides the same functionality as ExecuteWithContext.
func (re *RetryExecutor) Execute(ctx context.Context, fn func() error) error {
	return re.ExecuteWithContext(ctx, fn)
}

// isRetryableError checks if an error should trigger a retry
// isRetryableError determines if an error should trigger a retry attempt.
// Checks error message against configured retryable error patterns.
// Also handles startup-specific errors like Traefik default certificate errors
// and EOF errors that occur during service initialization.
func (re *RetryExecutor) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Traefik default certificate error (startup race condition)
	// See: https://github.com/lukaszraczylo/traefikoidc/issues/90
	if isTraefikDefaultCertError(err) {
		return true
	}

	// Check for EOF errors (common during startup when services aren't ready)
	if isEOFError(err) {
		return true
	}

	// Check for certificate errors (transient during startup)
	if isCertificateError(err) {
		return true
	}

	errStr := err.Error()

	for _, retryableErr := range re.config.RetryableErrors {
		if contains(errStr, retryableErr) {
			return true
		}
	}

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return true
		}
		errStr := netErr.Error()
		temporaryPatterns := []string{
			"connection refused",
			"connection reset",
			"network is unreachable",
			"no route to host",
			"temporary failure",
			"try again",
			"resource temporarily unavailable",
		}
		for _, pattern := range temporaryPatterns {
			if contains(errStr, pattern) {
				return true
			}
		}
	}

	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.StatusCode >= 500 || httpErr.StatusCode == 429
	}

	return false
}

// calculateDelay calculates the delay for the next retry attempt
// calculateDelay computes the delay before the next retry attempt.
// Uses exponential backoff with optional jitter to prevent thundering herd.
func (re *RetryExecutor) calculateDelay(attempt int) time.Duration {
	delay := float64(re.config.InitialDelay) * math.Pow(re.config.BackoffFactor, float64(attempt-1))

	if delay > float64(re.config.MaxDelay) {
		delay = float64(re.config.MaxDelay)
	}

	// #nosec G404 -- math/rand is acceptable for jitter timing, not security-sensitive
	if re.config.EnableJitter {
		jitter := delay * 0.1 * (2.0*rand.Float64() - 1.0)
		delay += jitter
	}

	return time.Duration(delay)
}

// Reset resets the retry executor state
// Reset clears any internal state of the retry executor.
// For RetryExecutor, this is primarily a logging operation.
func (re *RetryExecutor) Reset() {
	re.LogDebug("Retry executor reset")
}

// IsAvailable always returns true for RetryExecutor
// IsAvailable returns whether the retry executor is available.
// Always returns true as retry executors don't have availability state.
func (re *RetryExecutor) IsAvailable() bool {
	return true
}

// GetMetrics returns metrics about the retry executor
// GetMetrics returns comprehensive metrics about the retry executor.
// Includes base metrics plus retry-specific configuration information.
func (re *RetryExecutor) GetMetrics() map[string]interface{} {
	metrics := re.GetBaseMetrics()

	metrics["max_attempts"] = re.config.MaxAttempts
	metrics["initial_delay_ms"] = re.config.InitialDelay.Milliseconds()
	metrics["max_delay_ms"] = re.config.MaxDelay.Milliseconds()
	metrics["backoff_factor"] = re.config.BackoffFactor
	metrics["enable_jitter"] = re.config.EnableJitter
	metrics["retryable_errors"] = re.config.RetryableErrors

	return metrics
}

// HTTPError represents an HTTP error with status code and message.
// Used for categorizing HTTP-related errors in error recovery mechanisms.
type HTTPError struct {
	// Message is the error description
	Message string
	// StatusCode is the HTTP status code
	StatusCode int
}

// Error returns the string representation of the HTTP error.
// Implements the error interface.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// OIDCError represents OIDC-specific errors with context information.
// It provides structured error reporting for authentication and authorization failures.
type OIDCError struct {
	Cause   error
	Context map[string]interface{}
	Code    string
	Message string
}

// Error returns the string representation of the OIDC error.
// Implements the error interface.
func (e *OIDCError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("OIDC error [%s]: %s - caused by: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("OIDC error [%s]: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error chain unwrapping.
func (e *OIDCError) Unwrap() error {
	return e.Cause
}

// SessionError represents session-related errors with context.
// Used for session management, validation, and storage errors.
type SessionError struct {
	Cause     error
	Operation string
	Message   string
	SessionID string
}

// Error returns the string representation of the session error.
// Implements the error interface.
func (e *SessionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("Session error in %s: %s - caused by: %v", e.Operation, e.Message, e.Cause)
	}
	return fmt.Sprintf("Session error in %s: %s", e.Operation, e.Message)
}

// Unwrap returns the underlying error for error chain unwrapping.
func (e *SessionError) Unwrap() error {
	return e.Cause
}

// TokenError represents token-related errors with validation context.
// Used for JWT validation, token refresh, and token format errors.
type TokenError struct {
	Cause     error
	TokenType string
	Reason    string
	Message   string
}

// Error returns the string representation of the token error.
// Implements the error interface.
func (e *TokenError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("Token error (%s) - %s: %s - caused by: %v", e.TokenType, e.Reason, e.Message, e.Cause)
	}
	return fmt.Sprintf("Token error (%s) - %s: %s", e.TokenType, e.Reason, e.Message)
}

// Unwrap returns the underlying error for error chain unwrapping.
func (e *TokenError) Unwrap() error {
	return e.Cause
}

// NewOIDCError creates a new OIDC error with context.
func NewOIDCError(code, message string, cause error) *OIDCError {
	return &OIDCError{
		Code:    code,
		Message: message,
		Context: make(map[string]interface{}),
		Cause:   cause,
	}
}

// WithContext adds context information to the OIDC error.
func (e *OIDCError) WithContext(key string, value interface{}) *OIDCError {
	e.Context[key] = value
	return e
}

// NewSessionError creates a new session error with operation context.
func NewSessionError(operation, message string, cause error) *SessionError {
	return &SessionError{
		Operation: operation,
		Message:   message,
		Cause:     cause,
	}
}

// WithSessionID adds session ID to the session error.
func (e *SessionError) WithSessionID(sessionID string) *SessionError {
	e.SessionID = sessionID
	return e
}

// NewTokenError creates a new token error with type and reason.
func NewTokenError(tokenType, reason, message string, cause error) *TokenError {
	return &TokenError{
		TokenType: tokenType,
		Reason:    reason,
		Message:   message,
		Cause:     cause,
	}
}

// GracefulDegradation implements graceful degradation patterns for service resilience.
// It provides fallback mechanisms when primary services are unavailable and monitors
// service health to automatically recover when services become available again.
type GracefulDegradation struct {
	*BaseRecoveryMechanism
	fallbacks        map[string]func() (interface{}, error)
	healthChecks     map[string]func() bool
	degradedServices map[string]time.Time
	healthCheckTask  *BackgroundTask
	stopChan         chan struct{}
	config           GracefulDegradationConfig
	mutex            sync.RWMutex
	shutdownOnce     sync.Once
}

// GracefulDegradationConfig holds configuration for graceful degradation behavior.
// Controls health checking frequency, recovery timing, and fallback enablement.
type GracefulDegradationConfig struct {
	// HealthCheckInterval defines how often to check service health
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	// RecoveryTimeout is how long to wait before attempting service recovery
	RecoveryTimeout time.Duration `json:"recovery_timeout"`
	// EnableFallbacks controls whether fallback mechanisms are active
	EnableFallbacks bool `json:"enable_fallbacks"`
}

// DefaultGracefulDegradationConfig returns sensible defaults for graceful degradation.
// Configured with moderate health check frequency and recovery timeouts.
func DefaultGracefulDegradationConfig() GracefulDegradationConfig {
	return GracefulDegradationConfig{
		HealthCheckInterval: 30 * time.Second,
		RecoveryTimeout:     5 * time.Minute,
		EnableFallbacks:     true,
	}
}

// NewGracefulDegradation creates a new graceful degradation manager
// NewGracefulDegradation creates a new graceful degradation mechanism.
// Initializes fallback and health check maps and starts background health monitoring.
func NewGracefulDegradation(config GracefulDegradationConfig, logger *Logger) *GracefulDegradation {
	gd := &GracefulDegradation{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("graceful-degradation", logger),
		fallbacks:             make(map[string]func() (interface{}, error)),
		healthChecks:          make(map[string]func() bool),
		degradedServices:      make(map[string]time.Time),
		config:                config,
	}

	gd.stopChan = make(chan struct{})
	go gd.startHealthCheckRoutine()

	return gd
}

// RegisterFallback registers a fallback function for a service
func (gd *GracefulDegradation) RegisterFallback(serviceName string, fallback func() (interface{}, error)) {
	gd.mutex.Lock()
	defer gd.mutex.Unlock()
	gd.fallbacks[serviceName] = fallback
}

// RegisterHealthCheck registers a health check function for a service
func (gd *GracefulDegradation) RegisterHealthCheck(serviceName string, healthCheck func() bool) {
	gd.mutex.Lock()
	defer gd.mutex.Unlock()
	gd.healthChecks[serviceName] = healthCheck
}

// ExecuteWithContext implements the ErrorRecoveryMechanism interface
func (gd *GracefulDegradation) ExecuteWithContext(ctx context.Context, fn func() error) error {
	gd.RecordRequest()

	_, err := gd.ExecuteWithFallback("default", func() (interface{}, error) {
		return nil, fn()
	})

	if err != nil {
		gd.RecordFailure()
	} else {
		gd.RecordSuccess()
	}

	return err
}

// ExecuteWithFallback executes a function with fallback support
func (gd *GracefulDegradation) ExecuteWithFallback(serviceName string, primary func() (interface{}, error)) (interface{}, error) {
	if gd.isServiceDegraded(serviceName) {
		gd.LogInfo("Service %s is degraded, using fallback", serviceName)
		return gd.executeFallback(serviceName)
	}

	result, err := primary()
	if err != nil {
		gd.markServiceDegraded(serviceName)
		gd.LogError("Service %s failed: %v", serviceName, err)

		if gd.config.EnableFallbacks {
			gd.LogInfo("Using fallback for service %s", serviceName)
			return gd.executeFallback(serviceName)
		}

		return nil, err
	}

	return result, nil
}

// isServiceDegraded checks if a service is currently degraded
func (gd *GracefulDegradation) isServiceDegraded(serviceName string) bool {
	gd.mutex.RLock()
	defer gd.mutex.RUnlock()

	degradedTime, exists := gd.degradedServices[serviceName]
	if !exists {
		return false
	}

	if time.Since(degradedTime) > gd.config.RecoveryTimeout {
		delete(gd.degradedServices, serviceName)
		return false
	}

	return true
}

// markServiceDegraded marks a service as degraded
func (gd *GracefulDegradation) markServiceDegraded(serviceName string) {
	gd.mutex.Lock()
	defer gd.mutex.Unlock()

	if _, exists := gd.degradedServices[serviceName]; !exists {
		gd.LogError("Service %s marked as degraded", serviceName)
	}

	gd.degradedServices[serviceName] = time.Now()
}

// executeFallback executes the fallback function for a service
func (gd *GracefulDegradation) executeFallback(serviceName string) (interface{}, error) {
	gd.mutex.RLock()
	fallback, exists := gd.fallbacks[serviceName]
	gd.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no fallback available for service %s", serviceName)
	}

	gd.LogInfo("Executing fallback for degraded service %s", serviceName)
	return fallback()
}

// startHealthCheckRoutine starts the background health check routine
func (gd *GracefulDegradation) startHealthCheckRoutine() {
	// Use singleton task registry to prevent multiple instances
	registry := GetGlobalTaskRegistry()

	task, err := registry.CreateSingletonTask(
		"graceful-degradation-health-check",
		gd.config.HealthCheckInterval,
		gd.performHealthChecks,
		gd.BaseRecoveryMechanism.logger,
		nil, // No specific wait group
	)

	if err != nil {
		gd.BaseRecoveryMechanism.logger.Errorf("Failed to create health check task: %v", err)
		return
	}

	gd.mutex.Lock()
	gd.healthCheckTask = task
	gd.mutex.Unlock()

	task.Start()
}

// performHealthChecks runs health checks for all registered services
func (gd *GracefulDegradation) performHealthChecks() {
	gd.mutex.RLock()
	healthChecks := make(map[string]func() bool)
	for k, v := range gd.healthChecks {
		healthChecks[k] = v
	}
	gd.mutex.RUnlock()

	for serviceName, healthCheck := range healthChecks {
		if healthCheck() {
			gd.mutex.Lock()
			if _, wasDegraded := gd.degradedServices[serviceName]; wasDegraded {
				delete(gd.degradedServices, serviceName)
				gd.logger.Infof("Service %s recovered from degraded state", serviceName)
			}
			gd.mutex.Unlock()
		} else {
			gd.markServiceDegraded(serviceName)
		}
	}
}

// GetDegradedServices returns a list of currently degraded services
func (gd *GracefulDegradation) GetDegradedServices() []string {
	gd.mutex.RLock()
	defer gd.mutex.RUnlock()

	degraded := make([]string, 0, len(gd.degradedServices))
	for serviceName := range gd.degradedServices {
		degraded = append(degraded, serviceName)
	}

	return degraded
}

// Reset resets the state of all degraded services
func (gd *GracefulDegradation) Reset() {
	gd.mutex.Lock()
	defer gd.mutex.Unlock()

	gd.degradedServices = make(map[string]time.Time)
	gd.LogInfo("Graceful degradation state has been reset")
}

// Close shuts down the graceful degradation system and cleans up resources
func (gd *GracefulDegradation) Close() {
	gd.shutdownOnce.Do(func() {
		// Signal shutdown
		select {
		case <-gd.stopChan:
			// Already closed
		default:
			close(gd.stopChan)
		}

		// Stop health check task
		gd.mutex.Lock()
		task := gd.healthCheckTask
		gd.mutex.Unlock()

		if task != nil {
			task.Stop()
			// Don't set to nil to avoid race conditions
		}

		gd.logger.Debug("GracefulDegradation shut down successfully")
	})
}

// IsAvailable returns whether the mechanism is available for use
func (gd *GracefulDegradation) IsAvailable() bool {
	return true
}

// GetMetrics returns metrics about the graceful degradation mechanism
func (gd *GracefulDegradation) GetMetrics() map[string]interface{} {
	gd.mutex.RLock()
	degradedCount := len(gd.degradedServices)

	degradedServices := make([]string, 0, degradedCount)
	for service := range gd.degradedServices {
		degradedServices = append(degradedServices, service)
	}

	fallbackCount := len(gd.fallbacks)
	healthCheckCount := len(gd.healthChecks)
	gd.mutex.RUnlock()

	metrics := gd.GetBaseMetrics()

	metrics["degraded_services_count"] = degradedCount
	metrics["degraded_services"] = degradedServices
	metrics["registered_fallbacks_count"] = fallbackCount
	metrics["registered_health_checks_count"] = healthCheckCount
	metrics["health_check_interval_seconds"] = gd.config.HealthCheckInterval.Seconds()
	metrics["recovery_timeout_seconds"] = gd.config.RecoveryTimeout.Seconds()
	metrics["fallbacks_enabled"] = gd.config.EnableFallbacks

	return metrics
}

// ErrorRecoveryManager coordinates all error recovery mechanisms
type ErrorRecoveryManager struct {
	circuitBreakers     map[string]*CircuitBreaker
	retryExecutor       *RetryExecutor
	gracefulDegradation *GracefulDegradation
	logger              *Logger
	mutex               sync.RWMutex
}

// NewErrorRecoveryManager creates a new error recovery manager
// NewErrorRecoveryManager creates a comprehensive error recovery manager.
// Combines circuit breakers, retry logic, and graceful degradation into a unified system.
func NewErrorRecoveryManager(logger *Logger) *ErrorRecoveryManager {
	return &ErrorRecoveryManager{
		circuitBreakers:     make(map[string]*CircuitBreaker),
		retryExecutor:       NewRetryExecutor(DefaultRetryConfig(), logger),
		gracefulDegradation: NewGracefulDegradation(DefaultGracefulDegradationConfig(), logger),
		logger:              logger,
	}
}

// GetCircuitBreaker gets or creates a circuit breaker for a service
// GetCircuitBreaker returns the circuit breaker for a specific service.
// Creates a new circuit breaker if one doesn't exist for the service.
func (erm *ErrorRecoveryManager) GetCircuitBreaker(serviceName string) *CircuitBreaker {
	erm.mutex.Lock()
	defer erm.mutex.Unlock()

	if cb, exists := erm.circuitBreakers[serviceName]; exists {
		return cb
	}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), erm.logger)
	erm.circuitBreakers[serviceName] = cb
	return cb
}

// ExecuteWithRecovery executes a function with full error recovery support
// ExecuteWithRecovery executes a function with comprehensive error recovery.
// Applies circuit breaker protection and retry logic for the specified service.
func (erm *ErrorRecoveryManager) ExecuteWithRecovery(ctx context.Context, serviceName string, fn func() error) error {
	cb := erm.GetCircuitBreaker(serviceName)

	return erm.retryExecutor.Execute(ctx, func() error {
		return cb.Execute(fn)
	})
}

// GetRecoveryMetrics returns metrics for all recovery mechanisms
// GetRecoveryMetrics returns comprehensive metrics for all recovery mechanisms.
// Includes circuit breaker states, retry statistics, and graceful degradation status.
func (erm *ErrorRecoveryManager) GetRecoveryMetrics() map[string]interface{} {
	erm.mutex.RLock()
	defer erm.mutex.RUnlock()

	metrics := make(map[string]interface{})

	cbMetrics := make(map[string]interface{})
	for name, cb := range erm.circuitBreakers {
		cbMetrics[name] = cb.GetMetrics()
	}
	metrics["circuit_breakers"] = cbMetrics

	metrics["degraded_services"] = erm.gracefulDegradation.GetDegradedServices()

	return metrics
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// isTraefikDefaultCertError detects when Traefik is serving its default self-signed
// certificate during cold-start, before the real certificates are loaded.
// This manifests as an x509.HostnameError where one of the certificate's DNS names
// ends with "traefik.default" (the default Traefik certificate pattern).
// See: https://github.com/lukaszraczylo/traefikoidc/issues/90
func isTraefikDefaultCertError(err error) bool {
	if err == nil {
		return false
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		if hostnameErr.Certificate != nil {
			for _, name := range hostnameErr.Certificate.DNSNames {
				if strings.HasSuffix(name, "traefik.default") {
					return true
				}
			}
		}
	}

	return false
}

// isEOFError checks if an error is an EOF error, which can occur during
// connection establishment when the remote end closes unexpectedly.
// This is common during service startup when endpoints aren't fully ready.
func isEOFError(err error) bool {
	if err == nil {
		return false
	}

	// Check for direct EOF
	if errors.Is(err, io.EOF) {
		return true
	}

	// Check for unexpected EOF
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Check error message for EOF patterns (wrapped errors)
	errStr := err.Error()
	return strings.Contains(errStr, "EOF") || strings.Contains(errStr, "unexpected EOF")
}

// isCertificateError checks if an error is related to TLS certificate validation.
// These errors are often transient during startup when services are still initializing.
func isCertificateError(err error) bool {
	if err == nil {
		return false
	}

	// Check for x509 certificate errors
	var certInvalidErr x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var unknownAuthErr x509.UnknownAuthorityError

	if errors.As(err, &certInvalidErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &unknownAuthErr) {
		return true
	}

	// Check error message for certificate patterns
	errStr := strings.ToLower(err.Error())
	certPatterns := []string{
		"certificate",
		"x509",
		"tls",
		"ssl",
	}

	for _, pattern := range certPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}
