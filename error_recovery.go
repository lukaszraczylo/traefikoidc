package traefikoidc

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// CircuitBreakerState represents the current state of a circuit breaker
type CircuitBreakerState int

const (
	// CircuitBreakerClosed - normal operation, requests are allowed
	CircuitBreakerClosed CircuitBreakerState = iota
	// CircuitBreakerOpen - circuit is open, requests are rejected
	CircuitBreakerOpen
	// CircuitBreakerHalfOpen - testing if service has recovered
	CircuitBreakerHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for external service calls
type CircuitBreaker struct {
	// Configuration
	maxFailures  int           // Maximum failures before opening
	timeout      time.Duration // How long to wait before trying again
	resetTimeout time.Duration // How long to wait in half-open state

	// State
	state           CircuitBreakerState
	failures        int64
	lastFailureTime time.Time
	lastSuccessTime time.Time
	mutex           sync.RWMutex

	// Metrics
	totalRequests  int64
	totalFailures  int64
	totalSuccesses int64

	// Logger
	logger *Logger
}

// CircuitBreakerConfig holds configuration for circuit breakers
type CircuitBreakerConfig struct {
	MaxFailures  int           `json:"max_failures"`
	Timeout      time.Duration `json:"timeout"`
	ResetTimeout time.Duration `json:"reset_timeout"`
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:  5,
		Timeout:      30 * time.Second,
		ResetTimeout: 10 * time.Second,
	}
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig, logger *Logger) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  config.MaxFailures,
		timeout:      config.Timeout,
		resetTimeout: config.ResetTimeout,
		state:        CircuitBreakerClosed,
		logger:       logger,
	}
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	atomic.AddInt64(&cb.totalRequests, 1)

	// Check if circuit breaker allows the request
	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}

	// Execute the function
	err := fn()
	// Record the result
	if err != nil {
		cb.recordFailure()
		atomic.AddInt64(&cb.totalFailures, 1)
		return err
	}

	cb.recordSuccess()
	atomic.AddInt64(&cb.totalSuccesses, 1)
	return nil
}

// allowRequest checks if the circuit breaker allows the request
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		return true

	case CircuitBreakerOpen:
		// Check if timeout has passed
		if now.Sub(cb.lastFailureTime) > cb.timeout {
			cb.state = CircuitBreakerHalfOpen
			cb.logger.Infof("Circuit breaker transitioning to half-open state")
			return true
		}
		return false

	case CircuitBreakerHalfOpen:
		// Allow limited requests in half-open state
		return true

	default:
		return false
	}
}

// recordFailure records a failure and potentially opens the circuit
func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		if cb.failures >= int64(cb.maxFailures) {
			cb.state = CircuitBreakerOpen
			cb.logger.Errorf("Circuit breaker opened after %d failures", cb.failures)
		}

	case CircuitBreakerHalfOpen:
		// Go back to open state on any failure in half-open
		cb.state = CircuitBreakerOpen
		cb.logger.Errorf("Circuit breaker returned to open state after failure in half-open")
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.lastSuccessTime = time.Now()

	switch cb.state {
	case CircuitBreakerHalfOpen:
		// Reset failures and close circuit on success in half-open
		cb.failures = 0
		cb.state = CircuitBreakerClosed
		cb.logger.Infof("Circuit breaker closed after successful request in half-open state")

	case CircuitBreakerClosed:
		// Reset failure count on success
		cb.failures = 0
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetMetrics returns circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() map[string]interface{} {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	return map[string]interface{}{
		"state":           cb.state,
		"failures":        cb.failures,
		"total_requests":  atomic.LoadInt64(&cb.totalRequests),
		"total_failures":  atomic.LoadInt64(&cb.totalFailures),
		"total_successes": atomic.LoadInt64(&cb.totalSuccesses),
		"last_failure":    cb.lastFailureTime,
		"last_success":    cb.lastSuccessTime,
	}
}

// RetryConfig holds configuration for retry mechanisms
type RetryConfig struct {
	MaxAttempts     int           `json:"max_attempts"`
	InitialDelay    time.Duration `json:"initial_delay"`
	MaxDelay        time.Duration `json:"max_delay"`
	BackoffFactor   float64       `json:"backoff_factor"`
	EnableJitter    bool          `json:"enable_jitter"`
	RetryableErrors []string      `json:"retryable_errors"`
}

// DefaultRetryConfig returns default retry configuration
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

// RetryExecutor implements retry logic with exponential backoff
type RetryExecutor struct {
	config RetryConfig
	logger *Logger
}

// NewRetryExecutor creates a new retry executor
func NewRetryExecutor(config RetryConfig, logger *Logger) *RetryExecutor {
	return &RetryExecutor{
		config: config,
		logger: logger,
	}
}

// Execute runs the given function with retry logic
func (re *RetryExecutor) Execute(ctx context.Context, fn func() error) error {
	var lastErr error

	for attempt := 1; attempt <= re.config.MaxAttempts; attempt++ {
		// Execute the function
		err := fn()
		if err == nil {
			if attempt > 1 {
				re.logger.Infof("Operation succeeded on attempt %d", attempt)
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !re.isRetryableError(err) {
			re.logger.Debugf("Non-retryable error on attempt %d: %v", attempt, err)
			return err
		}

		// Don't wait after the last attempt
		if attempt == re.config.MaxAttempts {
			break
		}

		// Calculate delay with exponential backoff
		delay := re.calculateDelay(attempt)
		re.logger.Debugf("Retrying operation after %v (attempt %d/%d): %v",
			delay, attempt, re.config.MaxAttempts, err)

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", re.config.MaxAttempts, lastErr)
}

// isRetryableError checks if an error should trigger a retry
func (re *RetryExecutor) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Check against configured retryable errors
	for _, retryableErr := range re.config.RetryableErrors {
		if contains(errStr, retryableErr) {
			return true
		}
	}

	// Check for common network errors using modern Go error handling
	if netErr, ok := err.(net.Error); ok {
		// Use Timeout() method which is still valid
		if netErr.Timeout() {
			return true
		}
		// Check for specific temporary error patterns instead of deprecated Temporary()
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

	// Check for HTTP status codes that are retryable
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.StatusCode >= 500 || httpErr.StatusCode == 429
	}

	return false
}

// calculateDelay calculates the delay for the next retry attempt
func (re *RetryExecutor) calculateDelay(attempt int) time.Duration {
	// Calculate exponential backoff
	delay := float64(re.config.InitialDelay) * math.Pow(re.config.BackoffFactor, float64(attempt-1))

	// Apply maximum delay limit
	if delay > float64(re.config.MaxDelay) {
		delay = float64(re.config.MaxDelay)
	}

	// Add jitter to prevent thundering herd
	if re.config.EnableJitter {
		jitter := delay * 0.1 * (2.0*rand.Float64() - 1.0) // ±10% jitter
		delay += jitter
	}

	return time.Duration(delay)
}

// HTTPError represents an HTTP error with status code
type HTTPError struct {
	StatusCode int
	Message    string
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// GracefulDegradation implements graceful degradation patterns
type GracefulDegradation struct {
	// Fallback functions for different operations
	fallbacks map[string]func() (interface{}, error)

	// Health checks for dependencies
	healthChecks map[string]func() bool

	// Configuration
	config GracefulDegradationConfig

	// State tracking
	degradedServices map[string]time.Time
	mutex            sync.RWMutex

	logger *Logger
}

// GracefulDegradationConfig holds configuration for graceful degradation
type GracefulDegradationConfig struct {
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	RecoveryTimeout     time.Duration `json:"recovery_timeout"`
	EnableFallbacks     bool          `json:"enable_fallbacks"`
}

// DefaultGracefulDegradationConfig returns default configuration
func DefaultGracefulDegradationConfig() GracefulDegradationConfig {
	return GracefulDegradationConfig{
		HealthCheckInterval: 30 * time.Second,
		RecoveryTimeout:     5 * time.Minute,
		EnableFallbacks:     true,
	}
}

// NewGracefulDegradation creates a new graceful degradation manager
func NewGracefulDegradation(config GracefulDegradationConfig, logger *Logger) *GracefulDegradation {
	gd := &GracefulDegradation{
		fallbacks:        make(map[string]func() (interface{}, error)),
		healthChecks:     make(map[string]func() bool),
		degradedServices: make(map[string]time.Time),
		config:           config,
		logger:           logger,
	}

	// Start health check routine
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

// ExecuteWithFallback executes a function with fallback support
func (gd *GracefulDegradation) ExecuteWithFallback(serviceName string, primary func() (interface{}, error)) (interface{}, error) {
	// Check if service is degraded
	if gd.isServiceDegraded(serviceName) {
		return gd.executeFallback(serviceName)
	}

	// Try primary function
	result, err := primary()
	if err != nil {
		// Mark service as degraded
		gd.markServiceDegraded(serviceName)

		// Try fallback if available
		if gd.config.EnableFallbacks {
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

	// Check if recovery timeout has passed
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
		gd.logger.Errorf("Service %s marked as degraded", serviceName)
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

	gd.logger.Infof("Executing fallback for degraded service %s", serviceName)
	return fallback()
}

// startHealthCheckRoutine starts the background health check routine
func (gd *GracefulDegradation) startHealthCheckRoutine() {
	ticker := time.NewTicker(gd.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		gd.performHealthChecks()
	}
}

// performHealthChecks runs health checks for all registered services
func (gd *GracefulDegradation) performHealthChecks() {
	gd.mutex.RLock()
	healthChecks := make(map[string]func() bool)
	for name, check := range gd.healthChecks {
		healthChecks[name] = check
	}
	gd.mutex.RUnlock()

	for serviceName, healthCheck := range healthChecks {
		if healthCheck() {
			// Service is healthy, remove from degraded list
			gd.mutex.Lock()
			if _, wasDegraded := gd.degradedServices[serviceName]; wasDegraded {
				delete(gd.degradedServices, serviceName)
				gd.logger.Infof("Service %s recovered from degraded state", serviceName)
			}
			gd.mutex.Unlock()
		} else {
			// Service is unhealthy, mark as degraded
			gd.markServiceDegraded(serviceName)
		}
	}
}

// GetDegradedServices returns a list of currently degraded services
func (gd *GracefulDegradation) GetDegradedServices() []string {
	gd.mutex.RLock()
	defer gd.mutex.RUnlock()

	var degraded []string
	for serviceName := range gd.degradedServices {
		degraded = append(degraded, serviceName)
	}

	return degraded
}

// ErrorRecoveryManager coordinates all error recovery mechanisms
type ErrorRecoveryManager struct {
	circuitBreakers     map[string]*CircuitBreaker
	retryExecutor       *RetryExecutor
	gracefulDegradation *GracefulDegradation
	mutex               sync.RWMutex
	logger              *Logger
}

// NewErrorRecoveryManager creates a new error recovery manager
func NewErrorRecoveryManager(logger *Logger) *ErrorRecoveryManager {
	return &ErrorRecoveryManager{
		circuitBreakers:     make(map[string]*CircuitBreaker),
		retryExecutor:       NewRetryExecutor(DefaultRetryConfig(), logger),
		gracefulDegradation: NewGracefulDegradation(DefaultGracefulDegradationConfig(), logger),
		logger:              logger,
	}
}

// GetCircuitBreaker gets or creates a circuit breaker for a service
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
func (erm *ErrorRecoveryManager) ExecuteWithRecovery(ctx context.Context, serviceName string, fn func() error) error {
	cb := erm.GetCircuitBreaker(serviceName)

	return erm.retryExecutor.Execute(ctx, func() error {
		return cb.Execute(fn)
	})
}

// GetRecoveryMetrics returns metrics for all recovery mechanisms
func (erm *ErrorRecoveryManager) GetRecoveryMetrics() map[string]interface{} {
	erm.mutex.RLock()
	defer erm.mutex.RUnlock()

	metrics := make(map[string]interface{})

	// Circuit breaker metrics
	cbMetrics := make(map[string]interface{})
	for name, cb := range erm.circuitBreakers {
		cbMetrics[name] = cb.GetMetrics()
	}
	metrics["circuit_breakers"] = cbMetrics

	// Degraded services
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
