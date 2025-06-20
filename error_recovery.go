package traefikoidc

import (
	"context"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrorRecoveryMechanism defines the common interface for all error recovery mechanisms
type ErrorRecoveryMechanism interface {
	// ExecuteWithContext executes a function with error recovery
	ExecuteWithContext(ctx context.Context, fn func() error) error
	// GetMetrics returns metrics about the error recovery mechanism
	GetMetrics() map[string]any
	// Reset resets the state of the error recovery mechanism
	Reset()
	// IsAvailable returns whether the mechanism is available for use
	IsAvailable() bool
}

// BaseRecoveryMechanism provides common functionality for error recovery mechanisms
type BaseRecoveryMechanism struct {
	startTime       time.Time
	lastFailureTime time.Time
	lastSuccessTime time.Time
	logger          *Logger
	name            string
	totalRequests   int64
	totalFailures   int64
	totalSuccesses  int64
	mutex           sync.RWMutex
}

// NewBaseRecoveryMechanism creates a new base recovery mechanism
func NewBaseRecoveryMechanism(name string, logger *Logger) *BaseRecoveryMechanism {
	if logger == nil {
		logger = newNoOpLogger()
	}

	return &BaseRecoveryMechanism{
		name:      name,
		logger:    logger,
		startTime: time.Now(),
	}
}

// RecordRequest records a request to the error recovery mechanism
func (b *BaseRecoveryMechanism) RecordRequest() {
	atomic.AddInt64(&b.totalRequests, 1)
}

// RecordSuccess records a successful operation
func (b *BaseRecoveryMechanism) RecordSuccess() {
	atomic.AddInt64(&b.totalSuccesses, 1)

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.lastSuccessTime = time.Now()
}

// RecordFailure records a failed operation
func (b *BaseRecoveryMechanism) RecordFailure() {
	atomic.AddInt64(&b.totalFailures, 1)

	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.lastFailureTime = time.Now()
}

// GetBaseMetrics returns base metrics common to all recovery mechanisms
func (b *BaseRecoveryMechanism) GetBaseMetrics() map[string]any {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	metrics := map[string]any{
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

	// Calculate success rate
	if metrics["total_requests"].(int64) > 0 {
		successRate := float64(metrics["total_successes"].(int64)) / float64(metrics["total_requests"].(int64))
		metrics["success_rate"] = successRate
	} else {
		metrics["success_rate"] = 1.0 // Default to 100% if no requests
	}

	return metrics
}

// LogInfo logs an informational message
func (b *BaseRecoveryMechanism) LogInfo(format string, args ...any) {
	if b.logger != nil {
		b.logger.Infof("%s: "+format, append([]any{b.name}, args...)...)
	}
}

// LogError logs an error message
func (b *BaseRecoveryMechanism) LogError(format string, args ...any) {
	if b.logger != nil {
		b.logger.Errorf("%s: "+format, append([]any{b.name}, args...)...)
	}
}

// LogDebug logs a debug message
func (b *BaseRecoveryMechanism) LogDebug(format string, args ...any) {
	if b.logger != nil {
		b.logger.Debugf("%s: "+format, append([]any{b.name}, args...)...)
	}
}

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
	*BaseRecoveryMechanism
	maxFailures  int
	timeout      time.Duration
	resetTimeout time.Duration
	state        CircuitBreakerState
	failures     int64
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
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("circuit-breaker", logger),
		maxFailures:           config.MaxFailures,
		timeout:               config.Timeout,
		resetTimeout:          config.ResetTimeout,
		state:                 CircuitBreakerClosed,
	}
}

// ExecuteWithContext implements the ErrorRecoveryMechanism interface
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func() error) error {
	cb.RecordRequest()

	// Check if circuit breaker allows the request
	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}

	// Execute the function
	err := fn()
	// Record the result
	if err != nil {
		cb.recordFailure()
		cb.RecordFailure()
		return err
	}

	cb.recordSuccess()
	cb.RecordSuccess()
	return nil
}

// Execute is the original method for backward compatibility
func (cb *CircuitBreaker) Execute(fn func() error) error {
	return cb.ExecuteWithContext(context.Background(), fn)
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

	switch cb.state {
	case CircuitBreakerClosed:
		if cb.failures >= int64(cb.maxFailures) {
			cb.state = CircuitBreakerOpen
			cb.LogError("Circuit breaker opened after %d failures", cb.failures)
		}

	case CircuitBreakerHalfOpen:
		// Go back to open state on any failure in half-open
		cb.state = CircuitBreakerOpen
		cb.LogError("Circuit breaker returned to open state after failure in half-open")
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	switch cb.state {
	case CircuitBreakerHalfOpen:
		// Reset failures and close circuit on success in half-open
		cb.failures = 0
		cb.state = CircuitBreakerClosed
		cb.LogInfo("Circuit breaker closed after successful request in half-open state")

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

// Reset resets the circuit breaker to its initial state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.state = CircuitBreakerClosed
	atomic.StoreInt64(&cb.failures, 0)
	cb.LogInfo("Circuit breaker has been reset")
}

// IsAvailable returns whether the circuit breaker is allowing requests
func (cb *CircuitBreaker) IsAvailable() bool {
	return cb.allowRequest()
}

// GetMetrics returns metrics about the circuit breaker
func (cb *CircuitBreaker) GetMetrics() map[string]any {
	cb.mutex.RLock()
	state := cb.state
	failures := cb.failures
	cb.mutex.RUnlock()

	metrics := cb.GetBaseMetrics()

	// Add circuit breaker specific metrics
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

// RetryConfig holds configuration for retry mechanisms
type RetryConfig struct {
	RetryableErrors []string      `json:"retryable_errors"`
	MaxAttempts     int           `json:"max_attempts"`
	InitialDelay    time.Duration `json:"initial_delay"`
	MaxDelay        time.Duration `json:"max_delay"`
	BackoffFactor   float64       `json:"backoff_factor"`
	EnableJitter    bool          `json:"enable_jitter"`
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
	*BaseRecoveryMechanism
	config RetryConfig
}

// NewRetryExecutor creates a new retry executor
func NewRetryExecutor(config RetryConfig, logger *Logger) *RetryExecutor {
	return &RetryExecutor{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("retry-executor", logger),
		config:                config,
	}
}

// ExecuteWithContext implements the ErrorRecoveryMechanism interface
func (re *RetryExecutor) ExecuteWithContext(ctx context.Context, fn func() error) error {
	re.RecordRequest()
	var lastErr error

	for attempt := 1; attempt <= re.config.MaxAttempts; attempt++ {
		// Execute the function
		err := fn()
		if err == nil {
			if attempt > 1 {
				re.LogInfo("Operation succeeded on attempt %d", attempt)
			}
			re.RecordSuccess()
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !re.isRetryableError(err) {
			re.LogDebug("Non-retryable error on attempt %d: %v", attempt, err)
			re.RecordFailure()
			return err
		}

		// Don't wait after the last attempt
		if attempt == re.config.MaxAttempts {
			re.RecordFailure()
			break
		}

		// Calculate delay with exponential backoff
		delay := re.calculateDelay(attempt)
		re.LogDebug("Retrying operation after %v (attempt %d/%d): %v",
			delay, attempt, re.config.MaxAttempts, err)

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			re.RecordFailure()
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	finalErr := fmt.Errorf("operation failed after %d attempts: %w", re.config.MaxAttempts, lastErr)
	return finalErr
}

// Execute runs the given function with retry logic (for backward compatibility)
func (re *RetryExecutor) Execute(ctx context.Context, fn func() error) error {
	return re.ExecuteWithContext(ctx, fn)
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

// Reset resets the retry executor state
func (re *RetryExecutor) Reset() {
	// Nothing to reset for RetryExecutor
	re.LogDebug("Retry executor reset")
}

// IsAvailable always returns true for RetryExecutor
func (re *RetryExecutor) IsAvailable() bool {
	return true
}

// GetMetrics returns metrics about the retry executor
func (re *RetryExecutor) GetMetrics() map[string]any {
	metrics := re.GetBaseMetrics()

	// Add retry executor specific metrics
	metrics["max_attempts"] = re.config.MaxAttempts
	metrics["initial_delay_ms"] = re.config.InitialDelay.Milliseconds()
	metrics["max_delay_ms"] = re.config.MaxDelay.Milliseconds()
	metrics["backoff_factor"] = re.config.BackoffFactor
	metrics["enable_jitter"] = re.config.EnableJitter
	metrics["retryable_errors"] = re.config.RetryableErrors

	return metrics
}

// HTTPError represents an HTTP error with status code
type HTTPError struct {
	Message    string
	StatusCode int
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// GracefulDegradation implements graceful degradation patterns
type GracefulDegradation struct {
	*BaseRecoveryMechanism
	fallbacks        map[string]func() (any, error)
	healthChecks     map[string]func() bool
	degradedServices map[string]time.Time
	config           GracefulDegradationConfig
	mutex            sync.RWMutex
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
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("graceful-degradation", logger),
		fallbacks:             make(map[string]func() (any, error)),
		healthChecks:          make(map[string]func() bool),
		degradedServices:      make(map[string]time.Time),
		config:                config,
	}

	// Start health check routine
	go gd.startHealthCheckRoutine()

	return gd
}

// RegisterFallback registers a fallback function for a service
func (gd *GracefulDegradation) RegisterFallback(serviceName string, fallback func() (any, error)) {
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

	// Execute with a simple wrapper
	_, err := gd.ExecuteWithFallback("default", func() (any, error) {
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
func (gd *GracefulDegradation) ExecuteWithFallback(serviceName string, primary func() (any, error)) (any, error) {
	// Check if service is degraded
	if gd.isServiceDegraded(serviceName) {
		gd.LogInfo("Service %s is degraded, using fallback", serviceName)
		return gd.executeFallback(serviceName)
	}

	// Try primary function
	result, err := primary()
	if err != nil {
		// Mark service as degraded
		gd.markServiceDegraded(serviceName)
		gd.LogError("Service %s failed: %v", serviceName, err)

		// Try fallback if available
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
		gd.LogError("Service %s marked as degraded", serviceName)
	}

	gd.degradedServices[serviceName] = time.Now()
}

// executeFallback executes the fallback function for a service
func (gd *GracefulDegradation) executeFallback(serviceName string) (any, error) {
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
	healthCheckTask := NewBackgroundTask(
		"graceful-degradation-health-check",
		gd.config.HealthCheckInterval,
		gd.performHealthChecks,
		gd.BaseRecoveryMechanism.logger,
	)
	healthCheckTask.Start()
}

// performHealthChecks runs health checks for all registered services
func (gd *GracefulDegradation) performHealthChecks() {
	gd.mutex.RLock()
	healthChecks := make(map[string]func() bool)
	maps.Copy(healthChecks, gd.healthChecks)
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

// Reset resets the state of all degraded services
func (gd *GracefulDegradation) Reset() {
	gd.mutex.Lock()
	defer gd.mutex.Unlock()

	// Clear degraded services
	gd.degradedServices = make(map[string]time.Time)
	gd.LogInfo("Graceful degradation state has been reset")
}

// IsAvailable returns whether the mechanism is available for use
func (gd *GracefulDegradation) IsAvailable() bool {
	return true
}

// GetMetrics returns metrics about the graceful degradation mechanism
func (gd *GracefulDegradation) GetMetrics() map[string]any {
	gd.mutex.RLock()
	degradedCount := len(gd.degradedServices)

	// Get the names of degraded services
	degradedServices := make([]string, 0, degradedCount)
	for service := range gd.degradedServices {
		degradedServices = append(degradedServices, service)
	}

	// Get total count of registered fallbacks and health checks
	fallbackCount := len(gd.fallbacks)
	healthCheckCount := len(gd.healthChecks)
	gd.mutex.RUnlock()

	// Get base metrics
	metrics := gd.GetBaseMetrics()

	// Add graceful degradation specific metrics
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
func (erm *ErrorRecoveryManager) GetRecoveryMetrics() map[string]any {
	erm.mutex.RLock()
	defer erm.mutex.RUnlock()

	metrics := make(map[string]any)

	// Circuit breaker metrics
	cbMetrics := make(map[string]any)
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
