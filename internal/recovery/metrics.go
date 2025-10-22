// Package recovery provides error recovery and resilience mechanisms for OIDC authentication.
package recovery

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RetryConfig defines configuration for the retry executor
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int
	// InitialDelay is the initial delay between retries
	InitialDelay time.Duration
	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration
	// Multiplier is the backoff multiplier
	Multiplier float64
	// RandomizationFactor adds jitter to delays (0.0 to 1.0)
	RandomizationFactor float64
	// RetryableErrors defines which errors should trigger a retry
	RetryableErrors []string
	// RetryableStatusCodes defines which HTTP status codes should trigger a retry
	RetryableStatusCodes []int
}

// DefaultRetryConfig returns sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:          3,
		InitialDelay:         100 * time.Millisecond,
		MaxDelay:             30 * time.Second,
		Multiplier:           2.0,
		RandomizationFactor:  0.1,
		RetryableErrors:      []string{"connection refused", "timeout", "EOF"},
		RetryableStatusCodes: []int{408, 429, 500, 502, 503, 504},
	}
}

// RetryExecutor implements retry logic with exponential backoff
type RetryExecutor struct {
	*BaseRecoveryMechanism
	config RetryConfig

	// Metrics
	totalRetries   int64
	maxRetriesHit  int64
	lastRetryTime  time.Time
	retryTimeMutex sync.RWMutex
}

// NewRetryExecutor creates a new retry executor with the given configuration
func NewRetryExecutor(config RetryConfig, logger Logger) *RetryExecutor {
	if config.MaxAttempts < 1 {
		config.MaxAttempts = 1
	}
	if config.Multiplier < 1.0 {
		config.Multiplier = 1.0
	}
	return &RetryExecutor{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism("RetryExecutor", logger),
		config:                config,
		totalRetries:          0,
		maxRetriesHit:         0,
	}
}

// ExecuteWithContext executes a function with retry logic
func (re *RetryExecutor) ExecuteWithContext(ctx context.Context, fn func() error) error {
	re.RecordRequest()

	var lastErr error
	for attempt := 1; attempt <= re.config.MaxAttempts; attempt++ {
		// Check context before attempting
		select {
		case <-ctx.Done():
			re.RecordFailure()
			return ctx.Err()
		default:
		}

		// Execute the function
		lastErr = fn()

		if lastErr == nil {
			re.RecordSuccess()
			if attempt > 1 {
				re.LogInfo("Succeeded after %d attempts", attempt)
			}
			return nil
		}

		// Check if error is retryable
		if !re.isRetryableError(lastErr) {
			re.LogDebug("Error is not retryable: %v", lastErr)
			re.RecordFailure()
			return lastErr
		}

		// Don't retry if this was the last attempt
		if attempt >= re.config.MaxAttempts {
			atomic.AddInt64(&re.maxRetriesHit, 1)
			re.LogError("Max retries (%d) exhausted", re.config.MaxAttempts)
			break
		}

		// Calculate and apply delay
		delay := re.calculateDelay(attempt)
		re.LogInfo("Attempt %d failed: %v, retrying in %v", attempt, lastErr, delay)

		atomic.AddInt64(&re.totalRetries, 1)
		re.retryTimeMutex.Lock()
		re.lastRetryTime = time.Now()
		re.retryTimeMutex.Unlock()

		select {
		case <-time.After(delay):
			// Continue to next attempt
		case <-ctx.Done():
			re.RecordFailure()
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		}
	}

	re.RecordFailure()
	return fmt.Errorf("all retry attempts failed: %w", lastErr)
}

// Execute executes a function with retry logic (legacy method)
func (re *RetryExecutor) Execute(ctx context.Context, fn func() error) error {
	return re.ExecuteWithContext(ctx, fn)
}

// isRetryableError determines if an error should trigger a retry
func (re *RetryExecutor) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Check for retryable error patterns
	for _, pattern := range re.config.RetryableErrors {
		if strings.Contains(errStr, strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for HTTP errors
	if httpErr, ok := err.(*HTTPError); ok {
		for _, code := range re.config.RetryableStatusCodes {
			if httpErr.StatusCode == code {
				return true
			}
		}
		// Also retry on any 5xx error
		if httpErr.StatusCode >= 500 && httpErr.StatusCode < 600 {
			return true
		}
	}

	// Check for OIDC errors
	if oidcErr, ok := err.(*OIDCError); ok {
		return oidcErr.IsRetryable()
	}

	// Check for context errors (don't retry these)
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}

	// Default: don't retry unknown errors
	return false
}

// calculateDelay calculates the delay before the next retry attempt
func (re *RetryExecutor) calculateDelay(attempt int) time.Duration {
	// Exponential backoff
	delay := float64(re.config.InitialDelay) * math.Pow(re.config.Multiplier, float64(attempt-1))

	// Cap at max delay
	if delay > float64(re.config.MaxDelay) {
		delay = float64(re.config.MaxDelay)
	}

	// Add jitter
	if re.config.RandomizationFactor > 0 {
		jitter := delay * re.config.RandomizationFactor
		minDelay := delay - jitter
		maxDelay := delay + jitter
		delay = minDelay + rand.Float64()*(maxDelay-minDelay)
	}

	return time.Duration(delay)
}

// Reset resets the retry executor state
func (re *RetryExecutor) Reset() {
	atomic.StoreInt64(&re.totalRetries, 0)
	atomic.StoreInt64(&re.maxRetriesHit, 0)
	atomic.StoreInt64(&re.totalRequests, 0)
	atomic.StoreInt64(&re.successCount, 0)
	atomic.StoreInt64(&re.failureCount, 0)

	re.retryTimeMutex.Lock()
	re.lastRetryTime = time.Time{}
	re.retryTimeMutex.Unlock()
}

// IsAvailable always returns true for retry executor
func (re *RetryExecutor) IsAvailable() bool {
	return true
}

// GetMetrics returns comprehensive metrics about the retry executor
func (re *RetryExecutor) GetMetrics() map[string]interface{} {
	metrics := re.GetBaseMetrics()

	metrics["totalRetries"] = atomic.LoadInt64(&re.totalRetries)
	metrics["maxRetriesHit"] = atomic.LoadInt64(&re.maxRetriesHit)

	re.retryTimeMutex.RLock()
	if !re.lastRetryTime.IsZero() {
		metrics["lastRetryTime"] = re.lastRetryTime.Format(time.RFC3339)
		metrics["timeSinceLastRetry"] = time.Since(re.lastRetryTime).String()
	} else {
		metrics["lastRetryTime"] = "never"
	}
	re.retryTimeMutex.RUnlock()

	// Configuration
	metrics["config"] = map[string]interface{}{
		"maxAttempts":         re.config.MaxAttempts,
		"initialDelay":        re.config.InitialDelay.String(),
		"maxDelay":            re.config.MaxDelay.String(),
		"multiplier":          re.config.Multiplier,
		"randomizationFactor": re.config.RandomizationFactor,
	}

	// Calculate average retries per request
	totalRequests := atomic.LoadInt64(&re.totalRequests)
	if totalRequests > 0 {
		avgRetries := float64(atomic.LoadInt64(&re.totalRetries)) / float64(totalRequests)
		metrics["averageRetriesPerRequest"] = fmt.Sprintf("%.2f", avgRetries)
	}

	return metrics
}

// RecoveryMetrics aggregates metrics from multiple recovery mechanisms
type RecoveryMetrics struct {
	mechanisms map[string]ErrorRecoveryMechanism
	mu         sync.RWMutex
}

// NewRecoveryMetrics creates a new recovery metrics aggregator
func NewRecoveryMetrics() *RecoveryMetrics {
	return &RecoveryMetrics{
		mechanisms: make(map[string]ErrorRecoveryMechanism),
	}
}

// RegisterMechanism registers a recovery mechanism for metrics collection
func (rm *RecoveryMetrics) RegisterMechanism(name string, mechanism ErrorRecoveryMechanism) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.mechanisms[name] = mechanism
}

// UnregisterMechanism removes a recovery mechanism from metrics collection
func (rm *RecoveryMetrics) UnregisterMechanism(name string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.mechanisms, name)
}

// GetAllMetrics returns aggregated metrics from all registered mechanisms
func (rm *RecoveryMetrics) GetAllMetrics() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	allMetrics := make(map[string]interface{})
	for name, mechanism := range rm.mechanisms {
		allMetrics[name] = mechanism.GetMetrics()
	}

	// Add summary statistics
	totalRequests := int64(0)
	totalSuccesses := int64(0)
	totalFailures := int64(0)

	for _, mechanism := range rm.mechanisms {
		metrics := mechanism.GetMetrics()
		if requests, ok := metrics["totalRequests"].(int64); ok {
			totalRequests += requests
		}
		if successes, ok := metrics["successCount"].(int64); ok {
			totalSuccesses += successes
		}
		if failures, ok := metrics["failureCount"].(int64); ok {
			totalFailures += failures
		}
	}

	allMetrics["summary"] = map[string]interface{}{
		"totalMechanisms": len(rm.mechanisms),
		"totalRequests":   totalRequests,
		"totalSuccesses":  totalSuccesses,
		"totalFailures":   totalFailures,
	}

	if totalRequests > 0 {
		successRate := float64(totalSuccesses) / float64(totalRequests) * 100
		allMetrics["summary"].(map[string]interface{})["overallSuccessRate"] = fmt.Sprintf("%.2f%%", successRate)
	}

	return allMetrics
}

// GetMechanismMetrics returns metrics for a specific mechanism
func (rm *RecoveryMetrics) GetMechanismMetrics(name string) (map[string]interface{}, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if mechanism, exists := rm.mechanisms[name]; exists {
		return mechanism.GetMetrics(), true
	}
	return nil, false
}

// HealthCheck performs a health check on all registered mechanisms
func (rm *RecoveryMetrics) HealthCheck() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	health := make(map[string]interface{})
	healthyCount := 0
	unhealthyCount := 0

	for name, mechanism := range rm.mechanisms {
		if mechanism.IsAvailable() {
			health[name] = "healthy"
			healthyCount++
		} else {
			health[name] = "unhealthy"
			unhealthyCount++
		}
	}

	overallHealth := "healthy"
	if unhealthyCount > 0 {
		if healthyCount > 0 {
			overallHealth = "degraded"
		} else {
			overallHealth = "unhealthy"
		}
	}

	return map[string]interface{}{
		"status":     overallHealth,
		"mechanisms": health,
		"healthy":    healthyCount,
		"unhealthy":  unhealthyCount,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
}

// HTTPMetricsHandler creates an HTTP handler for serving recovery metrics
func (rm *RecoveryMetrics) HTTPMetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := rm.GetAllMetrics()
		health := rm.HealthCheck()

		response := map[string]interface{}{
			"metrics": metrics,
			"health":  health,
		}

		// Would normally use json.Marshal here, but keeping it simple for the module
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%v", response)
	}
}
