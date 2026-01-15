//go:build !yaegi

package recovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// RETRY CONFIG TESTS
// =============================================================================

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts to be 3, got %d", config.MaxAttempts)
	}

	if config.InitialDelay != 100*time.Millisecond {
		t.Errorf("Expected InitialDelay to be 100ms, got %v", config.InitialDelay)
	}

	if config.MaxDelay != 30*time.Second {
		t.Errorf("Expected MaxDelay to be 30s, got %v", config.MaxDelay)
	}

	if config.Multiplier != 2.0 {
		t.Errorf("Expected Multiplier to be 2.0, got %f", config.Multiplier)
	}

	if config.RandomizationFactor != 0.1 {
		t.Errorf("Expected RandomizationFactor to be 0.1, got %f", config.RandomizationFactor)
	}

	if len(config.RetryableErrors) != 3 {
		t.Errorf("Expected 3 retryable errors, got %d", len(config.RetryableErrors))
	}

	if len(config.RetryableStatusCodes) != 6 {
		t.Errorf("Expected 6 retryable status codes, got %d", len(config.RetryableStatusCodes))
	}
}

// =============================================================================
// RETRY EXECUTOR TESTS
// =============================================================================

func TestNewRetryExecutor(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()

	executor := NewRetryExecutor(config, logger)

	if executor == nil {
		t.Fatal("Expected NewRetryExecutor to return non-nil")
	}

	if executor.config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts to be 3, got %d", executor.config.MaxAttempts)
	}
}

func TestNewRetryExecutor_InvalidConfig(t *testing.T) {
	logger := &mockLogger{}

	// Test with invalid MaxAttempts
	config := RetryConfig{
		MaxAttempts: 0, // Invalid
		Multiplier:  0, // Invalid
	}

	executor := NewRetryExecutor(config, logger)

	if executor.config.MaxAttempts != 1 {
		t.Errorf("Expected MaxAttempts to be corrected to 1, got %d", executor.config.MaxAttempts)
	}

	if executor.config.Multiplier != 1.0 {
		t.Errorf("Expected Multiplier to be corrected to 1.0, got %f", executor.config.Multiplier)
	}
}

func TestRetryExecutor_ExecuteWithContext_Success(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	callCount := 0
	err := executor.ExecuteWithContext(context.Background(), func() error {
		callCount++
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}
}

func TestRetryExecutor_ExecuteWithContext_Retry(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    1 * time.Millisecond,
		MaxDelay:        10 * time.Millisecond,
		Multiplier:      2.0,
		RetryableErrors: []string{"connection refused"},
	}
	executor := NewRetryExecutor(config, logger)

	callCount := 0
	err := executor.ExecuteWithContext(context.Background(), func() error {
		callCount++
		if callCount < 3 {
			return errors.New("connection refused")
		}
		return nil
	})

	if err != nil {
		t.Errorf("Expected success after retries, got %v", err)
	}

	if callCount != 3 {
		t.Errorf("Expected function to be called 3 times, got %d", callCount)
	}
}

func TestRetryExecutor_ExecuteWithContext_MaxRetriesExhausted(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    1 * time.Millisecond,
		MaxDelay:        10 * time.Millisecond,
		Multiplier:      2.0,
		RetryableErrors: []string{"timeout"},
	}
	executor := NewRetryExecutor(config, logger)

	callCount := 0
	err := executor.ExecuteWithContext(context.Background(), func() error {
		callCount++
		return errors.New("timeout")
	})

	if err == nil {
		t.Error("Expected error after max retries exhausted")
	}

	if !strings.Contains(err.Error(), "all retry attempts failed") {
		t.Errorf("Expected 'all retry attempts failed' error, got %v", err)
	}

	if callCount != 3 {
		t.Errorf("Expected function to be called 3 times, got %d", callCount)
	}
}

func TestRetryExecutor_ExecuteWithContext_NonRetryableError(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    1 * time.Millisecond,
		RetryableErrors: []string{"timeout"},
	}
	executor := NewRetryExecutor(config, logger)

	callCount := 0
	err := executor.ExecuteWithContext(context.Background(), func() error {
		callCount++
		return errors.New("permanent error")
	})

	if err == nil {
		t.Error("Expected error for non-retryable error")
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once (non-retryable), got %d", callCount)
	}
}

func TestRetryExecutor_ExecuteWithContext_ContextCancelled(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    1 * time.Second, // Long delay
		RetryableErrors: []string{"timeout"},
	}
	executor := NewRetryExecutor(config, logger)

	ctx, cancel := context.WithCancel(context.Background())

	callCount := 0
	var wg sync.WaitGroup
	wg.Add(1)

	var execErr error
	go func() {
		defer wg.Done()
		execErr = executor.ExecuteWithContext(ctx, func() error {
			callCount++
			return errors.New("timeout")
		})
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	wg.Wait()

	if execErr == nil {
		t.Error("Expected error when context is canceled")
	}
}

func TestRetryExecutor_ExecuteWithContext_ContextCancelledBeforeStart(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := executor.ExecuteWithContext(ctx, func() error {
		return nil
	})

	if err == nil {
		t.Error("Expected error when context is already canceled")
	}
}

func TestRetryExecutor_Execute(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	called := false
	err := executor.Execute(context.Background(), func() error {
		called = true
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !called {
		t.Error("Expected function to be called")
	}
}

func TestRetryExecutor_isRetryableError(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		RetryableErrors:      []string{"connection refused", "timeout"},
		RetryableStatusCodes: []int{500, 503},
	}
	executor := NewRetryExecutor(config, logger)

	tests := []struct {
		err      error
		name     string
		expected bool
	}{
		{name: "nil error", err: nil, expected: false},
		{name: "connection refused", err: errors.New("connection refused"), expected: true},
		{name: "timeout", err: errors.New("TIMEOUT"), expected: true}, // case insensitive
		{name: "EOF", err: errors.New("EOF"), expected: false},
		{name: "random error", err: errors.New("something else"), expected: false},
		{name: "context canceled", err: context.Canceled, expected: false},
		{name: "context deadline exceeded", err: context.DeadlineExceeded, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := executor.isRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRetryExecutor_isRetryableError_HTTPError(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		RetryableStatusCodes: []int{500, 503},
	}
	executor := NewRetryExecutor(config, logger)

	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"500 error", 500, true},
		{"503 error", 503, true},
		{"502 error (5xx)", 502, true},
		{"400 error", 400, false},
		{"401 error", 401, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpErr := &HTTPError{StatusCode: tt.statusCode}
			result := executor.isRetryableError(httpErr)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRetryExecutor_isRetryableError_OIDCError(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	// Test retryable OIDC error
	retryableErr := &OIDCError{Code: "temporarily_unavailable", Description: "Server busy"}
	if !executor.isRetryableError(retryableErr) {
		t.Error("Expected temporarily_unavailable to be retryable")
	}

	// Test non-retryable OIDC error
	nonRetryableErr := &OIDCError{Code: "invalid_token", Description: "Token expired"}
	if executor.isRetryableError(nonRetryableErr) {
		t.Error("Expected invalid_token to not be retryable")
	}
}

func TestRetryExecutor_calculateDelay(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		InitialDelay:        100 * time.Millisecond,
		MaxDelay:            1 * time.Second,
		Multiplier:          2.0,
		RandomizationFactor: 0.0, // No jitter for predictable tests
	}
	executor := NewRetryExecutor(config, logger)

	// Test exponential backoff without jitter
	delay1 := executor.calculateDelay(1)
	if delay1 != 100*time.Millisecond {
		t.Errorf("Expected 100ms for attempt 1, got %v", delay1)
	}

	delay2 := executor.calculateDelay(2)
	if delay2 != 200*time.Millisecond {
		t.Errorf("Expected 200ms for attempt 2, got %v", delay2)
	}

	delay3 := executor.calculateDelay(3)
	if delay3 != 400*time.Millisecond {
		t.Errorf("Expected 400ms for attempt 3, got %v", delay3)
	}

	// Test max delay cap
	delay10 := executor.calculateDelay(10)
	if delay10 > 1*time.Second {
		t.Errorf("Expected delay capped at 1s, got %v", delay10)
	}
}

func TestRetryExecutor_calculateDelay_WithJitter(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		InitialDelay:        100 * time.Millisecond,
		MaxDelay:            1 * time.Second,
		Multiplier:          2.0,
		RandomizationFactor: 0.5, // 50% jitter
	}
	executor := NewRetryExecutor(config, logger)

	// With jitter, delay should be within range
	baseDelay := 100 * time.Millisecond
	minExpected := time.Duration(float64(baseDelay) * 0.5)
	maxExpected := time.Duration(float64(baseDelay) * 1.5)

	for i := 0; i < 10; i++ {
		delay := executor.calculateDelay(1)
		if delay < minExpected || delay > maxExpected {
			t.Errorf("Delay %v outside expected range [%v, %v]", delay, minExpected, maxExpected)
		}
	}
}

func TestRetryExecutor_Reset(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	// Generate some metrics
	executor.ExecuteWithContext(context.Background(), func() error { return nil })
	executor.ExecuteWithContext(context.Background(), func() error { return nil })

	// Reset
	executor.Reset()

	if atomic.LoadInt64(&executor.totalRetries) != 0 {
		t.Error("Expected totalRetries to be 0 after reset")
	}

	if atomic.LoadInt64(&executor.maxRetriesHit) != 0 {
		t.Error("Expected maxRetriesHit to be 0 after reset")
	}

	if atomic.LoadInt64(&executor.totalRequests) != 0 {
		t.Error("Expected totalRequests to be 0 after reset")
	}
}

func TestRetryExecutor_IsAvailable(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	if !executor.IsAvailable() {
		t.Error("Expected IsAvailable to return true")
	}
}

func TestRetryExecutor_GetMetrics(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultRetryConfig()
	executor := NewRetryExecutor(config, logger)

	// Generate some metrics
	executor.ExecuteWithContext(context.Background(), func() error { return nil })

	metrics := executor.GetMetrics()

	// Check required fields
	if _, ok := metrics["totalRetries"]; !ok {
		t.Error("Expected 'totalRetries' in metrics")
	}

	if _, ok := metrics["maxRetriesHit"]; !ok {
		t.Error("Expected 'maxRetriesHit' in metrics")
	}

	if _, ok := metrics["config"]; !ok {
		t.Error("Expected 'config' in metrics")
	}

	if _, ok := metrics["lastRetryTime"]; !ok {
		t.Error("Expected 'lastRetryTime' in metrics")
	}
}

func TestRetryExecutor_GetMetrics_WithRetries(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    1 * time.Millisecond,
		MaxDelay:        10 * time.Millisecond,
		Multiplier:      2.0,
		RetryableErrors: []string{"retry"},
	}
	executor := NewRetryExecutor(config, logger)

	// Generate retries
	callCount := 0
	executor.ExecuteWithContext(context.Background(), func() error {
		callCount++
		if callCount < 2 {
			return errors.New("retry me")
		}
		return nil
	})

	metrics := executor.GetMetrics()

	totalRetries := metrics["totalRetries"].(int64)
	if totalRetries < 1 {
		t.Errorf("Expected at least 1 retry, got %d", totalRetries)
	}

	// Check for average retries calculation
	if _, ok := metrics["averageRetriesPerRequest"]; !ok {
		t.Error("Expected 'averageRetriesPerRequest' in metrics")
	}
}

// =============================================================================
// RECOVERY METRICS TESTS
// =============================================================================

func TestNewRecoveryMetrics(t *testing.T) {
	rm := NewRecoveryMetrics()

	if rm == nil {
		t.Fatal("Expected NewRecoveryMetrics to return non-nil")
	}

	if rm.mechanisms == nil {
		t.Error("Expected mechanisms map to be initialized")
	}
}

func TestRecoveryMetrics_RegisterMechanism(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if _, exists := rm.mechanisms["circuit_breaker"]; !exists {
		t.Error("Expected mechanism to be registered")
	}
}

func TestRecoveryMetrics_UnregisterMechanism(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)
	rm.UnregisterMechanism("circuit_breaker")

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if _, exists := rm.mechanisms["circuit_breaker"]; exists {
		t.Error("Expected mechanism to be unregistered")
	}
}

func TestRecoveryMetrics_GetAllMetrics(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)

	re := NewRetryExecutor(DefaultRetryConfig(), logger)
	rm.RegisterMechanism("retry_executor", re)

	metrics := rm.GetAllMetrics()

	if _, ok := metrics["circuit_breaker"]; !ok {
		t.Error("Expected 'circuit_breaker' in metrics")
	}

	if _, ok := metrics["retry_executor"]; !ok {
		t.Error("Expected 'retry_executor' in metrics")
	}

	if _, ok := metrics["summary"]; !ok {
		t.Error("Expected 'summary' in metrics")
	}

	summary := metrics["summary"].(map[string]interface{})
	if summary["totalMechanisms"] != 2 {
		t.Errorf("Expected 2 mechanisms, got %v", summary["totalMechanisms"])
	}
}

func TestRecoveryMetrics_GetAllMetrics_WithActivity(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)

	// Generate some activity
	cb.Execute(func() error { return nil })
	cb.Execute(func() error { return nil })

	metrics := rm.GetAllMetrics()
	summary := metrics["summary"].(map[string]interface{})

	// Should have success rate calculated
	if _, ok := summary["overallSuccessRate"]; !ok {
		t.Error("Expected 'overallSuccessRate' in summary")
	}
}

func TestRecoveryMetrics_GetMechanismMetrics(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)

	// Test existing mechanism
	metrics, ok := rm.GetMechanismMetrics("circuit_breaker")
	if !ok {
		t.Error("Expected to find circuit_breaker mechanism")
	}
	if metrics == nil {
		t.Error("Expected metrics to be non-nil")
	}

	// Test non-existing mechanism
	_, ok = rm.GetMechanismMetrics("non_existent")
	if ok {
		t.Error("Expected to not find non_existent mechanism")
	}
}

func TestRecoveryMetrics_HealthCheck(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	// Test with healthy mechanism
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)

	health := rm.HealthCheck()

	if health["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", health["status"])
	}

	mechanisms := health["mechanisms"].(map[string]interface{})
	if mechanisms["circuit_breaker"] != "healthy" {
		t.Errorf("Expected circuit_breaker to be 'healthy', got %v", mechanisms["circuit_breaker"])
	}

	if health["healthy"] != 1 {
		t.Errorf("Expected 1 healthy, got %v", health["healthy"])
	}

	if health["unhealthy"] != 0 {
		t.Errorf("Expected 0 unhealthy, got %v", health["unhealthy"])
	}
}

func TestRecoveryMetrics_HealthCheck_Degraded(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	// Add a healthy mechanism
	cb1 := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("healthy_cb", cb1)

	// Add an unhealthy mechanism (trip the circuit breaker)
	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 10,
		Timeout:          1 * time.Hour,
		MaxRequests:      1,
	}
	cb2 := NewCircuitBreaker(config, logger)
	cb2.Execute(func() error { return errors.New("fail") })
	rm.RegisterMechanism("unhealthy_cb", cb2)

	health := rm.HealthCheck()

	if health["status"] != "degraded" {
		t.Errorf("Expected status 'degraded', got %v", health["status"])
	}
}

func TestRecoveryMetrics_HealthCheck_Unhealthy(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	// Add only an unhealthy mechanism
	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 10,
		Timeout:          1 * time.Hour,
		MaxRequests:      1,
	}
	cb := NewCircuitBreaker(config, logger)
	cb.Execute(func() error { return errors.New("fail") })
	rm.RegisterMechanism("unhealthy_cb", cb)

	health := rm.HealthCheck()

	if health["status"] != "unhealthy" {
		t.Errorf("Expected status 'unhealthy', got %v", health["status"])
	}
}

func TestRecoveryMetrics_HTTPMetricsHandler(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
	rm.RegisterMechanism("circuit_breaker", cb)

	handler := rm.HTTPMetricsHandler()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", contentType)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

// =============================================================================
// CONCURRENT ACCESS TESTS
// =============================================================================

func TestRecoveryMetrics_ConcurrentAccess(t *testing.T) {
	rm := NewRecoveryMetrics()
	logger := &mockLogger{}

	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cb := NewCircuitBreaker(DefaultCircuitBreakerConfig(), logger)
			rm.RegisterMechanism(string(rune('a'+idx)), cb)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = rm.GetAllMetrics()
			_ = rm.HealthCheck()
		}()
	}

	wg.Wait()

	// Verify no race conditions
	health := rm.HealthCheck()
	if health == nil {
		t.Error("Expected HealthCheck to return non-nil after concurrent access")
	}
}

func TestRetryExecutor_ConcurrentExecution(t *testing.T) {
	logger := &mockLogger{}
	config := RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    1 * time.Millisecond,
		MaxDelay:        10 * time.Millisecond,
		Multiplier:      2.0,
		RetryableErrors: []string{"retry"},
	}
	executor := NewRetryExecutor(config, logger)

	var wg sync.WaitGroup
	successCount := int64(0)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := executor.ExecuteWithContext(context.Background(), func() error {
				return nil
			})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 100 {
		t.Errorf("Expected 100 successes, got %d", successCount)
	}
}
