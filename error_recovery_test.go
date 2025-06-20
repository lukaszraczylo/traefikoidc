package traefikoidc

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

func TestCircuitBreaker(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultCircuitBreakerConfig()
	config.MaxFailures = 2
	config.Timeout = 100 * time.Millisecond

	cb := NewCircuitBreaker(config, logger)

	t.Run("Initial state is closed", func(t *testing.T) {
		if cb.GetState() != CircuitBreakerClosed {
			t.Errorf("Expected initial state to be closed, got %v", cb.GetState())
		}
	})

	t.Run("Successful execution", func(t *testing.T) {
		err := cb.Execute(func() error {
			return nil
		})
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	t.Run("Circuit opens after max failures", func(t *testing.T) {
		// Trigger failures to open circuit
		for i := 0; i < config.MaxFailures; i++ {
			cb.Execute(func() error {
				return errors.New("test error")
			})
		}

		if cb.GetState() != CircuitBreakerOpen {
			t.Errorf("Expected circuit to be open, got %v", cb.GetState())
		}

		// Should reject requests when open
		err := cb.Execute(func() error {
			return nil
		})
		if err == nil || err.Error() != "circuit breaker is open" {
			t.Errorf("Expected circuit breaker open error, got %v", err)
		}
	})

	t.Run("Circuit transitions to half-open after timeout", func(t *testing.T) {
		// Wait for timeout
		time.Sleep(config.Timeout + 10*time.Millisecond)

		// Next request should transition to half-open
		cb.Execute(func() error {
			return nil
		})

		if cb.GetState() != CircuitBreakerClosed {
			t.Errorf("Expected circuit to be closed after successful request, got %v", cb.GetState())
		}
	})

	t.Run("Get metrics", func(t *testing.T) {
		metrics := cb.GetMetrics()
		if metrics["state"] == nil {
			t.Error("Expected metrics to contain state")
		}
		if metrics["total_requests"] == nil {
			t.Error("Expected metrics to contain total_requests")
		}
	})
}

func TestRetryExecutor(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond

	re := NewRetryExecutor(config, logger)

	t.Run("Successful execution on first attempt", func(t *testing.T) {
		attempts := 0
		err := re.Execute(context.Background(), func() error {
			attempts++
			return nil
		})
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("Retry on retryable error", func(t *testing.T) {
		attempts := 0
		err := re.Execute(context.Background(), func() error {
			attempts++
			if attempts < 2 {
				return errors.New("connection refused")
			}
			return nil
		})
		if err != nil {
			t.Errorf("Expected no error after retry, got %v", err)
		}
		if attempts != 2 {
			t.Errorf("Expected 2 attempts, got %d", attempts)
		}
	})

	t.Run("No retry on non-retryable error", func(t *testing.T) {
		attempts := 0
		err := re.Execute(context.Background(), func() error {
			attempts++
			return errors.New("non-retryable error")
		})

		if err == nil {
			t.Error("Expected error to be returned")
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("Max attempts reached", func(t *testing.T) {
		attempts := 0
		err := re.Execute(context.Background(), func() error {
			attempts++
			return errors.New("timeout")
		})

		if err == nil {
			t.Error("Expected error after max attempts")
		}
		if attempts != config.MaxAttempts {
			t.Errorf("Expected %d attempts, got %d", config.MaxAttempts, attempts)
		}
	})

	t.Run("Context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := re.Execute(ctx, func() error {
			return errors.New("timeout")
		})

		if err != context.Canceled {
			t.Errorf("Expected context canceled error, got %v", err)
		}
	})

	t.Run("Network error handling", func(t *testing.T) {
		// Test timeout error
		timeoutErr := &net.OpError{Op: "dial", Err: errors.New("timeout")}
		if !re.isRetryableError(timeoutErr) {
			t.Error("Expected timeout error to be retryable")
		}

		// Test connection refused
		connErr := errors.New("connection refused")
		if !re.isRetryableError(connErr) {
			t.Error("Expected connection refused to be retryable")
		}
	})

	t.Run("HTTP error handling", func(t *testing.T) {
		// Test 500 error (retryable)
		httpErr500 := &HTTPError{StatusCode: 500, Message: "Internal Server Error"}
		if !re.isRetryableError(httpErr500) {
			t.Error("Expected 500 error to be retryable")
		}

		// Test 429 error (retryable)
		httpErr429 := &HTTPError{StatusCode: 429, Message: "Too Many Requests"}
		if !re.isRetryableError(httpErr429) {
			t.Error("Expected 429 error to be retryable")
		}

		// Test 400 error (not retryable)
		httpErr400 := &HTTPError{StatusCode: 400, Message: "Bad Request"}
		if re.isRetryableError(httpErr400) {
			t.Error("Expected 400 error to not be retryable")
		}
	})
}

func TestGracefulDegradation(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultGracefulDegradationConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	config.RecoveryTimeout = 100 * time.Millisecond

	gd := NewGracefulDegradation(config, logger)
	defer func() {
		// Clean up goroutine
		time.Sleep(100 * time.Millisecond)
	}()

	t.Run("Register fallback and health check", func(t *testing.T) {
		gd.RegisterFallback("test-service", func() (any, error) {
			return "fallback-result", nil
		})

		gd.RegisterHealthCheck("test-service", func() bool {
			return true
		})

		// Should not be degraded initially
		if gd.isServiceDegraded("test-service") {
			t.Error("Service should not be degraded initially")
		}
	})

	t.Run("Execute with fallback on failure", func(t *testing.T) {
		gd.RegisterFallback("failing-service", func() (any, error) {
			return "fallback-result", nil
		})

		// First call should fail and mark service as degraded
		result, err := gd.ExecuteWithFallback("failing-service", func() (any, error) {
			return nil, errors.New("service failure")
		})
		if err != nil {
			t.Errorf("Expected fallback to succeed, got error: %v", err)
		}
		if result != "fallback-result" {
			t.Errorf("Expected fallback result, got %v", result)
		}

		// Service should now be degraded
		if !gd.isServiceDegraded("failing-service") {
			t.Error("Service should be marked as degraded")
		}
	})

	t.Run("No fallback available", func(t *testing.T) {
		_, err := gd.ExecuteWithFallback("no-fallback-service", func() (any, error) {
			return nil, errors.New("service failure")
		})

		if err == nil {
			t.Error("Expected error when no fallback available")
		}
	})

	t.Run("Get degraded services", func(t *testing.T) {
		degraded := gd.GetDegradedServices()
		found := slices.Contains(degraded, "failing-service")
		if !found {
			t.Error("Expected failing-service to be in degraded list")
		}
	})

	t.Run("Service recovery after timeout", func(t *testing.T) {
		// Wait for recovery timeout
		time.Sleep(config.RecoveryTimeout + 20*time.Millisecond)

		// Service should no longer be degraded
		if gd.isServiceDegraded("failing-service") {
			t.Error("Service should have recovered after timeout")
		}
	})
}

func TestErrorRecoveryManager(t *testing.T) {
	logger := NewLogger("debug")
	erm := NewErrorRecoveryManager(logger)

	t.Run("Get circuit breaker", func(t *testing.T) {
		cb1 := erm.GetCircuitBreaker("service1")
		cb2 := erm.GetCircuitBreaker("service1")

		// Should return the same instance
		if cb1 != cb2 {
			t.Error("Expected same circuit breaker instance for same service")
		}

		cb3 := erm.GetCircuitBreaker("service2")
		if cb1 == cb3 {
			t.Error("Expected different circuit breaker instances for different services")
		}
	})

	t.Run("Execute with recovery", func(t *testing.T) {
		attempts := 0
		err := erm.ExecuteWithRecovery(context.Background(), "test-service", func() error {
			attempts++
			if attempts < 2 {
				return errors.New("temporary failure")
			}
			return nil
		})
		if err != nil {
			t.Errorf("Expected recovery to succeed, got %v", err)
		}
		if attempts < 2 {
			t.Errorf("Expected at least 2 attempts, got %d", attempts)
		}
	})

	t.Run("Get recovery metrics", func(t *testing.T) {
		metrics := erm.GetRecoveryMetrics()

		if metrics["circuit_breakers"] == nil {
			t.Error("Expected circuit_breakers in metrics")
		}
		if metrics["degraded_services"] == nil {
			t.Error("Expected degraded_services in metrics")
		}
	})
}

func TestHTTPError(t *testing.T) {
	err := &HTTPError{StatusCode: 500, Message: "Internal Server Error"}
	expected := "HTTP 500: Internal Server Error"
	if err.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, err.Error())
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("contains function", func(t *testing.T) {
		if !contains("hello world", "hello") {
			t.Error("Expected contains to find substring at start")
		}
		if !contains("hello world", "world") {
			t.Error("Expected contains to find substring at end")
		}
		if !contains("hello world", "lo wo") {
			t.Error("Expected contains to find substring in middle")
		}
		if contains("hello world", "xyz") {
			t.Error("Expected contains to not find non-existent substring")
		}
	})

	t.Run("containsSubstring function", func(t *testing.T) {
		if !containsSubstring("hello world", "lo wo") {
			t.Error("Expected containsSubstring to find substring")
		}
		if containsSubstring("hello", "hello world") {
			t.Error("Expected containsSubstring to not find longer substring")
		}
	})
}

func TestDefaultConfigs(t *testing.T) {
	t.Run("DefaultCircuitBreakerConfig", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		if config.MaxFailures <= 0 {
			t.Error("Expected positive MaxFailures")
		}
		if config.Timeout <= 0 {
			t.Error("Expected positive Timeout")
		}
		if config.ResetTimeout <= 0 {
			t.Error("Expected positive ResetTimeout")
		}
	})

	t.Run("DefaultRetryConfig", func(t *testing.T) {
		config := DefaultRetryConfig()
		if config.MaxAttempts <= 0 {
			t.Error("Expected positive MaxAttempts")
		}
		if config.InitialDelay <= 0 {
			t.Error("Expected positive InitialDelay")
		}
		if config.BackoffFactor <= 1 {
			t.Error("Expected BackoffFactor > 1")
		}
		if len(config.RetryableErrors) == 0 {
			t.Error("Expected some retryable errors")
		}
	})

	t.Run("DefaultGracefulDegradationConfig", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		if config.HealthCheckInterval <= 0 {
			t.Error("Expected positive HealthCheckInterval")
		}
		if config.RecoveryTimeout <= 0 {
			t.Error("Expected positive RecoveryTimeout")
		}
	})
}

// Mock network error for testing
type mockNetError struct {
	timeout bool
	temp    bool
}

func (e *mockNetError) Error() string   { return "mock network error" }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temp }

func TestNetworkErrorHandling(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultRetryConfig()
	re := NewRetryExecutor(config, logger)

	t.Run("Timeout error is retryable", func(t *testing.T) {
		err := &mockNetError{timeout: true}
		if !re.isRetryableError(err) {
			t.Error("Expected timeout error to be retryable")
		}
	})

	t.Run("Non-timeout network error with retryable pattern", func(t *testing.T) {
		err := &mockNetError{timeout: false}
		// This should not be retryable since it doesn't match patterns and isn't timeout
		if re.isRetryableError(err) {
			t.Error("Expected non-timeout network error without pattern to not be retryable")
		}
	})
}
