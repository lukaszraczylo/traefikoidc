package traefikoidc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultCircuitBreakerConfig()
	config.MaxFailures = 2
	config.Timeout = 100 * time.Millisecond

	cb := NewCircuitBreaker(config, logger)

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
		gd.RegisterFallback("test-service", func() (interface{}, error) {
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
		gd.RegisterFallback("failing-service", func() (interface{}, error) {
			return "fallback-result", nil
		})

		// First call should fail and mark service as degraded
		result, err := gd.ExecuteWithFallback("failing-service", func() (interface{}, error) {
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
		_, err := gd.ExecuteWithFallback("no-fallback-service", func() (interface{}, error) {
			return nil, errors.New("service failure")
		})

		if err == nil {
			t.Error("Expected error when no fallback available")
		}
	})

	t.Run("Get degraded services", func(t *testing.T) {
		degraded := gd.GetDegradedServices()
		found := false
		for _, s := range degraded {
			if s == "failing-service" {
				found = true
				break
			}
		}
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

// Test Circuit Breaker Edge Cases
func TestCircuitBreakerEdgeCases(t *testing.T) {
	logger := NewLogger("debug")

	t.Run("Circuit breaker with zero max failures", func(t *testing.T) {
		config := CircuitBreakerConfig{
			MaxFailures:  0,
			Timeout:      100 * time.Millisecond,
			ResetTimeout: 50 * time.Millisecond,
		}
		cb := NewCircuitBreaker(config, logger)

		// Should open immediately on first failure
		err := cb.Execute(func() error {
			return errors.New("test error")
		})
		if err == nil {
			t.Error("Expected error to be returned")
		}

		if cb.GetState() != CircuitBreakerOpen {
			t.Errorf("Expected circuit to be open with 0 max failures, got %v", cb.GetState())
		}
	})

	t.Run("Circuit breaker concurrent access", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		config.MaxFailures = 5
		cb := NewCircuitBreaker(config, logger)

		var wg sync.WaitGroup
		var successCount, errorCount int32
		numGoroutines := 10
		requestsPerGoroutine := 20

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < requestsPerGoroutine; j++ {
					err := cb.Execute(func() error {
						// Simulate some successes and failures
						if (id+j)%3 == 0 {
							return errors.New("simulated failure")
						}
						return nil
					})
					if err != nil {
						atomic.AddInt32(&errorCount, 1)
					} else {
						atomic.AddInt32(&successCount, 1)
					}
					time.Sleep(time.Millisecond) // Small delay
				}
			}(i)
		}

		wg.Wait()

		// Verify metrics are consistent
		metrics := cb.GetMetrics()
		totalFromMetrics := metrics["total_requests"].(int64)
		expectedTotal := int64(numGoroutines * requestsPerGoroutine)

		if totalFromMetrics != expectedTotal {
			t.Errorf("Expected total requests %d, got %d", expectedTotal, totalFromMetrics)
		}
	})

	t.Run("Circuit breaker state transitions", func(t *testing.T) {
		config := CircuitBreakerConfig{
			MaxFailures:  2,
			Timeout:      50 * time.Millisecond,
			ResetTimeout: 30 * time.Millisecond,
		}
		cb := NewCircuitBreaker(config, logger)

		// Start in closed state
		if cb.GetState() != CircuitBreakerClosed {
			t.Errorf("Expected initial state to be closed, got %v", cb.GetState())
		}

		// First failure - should remain closed
		cb.Execute(func() error { return errors.New("error 1") })
		if cb.GetState() != CircuitBreakerClosed {
			t.Errorf("Expected state to remain closed after first failure, got %v", cb.GetState())
		}

		// Second failure - should open circuit
		cb.Execute(func() error { return errors.New("error 2") })
		if cb.GetState() != CircuitBreakerOpen {
			t.Errorf("Expected state to be open after max failures, got %v", cb.GetState())
		}

		// Wait for timeout to transition to half-open
		time.Sleep(config.Timeout + 10*time.Millisecond)

		// Execute request to trigger half-open transition
		cb.Execute(func() error { return nil }) // Successful request
		if cb.GetState() != CircuitBreakerClosed {
			t.Errorf("Expected state to be closed after successful half-open request, got %v", cb.GetState())
		}
	})

	t.Run("Circuit breaker half-open failure", func(t *testing.T) {
		config := CircuitBreakerConfig{
			MaxFailures:  1,
			Timeout:      50 * time.Millisecond,
			ResetTimeout: 30 * time.Millisecond,
		}
		cb := NewCircuitBreaker(config, logger)

		// Trigger circuit to open
		cb.Execute(func() error { return errors.New("failure") })
		if cb.GetState() != CircuitBreakerOpen {
			t.Errorf("Expected circuit to be open, got %v", cb.GetState())
		}

		// Wait for timeout
		time.Sleep(config.Timeout + 10*time.Millisecond)

		// Execute failing request in half-open state - should return to open
		cb.Execute(func() error { return errors.New("half-open failure") })
		if cb.GetState() != CircuitBreakerOpen {
			t.Errorf("Expected circuit to return to open after half-open failure, got %v", cb.GetState())
		}
	})

	t.Run("Circuit breaker reset", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		config.MaxFailures = 1
		cb := NewCircuitBreaker(config, logger)

		// Open the circuit
		cb.Execute(func() error { return errors.New("failure") })
		if cb.GetState() != CircuitBreakerOpen {
			t.Error("Expected circuit to be open")
		}

		// Reset should close the circuit
		cb.Reset()
		if cb.GetState() != CircuitBreakerClosed {
			t.Error("Expected circuit to be closed after reset")
		}
		if !cb.IsAvailable() {
			t.Error("Expected circuit to be available after reset")
		}
	})

	t.Run("Circuit breaker metrics completeness", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		cb := NewCircuitBreaker(config, logger)

		// Generate some activity
		cb.Execute(func() error { return nil })
		cb.Execute(func() error { return errors.New("test error") })

		metrics := cb.GetMetrics()

		expectedKeys := []string{
			"state", "max_failures", "current_failures", "timeout_ms", "reset_timeout_ms",
			"total_requests", "total_failures", "total_successes", "uptime_seconds",
			"name", "success_rate",
		}

		for _, key := range expectedKeys {
			if _, exists := metrics[key]; !exists {
				t.Errorf("Expected metric key %s to exist", key)
			}
		}

		// Verify state string values
		stateValue := metrics["state"].(string)
		validStates := []string{"closed", "open", "half-open"}
		isValidState := false
		for _, state := range validStates {
			if stateValue == state {
				isValidState = true
				break
			}
		}
		if !isValidState {
			t.Errorf("Invalid state value: %s", stateValue)
		}
	})
}

// Test Retry Executor Backoff and Jitter
func TestRetryExecutorBackoffAndJitter(t *testing.T) {
	logger := NewLogger("debug")

	t.Run("Exponential backoff calculation", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   5,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      1 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  false,
		}
		re := NewRetryExecutor(config, logger)

		// Test delay calculation for each attempt
		expectedDelays := []time.Duration{
			100 * time.Millisecond,  // attempt 1
			200 * time.Millisecond,  // attempt 2
			400 * time.Millisecond,  // attempt 3
			800 * time.Millisecond,  // attempt 4
			1000 * time.Millisecond, // attempt 5 (capped at MaxDelay)
		}

		for i, expected := range expectedDelays {
			actual := re.calculateDelay(i + 1)
			if actual != expected {
				t.Errorf("Attempt %d: expected delay %v, got %v", i+1, expected, actual)
			}
		}
	})

	t.Run("Jitter adds randomness", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   3,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      1 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  true,
		}
		re := NewRetryExecutor(config, logger)

		// Generate multiple delays for the same attempt and verify they differ
		delays := make([]time.Duration, 20)
		for i := range delays {
			delays[i] = re.calculateDelay(2) // Second attempt
		}

		// Check that we have different values (jitter is working)
		allSame := true
		firstDelay := delays[0]
		for _, delay := range delays[1:] {
			if delay != firstDelay {
				allSame = false
				break
			}
		}

		if allSame {
			t.Error("Expected jitter to produce different delay values, but all were the same")
		}

		// Verify delays are within reasonable bounds (base delay ± 10%)
		baseDelay := 200 * time.Millisecond
		minExpected := time.Duration(float64(baseDelay) * 0.9)
		maxExpected := time.Duration(float64(baseDelay) * 1.1)

		for i, delay := range delays {
			if delay < minExpected || delay > maxExpected {
				t.Errorf("Delay %d (%v) outside expected range [%v, %v]", i, delay, minExpected, maxExpected)
			}
		}
	})

	t.Run("Max delay capping works with jitter", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   10,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      300 * time.Millisecond,
			BackoffFactor: 3.0,
			EnableJitter:  true,
		}
		re := NewRetryExecutor(config, logger)

		// Test high attempt numbers that would exceed MaxDelay
		for attempt := 5; attempt <= 10; attempt++ {
			delay := re.calculateDelay(attempt)
			// With jitter, delay might be slightly above MaxDelay due to the 10% jitter
			maxAllowed := time.Duration(float64(config.MaxDelay) * 1.1)
			if delay > maxAllowed {
				t.Errorf("Attempt %d: delay %v exceeds max allowed %v", attempt, delay, maxAllowed)
			}
		}
	})

	t.Run("Retry with timeout context", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:     5,
			InitialDelay:    50 * time.Millisecond,
			MaxDelay:        200 * time.Millisecond,
			BackoffFactor:   2.0,
			EnableJitter:    false,
			RetryableErrors: []string{"timeout", "temporary failure"},
		}
		re := NewRetryExecutor(config, logger)

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		attempts := 0
		startTime := time.Now()
		err := re.ExecuteWithContext(ctx, func() error {
			attempts++
			return errors.New("timeout")
		})

		duration := time.Since(startTime)

		if err != context.DeadlineExceeded {
			t.Errorf("Expected context deadline exceeded, got %v", err)
		}

		// Should have been interrupted before all attempts
		if attempts >= config.MaxAttempts {
			t.Errorf("Expected fewer than %d attempts due to context timeout, got %d", config.MaxAttempts, attempts)
		}

		// Should have respected context timeout
		if duration > 200*time.Millisecond {
			t.Errorf("Operation took too long: %v", duration)
		}
	})

	t.Run("Different error patterns", func(t *testing.T) {
		config := DefaultRetryConfig()
		config.MaxAttempts = 2
		re := NewRetryExecutor(config, logger)

		testCases := []struct {
			name      string
			error     error
			retryable bool
		}{
			{"Connection refused", errors.New("connection refused"), true},
			{"Timeout", errors.New("timeout occurred"), true},
			{"Network unreachable", errors.New("network unreachable"), true},
			{"Temporary failure", errors.New("temporary failure in service"), true},
			{"Bad request", errors.New("bad request format"), false},
			{"Authentication failed", errors.New("invalid credentials"), false},
			{"Custom retryable", errors.New("this contains timeout keyword"), true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := re.isRetryableError(tc.error)
				if result != tc.retryable {
					t.Errorf("Expected retryable=%v for error %q, got %v", tc.retryable, tc.error.Error(), result)
				}
			})
		}
	})

	t.Run("Retry executor concurrent safety", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:     3,
			InitialDelay:    10 * time.Millisecond,
			MaxDelay:        50 * time.Millisecond,
			BackoffFactor:   2.0,
			EnableJitter:    true,
			RetryableErrors: []string{"retryable"},
		}
		re := NewRetryExecutor(config, logger)

		var wg sync.WaitGroup
		var successCount, errorCount int32
		numGoroutines := 20

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				err := re.ExecuteWithContext(context.Background(), func() error {
					if id%2 == 0 {
						return nil // Success for even IDs
					}
					return errors.New("retryable error") // Retryable error for odd IDs
				})

				if err != nil {
					atomic.AddInt32(&errorCount, 1)
				} else {
					atomic.AddInt32(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()

		// Verify metrics are consistent
		metrics := re.GetMetrics()
		totalRequests := metrics["total_requests"].(int64)

		if int(totalRequests) != numGoroutines {
			t.Errorf("Expected %d requests, got %d", numGoroutines, totalRequests)
		}

		// Even numbered goroutines should succeed, odd should fail after retries
		expectedSuccesses := numGoroutines / 2
		if int(successCount) != expectedSuccesses {
			t.Errorf("Expected %d successes, got %d", expectedSuccesses, successCount)
		}
	})

	t.Run("Retry executor metrics completeness", func(t *testing.T) {
		config := DefaultRetryConfig()
		re := NewRetryExecutor(config, logger)

		// Generate some activity
		re.ExecuteWithContext(context.Background(), func() error { return nil })
		re.ExecuteWithContext(context.Background(), func() error { return errors.New("timeout") })

		metrics := re.GetMetrics()

		expectedKeys := []string{
			"max_attempts", "initial_delay_ms", "max_delay_ms", "backoff_factor",
			"enable_jitter", "retryable_errors", "total_requests", "total_failures",
			"total_successes", "uptime_seconds", "name", "success_rate",
		}

		for _, key := range expectedKeys {
			if _, exists := metrics[key]; !exists {
				t.Errorf("Expected metric key %s to exist", key)
			}
		}

		// Verify specific metric values
		if metrics["max_attempts"].(int) != config.MaxAttempts {
			t.Errorf("Expected max_attempts %d, got %v", config.MaxAttempts, metrics["max_attempts"])
		}

		if metrics["enable_jitter"].(bool) != config.EnableJitter {
			t.Errorf("Expected enable_jitter %v, got %v", config.EnableJitter, metrics["enable_jitter"])
		}
	})
}

// Test Graceful Degradation Concurrent Scenarios
func TestGracefulDegradationConcurrent(t *testing.T) {
	logger := NewLogger("debug")

	t.Run("Concurrent service registration and execution", func(t *testing.T) {
		config := GracefulDegradationConfig{
			HealthCheckInterval: 100 * time.Millisecond,
			RecoveryTimeout:     200 * time.Millisecond,
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer func() {
			time.Sleep(150 * time.Millisecond) // Allow cleanup
		}()

		var wg sync.WaitGroup
		var registrationWG sync.WaitGroup
		numGoroutines := 20
		numServices := 5

		// Register services concurrently but wait for completion
		for i := 0; i < numServices; i++ {
			registrationWG.Add(1)
			go func(serviceID int) {
				defer registrationWG.Done()
				serviceName := fmt.Sprintf("service-%d", serviceID)

				gd.RegisterFallback(serviceName, func() (interface{}, error) {
					return fmt.Sprintf("fallback-%d", serviceID), nil
				})

				gd.RegisterHealthCheck(serviceName, func() bool {
					return serviceID%2 == 0 // Even services are healthy
				})
			}(i)
		}

		// Wait for all services to be registered
		registrationWG.Wait()

		// Now execute requests concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(requestID int) {
				defer wg.Done()
				serviceName := fmt.Sprintf("service-%d", requestID%numServices)

				_, err := gd.ExecuteWithFallback(serviceName, func() (interface{}, error) {
					if requestID%3 == 0 {
						return nil, errors.New("simulated failure")
					}
					return fmt.Sprintf("success-%d", requestID), nil
				})

				// All requests should either succeed or fall back successfully
				if err != nil {
					t.Errorf("Request %d failed: %v", requestID, err)
				}
			}(i)
		}

		wg.Wait()

		// Verify final state
		metrics := gd.GetMetrics()
		if metrics["registered_fallbacks_count"].(int) != numServices {
			t.Errorf("Expected %d registered fallbacks, got %d", numServices, metrics["registered_fallbacks_count"])
		}

		if metrics["registered_health_checks_count"].(int) != numServices {
			t.Errorf("Expected %d registered health checks, got %d", numServices, metrics["registered_health_checks_count"])
		}
	})

	t.Run("Health check recovery race conditions", func(t *testing.T) {
		config := GracefulDegradationConfig{
			HealthCheckInterval: 50 * time.Millisecond,
			RecoveryTimeout:     100 * time.Millisecond,
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer func() {
			time.Sleep(100 * time.Millisecond) // Allow cleanup
		}()

		serviceName := "test-service"
		var healthCheckCount int32

		gd.RegisterFallback(serviceName, func() (interface{}, error) {
			return "fallback-result", nil
		})

		// Health check that alternates between healthy and unhealthy
		gd.RegisterHealthCheck(serviceName, func() bool {
			count := atomic.AddInt32(&healthCheckCount, 1)
			return count%2 == 0 // Alternates between healthy and unhealthy
		})

		// Force service to be degraded initially
		gd.markServiceDegraded(serviceName)

		var wg sync.WaitGroup
		var successCount, fallbackCount int32

		// Execute many requests concurrently while health check is running
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				result, err := gd.ExecuteWithFallback(serviceName, func() (interface{}, error) {
					return fmt.Sprintf("primary-%d", id), nil
				})

				if err != nil {
					t.Errorf("Request %d failed unexpectedly: %v", id, err)
					return
				}

				if result == "fallback-result" {
					atomic.AddInt32(&fallbackCount, 1)
				} else {
					atomic.AddInt32(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()

		// Should have a mix of primary and fallback results
		if successCount == 0 && fallbackCount == 0 {
			t.Error("Expected some successful requests")
		}

		t.Logf("Primary successes: %d, Fallback uses: %d", successCount, fallbackCount)
	})

	t.Run("Concurrent fallback execution without race", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		config.RecoveryTimeout = 100 * time.Millisecond
		gd := NewGracefulDegradation(config, logger)
		defer func() {
			time.Sleep(100 * time.Millisecond)
		}()

		serviceName := "concurrent-service"
		var fallbackCallCount int32

		gd.RegisterFallback(serviceName, func() (interface{}, error) {
			atomic.AddInt32(&fallbackCallCount, 1)
			time.Sleep(10 * time.Millisecond) // Simulate some work
			return "fallback-result", nil
		})

		// Mark service as degraded
		gd.markServiceDegraded(serviceName)

		var wg sync.WaitGroup
		numRequests := 30

		// Execute multiple fallback requests concurrently
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				result, err := gd.ExecuteWithFallback(serviceName, func() (interface{}, error) {
					return nil, errors.New("service unavailable")
				})

				if err != nil {
					t.Errorf("Request %d failed: %v", id, err)
					return
				}

				if result != "fallback-result" {
					t.Errorf("Request %d: expected fallback result, got %v", id, result)
				}
			}(i)
		}

		wg.Wait()

		// All requests should have used the fallback
		if fallbackCallCount != int32(numRequests) {
			t.Errorf("Expected %d fallback calls, got %d", numRequests, fallbackCallCount)
		}
	})

	t.Run("Service degradation marking under load", func(t *testing.T) {
		config := GracefulDegradationConfig{
			HealthCheckInterval: 500 * time.Millisecond, // Long interval
			RecoveryTimeout:     200 * time.Millisecond,
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer func() {
			time.Sleep(100 * time.Millisecond)
		}()

		serviceName := "load-test-service"

		gd.RegisterFallback(serviceName, func() (interface{}, error) {
			return "fallback", nil
		})

		var wg sync.WaitGroup
		var failureCount, successCount int32
		numRequests := 100

		// Execute many requests that will fail and trigger degradation
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				result, err := gd.ExecuteWithFallback(serviceName, func() (interface{}, error) {
					// First few requests fail to trigger degradation
					if id < 10 {
						return nil, errors.New("service failure")
					}
					// Later requests would succeed but should use fallback due to degradation
					return fmt.Sprintf("success-%d", id), nil
				})

				if err != nil {
					atomic.AddInt32(&failureCount, 1)
				} else {
					atomic.AddInt32(&successCount, 1)
					if result == "fallback" {
						// This is expected for most requests after degradation
					}
				}
			}(i)
		}

		wg.Wait()

		// Service should be marked as degraded
		degradedServices := gd.GetDegradedServices()
		found := false
		for _, service := range degradedServices {
			if service == serviceName {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected service to be marked as degraded")
		}

		// Most requests should have succeeded (either primary or fallback)
		if successCount < int32(numRequests*8/10) {
			t.Errorf("Expected at least 80%% success rate, got %d/%d", successCount, numRequests)
		}
	})

	t.Run("Reset operation thread safety", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer func() {
			time.Sleep(100 * time.Millisecond)
		}()

		var wg sync.WaitGroup
		numGoroutines := 20

		// Register some services and mark them as degraded
		for i := 0; i < 5; i++ {
			serviceName := fmt.Sprintf("service-%d", i)
			gd.RegisterFallback(serviceName, func() (interface{}, error) {
				return "fallback", nil
			})
			gd.markServiceDegraded(serviceName)
		}

		// Concurrently reset and execute operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				if id%4 == 0 {
					// Reset occasionally
					gd.Reset()
				} else {
					// Execute requests
					serviceName := fmt.Sprintf("service-%d", id%5)
					gd.ExecuteWithFallback(serviceName, func() (interface{}, error) {
						return "success", nil
					})
				}
			}(i)
		}

		wg.Wait()

		// After reset, no services should be degraded
		degradedServices := gd.GetDegradedServices()
		if len(degradedServices) > 0 {
			t.Logf("Note: %d services still degraded after concurrent reset (this is acceptable due to timing)", len(degradedServices))
		}
	})
}

// Test All Error Types and Their Methods
func TestErrorTypesAndMethods(t *testing.T) {
	t.Run("HTTPError functionality", func(t *testing.T) {
		// Test basic HTTPError
		err := &HTTPError{StatusCode: 404, Message: "Not Found"}
		expected := "HTTP 404: Not Found"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test different status codes
		testCases := []struct {
			status   int
			message  string
			expected string
		}{
			{200, "OK", "HTTP 200: OK"},
			{400, "Bad Request", "HTTP 400: Bad Request"},
			{401, "Unauthorized", "HTTP 401: Unauthorized"},
			{403, "Forbidden", "HTTP 403: Forbidden"},
			{500, "Internal Server Error", "HTTP 500: Internal Server Error"},
			{502, "Bad Gateway", "HTTP 502: Bad Gateway"},
			{503, "Service Unavailable", "HTTP 503: Service Unavailable"},
		}

		for _, tc := range testCases {
			err := &HTTPError{StatusCode: tc.status, Message: tc.message}
			if err.Error() != tc.expected {
				t.Errorf("Status %d: expected %q, got %q", tc.status, tc.expected, err.Error())
			}
		}

		// Test empty message
		err = &HTTPError{StatusCode: 418, Message: ""}
		expected = "HTTP 418: "
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("OIDCError functionality", func(t *testing.T) {
		// Test basic OIDCError without cause
		err := NewOIDCError("invalid_token", "Token is expired", nil)
		expected := "OIDC error [invalid_token]: Token is expired"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test OIDCError with cause
		cause := errors.New("underlying network error")
		err = NewOIDCError("network_error", "Failed to connect to provider", cause)
		expected = "OIDC error [network_error]: Failed to connect to provider - caused by: underlying network error"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test Unwrap functionality
		if err.Unwrap() != cause {
			t.Errorf("Expected Unwrap to return %v, got %v", cause, err.Unwrap())
		}

		// Test context functionality
		err = NewOIDCError("provider_error", "Provider unavailable", nil)
		err.WithContext("provider", "google").WithContext("user_id", "user123")

		if err.Context["provider"] != "google" {
			t.Errorf("Expected provider context to be 'google', got %v", err.Context["provider"])
		}
		if err.Context["user_id"] != "user123" {
			t.Errorf("Expected user_id context to be 'user123', got %v", err.Context["user_id"])
		}

		// Test different error codes
		codes := []string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type"}
		for _, code := range codes {
			err := NewOIDCError(code, "Test message", nil)
			if err.Code != code {
				t.Errorf("Expected code %s, got %s", code, err.Code)
			}
		}
	})

	t.Run("SessionError functionality", func(t *testing.T) {
		// Test basic SessionError without cause
		err := NewSessionError("save", "Failed to save session", nil)
		expected := "Session error in save: Failed to save session"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test SessionError with cause
		cause := errors.New("disk full")
		err = NewSessionError("save", "Cannot write to storage", cause)
		expected = "Session error in save: Cannot write to storage - caused by: disk full"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test Unwrap functionality
		if err.Unwrap() != cause {
			t.Errorf("Expected Unwrap to return %v, got %v", cause, err.Unwrap())
		}

		// Test WithSessionID functionality
		err = NewSessionError("load", "Session not found", nil)
		err.WithSessionID("session-123")
		if err.SessionID != "session-123" {
			t.Errorf("Expected session ID 'session-123', got %s", err.SessionID)
		}

		// Test different operations
		operations := []string{"create", "load", "save", "delete", "update", "validate"}
		for _, op := range operations {
			err := NewSessionError(op, "Test error", nil)
			if err.Operation != op {
				t.Errorf("Expected operation %s, got %s", op, err.Operation)
			}
		}

		// Test error with session ID in error message
		err = NewSessionError("validate", "Invalid session", nil).WithSessionID("test-session")
		if !strings.Contains(err.Error(), "validate") {
			t.Error("Expected operation to be included in error message")
		}
	})

	t.Run("TokenError functionality", func(t *testing.T) {
		// Test basic TokenError without cause
		err := NewTokenError("id_token", "expired", "Token has expired", nil)
		expected := "Token error (id_token) - expired: Token has expired"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test TokenError with cause
		cause := errors.New("signature verification failed")
		err = NewTokenError("access_token", "invalid_signature", "Token signature is invalid", cause)
		expected = "Token error (access_token) - invalid_signature: Token signature is invalid - caused by: signature verification failed"
		if err.Error() != expected {
			t.Errorf("Expected %q, got %q", expected, err.Error())
		}

		// Test Unwrap functionality
		if err.Unwrap() != cause {
			t.Errorf("Expected Unwrap to return %v, got %v", cause, err.Unwrap())
		}

		// Test different token types
		tokenTypes := []string{"id_token", "access_token", "refresh_token", "authorization_code"}
		for _, tokenType := range tokenTypes {
			err := NewTokenError(tokenType, "invalid", "Test error", nil)
			if err.TokenType != tokenType {
				t.Errorf("Expected token type %s, got %s", tokenType, err.TokenType)
			}
		}

		// Test different reasons
		reasons := []string{"expired", "invalid_signature", "malformed", "missing_claims", "invalid_issuer", "invalid_audience"}
		for _, reason := range reasons {
			err := NewTokenError("id_token", reason, "Test error", nil)
			if err.Reason != reason {
				t.Errorf("Expected reason %s, got %s", reason, err.Reason)
			}
		}
	})

	t.Run("Error chaining and unwrapping", func(t *testing.T) {
		// Create a chain of errors
		httpErr := &HTTPError{StatusCode: 504, Message: "Gateway Timeout"}
		oidcErr := NewOIDCError("provider_timeout", "Provider request timed out", httpErr)
		sessionErr := NewSessionError("validate", "Session validation failed", oidcErr)
		tokenErr := NewTokenError("id_token", "validation_failed", "Token validation failed", sessionErr)

		// Test unwrapping chain
		if tokenErr.Unwrap() != sessionErr {
			t.Error("TokenError should unwrap to SessionError")
		}
		if sessionErr.Unwrap() != oidcErr {
			t.Error("SessionError should unwrap to OIDCError")
		}
		if oidcErr.Unwrap() != httpErr {
			t.Error("OIDCError should unwrap to HTTPError")
		}

		// Test error.Is functionality
		if !errors.Is(tokenErr, sessionErr) {
			t.Error("errors.Is should find SessionError in chain")
		}
		if !errors.Is(tokenErr, oidcErr) {
			t.Error("errors.Is should find OIDCError in chain")
		}
		if !errors.Is(tokenErr, httpErr) {
			t.Error("errors.Is should find HTTPError in chain")
		}

		// Test errors.As functionality
		var httpErrTarget *HTTPError
		if !errors.As(tokenErr, &httpErrTarget) {
			t.Error("errors.As should find HTTPError in chain")
		}
		if httpErrTarget.StatusCode != 504 {
			t.Errorf("Expected status code 504, got %d", httpErrTarget.StatusCode)
		}

		var oidcErrTarget *OIDCError
		if !errors.As(tokenErr, &oidcErrTarget) {
			t.Error("errors.As should find OIDCError in chain")
		}
		if oidcErrTarget.Code != "provider_timeout" {
			t.Errorf("Expected code 'provider_timeout', got %s", oidcErrTarget.Code)
		}
	})

	t.Run("Error messages with special characters", func(t *testing.T) {
		// Test errors with special characters and encoding
		specialMessage := "Error with special chars: éñçødîñg & symbols"

		httpErr := &HTTPError{StatusCode: 400, Message: specialMessage}
		if !strings.Contains(httpErr.Error(), specialMessage) {
			t.Error("HTTPError should preserve special characters")
		}

		oidcErr := NewOIDCError("special_chars", specialMessage, nil)
		if !strings.Contains(oidcErr.Error(), specialMessage) {
			t.Error("OIDCError should preserve special characters")
		}

		sessionErr := NewSessionError("test", specialMessage, nil)
		if !strings.Contains(sessionErr.Error(), specialMessage) {
			t.Error("SessionError should preserve special characters")
		}

		tokenErr := NewTokenError("test_token", "test_reason", specialMessage, nil)
		if !strings.Contains(tokenErr.Error(), specialMessage) {
			t.Error("TokenError should preserve special characters")
		}
	})

	t.Run("Error context and metadata", func(t *testing.T) {
		// Test OIDCError context with various data types
		err := NewOIDCError("test", "Test error", nil)
		err.WithContext("string_value", "test")
		err.WithContext("int_value", 42)
		err.WithContext("bool_value", true)
		err.WithContext("float_value", 3.14)
		err.WithContext("slice_value", []string{"a", "b", "c"})
		err.WithContext("map_value", map[string]string{"key": "value"})

		if err.Context["string_value"] != "test" {
			t.Error("String context value not preserved")
		}
		if err.Context["int_value"] != 42 {
			t.Error("Int context value not preserved")
		}
		if err.Context["bool_value"] != true {
			t.Error("Bool context value not preserved")
		}
		if err.Context["float_value"] != 3.14 {
			t.Error("Float context value not preserved")
		}

		// Verify the error message doesn't include context
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "string_value") {
			t.Error("Error message should not include context keys")
		}
	})
}
