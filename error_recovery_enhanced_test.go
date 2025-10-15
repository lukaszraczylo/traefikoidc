package traefikoidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestCircuitBreakerAllowRequestEdgeCases tests edge cases in circuit breaker request allowing
func TestCircuitBreakerAllowRequestEdgeCases(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("invalid state returns false", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		cb := NewCircuitBreaker(config, logger)

		// Force invalid state
		cb.mutex.Lock()
		cb.state = CircuitBreakerState(999) // Invalid state
		cb.mutex.Unlock()

		// Should return false for invalid state
		allowed := cb.allowRequest()
		assert.False(t, allowed, "invalid state should not allow requests")
	})

	t.Run("open to half-open transition on timeout", func(t *testing.T) {
		baseTimeout := GetTestDuration(50 * time.Millisecond)
		config := CircuitBreakerConfig{
			MaxFailures:  1,
			Timeout:      baseTimeout,
			ResetTimeout: 30 * time.Second,
		}
		cb := NewCircuitBreaker(config, logger)

		// Trip the circuit
		cb.Execute(func() error { return errors.New("fail") })

		// Verify circuit is open
		assert.Equal(t, CircuitBreakerOpen, cb.GetState())
		assert.False(t, cb.allowRequest())

		// Wait for timeout (longer than timeout to ensure transition)
		time.Sleep(baseTimeout + GetTestDuration(20*time.Millisecond))

		// Should transition to half-open
		allowed := cb.allowRequest()
		assert.True(t, allowed, "should allow request after timeout")
		assert.Equal(t, CircuitBreakerHalfOpen, cb.GetState())
	})

	t.Run("half-open allows requests", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		cb := NewCircuitBreaker(config, logger)

		// Manually set to half-open
		cb.mutex.Lock()
		cb.state = CircuitBreakerHalfOpen
		cb.mutex.Unlock()

		allowed := cb.allowRequest()
		assert.True(t, allowed, "half-open should allow requests")
	})

	t.Run("open blocks requests before timeout", func(t *testing.T) {
		config := CircuitBreakerConfig{
			MaxFailures:  1,
			Timeout:      1 * time.Hour, // Long timeout
			ResetTimeout: 30 * time.Second,
		}
		cb := NewCircuitBreaker(config, logger)

		// Trip the circuit
		cb.Execute(func() error { return errors.New("fail") })

		// Should be blocked
		allowed := cb.allowRequest()
		assert.False(t, allowed, "open circuit should block requests")
	})
}

// TestRetryExecutorIsRetryableErrorEdgeCases tests edge cases for retry decision
func TestRetryExecutorIsRetryableErrorEdgeCases(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRetryConfig()
	re := NewRetryExecutor(config, logger)

	t.Run("nil error is not retryable", func(t *testing.T) {
		retryable := re.isRetryableError(nil)
		assert.False(t, retryable)
	})

	t.Run("HTTPError with 429 is retryable", func(t *testing.T) {
		httpErr := &HTTPError{
			StatusCode: 429,
			Message:    "Too Many Requests",
		}

		retryable := re.isRetryableError(httpErr)
		assert.True(t, retryable, "429 Too Many Requests should be retryable")
	})

	t.Run("HTTPError with 500 is retryable", func(t *testing.T) {
		httpErr := &HTTPError{
			StatusCode: 500,
			Message:    "Internal Server Error",
		}

		retryable := re.isRetryableError(httpErr)
		assert.True(t, retryable, "500 errors should be retryable")
	})

	t.Run("HTTPError with 503 is retryable", func(t *testing.T) {
		httpErr := &HTTPError{
			StatusCode: 503,
			Message:    "Service Unavailable",
		}

		retryable := re.isRetryableError(httpErr)
		assert.True(t, retryable, "503 errors should be retryable")
	})

	t.Run("HTTPError with 400 is not retryable", func(t *testing.T) {
		httpErr := &HTTPError{
			StatusCode: 400,
			Message:    "Bad Request",
		}

		retryable := re.isRetryableError(httpErr)
		assert.False(t, retryable, "400 errors should not be retryable")
	})

	t.Run("net.Error with timeout is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   true,
			temporary: false,
			msg:       "timeout error",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "timeout errors should be retryable")
	})

	t.Run("net.Error with connection refused is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "connection refused",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "connection refused should be retryable")
	})

	t.Run("net.Error with connection reset is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "connection reset by peer",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "connection reset should be retryable")
	})

	t.Run("net.Error with network unreachable is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "network is unreachable",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "network unreachable should be retryable")
	})

	t.Run("net.Error with no route to host is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "no route to host",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "no route to host should be retryable")
	})

	t.Run("net.Error with temporary failure is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "temporary failure in name resolution",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "temporary failure should be retryable")
	})

	t.Run("net.Error with try again is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "try again later",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "try again should be retryable")
	})

	t.Run("net.Error with resource temporarily unavailable is retryable", func(t *testing.T) {
		netErr := &mockNetError{
			timeout:   false,
			temporary: false,
			msg:       "resource temporarily unavailable",
		}

		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "resource temporarily unavailable should be retryable")
	})

	t.Run("configured retryable error patterns", func(t *testing.T) {
		err := errors.New("connection refused by server")

		retryable := re.isRetryableError(err)
		assert.True(t, retryable, "configured pattern should be retryable")
	})

	t.Run("non-retryable error", func(t *testing.T) {
		err := errors.New("invalid input data")

		retryable := re.isRetryableError(err)
		assert.False(t, retryable, "non-configured error should not be retryable")
	})
}

// TestRetryExecutorCalculateDelayEdgeCases tests delay calculation edge cases
func TestRetryExecutorCalculateDelayEdgeCases(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("delay calculation without jitter", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   3,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      5 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  false, // Jitter disabled
		}
		re := NewRetryExecutor(config, logger)

		// Attempt 1: 100ms * 2^0 = 100ms
		delay1 := re.calculateDelay(1)
		assert.Equal(t, 100*time.Millisecond, delay1)

		// Attempt 2: 100ms * 2^1 = 200ms
		delay2 := re.calculateDelay(2)
		assert.Equal(t, 200*time.Millisecond, delay2)

		// Attempt 3: 100ms * 2^2 = 400ms
		delay3 := re.calculateDelay(3)
		assert.Equal(t, 400*time.Millisecond, delay3)
	})

	t.Run("delay calculation with jitter", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   3,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      5 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  true, // Jitter enabled
		}
		re := NewRetryExecutor(config, logger)

		// With jitter, delay should be within 10% of expected
		delay := re.calculateDelay(2)
		expectedBase := 200 * time.Millisecond
		minDelay := time.Duration(float64(expectedBase) * 0.9)
		maxDelay := time.Duration(float64(expectedBase) * 1.1)

		assert.GreaterOrEqual(t, delay, minDelay, "delay should be >= 90% of base")
		assert.LessOrEqual(t, delay, maxDelay, "delay should be <= 110% of base")
	})

	t.Run("delay capped at max delay", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   10,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      500 * time.Millisecond, // Low max delay
			BackoffFactor: 2.0,
			EnableJitter:  false,
		}
		re := NewRetryExecutor(config, logger)

		// Attempt 10: would be 100ms * 2^9 = 51200ms, but capped at 500ms
		delay := re.calculateDelay(10)
		assert.Equal(t, 500*time.Millisecond, delay, "delay should be capped at max")
	})

	t.Run("delay with large backoff factor", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   5,
			InitialDelay:  50 * time.Millisecond,
			MaxDelay:      10 * time.Second,
			BackoffFactor: 3.0, // Larger backoff
			EnableJitter:  false,
		}
		re := NewRetryExecutor(config, logger)

		// Attempt 3: 50ms * 3^2 = 450ms
		delay := re.calculateDelay(3)
		assert.Equal(t, 450*time.Millisecond, delay)
	})
}

// TestErrorTypesErrorMethodsWithoutCause tests error type Error() methods without cause
func TestErrorTypesErrorMethodsWithoutCause(t *testing.T) {
	t.Run("HTTPError.Error without cause", func(t *testing.T) {
		httpErr := &HTTPError{
			StatusCode: 404,
			Message:    "Not Found",
		}

		errStr := httpErr.Error()
		assert.Equal(t, "HTTP 404: Not Found", errStr)
	})

	t.Run("HTTPError.Error with different status codes", func(t *testing.T) {
		testCases := []struct {
			code     int
			message  string
			expected string
		}{
			{200, "OK", "HTTP 200: OK"},
			{301, "Moved", "HTTP 301: Moved"},
			{401, "Unauthorized", "HTTP 401: Unauthorized"},
			{500, "Server Error", "HTTP 500: Server Error"},
		}

		for _, tc := range testCases {
			httpErr := &HTTPError{
				StatusCode: tc.code,
				Message:    tc.message,
			}
			assert.Equal(t, tc.expected, httpErr.Error())
		}
	})

	t.Run("OIDCError.Error without cause", func(t *testing.T) {
		oidcErr := &OIDCError{
			Code:    "invalid_token",
			Message: "Token validation failed",
			Context: make(map[string]interface{}),
		}

		errStr := oidcErr.Error()
		assert.Equal(t, "OIDC error [invalid_token]: Token validation failed", errStr)
	})

	t.Run("OIDCError.Error with cause", func(t *testing.T) {
		rootErr := errors.New("signature mismatch")
		oidcErr := &OIDCError{
			Code:    "invalid_signature",
			Message: "JWT signature invalid",
			Context: make(map[string]interface{}),
			Cause:   rootErr,
		}

		errStr := oidcErr.Error()
		assert.Contains(t, errStr, "OIDC error [invalid_signature]: JWT signature invalid")
		assert.Contains(t, errStr, "caused by: signature mismatch")
	})

	t.Run("SessionError.Error without cause", func(t *testing.T) {
		sessErr := &SessionError{
			Operation: "load",
			Message:   "Session not found",
			SessionID: "sess123",
		}

		errStr := sessErr.Error()
		assert.Equal(t, "Session error in load: Session not found", errStr)
	})

	t.Run("SessionError.Error with cause", func(t *testing.T) {
		rootErr := errors.New("database connection failed")
		sessErr := &SessionError{
			Operation: "save",
			Message:   "Failed to persist session",
			SessionID: "sess456",
			Cause:     rootErr,
		}

		errStr := sessErr.Error()
		assert.Contains(t, errStr, "Session error in save: Failed to persist session")
		assert.Contains(t, errStr, "caused by: database connection failed")
	})

	t.Run("TokenError.Error without cause", func(t *testing.T) {
		tokenErr := &TokenError{
			TokenType: "access_token",
			Reason:    "expired",
			Message:   "Token has expired",
		}

		errStr := tokenErr.Error()
		assert.Equal(t, "Token error (access_token) - expired: Token has expired", errStr)
	})

	t.Run("TokenError.Error with cause", func(t *testing.T) {
		rootErr := errors.New("time check failed")
		tokenErr := &TokenError{
			TokenType: "id_token",
			Reason:    "expired",
			Message:   "Token validity period exceeded",
			Cause:     rootErr,
		}

		errStr := tokenErr.Error()
		assert.Contains(t, errStr, "Token error (id_token) - expired: Token validity period exceeded")
		assert.Contains(t, errStr, "caused by: time check failed")
	})
}

// TestGracefulDegradationHealthChecks tests health check functionality
func TestGracefulDegradationHealthChecks(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("performHealthChecks recovers degraded service", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		// Register health check that returns true
		healthCheckCalled := false
		gd.RegisterHealthCheck("test-service", func() bool {
			healthCheckCalled = true
			return true // Service is healthy
		})

		// Mark service as degraded
		gd.markServiceDegraded("test-service")

		// Verify service is degraded
		assert.True(t, gd.isServiceDegraded("test-service"))

		// Manually trigger health check
		gd.performHealthChecks()

		// Health check should have been called
		assert.True(t, healthCheckCalled, "health check should be called")

		// Service should be recovered
		assert.False(t, gd.isServiceDegraded("test-service"), "service should be recovered")
	})

	t.Run("performHealthChecks marks service degraded on failure", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		// Register health check that returns false
		gd.RegisterHealthCheck("failing-service", func() bool {
			return false // Service is unhealthy
		})

		// Initially not degraded
		assert.False(t, gd.isServiceDegraded("failing-service"))

		// Manually trigger health check
		gd.performHealthChecks()

		// Service should be marked degraded
		assert.True(t, gd.isServiceDegraded("failing-service"), "service should be degraded")
	})

	t.Run("performHealthChecks runs multiple health checks independently", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		service1Checked := false
		service2Checked := false

		gd.RegisterHealthCheck("service1", func() bool {
			service1Checked = true
			return true
		})

		gd.RegisterHealthCheck("service2", func() bool {
			service2Checked = true
			return true
		})

		// Manually trigger health checks
		gd.performHealthChecks()

		assert.True(t, service1Checked, "service1 health check should run")
		assert.True(t, service2Checked, "service2 health check should run")
	})

	t.Run("performHealthChecks handles empty health checks", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		// Call performHealthChecks with no registered health checks
		// Should not panic
		assert.NotPanics(t, func() {
			gd.performHealthChecks()
		})
	})
}

// TestGracefulDegradationServiceRecoveryTimeout tests recovery timeout behavior
func TestGracefulDegradationServiceRecoveryTimeout(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("service auto-recovers after timeout", func(t *testing.T) {
		baseTimeout := GetTestDuration(50 * time.Millisecond)
		config := GracefulDegradationConfig{
			HealthCheckInterval: 1 * time.Hour, // Long interval, won't run during test
			RecoveryTimeout:     baseTimeout,
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		// Mark service degraded
		gd.markServiceDegraded("auto-recover-service")

		// Verify degraded
		assert.True(t, gd.isServiceDegraded("auto-recover-service"))

		// Wait for recovery timeout (longer than timeout to ensure recovery)
		time.Sleep(baseTimeout + GetTestDuration(20*time.Millisecond))

		// Should auto-recover
		assert.False(t, gd.isServiceDegraded("auto-recover-service"), "service should auto-recover after timeout")
	})

	t.Run("service remains degraded before timeout", func(t *testing.T) {
		config := GracefulDegradationConfig{
			HealthCheckInterval: 1 * time.Hour,
			RecoveryTimeout:     1 * time.Hour, // Very long timeout
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		// Mark service degraded
		gd.markServiceDegraded("long-timeout-service")

		// Verify degraded
		assert.True(t, gd.isServiceDegraded("long-timeout-service"))

		// Wait a bit
		time.Sleep(GetTestDuration(10 * time.Millisecond))

		// Should still be degraded
		assert.True(t, gd.isServiceDegraded("long-timeout-service"), "service should remain degraded before timeout")
	})
}

// TestErrorRecoveryManagerIntegration tests full integration of error recovery mechanisms
func TestErrorRecoveryManagerIntegration(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	erm := NewErrorRecoveryManager(logger)

	t.Run("circuit breaker and retry integration", func(t *testing.T) {
		// Create a circuit breaker with higher max failures to allow retries
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			MaxFailures:  10, // High threshold
			Timeout:      60 * time.Second,
			ResetTimeout: 30 * time.Second,
		}, logger)

		erm.mutex.Lock()
		erm.circuitBreakers["test-service-integration"] = cb
		erm.mutex.Unlock()

		attempts := 0
		fn := func() error {
			attempts++
			if attempts < 3 {
				return errors.New("temporary failure")
			}
			return nil
		}

		err := erm.ExecuteWithRecovery(context.Background(), "test-service-integration", fn)

		assert.NoError(t, err)
		assert.GreaterOrEqual(t, attempts, 3, "should retry until success")
	})

	t.Run("circuit breaker opens on repeated failures", func(t *testing.T) {
		fn := func() error {
			return errors.New("persistent failure")
		}

		// First call - should fail after retries
		err1 := erm.ExecuteWithRecovery(context.Background(), "failing-service", fn)
		assert.Error(t, err1)

		// Second call - should fail after retries
		err2 := erm.ExecuteWithRecovery(context.Background(), "failing-service", fn)
		assert.Error(t, err2)

		// Check circuit breaker state
		cb := erm.GetCircuitBreaker("failing-service")
		state := cb.GetState()
		assert.Equal(t, CircuitBreakerOpen, state, "circuit should be open after repeated failures")
	})

	t.Run("recovery metrics include all mechanisms", func(t *testing.T) {
		metrics := erm.GetRecoveryMetrics()

		assert.NotNil(t, metrics)
		assert.Contains(t, metrics, "circuit_breakers")
		assert.Contains(t, metrics, "degraded_services")
	})
}

// TestContainsHelperFunction tests the contains helper function edge cases
func TestContainsHelperFunction(t *testing.T) {
	t.Run("exact match", func(t *testing.T) {
		assert.True(t, contains("timeout", "timeout"))
	})

	t.Run("prefix match", func(t *testing.T) {
		assert.True(t, contains("timeout error occurred", "timeout"))
	})

	t.Run("suffix match", func(t *testing.T) {
		assert.True(t, contains("connection timeout", "timeout"))
	})

	t.Run("middle match", func(t *testing.T) {
		assert.True(t, contains("a connection timeout error", "timeout"))
	})

	t.Run("no match", func(t *testing.T) {
		assert.False(t, contains("connection refused", "timeout"))
	})

	t.Run("substring longer than string", func(t *testing.T) {
		assert.False(t, contains("abc", "abcdef"))
	})

	t.Run("empty substring", func(t *testing.T) {
		assert.True(t, contains("test", ""))
	})

	t.Run("empty string", func(t *testing.T) {
		assert.False(t, contains("", "test"))
	})

	t.Run("both empty", func(t *testing.T) {
		assert.True(t, contains("", ""))
	})
}
