package traefikoidc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Circuit Breaker Tests
// =============================================================================

func TestCircuitBreakerStateTransitions(t *testing.T) {
	tests := []struct {
		name                string
		failures            int
		maxFailures         int
		expectedStateBefore string
		expectedStateAfter  string
	}{
		{
			name:                "stays closed below threshold",
			failures:            1,
			maxFailures:         3,
			expectedStateBefore: "closed",
			expectedStateAfter:  "closed",
		},
		{
			name:                "opens at threshold",
			failures:            3,
			maxFailures:         3,
			expectedStateBefore: "closed",
			expectedStateAfter:  "open",
		},
		{
			name:                "opens above threshold",
			failures:            5,
			maxFailures:         3,
			expectedStateBefore: "closed",
			expectedStateAfter:  "open",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := NewCircuitBreaker(CircuitBreakerConfig{
				MaxFailures:  tt.maxFailures,
				Timeout:      time.Second,
				ResetTimeout: time.Second,
			}, nil)

			if state := circuitBreakerStateToString(cb.GetState()); state != tt.expectedStateBefore {
				t.Errorf("Expected initial state %s, got %s", tt.expectedStateBefore, state)
			}

			for i := 0; i < tt.failures; i++ {
				_ = cb.Execute(func() error {
					return errors.New("test failure")
				})
			}

			if state := circuitBreakerStateToString(cb.GetState()); state != tt.expectedStateAfter {
				t.Errorf("Expected final state %s, got %s", tt.expectedStateAfter, state)
			}
		})
	}
}

func TestCircuitBreakerHalfOpenTransition(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      100 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, nil)

	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit should be open after failures")
	}

	time.Sleep(150 * time.Millisecond)

	allowed := false
	_ = cb.Execute(func() error {
		allowed = true
		return nil
	})

	if !allowed {
		t.Error("Request should be allowed in half-open state")
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Circuit should be closed after successful half-open request, got %v", cb.GetState())
	}
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      100 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, nil)

	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	time.Sleep(150 * time.Millisecond)

	_ = cb.Execute(func() error {
		return errors.New("fail again")
	})

	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Circuit should be open after half-open failure, got %v", cb.GetState())
	}
}

func TestCircuitBreakerConcurrency(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  10,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}, nil)

	var wg sync.WaitGroup
	successCount := int64(0)
	failureCount := int64(0)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cb.Execute(func() error {
				return nil
			})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&failureCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 100 {
		t.Errorf("Expected 100 successful requests, got %d", successCount)
	}

	metrics := cb.GetMetrics()
	if metrics["total_requests"].(int64) != 100 {
		t.Errorf("Expected 100 total requests, got %d", metrics["total_requests"])
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}, nil)

	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit should be open")
	}

	cb.Reset()

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Circuit should be closed after reset")
	}

	err := cb.Execute(func() error {
		return nil
	})

	if err != nil {
		t.Errorf("Should allow requests after reset, got error: %v", err)
	}
}

func TestCircuitBreakerMetrics(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  3,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}, nil)

	_ = cb.Execute(func() error { return nil })
	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return nil })

	metrics := cb.GetMetrics()

	if metrics["total_requests"].(int64) != 3 {
		t.Errorf("Expected 3 requests, got %d", metrics["total_requests"])
	}

	if metrics["total_successes"].(int64) != 2 {
		t.Errorf("Expected 2 successes, got %d", metrics["total_successes"])
	}

	if metrics["total_failures"].(int64) != 1 {
		t.Errorf("Expected 1 failure, got %d", metrics["total_failures"])
	}

	if metrics["state"] != "closed" {
		t.Errorf("Expected state 'closed', got %v", metrics["state"])
	}
}

func TestCircuitBreakerIsAvailable(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      100 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}, nil)

	if !cb.IsAvailable() {
		t.Error("Circuit should be available initially")
	}

	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	if cb.IsAvailable() {
		t.Error("Circuit should not be available when open")
	}

	time.Sleep(150 * time.Millisecond)

	if !cb.IsAvailable() {
		t.Error("Circuit should be available in half-open state")
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	if config.MaxFailures != 2 {
		t.Errorf("Expected MaxFailures 2, got %d", config.MaxFailures)
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("Expected Timeout 60s, got %v", config.Timeout)
	}

	if config.ResetTimeout != 30*time.Second {
		t.Errorf("Expected ResetTimeout 30s, got %v", config.ResetTimeout)
	}
}

func TestCircuitBreakerAllowRequestEdgeCases(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("invalid state returns false", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		cb := NewCircuitBreaker(config, logger)

		cb.mutex.Lock()
		cb.state = CircuitBreakerState(999)
		cb.mutex.Unlock()

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

		cb.Execute(func() error { return errors.New("fail") })

		assert.Equal(t, CircuitBreakerOpen, cb.GetState())
		assert.False(t, cb.allowRequest())

		time.Sleep(baseTimeout + GetTestDuration(20*time.Millisecond))

		allowed := cb.allowRequest()
		assert.True(t, allowed, "should allow request after timeout")
		assert.Equal(t, CircuitBreakerHalfOpen, cb.GetState())
	})

	t.Run("half-open allows requests", func(t *testing.T) {
		config := DefaultCircuitBreakerConfig()
		cb := NewCircuitBreaker(config, logger)

		cb.mutex.Lock()
		cb.state = CircuitBreakerHalfOpen
		cb.mutex.Unlock()

		allowed := cb.allowRequest()
		assert.True(t, allowed, "half-open should allow requests")
	})

	t.Run("open blocks requests before timeout", func(t *testing.T) {
		config := CircuitBreakerConfig{
			MaxFailures:  1,
			Timeout:      1 * time.Hour,
			ResetTimeout: 30 * time.Second,
		}
		cb := NewCircuitBreaker(config, logger)

		cb.Execute(func() error { return errors.New("fail") })

		allowed := cb.allowRequest()
		assert.False(t, allowed, "open circuit should block requests")
	})
}

// =============================================================================
// Retry Executor Tests
// =============================================================================

func TestRetryExecutorSuccess(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      time.Second,
		BackoffFactor: 2.0,
		EnableJitter:  false,
	}, nil)

	attempts := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		attempts++
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if attempts != 1 {
		t.Errorf("Expected 1 attempt for immediate success, got %d", attempts)
	}
}

func TestRetryExecutorEventualSuccess(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    false,
		RetryableErrors: []string{"temporary failure"},
	}, nil)

	attempts := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	})

	if err != nil {
		t.Errorf("Expected success after retries, got %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestRetryExecutorMaxAttemptsExceeded(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    false,
		RetryableErrors: []string{"temporary failure"},
	}, nil)

	attempts := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		attempts++
		return errors.New("temporary failure")
	})

	if err == nil {
		t.Error("Expected error after max attempts")
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestRetryExecutorNonRetryableError(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    10 * time.Millisecond,
		MaxDelay:        time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    false,
		RetryableErrors: []string{"temporary failure"},
	}, nil)

	attempts := 0
	err := re.ExecuteWithContext(context.Background(), func() error {
		attempts++
		return errors.New("permanent failure")
	})

	if err == nil {
		t.Error("Expected error for non-retryable failure")
	}

	if attempts != 1 {
		t.Errorf("Expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestRetryExecutorContextCancellation(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     5,
		InitialDelay:    100 * time.Millisecond,
		MaxDelay:        time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    false,
		RetryableErrors: []string{"temporary failure"},
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0
	done := make(chan error, 1)

	go func() {
		done <- re.ExecuteWithContext(ctx, func() error {
			attempts++
			return errors.New("temporary failure")
		})
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()

	err := <-done

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}

	if attempts == 0 {
		t.Error("Should have attempted at least once")
	}

	if attempts >= 5 {
		t.Error("Should not have completed all attempts after cancellation")
	}
}

func TestRetryExecutorExponentialBackoff(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     4,
		InitialDelay:    100 * time.Millisecond,
		MaxDelay:        time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    false,
		RetryableErrors: []string{"temporary failure"},
	}, nil)

	attempts := 0
	startTime := time.Now()

	_ = re.ExecuteWithContext(context.Background(), func() error {
		attempts++
		return errors.New("temporary failure")
	})

	elapsed := time.Since(startTime)

	if elapsed < 650*time.Millisecond || elapsed > 850*time.Millisecond {
		t.Errorf("Expected ~700ms elapsed with exponential backoff, got %v", elapsed)
	}

	if attempts != 4 {
		t.Errorf("Expected 4 attempts, got %d", attempts)
	}
}

func TestRetryExecutorWithJitter(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:     3,
		InitialDelay:    100 * time.Millisecond,
		MaxDelay:        time.Second,
		BackoffFactor:   2.0,
		EnableJitter:    true,
		RetryableErrors: []string{"temporary failure"},
	}, nil)

	durations := make([]time.Duration, 5)
	for i := 0; i < 5; i++ {
		startTime := time.Now()
		_ = re.ExecuteWithContext(context.Background(), func() error {
			return errors.New("temporary failure")
		})
		durations[i] = time.Since(startTime)
	}

	allSame := true
	for i := 1; i < len(durations); i++ {
		if durations[i] != durations[0] {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("Expected jitter to add variability to retry delays")
	}
}

func TestRetryExecutorNetworkErrors(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      time.Second,
		BackoffFactor: 2.0,
		EnableJitter:  false,
	}, nil)

	tests := []struct {
		name        string
		err         error
		shouldRetry bool
	}{
		{
			name:        "timeout error",
			err:         &mockNetError{timeout: true, temporary: true},
			shouldRetry: true,
		},
		{
			name:        "temporary network error",
			err:         &mockNetError{timeout: false, temporary: true, msg: "temporary failure"},
			shouldRetry: true,
		},
		{
			name:        "connection refused",
			err:         &mockNetError{timeout: false, temporary: false, msg: "connection refused"},
			shouldRetry: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			_ = re.ExecuteWithContext(context.Background(), func() error {
				attempts++
				return tt.err
			})

			expectedAttempts := 1
			if tt.shouldRetry {
				expectedAttempts = 3
			}

			if attempts != expectedAttempts {
				t.Errorf("Expected %d attempts, got %d", expectedAttempts, attempts)
			}
		})
	}
}

func TestRetryExecutorHTTPErrors(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      time.Second,
		BackoffFactor: 2.0,
		EnableJitter:  false,
	}, nil)

	tests := []struct {
		name        string
		statusCode  int
		shouldRetry bool
	}{
		{"500 Internal Server Error", 500, true},
		{"502 Bad Gateway", 502, true},
		{"503 Service Unavailable", 503, true},
		{"429 Too Many Requests", 429, true},
		{"400 Bad Request", 400, false},
		{"404 Not Found", 404, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			_ = re.ExecuteWithContext(context.Background(), func() error {
				attempts++
				return &HTTPError{StatusCode: tt.statusCode, Message: "test"}
			})

			expectedAttempts := 1
			if tt.shouldRetry {
				expectedAttempts = 3
			}

			if attempts != expectedAttempts {
				t.Errorf("Expected %d attempts, got %d", expectedAttempts, attempts)
			}
		})
	}
}

func TestRetryExecutorMetrics(t *testing.T) {
	re := NewRetryExecutor(RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      time.Second,
		BackoffFactor: 2.0,
		EnableJitter:  true,
	}, nil)

	_ = re.ExecuteWithContext(context.Background(), func() error {
		return nil
	})

	metrics := re.GetMetrics()

	if metrics["max_attempts"] != 3 {
		t.Errorf("Expected max_attempts 3, got %v", metrics["max_attempts"])
	}

	if metrics["backoff_factor"] != 2.0 {
		t.Errorf("Expected backoff_factor 2.0, got %v", metrics["backoff_factor"])
	}

	if metrics["enable_jitter"] != true {
		t.Errorf("Expected enable_jitter true, got %v", metrics["enable_jitter"])
	}
}

func TestRetryExecutorReset(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	executor := NewRetryExecutor(DefaultRetryConfig(), logger)

	require.NotNil(t, executor)

	assert.NotPanics(t, func() {
		executor.Reset()
	})

	executor.Reset()
	executor.Reset()
}

func TestRetryExecutorIsAvailable(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	executor := NewRetryExecutor(DefaultRetryConfig(), logger)

	assert.True(t, executor.IsAvailable())

	ctx := context.Background()
	executor.ExecuteWithContext(ctx, func() error {
		return nil
	})

	assert.True(t, executor.IsAvailable())
}

func TestRetryExecutorIsRetryableErrorEdgeCases(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultRetryConfig()
	re := NewRetryExecutor(config, logger)

	t.Run("nil error is not retryable", func(t *testing.T) {
		retryable := re.isRetryableError(nil)
		assert.False(t, retryable)
	})

	t.Run("HTTPError with 429 is retryable", func(t *testing.T) {
		httpErr := &HTTPError{StatusCode: 429, Message: "Too Many Requests"}
		retryable := re.isRetryableError(httpErr)
		assert.True(t, retryable, "429 Too Many Requests should be retryable")
	})

	t.Run("HTTPError with 500 is retryable", func(t *testing.T) {
		httpErr := &HTTPError{StatusCode: 500, Message: "Internal Server Error"}
		retryable := re.isRetryableError(httpErr)
		assert.True(t, retryable, "500 errors should be retryable")
	})

	t.Run("HTTPError with 503 is retryable", func(t *testing.T) {
		httpErr := &HTTPError{StatusCode: 503, Message: "Service Unavailable"}
		retryable := re.isRetryableError(httpErr)
		assert.True(t, retryable, "503 errors should be retryable")
	})

	t.Run("HTTPError with 400 is not retryable", func(t *testing.T) {
		httpErr := &HTTPError{StatusCode: 400, Message: "Bad Request"}
		retryable := re.isRetryableError(httpErr)
		assert.False(t, retryable, "400 errors should not be retryable")
	})

	t.Run("net.Error with timeout is retryable", func(t *testing.T) {
		netErr := &mockNetError{timeout: true, temporary: false, msg: "timeout error"}
		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "timeout errors should be retryable")
	})

	t.Run("net.Error with connection refused is retryable", func(t *testing.T) {
		netErr := &mockNetError{timeout: false, temporary: false, msg: "connection refused"}
		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "connection refused should be retryable")
	})

	t.Run("net.Error with connection reset is retryable", func(t *testing.T) {
		netErr := &mockNetError{timeout: false, temporary: false, msg: "connection reset by peer"}
		retryable := re.isRetryableError(netErr)
		assert.True(t, retryable, "connection reset should be retryable")
	})

	t.Run("non-retryable error", func(t *testing.T) {
		err := errors.New("invalid input data")
		retryable := re.isRetryableError(err)
		assert.False(t, retryable, "non-configured error should not be retryable")
	})
}

func TestRetryExecutorCalculateDelayEdgeCases(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("delay calculation without jitter", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   3,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      5 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  false,
		}
		re := NewRetryExecutor(config, logger)

		delay1 := re.calculateDelay(1)
		assert.Equal(t, 100*time.Millisecond, delay1)

		delay2 := re.calculateDelay(2)
		assert.Equal(t, 200*time.Millisecond, delay2)

		delay3 := re.calculateDelay(3)
		assert.Equal(t, 400*time.Millisecond, delay3)
	})

	t.Run("delay calculation with jitter", func(t *testing.T) {
		config := RetryConfig{
			MaxAttempts:   3,
			InitialDelay:  100 * time.Millisecond,
			MaxDelay:      5 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  true,
		}
		re := NewRetryExecutor(config, logger)

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
			MaxDelay:      500 * time.Millisecond,
			BackoffFactor: 2.0,
			EnableJitter:  false,
		}
		re := NewRetryExecutor(config, logger)

		delay := re.calculateDelay(10)
		assert.Equal(t, 500*time.Millisecond, delay, "delay should be capped at max")
	})
}

// =============================================================================
// Error Types Tests
// =============================================================================

func TestOIDCErrorCreation(t *testing.T) {
	err := NewOIDCError("invalid_token", "Token is expired", nil)

	if err.Code != "invalid_token" {
		t.Errorf("Expected code 'invalid_token', got %s", err.Code)
	}

	if err.Message != "Token is expired" {
		t.Errorf("Expected message 'Token is expired', got %s", err.Message)
	}

	expectedMsg := "OIDC error [invalid_token]: Token is expired"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error string '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestOIDCErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewOIDCError("token_error", "Failed to validate", cause)

	if err.Unwrap() != cause {
		t.Error("Expected unwrap to return underlying cause")
	}

	if err.Error() == "" {
		t.Error("Error string should include cause")
	}
}

func TestOIDCErrorWithContext(t *testing.T) {
	err := NewOIDCError("auth_failed", "Authentication failed", nil).
		WithContext("provider", "google").
		WithContext("user_id", "12345")

	if err.Context["provider"] != "google" {
		t.Errorf("Expected provider 'google', got %v", err.Context["provider"])
	}

	if err.Context["user_id"] != "12345" {
		t.Errorf("Expected user_id '12345', got %v", err.Context["user_id"])
	}
}

func TestSessionErrorCreation(t *testing.T) {
	err := NewSessionError("save", "Failed to save session", nil)

	if err.Operation != "save" {
		t.Errorf("Expected operation 'save', got %s", err.Operation)
	}

	expectedMsg := "Session error in save: Failed to save session"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error string '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestSessionErrorWithSessionID(t *testing.T) {
	err := NewSessionError("load", "Session not found", nil).
		WithSessionID("sess_12345")

	if err.SessionID != "sess_12345" {
		t.Errorf("Expected session ID 'sess_12345', got %s", err.SessionID)
	}
}

func TestSessionErrorUnwrap(t *testing.T) {
	t.Run("unwrap with cause", func(t *testing.T) {
		rootErr := errors.New("root cause")
		sessionErr := NewSessionError("save", "failed to save session", rootErr)

		unwrapped := sessionErr.Unwrap()
		assert.Equal(t, rootErr, unwrapped)
	})

	t.Run("unwrap without cause", func(t *testing.T) {
		sessionErr := NewSessionError("load", "failed to load session", nil)

		unwrapped := sessionErr.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("error chain", func(t *testing.T) {
		rootErr := errors.New("database error")
		sessionErr := NewSessionError("delete", "failed to delete session", rootErr)

		assert.True(t, errors.Is(sessionErr, rootErr))
	})
}

func TestTokenErrorCreation(t *testing.T) {
	err := NewTokenError("id_token", "expired", "Token has expired", nil)

	if err.TokenType != "id_token" {
		t.Errorf("Expected token type 'id_token', got %s", err.TokenType)
	}

	if err.Reason != "expired" {
		t.Errorf("Expected reason 'expired', got %s", err.Reason)
	}

	expectedMsg := "Token error (id_token) - expired: Token has expired"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error string '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestTokenErrorUnwrap(t *testing.T) {
	t.Run("unwrap with cause", func(t *testing.T) {
		rootErr := errors.New("signature verification failed")
		tokenErr := NewTokenError("id_token", "invalid", "token is invalid", rootErr)

		unwrapped := tokenErr.Unwrap()
		assert.Equal(t, rootErr, unwrapped)
	})

	t.Run("unwrap without cause", func(t *testing.T) {
		tokenErr := NewTokenError("access_token", "expired", "token has expired", nil)

		unwrapped := tokenErr.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("error chain", func(t *testing.T) {
		rootErr := errors.New("crypto error")
		tokenErr := NewTokenError("refresh_token", "malformed", "token is malformed", rootErr)

		assert.True(t, errors.Is(tokenErr, rootErr))
	})
}

func TestErrorTypesErrorMethodsWithoutCause(t *testing.T) {
	t.Run("HTTPError.Error without cause", func(t *testing.T) {
		httpErr := &HTTPError{StatusCode: 404, Message: "Not Found"}
		errStr := httpErr.Error()
		assert.Equal(t, "HTTP 404: Not Found", errStr)
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

// =============================================================================
// Base Recovery Mechanism Tests
// =============================================================================

func TestBaseRecoveryMechanismMetrics(t *testing.T) {
	base := NewBaseRecoveryMechanism("test-mechanism", nil)

	base.RecordRequest()
	base.RecordSuccess()
	base.RecordRequest()
	base.RecordFailure()

	metrics := base.GetBaseMetrics()

	if metrics["total_requests"].(int64) != 2 {
		t.Errorf("Expected 2 requests, got %d", metrics["total_requests"])
	}

	if metrics["total_successes"].(int64) != 1 {
		t.Errorf("Expected 1 success, got %d", metrics["total_successes"])
	}

	if metrics["total_failures"].(int64) != 1 {
		t.Errorf("Expected 1 failure, got %d", metrics["total_failures"])
	}

	if metrics["success_rate"].(float64) != 0.5 {
		t.Errorf("Expected success rate 0.5, got %v", metrics["success_rate"])
	}
}

func TestBaseRecoveryMechanismConcurrentUpdates(t *testing.T) {
	base := NewBaseRecoveryMechanism("concurrent-test", nil)

	var wg sync.WaitGroup
	iterations := 1000

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base.RecordRequest()
			if i%2 == 0 {
				base.RecordSuccess()
			} else {
				base.RecordFailure()
			}
		}()
	}

	wg.Wait()

	metrics := base.GetBaseMetrics()

	if metrics["total_requests"].(int64) != int64(iterations) {
		t.Errorf("Expected %d requests, got %d", iterations, metrics["total_requests"])
	}

	totalSuccessesAndFailures := metrics["total_successes"].(int64) + metrics["total_failures"].(int64)
	if totalSuccessesAndFailures != int64(iterations) {
		t.Errorf("Expected %d total successes+failures, got %d", iterations, totalSuccessesAndFailures)
	}
}

func TestBaseRecoveryMechanism_GetBaseMetrics(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	metrics := base.GetBaseMetrics()

	if metrics == nil {
		t.Fatal("Expected non-nil metrics")
	}

	expectedFields := []string{
		"total_requests",
		"total_failures",
		"total_successes",
		"uptime_seconds",
		"name",
	}

	for _, field := range expectedFields {
		if _, exists := metrics[field]; !exists {
			t.Errorf("Expected metric field %s to exist", field)
		}
	}
}

func TestBaseRecoveryMechanism_LogMethods(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	base.LogInfo("test message")
	base.LogInfo("test message with args: %s %d", "arg1", 42)

	base.LogError("error message")
	base.LogError("error message with args: %s %d", "error", 500)

	base.LogDebug("debug message")
	base.LogDebug("debug message with args: %s %d", "debug", 123)

	baseNoLogger := NewBaseRecoveryMechanism("test", nil)
	baseNoLogger.LogInfo("test message")
	baseNoLogger.LogError("error message")
	baseNoLogger.LogDebug("debug message")
}

// =============================================================================
// Error Recovery Manager Tests
// =============================================================================

func TestErrorRecoveryManagerCreation(t *testing.T) {
	erm := NewErrorRecoveryManager(nil)

	if erm == nil {
		t.Fatal("Expected non-nil error recovery manager")
	}

	if erm.retryExecutor == nil {
		t.Error("Expected retry executor to be initialized")
	}

	if erm.gracefulDegradation == nil {
		t.Error("Expected graceful degradation to be initialized")
	}
}

func TestErrorRecoveryManagerGetCircuitBreaker(t *testing.T) {
	erm := NewErrorRecoveryManager(nil)

	cb1 := erm.GetCircuitBreaker("service1")
	cb2 := erm.GetCircuitBreaker("service1")
	cb3 := erm.GetCircuitBreaker("service2")

	if cb1 == nil || cb2 == nil || cb3 == nil {
		t.Fatal("Expected non-nil circuit breakers")
	}

	if cb1 != cb2 {
		t.Error("Expected same circuit breaker instance for same service")
	}

	if cb1 == cb3 {
		t.Error("Expected different circuit breaker instances for different services")
	}
}

func TestErrorRecoveryManagerExecuteWithRecovery(t *testing.T) {
	erm := NewErrorRecoveryManager(nil)

	success := false
	err := erm.ExecuteWithRecovery(context.Background(), "test-service", func() error {
		success = true
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !success {
		t.Error("Expected function to execute")
	}
}

func TestErrorRecoveryManagerMetrics(t *testing.T) {
	erm := NewErrorRecoveryManager(nil)

	_ = erm.GetCircuitBreaker("service1")
	_ = erm.GetCircuitBreaker("service2")

	metrics := erm.GetRecoveryMetrics()

	cbMetrics, ok := metrics["circuit_breakers"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected circuit_breakers in metrics")
	}

	if len(cbMetrics) != 2 {
		t.Errorf("Expected 2 circuit breakers in metrics, got %d", len(cbMetrics))
	}
}

func TestErrorRecoveryManagerIntegration(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	erm := NewErrorRecoveryManager(logger)

	t.Run("circuit breaker and retry integration", func(t *testing.T) {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			MaxFailures:  10,
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

		err1 := erm.ExecuteWithRecovery(context.Background(), "failing-service", fn)
		assert.Error(t, err1)

		err2 := erm.ExecuteWithRecovery(context.Background(), "failing-service", fn)
		assert.Error(t, err2)

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

// =============================================================================
// Graceful Degradation Tests
// =============================================================================

func TestGracefulDegradationRegisterFallback(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("register single fallback", func(t *testing.T) {
		fallback := func() (interface{}, error) {
			return "fallback result", nil
		}

		gd.RegisterFallback("service1", fallback)

		result, err := gd.ExecuteWithFallback("service1", func() (interface{}, error) {
			return nil, errors.New("service failed")
		})

		assert.NoError(t, err)
		assert.Equal(t, "fallback result", result)
	})

	t.Run("override existing fallback", func(t *testing.T) {
		gd.RegisterFallback("service4", func() (interface{}, error) {
			return "old fallback", nil
		})
		gd.RegisterFallback("service4", func() (interface{}, error) {
			return "new fallback", nil
		})

		result, _ := gd.ExecuteWithFallback("service4", func() (interface{}, error) {
			return nil, errors.New("fail")
		})

		assert.Equal(t, "new fallback", result)
	})
}

func TestGracefulDegradationRegisterHealthCheck(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("register health check", func(t *testing.T) {
		healthy := true
		healthCheck := func() bool {
			return healthy
		}

		gd.RegisterHealthCheck("service1", healthCheck)

		gd.markServiceDegraded("service1")
		assert.True(t, gd.isServiceDegraded("service1"))

		healthy = true
		time.Sleep(100 * time.Millisecond)
	})
}

func TestGracefulDegradationExecuteWithContext(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("successful execution", func(t *testing.T) {
		ctx := context.Background()
		err := gd.ExecuteWithContext(ctx, func() error {
			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("failed execution", func(t *testing.T) {
		ctx := context.Background()
		testErr := errors.New("operation failed")

		err := gd.ExecuteWithContext(ctx, func() error {
			return testErr
		})

		assert.Error(t, err)
	})

	t.Run("uses fallback on failure", func(t *testing.T) {
		gd.RegisterFallback("default", func() (interface{}, error) {
			return nil, nil
		})

		ctx := context.Background()
		err := gd.ExecuteWithContext(ctx, func() error {
			return errors.New("primary failed")
		})

		assert.NoError(t, err)
	})
}

func TestGracefulDegradationExecuteWithFallback(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("primary succeeds", func(t *testing.T) {
		result, err := gd.ExecuteWithFallback("service1", func() (interface{}, error) {
			return "primary result", nil
		})

		assert.NoError(t, err)
		assert.Equal(t, "primary result", result)
	})

	t.Run("fallback succeeds when primary fails", func(t *testing.T) {
		gd.RegisterFallback("service2", func() (interface{}, error) {
			return "fallback result", nil
		})

		result, err := gd.ExecuteWithFallback("service2", func() (interface{}, error) {
			return nil, errors.New("primary failed")
		})

		assert.NoError(t, err)
		assert.Equal(t, "fallback result", result)
	})

	t.Run("fallback also fails", func(t *testing.T) {
		gd.RegisterFallback("service4", func() (interface{}, error) {
			return nil, errors.New("fallback also failed")
		})

		result, err := gd.ExecuteWithFallback("service4", func() (interface{}, error) {
			return nil, errors.New("primary failed")
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "fallback also failed")
	})
}

func TestGracefulDegradationIsServiceDegraded(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	config.RecoveryTimeout = 100 * time.Millisecond
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("service not degraded initially", func(t *testing.T) {
		assert.False(t, gd.isServiceDegraded("new-service"))
	})

	t.Run("service degraded after marking", func(t *testing.T) {
		gd.markServiceDegraded("service1")
		assert.True(t, gd.isServiceDegraded("service1"))
	})

	t.Run("service recovers after timeout", func(t *testing.T) {
		gd.markServiceDegraded("service2")
		assert.True(t, gd.isServiceDegraded("service2"))

		time.Sleep(150 * time.Millisecond)

		assert.False(t, gd.isServiceDegraded("service2"))
	})
}

func TestGracefulDegradationMarkServiceDegraded(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("mark single service", func(t *testing.T) {
		gd.markServiceDegraded("service1")

		degraded := gd.GetDegradedServices()
		assert.Contains(t, degraded, "service1")
	})

	t.Run("mark multiple services", func(t *testing.T) {
		gd.markServiceDegraded("service2")
		gd.markServiceDegraded("service3")

		degraded := gd.GetDegradedServices()
		assert.Contains(t, degraded, "service2")
		assert.Contains(t, degraded, "service3")
	})
}

func TestGracefulDegradationReset(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("reset clears degraded services", func(t *testing.T) {
		gd.markServiceDegraded("service1")
		gd.markServiceDegraded("service2")
		gd.markServiceDegraded("service3")

		assert.Len(t, gd.GetDegradedServices(), 3)

		gd.Reset()

		assert.Len(t, gd.GetDegradedServices(), 0)
	})

	t.Run("multiple resets are safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			gd.Reset()
			gd.Reset()
			gd.Reset()
		})
	})
}

func TestGracefulDegradationIsAvailable(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	assert.True(t, gd.IsAvailable())

	gd.markServiceDegraded("service1")
	assert.True(t, gd.IsAvailable())

	gd.Reset()
	assert.True(t, gd.IsAvailable())
}

func TestGracefulDegradationGetMetrics(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("basic metrics", func(t *testing.T) {
		metrics := gd.GetMetrics()

		require.NotNil(t, metrics)
		assert.Contains(t, metrics, "degraded_services_count")
		assert.Contains(t, metrics, "degraded_services")
		assert.Contains(t, metrics, "registered_fallbacks_count")
		assert.Contains(t, metrics, "registered_health_checks_count")
		assert.Contains(t, metrics, "health_check_interval_seconds")
		assert.Contains(t, metrics, "recovery_timeout_seconds")
		assert.Contains(t, metrics, "fallbacks_enabled")
	})

	t.Run("metrics reflect degraded services", func(t *testing.T) {
		gd.Reset()
		gd.markServiceDegraded("service1")
		gd.markServiceDegraded("service2")

		metrics := gd.GetMetrics()

		assert.Equal(t, 2, metrics["degraded_services_count"])
		degradedList := metrics["degraded_services"].([]string)
		assert.Len(t, degradedList, 2)
	})

	t.Run("metrics include base metrics", func(t *testing.T) {
		metrics := gd.GetMetrics()

		assert.Contains(t, metrics, "name")
		assert.Contains(t, metrics, "uptime_seconds")
		assert.Contains(t, metrics, "total_requests")
	})
}

func TestGracefulDegradationHealthChecks(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("performHealthChecks recovers degraded service", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		healthCheckCalled := false
		gd.RegisterHealthCheck("test-service", func() bool {
			healthCheckCalled = true
			return true
		})

		gd.markServiceDegraded("test-service")

		assert.True(t, gd.isServiceDegraded("test-service"))

		gd.performHealthChecks()

		assert.True(t, healthCheckCalled, "health check should be called")

		assert.False(t, gd.isServiceDegraded("test-service"), "service should be recovered")
	})

	t.Run("performHealthChecks marks service degraded on failure", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		gd.RegisterHealthCheck("failing-service", func() bool {
			return false
		})

		assert.False(t, gd.isServiceDegraded("failing-service"))

		gd.performHealthChecks()

		assert.True(t, gd.isServiceDegraded("failing-service"), "service should be degraded")
	})

	t.Run("performHealthChecks handles empty health checks", func(t *testing.T) {
		config := DefaultGracefulDegradationConfig()
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		assert.NotPanics(t, func() {
			gd.performHealthChecks()
		})
	})
}

func TestGracefulDegradationServiceRecoveryTimeout(t *testing.T) {
	logger := GetSingletonNoOpLogger()

	t.Run("service auto-recovers after timeout", func(t *testing.T) {
		baseTimeout := GetTestDuration(50 * time.Millisecond)
		config := GracefulDegradationConfig{
			HealthCheckInterval: 1 * time.Hour,
			RecoveryTimeout:     baseTimeout,
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		gd.markServiceDegraded("auto-recover-service")

		assert.True(t, gd.isServiceDegraded("auto-recover-service"))

		time.Sleep(baseTimeout + GetTestDuration(20*time.Millisecond))

		assert.False(t, gd.isServiceDegraded("auto-recover-service"), "service should auto-recover after timeout")
	})

	t.Run("service remains degraded before timeout", func(t *testing.T) {
		config := GracefulDegradationConfig{
			HealthCheckInterval: 1 * time.Hour,
			RecoveryTimeout:     1 * time.Hour,
			EnableFallbacks:     true,
		}
		gd := NewGracefulDegradation(config, logger)
		defer gd.Close()

		gd.markServiceDegraded("long-timeout-service")

		assert.True(t, gd.isServiceDegraded("long-timeout-service"))

		time.Sleep(GetTestDuration(10 * time.Millisecond))

		assert.True(t, gd.isServiceDegraded("long-timeout-service"), "service should remain degraded before timeout")
	})
}

func TestGracefulDegradationFullScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full scenario test in short mode")
	}

	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	config.RecoveryTimeout = 200 * time.Millisecond
	config.HealthCheckInterval = 50 * time.Millisecond
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	gd.RegisterFallback("critical-service", func() (interface{}, error) {
		return "fallback data", nil
	})

	serviceHealthy := false
	gd.RegisterHealthCheck("critical-service", func() bool {
		return serviceHealthy
	})

	result1, err1 := gd.ExecuteWithFallback("critical-service", func() (interface{}, error) {
		return "primary data", nil
	})
	assert.NoError(t, err1)
	assert.Equal(t, "primary data", result1)

	result2, err2 := gd.ExecuteWithFallback("critical-service", func() (interface{}, error) {
		return nil, errors.New("service down")
	})
	assert.NoError(t, err2)
	assert.Equal(t, "fallback data", result2)

	assert.True(t, gd.isServiceDegraded("critical-service"))

	result3, err3 := gd.ExecuteWithFallback("critical-service", func() (interface{}, error) {
		return "should not be called", nil
	})
	assert.NoError(t, err3)
	assert.Equal(t, "fallback data", result3)

	serviceHealthy = true
	time.Sleep(250 * time.Millisecond)

	metrics := gd.GetMetrics()
	assert.NotNil(t, metrics)
}

// =============================================================================
// Error Helper Functions Tests
// =============================================================================

func TestIsTraefikDefaultCertError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "network error",
			err:      &mockNetError{msg: "connection refused"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTraefikDefaultCertError(tt.err)
			if result != tt.expected {
				t.Errorf("isTraefikDefaultCertError() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsEOFError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "error containing EOF in message",
			err:      errors.New("connection closed: EOF"),
			expected: true,
		},
		{
			name:     "error containing unexpected EOF",
			err:      errors.New("read: unexpected EOF"),
			expected: true,
		},
		{
			name:     "network error without EOF",
			err:      &mockNetError{msg: "connection refused"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isEOFError(tt.err)
			if result != tt.expected {
				t.Errorf("isEOFError() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsCertificateError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "error containing certificate in message",
			err:      errors.New("tls: failed to verify certificate"),
			expected: true,
		},
		{
			name:     "error containing x509 in message",
			err:      errors.New("x509: certificate signed by unknown authority"),
			expected: true,
		},
		{
			name:     "error containing tls in message",
			err:      errors.New("tls handshake failed"),
			expected: true,
		},
		{
			name:     "error containing ssl in message",
			err:      errors.New("ssl connection error"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCertificateError(tt.err)
			if result != tt.expected {
				t.Errorf("isCertificateError() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestMetadataFetchRetryConfig(t *testing.T) {
	config := MetadataFetchRetryConfig()

	if config.MaxAttempts != 10 {
		t.Errorf("Expected MaxAttempts 10, got %d", config.MaxAttempts)
	}

	if config.InitialDelay != 1*time.Second {
		t.Errorf("Expected InitialDelay 1s, got %v", config.InitialDelay)
	}

	if config.MaxDelay != 10*time.Second {
		t.Errorf("Expected MaxDelay 10s, got %v", config.MaxDelay)
	}

	if config.BackoffFactor != 1.5 {
		t.Errorf("Expected BackoffFactor 1.5, got %v", config.BackoffFactor)
	}

	if !config.EnableJitter {
		t.Error("Expected EnableJitter to be true")
	}

	expectedPatterns := []string{"EOF", "certificate", "x509", "tls"}
	for _, pattern := range expectedPatterns {
		found := false
		for _, retryableErr := range config.RetryableErrors {
			if retryableErr == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected '%s' in RetryableErrors", pattern)
		}
	}
}

func TestRetryExecutorStartupErrors(t *testing.T) {
	_ = NewRetryExecutor(MetadataFetchRetryConfig(), nil)

	tests := []struct {
		name        string
		err         error
		shouldRetry bool
	}{
		{
			name:        "EOF error",
			err:         errors.New("read tcp: EOF"),
			shouldRetry: true,
		},
		{
			name:        "unexpected EOF",
			err:         errors.New("http: unexpected EOF"),
			shouldRetry: true,
		},
		{
			name:        "certificate error",
			err:         errors.New("x509: certificate signed by unknown authority"),
			shouldRetry: true,
		},
		{
			name:        "TLS error",
			err:         errors.New("tls: failed to verify certificate"),
			shouldRetry: true,
		},
		{
			name:        "connection refused",
			err:         errors.New("dial tcp: connection refused"),
			shouldRetry: true,
		},
		{
			name:        "permanent error",
			err:         errors.New("invalid response format"),
			shouldRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testConfig := RetryConfig{
				MaxAttempts:   3,
				InitialDelay:  1 * time.Millisecond,
				MaxDelay:      10 * time.Millisecond,
				BackoffFactor: 1.5,
				EnableJitter:  false,
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
			testRe := NewRetryExecutor(testConfig, nil)

			attempts := 0
			_ = testRe.ExecuteWithContext(context.Background(), func() error {
				attempts++
				return tt.err
			})

			expectedAttempts := 1
			if tt.shouldRetry {
				expectedAttempts = 3
			}

			if attempts != expectedAttempts {
				t.Errorf("Expected %d attempts for '%s', got %d", expectedAttempts, tt.name, attempts)
			}
		})
	}
}

func TestRetryExecutorIsRetryableErrorIntegration(t *testing.T) {
	re := NewRetryExecutor(DefaultRetryConfig(), nil)

	tests := []struct {
		name        string
		err         error
		shouldRetry bool
	}{
		{
			name:        "EOF in error message",
			err:         errors.New("connection reset by peer: EOF"),
			shouldRetry: true,
		},
		{
			name:        "certificate in error message",
			err:         errors.New("x509: certificate has expired"),
			shouldRetry: true,
		},
		{
			name:        "TLS in error message",
			err:         errors.New("tls: handshake failure"),
			shouldRetry: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := re.isRetryableError(tt.err)
			if result != tt.shouldRetry {
				t.Errorf("isRetryableError(%q) = %v, expected %v", tt.err.Error(), result, tt.shouldRetry)
			}
		})
	}
}

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

// =============================================================================
// Helper Types and Functions
// =============================================================================

func circuitBreakerStateToString(state CircuitBreakerState) string {
	switch state {
	case CircuitBreakerClosed:
		return "closed"
	case CircuitBreakerOpen:
		return "open"
	case CircuitBreakerHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

var _ net.Error = (*mockNetError)(nil)
