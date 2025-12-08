package traefikoidc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test Circuit Breaker State Transitions

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

			// Verify initial state
			if state := circuitBreakerStateToString(cb.GetState()); state != tt.expectedStateBefore {
				t.Errorf("Expected initial state %s, got %s", tt.expectedStateBefore, state)
			}

			// Trigger failures
			for i := 0; i < tt.failures; i++ {
				_ = cb.Execute(func() error {
					return errors.New("test failure")
				})
			}

			// Verify final state
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

	// Open the circuit
	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit should be open after failures")
	}

	// Wait for timeout to trigger half-open
	time.Sleep(150 * time.Millisecond)

	// Next request should be allowed (half-open)
	allowed := false
	_ = cb.Execute(func() error {
		allowed = true
		return nil
	})

	if !allowed {
		t.Error("Request should be allowed in half-open state")
	}

	// Successful request should close the circuit
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

	// Open the circuit
	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	// Wait for half-open
	time.Sleep(150 * time.Millisecond)

	// Fail in half-open state
	_ = cb.Execute(func() error {
		return errors.New("fail again")
	})

	// Should return to open state
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

	// Concurrent successful requests
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

	// Open the circuit
	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit should be open")
	}

	// Reset
	cb.Reset()

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Circuit should be closed after reset")
	}

	// Should allow requests after reset
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

	// Execute some requests
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

	// Should be available initially
	if !cb.IsAvailable() {
		t.Error("Circuit should be available initially")
	}

	// Open the circuit
	_ = cb.Execute(func() error { return errors.New("fail") })
	_ = cb.Execute(func() error { return errors.New("fail") })

	// Should not be available when open
	if cb.IsAvailable() {
		t.Error("Circuit should not be available when open")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Should be available in half-open
	if !cb.IsAvailable() {
		t.Error("Circuit should be available in half-open state")
	}
}

// Test Retry Executor

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

	// Cancel after short delay
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

	// Should have delays: 100ms, 200ms, 400ms = 700ms total (approx)
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

	// Run multiple times to verify jitter adds variability
	durations := make([]time.Duration, 5)
	for i := 0; i < 5; i++ {
		startTime := time.Now()
		_ = re.ExecuteWithContext(context.Background(), func() error {
			return errors.New("temporary failure")
		})
		durations[i] = time.Since(startTime)
	}

	// Check that not all durations are identical (jitter should add variance)
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

// Test Error Types

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

// Test Base Recovery Mechanism

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

	// Concurrent requests
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

// Test Error Recovery Manager

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

	// Should return same instance for same service
	if cb1 != cb2 {
		t.Error("Expected same circuit breaker instance for same service")
	}

	// Should return different instances for different services
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

	// Create some circuit breakers
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

// Helper functions and types

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

// Mock network error for testing
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

// Ensure mockNetError implements net.Error
var _ net.Error = (*mockNetError)(nil)

// Test isTraefikDefaultCertError
// See: https://github.com/lukaszraczylo/traefikoidc/issues/90

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

// Test isEOFError

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

// Test isCertificateError

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

// Test MetadataFetchRetryConfig

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

	// Verify retryable errors include startup-related patterns
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

// Test RetryExecutor with startup-specific errors

func TestRetryExecutorStartupErrors(t *testing.T) {
	// Verify MetadataFetchRetryConfig creates a valid retry executor
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
			// Use very short delays for testing
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

// Test that retry executor properly uses isRetryableError with new error types

func TestRetryExecutorIsRetryableErrorIntegration(t *testing.T) {
	re := NewRetryExecutor(DefaultRetryConfig(), nil)

	// Test that the enhanced isRetryableError is being used
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
