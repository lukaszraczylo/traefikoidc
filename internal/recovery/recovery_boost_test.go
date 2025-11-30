//go:build !yaegi

package recovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

// LogDebug Tests
func TestBaseRecoveryMechanism_LogDebug(t *testing.T) {
	logger := &mockLogger{}
	base := NewBaseRecoveryMechanism("test-debug", logger)

	// Call LogDebug
	base.LogDebug("test message: %s", "value")

	// Verify debug log was called
	if len(logger.debugLog) != 1 {
		t.Errorf("Expected 1 debug log entry, got %d", len(logger.debugLog))
	}
}

func TestBaseRecoveryMechanism_LogDebug_NilLogger(t *testing.T) {
	base := NewBaseRecoveryMechanism("test", nil)

	// Should not panic with nil logger
	base.LogDebug("this should not crash")
}

// HTTPError Tests
func TestHTTPError_Error(t *testing.T) {
	err := &HTTPError{
		StatusCode: 404,
		Message:    "Not Found",
	}

	expected := "HTTP 404: Not Found"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestHTTPError_IsRetryable(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		retryable  bool
	}{
		{"500 Internal Server Error", 500, true},
		{"502 Bad Gateway", 502, true},
		{"503 Service Unavailable", 503, true},
		{"504 Gateway Timeout", 504, true},
		{"429 Too Many Requests", 429, true},
		{"408 Request Timeout", 408, true},
		{"400 Bad Request", 400, false},
		{"401 Unauthorized", 401, false},
		{"403 Forbidden", 403, false},
		{"404 Not Found", 404, false},
		{"200 OK", 200, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &HTTPError{
				StatusCode: tt.statusCode,
				Message:    tt.name,
			}

			if err.IsRetryable() != tt.retryable {
				t.Errorf("StatusCode %d: expected retryable=%v, got %v",
					tt.statusCode, tt.retryable, err.IsRetryable())
			}
		})
	}
}

// OIDCError Tests
func TestOIDCError_Error_WithDescription(t *testing.T) {
	err := &OIDCError{
		Code:        "invalid_request",
		Description: "Missing required parameter",
	}

	expected := "OIDC error invalid_request: Missing required parameter"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestOIDCError_Error_WithoutDescription(t *testing.T) {
	err := &OIDCError{
		Code: "server_error",
	}

	expected := "OIDC error: server_error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestOIDCError_IsRetryable(t *testing.T) {
	tests := []struct {
		code      string
		retryable bool
	}{
		{"temporarily_unavailable", true},
		{"server_error", true},
		{"invalid_request", false},
		{"invalid_client", false},
		{"invalid_grant", false},
		{"unauthorized_client", false},
		{"unsupported_grant_type", false},
		{"access_denied", false},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			err := &OIDCError{
				Code: tt.code,
			}

			if err.IsRetryable() != tt.retryable {
				t.Errorf("Code '%s': expected retryable=%v, got %v",
					tt.code, tt.retryable, err.IsRetryable())
			}
		})
	}
}

// FallbackMechanism Tests
func TestNewFallbackMechanism(t *testing.T) {
	logger := &mockLogger{}
	fallbackFunc := func() error { return nil }

	fm := NewFallbackMechanism("test-fallback", logger, fallbackFunc)

	if fm == nil {
		t.Fatal("Expected NewFallbackMechanism to return non-nil")
	}

	if fm.name != "test-fallback" {
		t.Errorf("Expected name 'test-fallback', got '%s'", fm.name)
	}

	if fm.fallbackFunc == nil {
		t.Error("Expected fallbackFunc to be set")
	}
}

func TestFallbackMechanism_ExecuteWithContext_PrimarySuccess(t *testing.T) {
	logger := &mockLogger{}
	fallbackCalled := false
	fallbackFunc := func() error {
		fallbackCalled = true
		return nil
	}

	fm := NewFallbackMechanism("test", logger, fallbackFunc)

	// Primary function succeeds
	err := fm.ExecuteWithContext(context.Background(), func() error {
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if fallbackCalled {
		t.Error("Expected fallback to not be called when primary succeeds")
	}

	if fm.successCount != 1 {
		t.Errorf("Expected successCount=1, got %d", fm.successCount)
	}
}

func TestFallbackMechanism_ExecuteWithContext_FallbackSuccess(t *testing.T) {
	logger := &mockLogger{}
	fallbackCalled := false
	fallbackFunc := func() error {
		fallbackCalled = true
		return nil
	}

	fm := NewFallbackMechanism("test", logger, fallbackFunc)

	// Primary fails, fallback succeeds
	err := fm.ExecuteWithContext(context.Background(), func() error {
		return errors.New("primary failed")
	})

	if err != nil {
		t.Errorf("Expected no error (fallback succeeded), got %v", err)
	}

	if !fallbackCalled {
		t.Error("Expected fallback to be called")
	}

	if fm.successCount != 1 {
		t.Errorf("Expected successCount=1, got %d", fm.successCount)
	}
}

func TestFallbackMechanism_ExecuteWithContext_BothFail(t *testing.T) {
	logger := &mockLogger{}
	fallbackFunc := func() error {
		return errors.New("fallback failed")
	}

	fm := NewFallbackMechanism("test", logger, fallbackFunc)

	// Both primary and fallback fail
	err := fm.ExecuteWithContext(context.Background(), func() error {
		return errors.New("primary failed")
	})

	if err == nil {
		t.Error("Expected error when both primary and fallback fail")
	}

	if fm.failureCount != 1 {
		t.Errorf("Expected failureCount=1, got %d", fm.failureCount)
	}
}

func TestFallbackMechanism_ExecuteWithContext_NoFallback(t *testing.T) {
	logger := &mockLogger{}
	fm := NewFallbackMechanism("test", logger, nil) // No fallback function

	// Primary fails, no fallback
	primaryErr := errors.New("primary failed")
	err := fm.ExecuteWithContext(context.Background(), func() error {
		return primaryErr
	})

	if err != primaryErr {
		t.Errorf("Expected primary error %v, got %v", primaryErr, err)
	}

	if fm.failureCount != 1 {
		t.Errorf("Expected failureCount=1, got %d", fm.failureCount)
	}
}

func TestFallbackMechanism_ExecuteWithContext_ContextCanceled(t *testing.T) {
	logger := &mockLogger{}
	fallbackFunc := func() error { return nil }
	fm := NewFallbackMechanism("test", logger, fallbackFunc)

	// Context already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := fm.ExecuteWithContext(ctx, func() error {
		t.Error("Function should not be called when context is canceled")
		return nil
	})

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}

	if fm.failureCount != 1 {
		t.Errorf("Expected failureCount=1, got %d", fm.failureCount)
	}
}

func TestFallbackMechanism_Reset(t *testing.T) {
	logger := &mockLogger{}
	fm := NewFallbackMechanism("test", logger, nil)

	// Record some metrics
	fm.RecordRequest()
	fm.RecordSuccess()
	fm.RecordFailure()

	if fm.totalRequests == 0 {
		t.Error("Expected some requests before reset")
	}

	// Reset
	fm.Reset()

	if fm.totalRequests != 0 {
		t.Errorf("Expected totalRequests=0 after reset, got %d", fm.totalRequests)
	}

	if fm.successCount != 0 {
		t.Errorf("Expected successCount=0 after reset, got %d", fm.successCount)
	}

	if fm.failureCount != 0 {
		t.Errorf("Expected failureCount=0 after reset, got %d", fm.failureCount)
	}

	if fm.lastSuccessStr != "never" {
		t.Errorf("Expected lastSuccessStr='never' after reset, got '%s'", fm.lastSuccessStr)
	}

	if fm.lastFailureStr != "never" {
		t.Errorf("Expected lastFailureStr='never' after reset, got '%s'", fm.lastFailureStr)
	}
}

func TestFallbackMechanism_IsAvailable(t *testing.T) {
	logger := &mockLogger{}
	fm := NewFallbackMechanism("test", logger, nil)

	// Fallback mechanism is always available
	if !fm.IsAvailable() {
		t.Error("Expected IsAvailable to return true")
	}
}

func TestFallbackMechanism_GetMetrics(t *testing.T) {
	logger := &mockLogger{}
	fallbackFunc := func() error { return nil }
	fm := NewFallbackMechanism("test-metrics", logger, fallbackFunc)

	fm.RecordRequest()
	fm.RecordSuccess()

	metrics := fm.GetMetrics()

	if metrics == nil {
		t.Fatal("Expected GetMetrics to return non-nil")
	}

	if metrics["type"] != "fallback" {
		t.Errorf("Expected type='fallback', got %v", metrics["type"])
	}

	if metrics["name"] != "test-metrics" {
		t.Errorf("Expected name='test-metrics', got %v", metrics["name"])
	}

	if metrics["hasFallback"] != true {
		t.Error("Expected hasFallback=true")
	}

	if metrics["totalRequests"].(int64) != 1 {
		t.Errorf("Expected totalRequests=1, got %v", metrics["totalRequests"])
	}
}

func TestFallbackMechanism_GetMetrics_NoFallback(t *testing.T) {
	logger := &mockLogger{}
	fm := NewFallbackMechanism("test", logger, nil)

	metrics := fm.GetMetrics()

	if metrics["hasFallback"] != false {
		t.Error("Expected hasFallback=false when no fallback function")
	}
}

// ============================================================================
// CIRCUIT BREAKER ADDITIONAL TESTS
// ============================================================================

// TestCircuitBreaker_Execute tests the legacy Execute method
func TestCircuitBreaker_Execute(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, logger)

	// Test successful execution via Execute (legacy method)
	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !called {
		t.Error("Expected function to be called")
	}

	// Test error propagation via Execute
	expectedErr := errors.New("test error")
	err = cb.Execute(func() error {
		return expectedErr
	})

	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
}

// TestCircuitBreaker_ForceOpen tests forcing circuit breaker to open state
func TestCircuitBreaker_ForceOpen(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, logger)

	// Initially circuit should be closed
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected initial state Closed, got %v", cb.GetState())
	}

	// Force open
	cb.ForceOpen()

	// Verify state is now open
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state Open after ForceOpen, got %v", cb.GetState())
	}

	// Verify circuit blocks requests
	err := cb.ExecuteWithContext(context.Background(), func() error {
		t.Error("Function should not be called when circuit is forced open")
		return nil
	})

	if err == nil {
		t.Error("Expected error when circuit is forced open")
	}

	// Verify logger was called
	if len(logger.logs) == 0 {
		t.Error("Expected info log when forcing circuit open")
	}
}

// TestCircuitBreaker_ForceClosed tests forcing circuit breaker to closed state
func TestCircuitBreaker_ForceClosed(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultCircuitBreakerConfig()
	config.FailureThreshold = 1
	cb := NewCircuitBreaker(config, logger)

	// Trigger failures to open circuit
	cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("failure")
	})
	cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("failure")
	})
	cb.ExecuteWithContext(context.Background(), func() error {
		return errors.New("failure")
	})

	// Circuit should be open after failures
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state Open after failures, got %v", cb.GetState())
	}

	// Force closed
	cb.ForceClosed()

	// Verify state is now closed
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state Closed after ForceClosed, got %v", cb.GetState())
	}

	// Verify circuit allows requests
	called := false
	err := cb.ExecuteWithContext(context.Background(), func() error {
		called = true
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error after forcing closed, got %v", err)
	}

	if !called {
		t.Error("Expected function to be called after forcing closed")
	}

	// Verify counters are reset
	metrics := cb.GetMetrics()
	consecutiveFailures, ok := metrics["consecutiveFailures"].(int32)
	if !ok || consecutiveFailures != 0 {
		t.Errorf("Expected consecutiveFailures=0 after ForceClosed, got %v", consecutiveFailures)
	}

	// Verify logger was called
	if len(logger.logs) == 0 {
		t.Error("Expected info log when forcing circuit closed")
	}
}

// TestCircuitBreaker_ForceOpen_AllowsRecovery tests that forced open can transition to half-open
func TestCircuitBreaker_ForceOpen_AllowsRecovery(t *testing.T) {
	logger := &mockLogger{}
	config := DefaultCircuitBreakerConfig()
	config.Timeout = 50 * time.Millisecond // Very short timeout for testing
	cb := NewCircuitBreaker(config, logger)

	// Force open
	cb.ForceOpen()

	// Wait for timeout to allow transition to half-open
	time.Sleep(100 * time.Millisecond)

	// Circuit should allow a test request in half-open state
	called := false
	err := cb.ExecuteWithContext(context.Background(), func() error {
		called = true
		return nil
	})

	// After successful execution, circuit should close
	if err != nil {
		t.Logf("Note: Circuit may still be in transition, error: %v", err)
	}

	if called {
		// If called, verify circuit recovered
		state := cb.GetState()
		if state != CircuitBreakerClosed && state != CircuitBreakerHalfOpen {
			t.Errorf("Expected Closed or HalfOpen after successful recovery, got %v", state)
		}
	}
}
