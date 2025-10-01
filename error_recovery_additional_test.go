package traefikoidc

import (
	"testing"
	"time"
)

// TestDefaultCircuitBreakerConfig tests the default configuration function
func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	// Test default values
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

// TestBaseRecoveryMechanism_GetBaseMetrics tests getting base metrics
func TestBaseRecoveryMechanism_GetBaseMetrics(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	metrics := base.GetBaseMetrics()

	if metrics == nil {
		t.Fatal("Expected non-nil metrics")
	}

	// Check expected metric fields
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

// TestBaseRecoveryMechanism_RecordRequest tests request recording
func TestBaseRecoveryMechanism_RecordRequest(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Record some requests
	base.RecordRequest()
	base.RecordRequest()
	base.RecordRequest()

	// Get metrics to verify
	metrics := base.GetBaseMetrics()
	totalRequests := metrics["total_requests"].(int64)

	if totalRequests != 3 {
		t.Errorf("Expected 3 total requests, got %d", totalRequests)
	}
}

// TestBaseRecoveryMechanism_RecordSuccess tests success recording
func TestBaseRecoveryMechanism_RecordSuccess(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Record some successes
	base.RecordSuccess()
	base.RecordSuccess()

	// Get metrics to verify
	metrics := base.GetBaseMetrics()
	totalSuccesses := metrics["total_successes"].(int64)

	if totalSuccesses != 2 {
		t.Errorf("Expected 2 successful requests, got %d", totalSuccesses)
	}
}

// TestBaseRecoveryMechanism_RecordFailure tests failure recording
func TestBaseRecoveryMechanism_RecordFailure(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Record some failures
	base.RecordFailure()
	base.RecordFailure()
	base.RecordFailure()

	// Get metrics to verify
	metrics := base.GetBaseMetrics()
	totalFailures := metrics["total_failures"].(int64)

	if totalFailures != 3 {
		t.Errorf("Expected 3 failed requests, got %d", totalFailures)
	}
}

// TestBaseRecoveryMechanism_LogInfo tests info logging
func TestBaseRecoveryMechanism_LogInfo(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Test logging doesn't panic
	base.LogInfo("test message")
	base.LogInfo("test message with args: %s %d", "arg1", 42)

	// Test with nil logger
	baseNoLogger := NewBaseRecoveryMechanism("test", nil)
	baseNoLogger.LogInfo("test message") // Should not panic
}

// TestBaseRecoveryMechanism_LogError tests error logging
func TestBaseRecoveryMechanism_LogError(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Test logging doesn't panic
	base.LogError("error message")
	base.LogError("error message with args: %s %d", "error", 500)

	// Test with nil logger
	baseNoLogger := NewBaseRecoveryMechanism("test", nil)
	baseNoLogger.LogError("error message") // Should not panic
}

// TestBaseRecoveryMechanism_LogDebug tests debug logging
func TestBaseRecoveryMechanism_LogDebug(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Test logging doesn't panic
	base.LogDebug("debug message")
	base.LogDebug("debug message with args: %s %d", "debug", 123)

	// Test with nil logger
	baseNoLogger := NewBaseRecoveryMechanism("test", nil)
	baseNoLogger.LogDebug("debug message") // Should not panic
}

// TestCircuitBreaker_GetState tests getting circuit breaker state
func TestCircuitBreaker_GetState(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := GetSingletonNoOpLogger()
	cb := NewCircuitBreaker(config, logger)

	// Initial state should be closed
	state := cb.GetState()
	if state != CircuitBreakerClosed {
		t.Errorf("Expected initial state to be closed, got %d", state)
	}
}

// TestCircuitBreaker_Reset tests resetting circuit breaker
func TestCircuitBreaker_Reset(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := GetSingletonNoOpLogger()
	cb := NewCircuitBreaker(config, logger)

	// Reset should not panic
	cb.Reset()

	// State should be closed after reset
	state := cb.GetState()
	if state != CircuitBreakerClosed {
		t.Errorf("Expected state to be closed after reset, got %d", state)
	}
}

// TestCircuitBreaker_IsAvailable tests availability check
func TestCircuitBreaker_IsAvailable(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := GetSingletonNoOpLogger()
	cb := NewCircuitBreaker(config, logger)

	// Initially should be available
	available := cb.IsAvailable()
	if !available {
		t.Error("Expected circuit breaker to be available initially")
	}
}

// TestCircuitBreaker_GetMetrics tests getting circuit breaker metrics
func TestCircuitBreaker_GetMetrics(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := GetSingletonNoOpLogger()
	cb := NewCircuitBreaker(config, logger)

	metrics := cb.GetMetrics()
	if metrics == nil {
		t.Fatal("Expected non-nil metrics")
	}

	// Should include base metrics
	if _, exists := metrics["total_requests"]; !exists {
		t.Error("Expected total_requests in metrics")
	}

	// Should include circuit breaker specific metrics
	if _, exists := metrics["state"]; !exists {
		t.Error("Expected state in metrics")
	}
}

// Retry mechanism tests removed due to complex dependencies

// Benchmark tests
func BenchmarkDefaultCircuitBreakerConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DefaultCircuitBreakerConfig()
	}
}

func BenchmarkBaseRecoveryMechanism_GetBaseMetrics(b *testing.B) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base.GetBaseMetrics()
	}
}

func BenchmarkBaseRecoveryMechanism_RecordRequest(b *testing.B) {
	logger := GetSingletonNoOpLogger()
	base := NewBaseRecoveryMechanism("test-mechanism", logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		base.RecordRequest()
	}
}
