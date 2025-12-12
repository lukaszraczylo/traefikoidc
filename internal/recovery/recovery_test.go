//go:build !yaegi

package recovery

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock logger for testing
type mockLogger struct {
	logs     []string
	errLogs  []string
	debugLog []string
	mu       sync.Mutex
}

func (m *mockLogger) Logf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, format)
}

func (m *mockLogger) ErrorLogf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errLogs = append(m.errLogs, format)
}

func (m *mockLogger) DebugLogf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLog = append(m.debugLog, format)
}

// BaseRecoveryMechanism tests
func TestNewBaseRecoveryMechanism(t *testing.T) {
	logger := &mockLogger{}
	base := NewBaseRecoveryMechanism("test-recovery", logger)

	if base == nil {
		t.Fatal("Expected NewBaseRecoveryMechanism to return non-nil")
	}

	if base.name != "test-recovery" {
		t.Errorf("Expected name 'test-recovery', got '%s'", base.name)
	}

	if base.totalRequests != 0 {
		t.Error("Expected totalRequests to be 0")
	}

	if base.successCount != 0 {
		t.Error("Expected successCount to be 0")
	}

	if base.failureCount != 0 {
		t.Error("Expected failureCount to be 0")
	}

	if base.lastSuccessStr != "never" {
		t.Error("Expected lastSuccessStr to be 'never'")
	}

	if base.lastFailureStr != "never" {
		t.Error("Expected lastFailureStr to be 'never'")
	}
}

func TestBaseRecoveryMechanism_RecordRequest(t *testing.T) {
	base := NewBaseRecoveryMechanism("test", &mockLogger{})

	base.RecordRequest()
	if atomic.LoadInt64(&base.totalRequests) != 1 {
		t.Error("Expected totalRequests to be 1")
	}

	base.RecordRequest()
	base.RecordRequest()
	if atomic.LoadInt64(&base.totalRequests) != 3 {
		t.Error("Expected totalRequests to be 3")
	}
}

func TestBaseRecoveryMechanism_RecordSuccess(t *testing.T) {
	base := NewBaseRecoveryMechanism("test", &mockLogger{})

	base.RecordSuccess()
	if atomic.LoadInt64(&base.successCount) != 1 {
		t.Error("Expected successCount to be 1")
	}

	base.successMutex.RLock()
	lastSuccess := base.lastSuccessStr
	base.successMutex.RUnlock()

	if lastSuccess == "never" {
		t.Error("Expected lastSuccessStr to be updated")
	}
}

func TestBaseRecoveryMechanism_RecordFailure(t *testing.T) {
	base := NewBaseRecoveryMechanism("test", &mockLogger{})

	base.RecordFailure()
	if atomic.LoadInt64(&base.failureCount) != 1 {
		t.Error("Expected failureCount to be 1")
	}

	base.failureMutex.RLock()
	lastFailure := base.lastFailureStr
	base.failureMutex.RUnlock()

	if lastFailure == "never" {
		t.Error("Expected lastFailureStr to be updated")
	}
}

func TestBaseRecoveryMechanism_GetBaseMetrics(t *testing.T) {
	base := NewBaseRecoveryMechanism("test", &mockLogger{})

	base.RecordRequest()
	base.RecordRequest()
	base.RecordSuccess()
	base.RecordFailure()

	metrics := base.GetBaseMetrics()

	if metrics["totalRequests"].(int64) != 2 {
		t.Error("Expected totalRequests to be 2")
	}

	if metrics["successCount"].(int64) != 1 {
		t.Error("Expected successCount to be 1")
	}

	if metrics["failureCount"].(int64) != 1 {
		t.Error("Expected failureCount to be 1")
	}

	if metrics["successRate"].(string) != "50.00%" {
		t.Errorf("Expected successRate to be '50.00%%', got %v", metrics["successRate"])
	}

	if metrics["name"].(string) != "test" {
		t.Error("Expected name to be 'test'")
	}
}

func TestBaseRecoveryMechanism_ConcurrentAccess(t *testing.T) {
	base := NewBaseRecoveryMechanism("test", &mockLogger{})

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent requests
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base.RecordRequest()
		}()
	}

	// Concurrent successes
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base.RecordSuccess()
		}()
	}

	// Concurrent failures
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base.RecordFailure()
		}()
	}

	wg.Wait()

	if atomic.LoadInt64(&base.totalRequests) != int64(iterations) {
		t.Errorf("Expected %d total requests, got %d", iterations, base.totalRequests)
	}

	if atomic.LoadInt64(&base.successCount) != int64(iterations) {
		t.Errorf("Expected %d successes, got %d", iterations, base.successCount)
	}

	if atomic.LoadInt64(&base.failureCount) != int64(iterations) {
		t.Errorf("Expected %d failures, got %d", iterations, base.failureCount)
	}
}

// CircuitBreakerState tests
func TestCircuitBreakerState_String(t *testing.T) {
	tests := []struct {
		expected string
		state    CircuitBreakerState
	}{
		{state: CircuitBreakerClosed, expected: "closed"},
		{state: CircuitBreakerOpen, expected: "open"},
		{state: CircuitBreakerHalfOpen, expected: "half-open"},
		{state: CircuitBreakerState(99), expected: "unknown"},
	}

	for _, tt := range tests {
		if tt.state.String() != tt.expected {
			t.Errorf("Expected state %d to be '%s', got '%s'", tt.state, tt.expected, tt.state.String())
		}
	}
}

// CircuitBreakerConfig tests
func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	if config.FailureThreshold != 5 {
		t.Errorf("Expected FailureThreshold 5, got %d", config.FailureThreshold)
	}

	if config.SuccessThreshold != 2 {
		t.Errorf("Expected SuccessThreshold 2, got %d", config.SuccessThreshold)
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout 30s, got %v", config.Timeout)
	}

	if config.MaxRequests != 3 {
		t.Errorf("Expected MaxRequests 3, got %d", config.MaxRequests)
	}
}

// CircuitBreaker tests
func TestNewCircuitBreaker(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	cb := NewCircuitBreaker(config, logger)

	if cb == nil {
		t.Fatal("Expected NewCircuitBreaker to return non-nil")
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Expected initial state to be Closed")
	}

	if cb.config.FailureThreshold != 5 {
		t.Error("Expected config to be set")
	}
}

func TestCircuitBreaker_InitiallyClosed(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, &mockLogger{})

	if !cb.IsAvailable() {
		t.Error("Expected circuit breaker to be available initially")
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Expected state to be Closed")
	}
}

func TestCircuitBreaker_ExecuteWithContext_Success(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, &mockLogger{})

	callCount := 0
	err := cb.ExecuteWithContext(context.Background(), func() error {
		callCount++
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Error("Expected function to be called once")
	}

	if atomic.LoadInt64(&cb.successCount) != 1 {
		t.Error("Expected success count to be 1")
	}
}

func TestCircuitBreaker_ExecuteWithContext_Failure(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, &mockLogger{})

	testErr := errors.New("test error")
	err := cb.ExecuteWithContext(context.Background(), func() error {
		return testErr
	})

	if err != testErr {
		t.Errorf("Expected error %v, got %v", testErr, err)
	}

	if atomic.LoadInt64(&cb.failureCount) != 1 {
		t.Error("Expected failure count to be 1")
	}
}

func TestCircuitBreaker_OpensAfterThresholdFailures(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		MaxRequests:      2,
	}
	cb := NewCircuitBreaker(config, &mockLogger{})

	testErr := errors.New("test error")

	// Cause failures to reach threshold
	for i := 0; i < 3; i++ {
		_ = cb.ExecuteWithContext(context.Background(), func() error {
			return testErr
		})
	}

	// Circuit should now be open
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state to be Open after %d failures, got %s", config.FailureThreshold, cb.GetState())
	}

	if cb.IsAvailable() {
		t.Error("Expected circuit breaker to be unavailable when open")
	}

	// Subsequent requests should be blocked
	err := cb.ExecuteWithContext(context.Background(), func() error {
		t.Error("Function should not be called when circuit is open")
		return nil
	})

	if err == nil {
		t.Error("Expected error when circuit is open")
	}

	if err.Error() != "circuit breaker is open" {
		t.Errorf("Expected 'circuit breaker is open' error, got: %v", err)
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      2,
	}
	cb := NewCircuitBreaker(config, &mockLogger{})

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.ExecuteWithContext(context.Background(), func() error {
			return errors.New("fail")
		})
	}

	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Expected circuit to be open")
	}

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Next request should transition to half-open
	err := cb.ExecuteWithContext(context.Background(), func() error {
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error in half-open state, got %v", err)
	}

	// State should be closed after successful request in half-open
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to be Closed after success in half-open, got %s", cb.GetState())
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, &mockLogger{})

	// Record some metrics
	cb.RecordRequest()
	cb.RecordSuccess()
	cb.RecordFailure()

	// Reset
	cb.Reset()

	if atomic.LoadInt64(&cb.totalRequests) != 0 {
		t.Error("Expected totalRequests to be 0 after reset")
	}

	if atomic.LoadInt32(&cb.consecutiveFailures) != 0 {
		t.Error("Expected consecutiveFailures to be 0 after reset")
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Expected state to be Closed after reset")
	}
}

func TestCircuitBreaker_GetMetrics(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, &mockLogger{})

	cb.RecordRequest()
	cb.RecordSuccess()

	metrics := cb.GetMetrics()

	if metrics == nil {
		t.Fatal("Expected metrics to be non-nil")
	}

	if metrics["state"] != "closed" {
		t.Errorf("Expected state 'closed', got %v", metrics["state"])
	}

	if metrics["totalRequests"].(int64) != 1 {
		t.Errorf("Expected totalRequests 1, got %v", metrics["totalRequests"])
	}

	if metrics["successCount"].(int64) != 1 {
		t.Error("Expected successCount to be 1")
	}

	if _, ok := metrics["config"]; !ok {
		t.Error("Expected config in metrics")
	}
}

func TestCircuitBreaker_ConcurrentExecute(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 10,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
		MaxRequests:      5,
	}
	cb := NewCircuitBreaker(config, &mockLogger{})

	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	iterations := 50

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := cb.ExecuteWithContext(context.Background(), func() error {
				time.Sleep(time.Millisecond)
				if idx%2 == 0 {
					return nil
				}
				return errors.New("error")
			})
			if err == nil {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	// Should have processed requests without panicking
	if atomic.LoadInt64(&cb.totalRequests) < int64(iterations) {
		t.Logf("Processed %d requests out of %d (some may have been blocked)", cb.totalRequests, iterations)
	}
}

func TestCircuitBreaker_ContextCancellation(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config, &mockLogger{})

	ctx, cancel := context.WithCancel(context.Background())

	// Execute with valid context
	err := cb.ExecuteWithContext(ctx, func() error {
		// Cancel during execution
		cancel()
		// Circuit breaker doesn't check context during execution by design
		// It's the responsibility of the function to check context
		return nil
	})

	// Should complete successfully - circuit breaker passes context but doesn't enforce it
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestCircuitBreaker_HalfOpenMaxRequests(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      1,
	}
	cb := NewCircuitBreaker(config, &mockLogger{})

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.ExecuteWithContext(context.Background(), func() error {
			return errors.New("fail")
		})
	}

	// Wait for timeout to transition to half-open
	time.Sleep(60 * time.Millisecond)

	// First request should be allowed
	allowed := cb.allowRequest()
	if !allowed {
		t.Error("Expected first request to be allowed in half-open state")
	}

	// Manually transition to half-open if not already
	cb.stateMutex.Lock()
	atomic.StoreInt32(&cb.state, int32(CircuitBreakerHalfOpen))
	cb.stateMutex.Unlock()

	// Increment half-open requests to max
	atomic.StoreInt32(&cb.halfOpenRequests, int32(config.MaxRequests))

	// Next request should be blocked
	allowed = cb.allowRequest()
	if allowed {
		t.Error("Expected request to be blocked when max half-open requests reached")
	}
}
