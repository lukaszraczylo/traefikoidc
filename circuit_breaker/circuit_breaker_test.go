package circuit_breaker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock implementations for testing
type mockLogger struct {
	infoLogs  []string
	errorLogs []string
	debugLogs []string
	mu        sync.RWMutex
}

func (m *mockLogger) Infof(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = append(m.infoLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Errorf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Debugf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) getInfoLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.infoLogs))
	copy(result, m.infoLogs)
	return result
}

//lint:ignore U1000 May be needed for future error log verification tests
func (m *mockLogger) getErrorLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.errorLogs))
	copy(result, m.errorLogs)
	return result
}

//lint:ignore U1000 May be needed for future test isolation
func (m *mockLogger) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = nil
	m.errorLogs = nil
	m.debugLogs = nil
}

type mockBaseRecoveryMechanism struct {
	requestCount int64
	successCount int64
	failureCount int64
	infoLogs     []string
	errorLogs    []string
	debugLogs    []string
	baseMetrics  map[string]interface{}
	mu           sync.RWMutex
}

func newMockBaseRecovery() *mockBaseRecoveryMechanism {
	return &mockBaseRecoveryMechanism{
		baseMetrics: make(map[string]interface{}),
	}
}

func (m *mockBaseRecoveryMechanism) RecordRequest() {
	atomic.AddInt64(&m.requestCount, 1)
}

func (m *mockBaseRecoveryMechanism) RecordSuccess() {
	atomic.AddInt64(&m.successCount, 1)
}

func (m *mockBaseRecoveryMechanism) RecordFailure() {
	atomic.AddInt64(&m.failureCount, 1)
}

func (m *mockBaseRecoveryMechanism) GetBaseMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range m.baseMetrics {
		result[k] = v
	}
	result["total_requests"] = atomic.LoadInt64(&m.requestCount)
	result["total_successes"] = atomic.LoadInt64(&m.successCount)
	result["total_failures"] = atomic.LoadInt64(&m.failureCount)
	return result
}

func (m *mockBaseRecoveryMechanism) LogInfo(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = append(m.infoLogs, fmt.Sprintf(format, args...))
}

func (m *mockBaseRecoveryMechanism) LogError(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, fmt.Sprintf(format, args...))
}

func (m *mockBaseRecoveryMechanism) LogDebug(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, fmt.Sprintf(format, args...))
}

func (m *mockBaseRecoveryMechanism) getRequestCount() int64 {
	return atomic.LoadInt64(&m.requestCount)
}

func (m *mockBaseRecoveryMechanism) getSuccessCount() int64 {
	return atomic.LoadInt64(&m.successCount)
}

func (m *mockBaseRecoveryMechanism) getFailureCount() int64 {
	return atomic.LoadInt64(&m.failureCount)
}

func (m *mockBaseRecoveryMechanism) getInfoLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.infoLogs))
	copy(result, m.infoLogs)
	return result
}

func (m *mockBaseRecoveryMechanism) getErrorLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.errorLogs))
	copy(result, m.errorLogs)
	return result
}

func TestCircuitBreakerState_String(t *testing.T) {
	tests := []struct {
		state    CircuitBreakerState
		expected string
	}{
		{CircuitBreakerClosed, "closed"},
		{CircuitBreakerOpen, "open"},
		{CircuitBreakerHalfOpen, "half-open"},
		{CircuitBreakerState(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.state.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	if config.MaxFailures != 2 {
		t.Errorf("Expected MaxFailures to be 2, got %d", config.MaxFailures)
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("Expected Timeout to be 60s, got %v", config.Timeout)
	}

	if config.ResetTimeout != 30*time.Second {
		t.Errorf("Expected ResetTimeout to be 30s, got %v", config.ResetTimeout)
	}
}

func TestNewCircuitBreaker(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  3,
		Timeout:      30 * time.Second,
		ResetTimeout: 15 * time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()

	cb := NewCircuitBreaker(config, logger, baseRecovery)

	if cb == nil {
		t.Fatal("NewCircuitBreaker returned nil")
	}

	if cb.maxFailures != 3 {
		t.Errorf("Expected maxFailures to be 3, got %d", cb.maxFailures)
	}

	if cb.timeout != 30*time.Second {
		t.Errorf("Expected timeout to be 30s, got %v", cb.timeout)
	}

	if cb.resetTimeout != 15*time.Second {
		t.Errorf("Expected resetTimeout to be 15s, got %v", cb.resetTimeout)
	}

	if cb.state != CircuitBreakerClosed {
		t.Errorf("Expected initial state to be Closed, got %v", cb.state)
	}

	if cb.logger != logger {
		t.Error("Expected logger to be set")
	}

	if cb.baseRecovery != baseRecovery {
		t.Error("Expected baseRecovery to be set")
	}
}

func TestCircuitBreaker_ExecuteWithContext_Success(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	ctx := context.Background()
	err := cb.ExecuteWithContext(ctx, testFunc)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to remain Closed, got %v", cb.GetState())
	}

	if baseRecovery.getRequestCount() != 1 {
		t.Errorf("Expected 1 request recorded, got %d", baseRecovery.getRequestCount())
	}

	if baseRecovery.getSuccessCount() != 1 {
		t.Errorf("Expected 1 success recorded, got %d", baseRecovery.getSuccessCount())
	}
}

func TestCircuitBreaker_ExecuteWithContext_Failure(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	testError := fmt.Errorf("test error")
	testFunc := func() error {
		return testError
	}

	ctx := context.Background()
	err := cb.ExecuteWithContext(ctx, testFunc)

	if err != testError {
		t.Errorf("Expected test error, got %v", err)
	}

	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to remain Closed after single failure, got %v", cb.GetState())
	}

	if baseRecovery.getRequestCount() != 1 {
		t.Errorf("Expected 1 request recorded, got %d", baseRecovery.getRequestCount())
	}

	if baseRecovery.getFailureCount() != 1 {
		t.Errorf("Expected 1 failure recorded, got %d", baseRecovery.getFailureCount())
	}
}

func TestCircuitBreaker_Execute(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	err := cb.Execute(testFunc)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}
}

func TestCircuitBreaker_OpenAfterMaxFailures(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	testError := fmt.Errorf("test error")
	testFunc := func() error {
		return testError
	}

	ctx := context.Background()

	// First failure
	err := cb.ExecuteWithContext(ctx, testFunc)
	if err != testError {
		t.Errorf("Expected test error on first failure, got %v", err)
	}
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to remain Closed after first failure, got %v", cb.GetState())
	}

	// Second failure - should open circuit
	err = cb.ExecuteWithContext(ctx, testFunc)
	if err != testError {
		t.Errorf("Expected test error on second failure, got %v", err)
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state to be Open after max failures, got %v", cb.GetState())
	}

	// Third attempt - should be blocked
	callCount := 0
	blockedFunc := func() error {
		callCount++
		return nil
	}
	err = cb.ExecuteWithContext(ctx, blockedFunc)
	if err == nil {
		t.Error("Expected error when circuit is open")
	}
	if callCount != 0 {
		t.Errorf("Expected function not to be called when circuit is open, got %d calls", callCount)
	}
}

func TestCircuitBreaker_HalfOpenTransition(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      10 * time.Millisecond, // Very short for testing
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Trigger circuit opening
	testError := fmt.Errorf("test error")
	err := cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})
	if err != testError {
		t.Errorf("Expected test error, got %v", err)
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state to be Open, got %v", cb.GetState())
	}

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Next request should transition to half-open
	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	err = cb.ExecuteWithContext(context.Background(), testFunc)
	if err != nil {
		t.Errorf("Expected no error in half-open state, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected function to be called in half-open state, got %d calls", callCount)
	}
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to be Closed after successful half-open request, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_HalfOpenFailureReturnsToOpen(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      10 * time.Millisecond,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Trigger circuit opening
	testError := fmt.Errorf("test error")
	_ = cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state to be Open, got %v", cb.GetState())
	}

	// Wait for timeout to allow half-open transition
	time.Sleep(15 * time.Millisecond)

	// First call should transition to half-open, but we'll force it by checking allowRequest
	if !cb.allowRequest() {
		t.Error("Expected allowRequest to return true after timeout")
	}
	if cb.GetState() != CircuitBreakerHalfOpen {
		t.Errorf("Expected state to be HalfOpen, got %v", cb.GetState())
	}

	// Failure in half-open should return to open
	err := cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})
	if err != testError {
		t.Errorf("Expected test error, got %v", err)
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state to return to Open after half-open failure, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Trigger circuit opening
	testError := fmt.Errorf("test error")
	_ = cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})
	if cb.GetState() != CircuitBreakerOpen {
		t.Errorf("Expected state to be Open, got %v", cb.GetState())
	}

	// Reset circuit
	cb.Reset()

	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to be Closed after reset, got %v", cb.GetState())
	}

	if cb.GetFailureCount() != 0 {
		t.Errorf("Expected failure count to be 0 after reset, got %d", cb.GetFailureCount())
	}

	// Should allow requests again
	callCount := 0
	err := cb.ExecuteWithContext(context.Background(), func() error {
		callCount++
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error after reset, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected function to be called after reset, got %d calls", callCount)
	}
}

func TestCircuitBreaker_IsAvailable(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      10 * time.Millisecond,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Initially available
	if !cb.IsAvailable() {
		t.Error("Expected circuit breaker to be available initially")
	}

	// Trigger opening
	testError := fmt.Errorf("test error")
	cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})

	// Should not be available when open
	if cb.IsAvailable() {
		t.Error("Expected circuit breaker to be unavailable when open")
	}

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Should be available again after timeout (half-open)
	if !cb.IsAvailable() {
		t.Error("Expected circuit breaker to be available after timeout")
	}
}

func TestCircuitBreaker_StateCheckers(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      10 * time.Millisecond,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Initially closed
	if !cb.IsClosed() {
		t.Error("Expected circuit breaker to be closed initially")
	}
	if cb.IsOpen() {
		t.Error("Expected circuit breaker not to be open initially")
	}
	if cb.IsHalfOpen() {
		t.Error("Expected circuit breaker not to be half-open initially")
	}

	// Trigger opening
	testError := fmt.Errorf("test error")
	cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})

	// Should be open
	if cb.IsClosed() {
		t.Error("Expected circuit breaker not to be closed when open")
	}
	if !cb.IsOpen() {
		t.Error("Expected circuit breaker to be open")
	}
	if cb.IsHalfOpen() {
		t.Error("Expected circuit breaker not to be half-open when open")
	}

	// Wait for timeout and trigger half-open
	time.Sleep(15 * time.Millisecond)
	cb.allowRequest() // This will transition to half-open

	// Should be half-open
	if cb.IsClosed() {
		t.Error("Expected circuit breaker not to be closed when half-open")
	}
	if cb.IsOpen() {
		t.Error("Expected circuit breaker not to be open when half-open")
	}
	if !cb.IsHalfOpen() {
		t.Error("Expected circuit breaker to be half-open")
	}
}

func TestCircuitBreaker_GetMetrics(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  2,
		Timeout:      30 * time.Second,
		ResetTimeout: 15 * time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	baseRecovery.baseMetrics["custom_metric"] = "custom_value"
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Record some activity
	testError := fmt.Errorf("test error")
	cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})

	metrics := cb.GetMetrics()

	// Check circuit breaker specific metrics
	if metrics["state"] != "closed" {
		t.Errorf("Expected state to be 'closed', got %v", metrics["state"])
	}

	if metrics["current_failures"] != int64(1) {
		t.Errorf("Expected current_failures to be 1, got %v", metrics["current_failures"])
	}

	if metrics["max_failures"] != 2 {
		t.Errorf("Expected max_failures to be 2, got %v", metrics["max_failures"])
	}

	if metrics["timeout"] != "30s" {
		t.Errorf("Expected timeout to be '30s', got %v", metrics["timeout"])
	}

	if metrics["reset_timeout"] != "15s" {
		t.Errorf("Expected reset_timeout to be '15s', got %v", metrics["reset_timeout"])
	}

	// Check base metrics are included
	if metrics["total_requests"] != int64(1) {
		t.Errorf("Expected total_requests to be 1, got %v", metrics["total_requests"])
	}

	if metrics["custom_metric"] != "custom_value" {
		t.Errorf("Expected custom_metric to be 'custom_value', got %v", metrics["custom_metric"])
	}

	// Check failure time metrics
	if _, exists := metrics["last_failure_time"]; !exists {
		t.Error("Expected last_failure_time to exist")
	}

	if _, exists := metrics["time_since_last_failure"]; !exists {
		t.Error("Expected time_since_last_failure to exist")
	}
}

func TestCircuitBreaker_GetMetrics_NoBaseRecovery(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	cb := NewCircuitBreaker(config, logger, nil)

	metrics := cb.GetMetrics()

	// Should still have circuit breaker metrics
	if metrics["state"] != "closed" {
		t.Errorf("Expected state to be 'closed', got %v", metrics["state"])
	}

	if metrics["max_failures"] != 2 {
		t.Errorf("Expected max_failures to be 2, got %v", metrics["max_failures"])
	}

	// Should not have base metrics
	if _, exists := metrics["total_requests"]; exists {
		t.Error("Expected total_requests not to exist without base recovery")
	}
}

func TestCircuitBreaker_GetLastFailureTime(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Initially should be zero
	if !cb.GetLastFailureTime().IsZero() {
		t.Error("Expected last failure time to be zero initially")
	}

	// Record a failure
	before := time.Now()
	testError := fmt.Errorf("test error")
	cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})
	after := time.Now()

	lastFailure := cb.GetLastFailureTime()
	if lastFailure.IsZero() {
		t.Error("Expected last failure time to be set after failure")
	}

	if lastFailure.Before(before) || lastFailure.After(after) {
		t.Errorf("Expected last failure time to be between %v and %v, got %v",
			before, after, lastFailure)
	}
}

func TestCircuitBreaker_ExecuteWithoutBaseRecovery(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	cb := NewCircuitBreaker(config, logger, nil)

	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	err := cb.ExecuteWithContext(context.Background(), testFunc)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}

	// Should work fine without base recovery
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Expected state to be Closed, got %v", cb.GetState())
	}
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  10, // Higher threshold for concurrent test
		Timeout:      100 * time.Millisecond,
		ResetTimeout: 50 * time.Millisecond,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	const numGoroutines = 10
	const numOperations = 50

	var wg sync.WaitGroup
	successCount := int64(0)
	errorCount := int64(0)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				err := cb.ExecuteWithContext(context.Background(), func() error {
					// Simulate some failures
					if j%10 == 9 { // Every 10th operation fails
						return fmt.Errorf("simulated error")
					}
					return nil
				})

				if err != nil {
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}

				// Intermittently check state and metrics
				if j%5 == 0 {
					cb.GetState()
					cb.GetMetrics()
					cb.IsAvailable()
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify we got both successes and errors
	finalSuccessCount := atomic.LoadInt64(&successCount)
	finalErrorCount := atomic.LoadInt64(&errorCount)

	if finalSuccessCount == 0 {
		t.Error("Expected some successful operations")
	}

	if finalErrorCount == 0 {
		t.Error("Expected some failed operations")
	}

	totalOperations := finalSuccessCount + finalErrorCount
	expectedMax := int64(numGoroutines * numOperations)

	if totalOperations > expectedMax {
		t.Errorf("Expected at most %d operations, got %d", expectedMax, totalOperations)
	}

	t.Logf("Concurrent test completed: %d successes, %d errors, final state: %v",
		finalSuccessCount, finalErrorCount, cb.GetState())
}

func TestCircuitBreaker_StateTransitionLogging(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      10 * time.Millisecond,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Trigger circuit opening
	testError := fmt.Errorf("test error")
	cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})

	// Check that error was logged when circuit opened
	errorLogs := baseRecovery.getErrorLogs()
	if len(errorLogs) == 0 {
		t.Error("Expected error log when circuit breaker opened")
	} else {
		if !contains(errorLogs, "Circuit breaker opened after") {
			t.Errorf("Expected circuit opening log, got %v", errorLogs)
		}
	}

	// Wait and trigger half-open
	time.Sleep(15 * time.Millisecond)

	// Successful request should close circuit and log
	cb.ExecuteWithContext(context.Background(), func() error {
		return nil
	})

	// Check that success was logged when circuit closed
	infoLogs := baseRecovery.getInfoLogs()
	if len(infoLogs) == 0 {
		t.Error("Expected info log when circuit breaker closed")
	} else {
		if !contains(infoLogs, "Circuit breaker closed after successful request") {
			t.Errorf("Expected circuit closing log, got %v", infoLogs)
		}
	}

	// Reset should also be logged
	cb.Reset()
	infoLogs = baseRecovery.getInfoLogs()
	if !contains(infoLogs, "Circuit breaker has been reset") {
		t.Errorf("Expected reset log, got %v", infoLogs)
	}
}

func TestCircuitBreaker_LoggerTransitionLogging(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:  1,
		Timeout:      10 * time.Millisecond,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Wait for timeout and check half-open transition logging
	testError := fmt.Errorf("test error")
	cb.ExecuteWithContext(context.Background(), func() error {
		return testError
	})

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Next allowRequest call should log transition to half-open
	cb.allowRequest()

	infoLogs := logger.getInfoLogs()
	if len(infoLogs) == 0 {
		t.Error("Expected info log for half-open transition")
	} else {
		if !contains(infoLogs, "Circuit breaker transitioning to half-open state") {
			t.Errorf("Expected half-open transition log, got %v", infoLogs)
		}
	}
}

// Helper function to check if a slice contains a string with substring
func contains(slice []string, substr string) bool {
	for _, s := range slice {
		if len(s) >= len(substr) && s[:len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkCircuitBreaker_ExecuteWithContext_Success(b *testing.B) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	testFunc := func() error {
		return nil
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cb.ExecuteWithContext(ctx, testFunc)
		}
	})
}

func BenchmarkCircuitBreaker_ExecuteWithContext_Failure(b *testing.B) {
	config := CircuitBreakerConfig{
		MaxFailures:  1000, // High threshold to avoid opening during benchmark
		Timeout:      time.Second,
		ResetTimeout: time.Second,
	}
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	testError := fmt.Errorf("test error")
	testFunc := func() error {
		return testError
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.ExecuteWithContext(ctx, testFunc)
	}
}

func BenchmarkCircuitBreaker_GetState(b *testing.B) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cb.GetState()
		}
	})
}

func BenchmarkCircuitBreaker_GetMetrics(b *testing.B) {
	config := DefaultCircuitBreakerConfig()
	logger := &mockLogger{}
	baseRecovery := newMockBaseRecovery()
	cb := NewCircuitBreaker(config, logger, baseRecovery)

	// Add some activity
	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			cb.ExecuteWithContext(context.Background(), func() error { return nil })
		} else {
			cb.ExecuteWithContext(context.Background(), func() error { return fmt.Errorf("error") })
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cb.GetMetrics()
	}
}
