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
	infoMessages  []string
	debugMessages []string
	errorMessages []string
	mu            sync.Mutex
}

func (l *mockLogger) Infof(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infoMessages = append(l.infoMessages, format)
}

func (l *mockLogger) Errorf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errorMessages = append(l.errorMessages, format)
}

func (l *mockLogger) Debugf(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugMessages = append(l.debugMessages, format)
}

func (l *mockLogger) getInfoCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.infoMessages)
}

func (l *mockLogger) getErrorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errorMessages)
}

func (l *mockLogger) getDebugCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.debugMessages)
}

// Mock error recovery mechanism for testing
type mockRecoveryMechanism struct {
	*BaseRecoveryMechanism
	executeFunc func(ctx context.Context, fn func() error) error
	isAvailable bool
	resetCalled bool
}

func newMockRecoveryMechanism(name string, logger Logger) *mockRecoveryMechanism {
	return &mockRecoveryMechanism{
		BaseRecoveryMechanism: NewBaseRecoveryMechanism(name, logger),
		isAvailable:           true,
	}
}

func (m *mockRecoveryMechanism) ExecuteWithContext(ctx context.Context, fn func() error) error {
	m.RecordRequest()

	if m.executeFunc != nil {
		return m.executeFunc(ctx, fn)
	}

	// Default behavior - just execute the function
	err := fn()
	if err != nil {
		m.RecordFailure()
		return err
	}

	m.RecordSuccess()
	return nil
}

func (m *mockRecoveryMechanism) GetMetrics() map[string]interface{} {
	metrics := m.GetBaseMetrics()
	metrics["mock_specific"] = "test_value"
	return metrics
}

func (m *mockRecoveryMechanism) Reset() {
	m.resetCalled = true
}

func (m *mockRecoveryMechanism) IsAvailable() bool {
	return m.isAvailable
}

// TestNewBaseRecoveryMechanism tests the base recovery mechanism constructor
func TestNewBaseRecoveryMechanism(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-mechanism", logger)

	if mechanism == nil {
		t.Fatal("Expected mechanism to be created, got nil")
	}

	if mechanism.name != "test-mechanism" {
		t.Errorf("Expected name 'test-mechanism', got '%s'", mechanism.name)
	}

	if mechanism.logger != logger {
		t.Error("Logger not set correctly")
	}

	if mechanism.startTime.IsZero() {
		t.Error("Start time should be set")
	}

	// Test with nil logger
	mechanism2 := NewBaseRecoveryMechanism("test2", nil)
	if mechanism2.logger == nil {
		t.Error("Expected logger to be set to NoOpLogger when nil provided")
	}
}

// TestBaseRecoveryMechanism_RecordOperations tests request/success/failure recording
func TestBaseRecoveryMechanism_RecordOperations(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Initially all counters should be zero
	if atomic.LoadInt64(&mechanism.totalRequests) != 0 {
		t.Error("Expected initial requests to be 0")
	}
	if atomic.LoadInt64(&mechanism.totalSuccesses) != 0 {
		t.Error("Expected initial successes to be 0")
	}
	if atomic.LoadInt64(&mechanism.totalFailures) != 0 {
		t.Error("Expected initial failures to be 0")
	}

	// Record some operations
	mechanism.RecordRequest()
	mechanism.RecordSuccess()

	if atomic.LoadInt64(&mechanism.totalRequests) != 1 {
		t.Errorf("Expected 1 request, got %d", atomic.LoadInt64(&mechanism.totalRequests))
	}
	if atomic.LoadInt64(&mechanism.totalSuccesses) != 1 {
		t.Errorf("Expected 1 success, got %d", atomic.LoadInt64(&mechanism.totalSuccesses))
	}

	mechanism.RecordRequest()
	mechanism.RecordFailure()

	if atomic.LoadInt64(&mechanism.totalRequests) != 2 {
		t.Errorf("Expected 2 requests, got %d", atomic.LoadInt64(&mechanism.totalRequests))
	}
	if atomic.LoadInt64(&mechanism.totalFailures) != 1 {
		t.Errorf("Expected 1 failure, got %d", atomic.LoadInt64(&mechanism.totalFailures))
	}

	// Verify timestamps are set
	mechanism.mutex.RLock()
	lastSuccessSet := !mechanism.lastSuccessTime.IsZero()
	lastFailureSet := !mechanism.lastFailureTime.IsZero()
	mechanism.mutex.RUnlock()

	if !lastSuccessSet {
		t.Error("Last success time should be set")
	}
	if !lastFailureSet {
		t.Error("Last failure time should be set")
	}
}

// TestBaseRecoveryMechanism_GetBaseMetrics tests metrics collection
func TestBaseRecoveryMechanism_GetBaseMetrics(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-mechanism", logger)

	// Record some operations to have meaningful metrics
	mechanism.RecordRequest()
	mechanism.RecordSuccess()
	mechanism.RecordRequest()
	mechanism.RecordFailure()

	metrics := mechanism.GetBaseMetrics()

	// Verify basic metrics
	if metrics["name"] != "test-mechanism" {
		t.Errorf("Expected name 'test-mechanism', got '%s'", metrics["name"])
	}

	if metrics["total_requests"] != int64(2) {
		t.Errorf("Expected 2 total requests, got %v", metrics["total_requests"])
	}

	if metrics["total_successes"] != int64(1) {
		t.Errorf("Expected 1 total success, got %v", metrics["total_successes"])
	}

	if metrics["total_failures"] != int64(1) {
		t.Errorf("Expected 1 total failure, got %v", metrics["total_failures"])
	}

	// Verify calculated rates
	if metrics["success_rate"] != float64(0.5) {
		t.Errorf("Expected success rate 0.5, got %v", metrics["success_rate"])
	}

	if metrics["failure_rate"] != float64(0.5) {
		t.Errorf("Expected failure rate 0.5, got %v", metrics["failure_rate"])
	}

	// Verify time-related metrics
	if _, exists := metrics["start_time"]; !exists {
		t.Error("Expected start_time metric to exist")
	}

	if _, exists := metrics["uptime"]; !exists {
		t.Error("Expected uptime metric to exist")
	}

	if _, exists := metrics["last_success_time"]; !exists {
		t.Error("Expected last_success_time metric to exist")
	}

	if _, exists := metrics["last_failure_time"]; !exists {
		t.Error("Expected last_failure_time metric to exist")
	}

	if _, exists := metrics["time_since_last_success"]; !exists {
		t.Error("Expected time_since_last_success metric to exist")
	}

	if _, exists := metrics["time_since_last_failure"]; !exists {
		t.Error("Expected time_since_last_failure metric to exist")
	}
}

// TestBaseRecoveryMechanism_GetBaseMetrics_NoOperations tests metrics with no recorded operations
func TestBaseRecoveryMechanism_GetBaseMetrics_NoOperations(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-mechanism", logger)

	metrics := mechanism.GetBaseMetrics()

	// With no operations, rates should not be calculated
	if _, exists := metrics["success_rate"]; exists {
		t.Error("Success rate should not exist with no operations")
	}

	if _, exists := metrics["failure_rate"]; exists {
		t.Error("Failure rate should not exist with no operations")
	}

	// Time-specific metrics should not exist if no operations occurred
	if _, exists := metrics["last_success_time"]; exists {
		t.Error("Last success time should not exist with no operations")
	}

	if _, exists := metrics["last_failure_time"]; exists {
		t.Error("Last failure time should not exist with no operations")
	}

	// But basic metrics should exist
	if metrics["total_requests"] != int64(0) {
		t.Errorf("Expected 0 total requests, got %v", metrics["total_requests"])
	}

	if _, exists := metrics["uptime"]; !exists {
		t.Error("Uptime should always exist")
	}
}

// TestBaseRecoveryMechanism_LogMethods tests logging methods
func TestBaseRecoveryMechanism_LogMethods(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-mechanism", logger)

	mechanism.LogInfo("test info message")
	mechanism.LogError("test error message")
	mechanism.LogDebug("test debug message")

	if logger.getInfoCount() != 1 {
		t.Errorf("Expected 1 info message, got %d", logger.getInfoCount())
	}

	if logger.getErrorCount() != 1 {
		t.Errorf("Expected 1 error message, got %d", logger.getErrorCount())
	}

	if logger.getDebugCount() != 1 {
		t.Errorf("Expected 1 debug message, got %d", logger.getDebugCount())
	}
}

// TestBaseRecoveryMechanism_LogMethods_NilLogger tests logging with nil logger
func TestBaseRecoveryMechanism_LogMethods_NilLogger(t *testing.T) {
	mechanism := NewBaseRecoveryMechanism("test-mechanism", nil)

	// Should not panic
	mechanism.LogInfo("test info message")
	mechanism.LogError("test error message")
	mechanism.LogDebug("test debug message")
}

// TestNewErrorHandler tests error handler constructor
func TestNewErrorHandler(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("mechanism1", logger)
	mechanism2 := newMockRecoveryMechanism("mechanism2", logger)

	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	if handler == nil {
		t.Fatal("Expected handler to be created, got nil")
	}

	if handler.logger != logger {
		t.Error("Logger not set correctly")
	}

	if len(handler.mechanisms) != 2 {
		t.Errorf("Expected 2 mechanisms, got %d", len(handler.mechanisms))
	}
}

// TestErrorHandler_AddMechanism tests adding mechanisms to handler
func TestErrorHandler_AddMechanism(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	if len(handler.mechanisms) != 0 {
		t.Errorf("Expected 0 initial mechanisms, got %d", len(handler.mechanisms))
	}

	mechanism := newMockRecoveryMechanism("test-mechanism", logger)
	handler.AddMechanism(mechanism)

	if len(handler.mechanisms) != 1 {
		t.Errorf("Expected 1 mechanism after adding, got %d", len(handler.mechanisms))
	}
}

// TestErrorHandler_ExecuteWithRecovery tests execution without mechanisms
func TestErrorHandler_ExecuteWithRecovery_NoMechanisms(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	executed := false
	fn := func() error {
		executed = true
		return nil
	}

	err := handler.ExecuteWithRecovery(context.Background(), fn)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !executed {
		t.Error("Function should have been executed")
	}
}

// TestErrorHandler_ExecuteWithRecovery tests execution with mechanisms
func TestErrorHandler_ExecuteWithRecovery_WithMechanisms(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	mechanism1 := newMockRecoveryMechanism("mechanism1", logger)
	mechanism2 := newMockRecoveryMechanism("mechanism2", logger)

	handler.AddMechanism(mechanism1)
	handler.AddMechanism(mechanism2)

	executed := false
	fn := func() error {
		executed = true
		return nil
	}

	err := handler.ExecuteWithRecovery(context.Background(), fn)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !executed {
		t.Error("Function should have been executed")
	}

	// Verify both mechanisms recorded requests
	if atomic.LoadInt64(&mechanism1.totalRequests) != 1 {
		t.Errorf("Mechanism1 should have 1 request, got %d", atomic.LoadInt64(&mechanism1.totalRequests))
	}
	if atomic.LoadInt64(&mechanism2.totalRequests) != 1 {
		t.Errorf("Mechanism2 should have 1 request, got %d", atomic.LoadInt64(&mechanism2.totalRequests))
	}
}

// TestErrorHandler_ExecuteWithRecovery_Error tests execution with error
func TestErrorHandler_ExecuteWithRecovery_Error(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	mechanism := newMockRecoveryMechanism("test-mechanism", logger)
	handler.AddMechanism(mechanism)

	expectedError := errors.New("test error")
	fn := func() error {
		return expectedError
	}

	err := handler.ExecuteWithRecovery(context.Background(), fn)

	if err != expectedError {
		t.Errorf("Expected error %v, got %v", expectedError, err)
	}

	// Verify mechanism recorded failure
	if atomic.LoadInt64(&mechanism.totalFailures) != 1 {
		t.Errorf("Mechanism should have 1 failure, got %d", atomic.LoadInt64(&mechanism.totalFailures))
	}
}

// TestErrorHandler_ExecuteWithRecovery_MechanismChaining tests mechanism chaining
func TestErrorHandler_ExecuteWithRecovery_MechanismChaining(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	executionOrder := []string{}
	mutex := &sync.Mutex{}

	// Create mechanisms that record execution order
	mechanism1 := newMockRecoveryMechanism("mechanism1", logger)
	mechanism1.executeFunc = func(ctx context.Context, fn func() error) error {
		mutex.Lock()
		executionOrder = append(executionOrder, "mechanism1-start")
		mutex.Unlock()

		err := fn()

		mutex.Lock()
		executionOrder = append(executionOrder, "mechanism1-end")
		mutex.Unlock()

		return err
	}

	mechanism2 := newMockRecoveryMechanism("mechanism2", logger)
	mechanism2.executeFunc = func(ctx context.Context, fn func() error) error {
		mutex.Lock()
		executionOrder = append(executionOrder, "mechanism2-start")
		mutex.Unlock()

		err := fn()

		mutex.Lock()
		executionOrder = append(executionOrder, "mechanism2-end")
		mutex.Unlock()

		return err
	}

	handler.AddMechanism(mechanism1)
	handler.AddMechanism(mechanism2)

	fn := func() error {
		mutex.Lock()
		executionOrder = append(executionOrder, "function-executed")
		mutex.Unlock()
		return nil
	}

	err := handler.ExecuteWithRecovery(context.Background(), fn)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify execution order - mechanisms should wrap each other
	expectedOrder := []string{
		"mechanism1-start",
		"mechanism2-start",
		"function-executed",
		"mechanism2-end",
		"mechanism1-end",
	}

	mutex.Lock()
	actualOrder := make([]string, len(executionOrder))
	copy(actualOrder, executionOrder)
	mutex.Unlock()

	if len(actualOrder) != len(expectedOrder) {
		t.Errorf("Expected %d execution steps, got %d", len(expectedOrder), len(actualOrder))
	}

	for i, expected := range expectedOrder {
		if i >= len(actualOrder) || actualOrder[i] != expected {
			t.Errorf("Expected execution order[%d] = '%s', got '%s'", i, expected, actualOrder[i])
		}
	}
}

// TestErrorHandler_GetAllMetrics tests metrics collection from all mechanisms
func TestErrorHandler_GetAllMetrics(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	mechanism1 := newMockRecoveryMechanism("mechanism1", logger)
	mechanism2 := newMockRecoveryMechanism("mechanism2", logger)

	handler.AddMechanism(mechanism1)
	handler.AddMechanism(mechanism2)

	metrics := handler.GetAllMetrics()

	// Should have metrics from both mechanisms
	if len(metrics) != 2 {
		t.Errorf("Expected metrics from 2 mechanisms, got %d", len(metrics))
	}

	// Check mechanism keys exist - they use string(rune(i)) which converts to Unicode character
	expectedKey0 := "mechanism_" + string(rune(0)) // Unicode char 0
	expectedKey1 := "mechanism_" + string(rune(1)) // Unicode char 1

	if _, exists := metrics[expectedKey0]; !exists {
		t.Errorf("Expected key '%s' to exist in metrics", expectedKey0)
	}

	if _, exists := metrics[expectedKey1]; !exists {
		t.Errorf("Expected key '%s' to exist in metrics", expectedKey1)
	}
}

// TestErrorHandler_ResetAll tests resetting all mechanisms
func TestErrorHandler_ResetAll(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	mechanism1 := newMockRecoveryMechanism("mechanism1", logger)
	mechanism2 := newMockRecoveryMechanism("mechanism2", logger)

	handler.AddMechanism(mechanism1)
	handler.AddMechanism(mechanism2)

	handler.ResetAll()

	if !mechanism1.resetCalled {
		t.Error("Mechanism1 reset should have been called")
	}

	if !mechanism2.resetCalled {
		t.Error("Mechanism2 reset should have been called")
	}
}

// TestErrorHandler_IsHealthy tests health checking
func TestErrorHandler_IsHealthy(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	// No mechanisms - should be healthy
	if !handler.IsHealthy() {
		t.Error("Handler with no mechanisms should be healthy")
	}

	mechanism1 := newMockRecoveryMechanism("mechanism1", logger)
	mechanism1.isAvailable = true

	mechanism2 := newMockRecoveryMechanism("mechanism2", logger)
	mechanism2.isAvailable = true

	handler.AddMechanism(mechanism1)
	handler.AddMechanism(mechanism2)

	// All mechanisms available - should be healthy
	if !handler.IsHealthy() {
		t.Error("Handler with all available mechanisms should be healthy")
	}

	// Make one mechanism unavailable
	mechanism1.isAvailable = false

	// Should not be healthy
	if handler.IsHealthy() {
		t.Error("Handler with unavailable mechanism should not be healthy")
	}
}

// TestNoOpLogger tests the no-op logger
func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()

	// Should not panic
	logger.Infof("test info")
	logger.Errorf("test error")
	logger.Debugf("test debug")
}

// TestConcurrentAccess tests thread safety
func TestErrorHandler_ConcurrentAccess(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	mechanism := newMockRecoveryMechanism("test-mechanism", logger)
	handler.AddMechanism(mechanism)

	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	// Test concurrent execution
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				handler.ExecuteWithRecovery(context.Background(), func() error {
					time.Sleep(time.Microsecond)
					return nil
				})
			}
		}()
	}

	// Test concurrent metric access
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			handler.GetAllMetrics()
			time.Sleep(time.Microsecond)
		}
	}()

	// Test concurrent mechanism addition
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			newMech := newMockRecoveryMechanism("concurrent-mechanism", logger)
			handler.AddMechanism(newMech)
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()

	// Verify metrics are consistent
	totalRequests := atomic.LoadInt64(&mechanism.totalRequests)
	totalSuccesses := atomic.LoadInt64(&mechanism.totalSuccesses)

	if totalRequests != int64(goroutines*iterations) {
		t.Errorf("Expected %d total requests, got %d", goroutines*iterations, totalRequests)
	}

	if totalSuccesses != int64(goroutines*iterations) {
		t.Errorf("Expected %d total successes, got %d", goroutines*iterations, totalSuccesses)
	}
}

// Benchmark tests
func BenchmarkErrorHandler_ExecuteWithRecovery(b *testing.B) {
	logger := NewNoOpLogger()
	handler := NewErrorHandler(logger)
	mechanism := newMockRecoveryMechanism("benchmark-mechanism", logger)
	handler.AddMechanism(mechanism)

	fn := func() error {
		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ExecuteWithRecovery(context.Background(), fn)
	}
}

func BenchmarkBaseRecoveryMechanism_RecordOperations(b *testing.B) {
	logger := NewNoOpLogger()
	mechanism := NewBaseRecoveryMechanism("benchmark-mechanism", logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mechanism.RecordRequest()
		if i%2 == 0 {
			mechanism.RecordSuccess()
		} else {
			mechanism.RecordFailure()
		}
	}
}

func BenchmarkBaseRecoveryMechanism_GetBaseMetrics(b *testing.B) {
	logger := NewNoOpLogger()
	mechanism := NewBaseRecoveryMechanism("benchmark-mechanism", logger)

	// Add some data
	mechanism.RecordRequest()
	mechanism.RecordSuccess()
	mechanism.RecordRequest()
	mechanism.RecordFailure()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mechanism.GetBaseMetrics()
	}
}
