package recovery

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
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

func (m *mockLogger) getErrorLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.errorLogs))
	copy(result, m.errorLogs)
	return result
}

func (m *mockLogger) getDebugLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.debugLogs))
	copy(result, m.debugLogs)
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

type mockRecoveryMechanism struct {
	name             string
	executeError     error
	isAvailable      bool
	resetCalled      bool
	executeCallCount int64
	metrics          map[string]interface{}
	executeFunc      func(ctx context.Context, fn func() error) error
	mu               sync.RWMutex
}

func newMockRecoveryMechanism(name string) *mockRecoveryMechanism {
	return &mockRecoveryMechanism{
		name:        name,
		isAvailable: true,
		metrics:     make(map[string]interface{}),
	}
}

func (m *mockRecoveryMechanism) ExecuteWithContext(ctx context.Context, fn func() error) error {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, fn)
	}

	atomic.AddInt64(&m.executeCallCount, 1)

	m.mu.RLock()
	err := m.executeError
	m.mu.RUnlock()

	if err != nil {
		return err
	}

	return fn()
}

func (m *mockRecoveryMechanism) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})
	for k, v := range m.metrics {
		result[k] = v
	}
	result["name"] = m.name
	result["execute_call_count"] = atomic.LoadInt64(&m.executeCallCount)
	return result
}

func (m *mockRecoveryMechanism) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetCalled = true
	atomic.StoreInt64(&m.executeCallCount, 0)
}

func (m *mockRecoveryMechanism) IsAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isAvailable
}

func (m *mockRecoveryMechanism) setExecuteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executeError = err
}

func (m *mockRecoveryMechanism) setAvailable(available bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isAvailable = available
}

func (m *mockRecoveryMechanism) wasResetCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resetCalled
}

func (m *mockRecoveryMechanism) getExecuteCallCount() int64 {
	return atomic.LoadInt64(&m.executeCallCount)
}

func TestNewBaseRecoveryMechanism(t *testing.T) {
	tests := []struct {
		name       string
		loggerName string
		logger     Logger
	}{
		{
			name:       "with mock logger",
			loggerName: "test-mechanism",
			logger:     &mockLogger{},
		},
		{
			name:       "with nil logger",
			loggerName: "test-mechanism-nil",
			logger:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mechanism := NewBaseRecoveryMechanism(tt.loggerName, tt.logger)

			if mechanism == nil {
				t.Fatal("NewBaseRecoveryMechanism returned nil")
			}

			if mechanism.name != tt.loggerName {
				t.Errorf("Expected name %s, got %s", tt.loggerName, mechanism.name)
			}

			if tt.logger == nil && mechanism.logger == nil {
				t.Error("Expected NoOpLogger to be created when logger is nil")
			}

			if mechanism.startTime.IsZero() {
				t.Error("Expected startTime to be set")
			}
		})
	}
}

func TestBaseRecoveryMechanism_RecordMetrics(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test", logger)

	// Test initial state
	if atomic.LoadInt64(&mechanism.totalRequests) != 0 {
		t.Error("Expected initial totalRequests to be 0")
	}
	if atomic.LoadInt64(&mechanism.totalSuccesses) != 0 {
		t.Error("Expected initial totalSuccesses to be 0")
	}
	if atomic.LoadInt64(&mechanism.totalFailures) != 0 {
		t.Error("Expected initial totalFailures to be 0")
	}

	// Record some metrics
	mechanism.RecordRequest()
	mechanism.RecordSuccess()

	if atomic.LoadInt64(&mechanism.totalRequests) != 1 {
		t.Error("Expected totalRequests to be 1")
	}
	if atomic.LoadInt64(&mechanism.totalSuccesses) != 1 {
		t.Error("Expected totalSuccesses to be 1")
	}

	mechanism.RecordRequest()
	mechanism.RecordFailure()

	if atomic.LoadInt64(&mechanism.totalRequests) != 2 {
		t.Error("Expected totalRequests to be 2")
	}
	if atomic.LoadInt64(&mechanism.totalFailures) != 1 {
		t.Error("Expected totalFailures to be 1")
	}

	// Check timestamps are set
	if mechanism.lastSuccessTime.IsZero() {
		t.Error("Expected lastSuccessTime to be set")
	}
	if mechanism.lastFailureTime.IsZero() {
		t.Error("Expected lastFailureTime to be set")
	}
}

func TestBaseRecoveryMechanism_GetBaseMetrics(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-metrics", logger)

	// Record some activity
	mechanism.RecordRequest()
	mechanism.RecordRequest()
	mechanism.RecordSuccess()
	mechanism.RecordFailure()

	metrics := mechanism.GetBaseMetrics()

	expectedFields := []string{
		"name", "total_requests", "total_successes", "total_failures",
		"start_time", "success_rate", "failure_rate", "uptime",
		"last_success_time", "time_since_last_success",
		"last_failure_time", "time_since_last_failure",
	}

	for _, field := range expectedFields {
		if _, exists := metrics[field]; !exists {
			t.Errorf("Expected metric field %s to exist", field)
		}
	}

	// Check specific values
	if metrics["name"] != "test-metrics" {
		t.Errorf("Expected name to be 'test-metrics', got %v", metrics["name"])
	}

	if metrics["total_requests"] != int64(2) {
		t.Errorf("Expected total_requests to be 2, got %v", metrics["total_requests"])
	}

	if metrics["total_successes"] != int64(1) {
		t.Errorf("Expected total_successes to be 1, got %v", metrics["total_successes"])
	}

	if metrics["total_failures"] != int64(1) {
		t.Errorf("Expected total_failures to be 1, got %v", metrics["total_failures"])
	}

	if metrics["success_rate"] != float64(0.5) {
		t.Errorf("Expected success_rate to be 0.5, got %v", metrics["success_rate"])
	}

	if metrics["failure_rate"] != float64(0.5) {
		t.Errorf("Expected failure_rate to be 0.5, got %v", metrics["failure_rate"])
	}
}

func TestBaseRecoveryMechanism_GetBaseMetrics_NoRequests(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-empty", logger)

	metrics := mechanism.GetBaseMetrics()

	// Should not have success_rate or failure_rate when no requests
	if _, exists := metrics["success_rate"]; exists {
		t.Error("Expected success_rate to not exist when no requests")
	}
	if _, exists := metrics["failure_rate"]; exists {
		t.Error("Expected failure_rate to not exist when no requests")
	}

	// Should not have timestamp fields when no successes/failures
	if _, exists := metrics["last_success_time"]; exists {
		t.Error("Expected last_success_time to not exist when no successes")
	}
	if _, exists := metrics["last_failure_time"]; exists {
		t.Error("Expected last_failure_time to not exist when no failures")
	}
}

func TestBaseRecoveryMechanism_Logging(t *testing.T) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("test-logging", logger)

	mechanism.LogInfo("test info: %s", "value")
	mechanism.LogError("test error: %d", 42)
	mechanism.LogDebug("test debug: %v", true)

	infoLogs := logger.getInfoLogs()
	if len(infoLogs) != 1 || infoLogs[0] != "test info: value" {
		t.Errorf("Expected info log 'test info: value', got %v", infoLogs)
	}

	errorLogs := logger.getErrorLogs()
	if len(errorLogs) != 1 || errorLogs[0] != "test error: 42" {
		t.Errorf("Expected error log 'test error: 42', got %v", errorLogs)
	}

	debugLogs := logger.getDebugLogs()
	if len(debugLogs) != 1 || debugLogs[0] != "test debug: true" {
		t.Errorf("Expected debug log 'test debug: true', got %v", debugLogs)
	}
}

func TestBaseRecoveryMechanism_LoggingWithNilLogger(t *testing.T) {
	mechanism := NewBaseRecoveryMechanism("test-nil-logger", nil)

	// Should not panic when logger is nil (uses NoOpLogger)
	mechanism.LogInfo("test info")
	mechanism.LogError("test error")
	mechanism.LogDebug("test debug")
}

func TestNewErrorHandler(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("mech1")
	mechanism2 := newMockRecoveryMechanism("mech2")

	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	if handler == nil {
		t.Fatal("NewErrorHandler returned nil")
	}

	if handler.logger != logger {
		t.Error("Expected logger to be set")
	}

	if len(handler.mechanisms) != 2 {
		t.Errorf("Expected 2 mechanisms, got %d", len(handler.mechanisms))
	}
}

func TestErrorHandler_AddMechanism(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	if len(handler.mechanisms) != 0 {
		t.Errorf("Expected 0 initial mechanisms, got %d", len(handler.mechanisms))
	}

	mechanism := newMockRecoveryMechanism("test")
	handler.AddMechanism(mechanism)

	if len(handler.mechanisms) != 1 {
		t.Errorf("Expected 1 mechanism after adding, got %d", len(handler.mechanisms))
	}
}

func TestErrorHandler_ExecuteWithRecovery_NoMechanisms(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	ctx := context.Background()
	err := handler.ExecuteWithRecovery(ctx, testFunc)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}
}

func TestErrorHandler_ExecuteWithRecovery_WithMechanisms(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("mech1")
	mechanism2 := newMockRecoveryMechanism("mech2")
	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	ctx := context.Background()
	err := handler.ExecuteWithRecovery(ctx, testFunc)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected function to be called once, got %d", callCount)
	}

	// Both mechanisms should have been called
	if mechanism1.getExecuteCallCount() != 1 {
		t.Errorf("Expected mechanism1 to be called once, got %d", mechanism1.getExecuteCallCount())
	}
	if mechanism2.getExecuteCallCount() != 1 {
		t.Errorf("Expected mechanism2 to be called once, got %d", mechanism2.getExecuteCallCount())
	}
}

func TestErrorHandler_ExecuteWithRecovery_MechanismError(t *testing.T) {
	logger := &mockLogger{}
	mechanism := newMockRecoveryMechanism("failing-mech")
	mechanism.setExecuteError(fmt.Errorf("mechanism failed"))
	handler := NewErrorHandler(logger, mechanism)

	callCount := 0
	testFunc := func() error {
		callCount++
		return nil
	}

	ctx := context.Background()
	err := handler.ExecuteWithRecovery(ctx, testFunc)

	if err == nil {
		t.Error("Expected error from mechanism")
	}

	if err.Error() != "mechanism failed" {
		t.Errorf("Expected 'mechanism failed', got %v", err)
	}

	// Function should not be called if mechanism fails
	if callCount != 0 {
		t.Errorf("Expected function not to be called, got %d calls", callCount)
	}
}

func TestErrorHandler_ExecuteWithRecovery_FunctionError(t *testing.T) {
	logger := &mockLogger{}
	mechanism := newMockRecoveryMechanism("mech")
	handler := NewErrorHandler(logger, mechanism)

	testFunc := func() error {
		return fmt.Errorf("function failed")
	}

	ctx := context.Background()
	err := handler.ExecuteWithRecovery(ctx, testFunc)

	if err == nil {
		t.Error("Expected error from function")
	}

	if err.Error() != "function failed" {
		t.Errorf("Expected 'function failed', got %v", err)
	}
}

func TestErrorHandler_GetAllMetrics(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("mech1")
	mechanism2 := newMockRecoveryMechanism("mech2")
	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	// Add some custom metrics
	mechanism1.metrics["custom1"] = "value1"
	mechanism2.metrics["custom2"] = "value2"

	metrics := handler.GetAllMetrics()

	if len(metrics) != 2 {
		t.Errorf("Expected 2 mechanism metrics, got %d", len(metrics))
	}

	mechanism0Key := "mechanism_" + string(rune(0))
	mechanism0Metrics, exists := metrics[mechanism0Key]
	if !exists {
		t.Errorf("Expected %s metrics to exist", mechanism0Key)
	} else {
		mechanismMap, ok := mechanism0Metrics.(map[string]interface{})
		if !ok {
			t.Error("Expected mechanism metrics to be a map")
		} else {
			if mechanismMap["name"] != "mech1" {
				t.Errorf("Expected name 'mech1', got %v", mechanismMap["name"])
			}
			if mechanismMap["custom1"] != "value1" {
				t.Errorf("Expected custom1 'value1', got %v", mechanismMap["custom1"])
			}
		}
	}

	mechanism1Key := "mechanism_" + string(rune(1))
	mechanism1Metrics, exists := metrics[mechanism1Key]
	if !exists {
		t.Errorf("Expected %s metrics to exist", mechanism1Key)
	} else {
		mechanismMap, ok := mechanism1Metrics.(map[string]interface{})
		if !ok {
			t.Error("Expected mechanism metrics to be a map")
		} else {
			if mechanismMap["name"] != "mech2" {
				t.Errorf("Expected name 'mech2', got %v", mechanismMap["name"])
			}
			if mechanismMap["custom2"] != "value2" {
				t.Errorf("Expected custom2 'value2', got %v", mechanismMap["custom2"])
			}
		}
	}
}

func TestErrorHandler_ResetAll(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("mech1")
	mechanism2 := newMockRecoveryMechanism("mech2")
	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	handler.ResetAll()

	if !mechanism1.wasResetCalled() {
		t.Error("Expected mechanism1 to be reset")
	}
	if !mechanism2.wasResetCalled() {
		t.Error("Expected mechanism2 to be reset")
	}
}

func TestErrorHandler_IsHealthy(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("mech1")
	mechanism2 := newMockRecoveryMechanism("mech2")
	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	// Initially both are available
	if !handler.IsHealthy() {
		t.Error("Expected handler to be healthy when all mechanisms are available")
	}

	// Make one mechanism unavailable
	mechanism1.setAvailable(false)
	if handler.IsHealthy() {
		t.Error("Expected handler to be unhealthy when one mechanism is unavailable")
	}

	// Make both unavailable
	mechanism2.setAvailable(false)
	if handler.IsHealthy() {
		t.Error("Expected handler to be unhealthy when all mechanisms are unavailable")
	}

	// Make both available again
	mechanism1.setAvailable(true)
	mechanism2.setAvailable(true)
	if !handler.IsHealthy() {
		t.Error("Expected handler to be healthy when all mechanisms are available again")
	}
}

func TestErrorHandler_IsHealthy_NoMechanisms(t *testing.T) {
	logger := &mockLogger{}
	handler := NewErrorHandler(logger)

	// Should be healthy with no mechanisms
	if !handler.IsHealthy() {
		t.Error("Expected handler to be healthy with no mechanisms")
	}
}

func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()

	if logger == nil {
		t.Fatal("NewNoOpLogger returned nil")
	}

	// Should not panic
	logger.Infof("test info: %s", "value")
	logger.Errorf("test error: %d", 42)
	logger.Debugf("test debug: %v", true)
}

func TestConcurrentAccess(t *testing.T) {
	logger := &mockLogger{}
	baseMechanism := NewBaseRecoveryMechanism("concurrent-test", logger)

	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	// Test concurrent metric recording
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				baseMechanism.RecordRequest()
				if j%2 == 0 {
					baseMechanism.RecordSuccess()
				} else {
					baseMechanism.RecordFailure()
				}

				// Intermittently get metrics to test concurrent reads
				if j%10 == 0 {
					baseMechanism.GetBaseMetrics()
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	var errorCount int
	for err := range errors {
		t.Error(err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Found %d errors in concurrent access test", errorCount)
	}

	// Verify final counts
	expectedRequests := int64(numGoroutines * numOperations)
	expectedSuccesses := int64(numGoroutines * numOperations / 2)
	expectedFailures := int64(numGoroutines * numOperations / 2)

	if atomic.LoadInt64(&baseMechanism.totalRequests) != expectedRequests {
		t.Errorf("Expected %d total requests, got %d", expectedRequests,
			atomic.LoadInt64(&baseMechanism.totalRequests))
	}

	if atomic.LoadInt64(&baseMechanism.totalSuccesses) != expectedSuccesses {
		t.Errorf("Expected %d total successes, got %d", expectedSuccesses,
			atomic.LoadInt64(&baseMechanism.totalSuccesses))
	}

	if atomic.LoadInt64(&baseMechanism.totalFailures) != expectedFailures {
		t.Errorf("Expected %d total failures, got %d", expectedFailures,
			atomic.LoadInt64(&baseMechanism.totalFailures))
	}
}

func TestErrorHandler_ConcurrentAccess(t *testing.T) {
	logger := &mockLogger{}
	mechanism1 := newMockRecoveryMechanism("concurrent-mech1")
	mechanism2 := newMockRecoveryMechanism("concurrent-mech2")
	handler := NewErrorHandler(logger, mechanism1, mechanism2)

	const numGoroutines = 5
	const numExecutions = 20

	var wg sync.WaitGroup
	successCount := int64(0)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numExecutions; j++ {
				err := handler.ExecuteWithRecovery(context.Background(), func() error {
					atomic.AddInt64(&successCount, 1)
					return nil
				})
				if err != nil {
					t.Errorf("Unexpected error in goroutine %d: %v", id, err)
				}

				// Add some mechanisms concurrently
				if j == 0 {
					newMech := newMockRecoveryMechanism(fmt.Sprintf("dynamic-mech-%d", id))
					handler.AddMechanism(newMech)
				}

				// Get metrics concurrently
				if j%5 == 0 {
					handler.GetAllMetrics()
				}
			}
		}(i)
	}

	wg.Wait()

	expectedSuccesses := int64(numGoroutines * numExecutions)
	if atomic.LoadInt64(&successCount) != expectedSuccesses {
		t.Errorf("Expected %d successes, got %d", expectedSuccesses,
			atomic.LoadInt64(&successCount))
	}

	// Should have original 2 mechanisms plus 5 added dynamically
	if len(handler.mechanisms) != 7 {
		t.Errorf("Expected 7 mechanisms after concurrent additions, got %d",
			len(handler.mechanisms))
	}
}

func TestErrorHandler_ContextCancellation(t *testing.T) {
	logger := &mockLogger{}
	mechanism := newMockRecoveryMechanism("context-test")
	handler := NewErrorHandler(logger, mechanism)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	executedCount := 0
	testFunc := func() error {
		executedCount++
		return nil
	}

	// The mechanism implementation should handle context cancellation
	// For our mock, we'll make it check context cancellation
	mechanism.executeFunc = func(ctx context.Context, fn func() error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			atomic.AddInt64(&mechanism.executeCallCount, 1)
			return fn()
		}
	}

	err := handler.ExecuteWithRecovery(ctx, testFunc)

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}

	if executedCount != 0 {
		t.Errorf("Expected function not to execute when context is cancelled, got %d executions", executedCount)
	}
}

// Benchmark tests
func BenchmarkBaseRecoveryMechanism_RecordRequest(b *testing.B) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("benchmark", logger)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mechanism.RecordRequest()
		}
	})
}

func BenchmarkBaseRecoveryMechanism_RecordSuccess(b *testing.B) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("benchmark", logger)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mechanism.RecordSuccess()
		}
	})
}

func BenchmarkBaseRecoveryMechanism_GetBaseMetrics(b *testing.B) {
	logger := &mockLogger{}
	mechanism := NewBaseRecoveryMechanism("benchmark", logger)

	// Add some data
	for i := 0; i < 100; i++ {
		mechanism.RecordRequest()
		if i%2 == 0 {
			mechanism.RecordSuccess()
		} else {
			mechanism.RecordFailure()
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mechanism.GetBaseMetrics()
	}
}

func BenchmarkErrorHandler_ExecuteWithRecovery(b *testing.B) {
	logger := &mockLogger{}
	mechanism := newMockRecoveryMechanism("benchmark")
	handler := NewErrorHandler(logger, mechanism)

	testFunc := func() error {
		return nil
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ExecuteWithRecovery(ctx, testFunc)
	}
}
