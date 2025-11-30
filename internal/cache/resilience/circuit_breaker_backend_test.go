//go:build !yaegi

package resilience

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBackend is a simple mock implementation for testing
type mockBackend struct {
	data       map[string]mockEntry
	mu         sync.RWMutex
	failSet    bool
	failGet    bool
	failDelete bool
	failExists bool
	failClear  bool
	failPing   bool
	callCount  int
}

type mockEntry struct {
	value     []byte
	expiresAt time.Time
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		data: make(map[string]mockEntry),
	}
}

func (m *mockBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if m.failSet {
		return errors.New("mock set error")
	}

	expiresAt := time.Now().Add(ttl)
	if ttl == 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	m.data[key] = mockEntry{
		value:     value,
		expiresAt: expiresAt,
	}
	return nil
}

func (m *mockBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.callCount++

	if m.failGet {
		return nil, 0, false, errors.New("mock get error")
	}

	entry, exists := m.data[key]
	if !exists {
		return nil, 0, false, nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil, 0, false, nil
	}

	ttl := time.Until(entry.expiresAt)
	return entry.value, ttl, true, nil
}

func (m *mockBackend) Delete(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if m.failDelete {
		return false, errors.New("mock delete error")
	}

	_, existed := m.data[key]
	delete(m.data, key)
	return existed, nil
}

func (m *mockBackend) Exists(ctx context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.callCount++

	if m.failExists {
		return false, errors.New("mock exists error")
	}

	entry, exists := m.data[key]
	if !exists {
		return false, nil
	}

	if time.Now().After(entry.expiresAt) {
		return false, nil
	}

	return true, nil
}

func (m *mockBackend) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if m.failClear {
		return errors.New("mock clear error")
	}

	m.data = make(map[string]mockEntry)
	return nil
}

func (m *mockBackend) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"hits":       int64(0),
		"misses":     int64(0),
		"call_count": m.callCount,
	}
}

func (m *mockBackend) Close() error {
	return nil
}

func (m *mockBackend) Ping(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++

	if m.failPing {
		return errors.New("mock ping error")
	}
	return nil
}

// Constructor Tests

func TestNewCircuitBreakerBackend_WithDefaultConfig(t *testing.T) {
	mockBE := newMockBackend()

	cb := NewCircuitBreakerBackend(mockBE, nil)
	require.NotNil(t, cb)

	// Verify it implements the interface (compile-time check)
	var _ backends.CacheBackend = cb
}

func TestNewCircuitBreakerBackend_WithCustomConfig(t *testing.T) {
	mockBE := newMockBackend()

	config := &CircuitBreakerConfig{
		MaxFailures:         3,
		FailureThreshold:    0.5,
		Timeout:             5 * time.Second,
		HalfOpenMaxRequests: 2,
		ResetTimeout:        10 * time.Second,
	}

	cb := NewCircuitBreakerBackend(mockBE, config)
	require.NotNil(t, cb)
}

// Set Operation Tests

func TestCircuitBreakerBackend_Set_Success(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()
	err := cb.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	assert.NoError(t, err)
	assert.Equal(t, 1, mockBE.callCount)

	// Verify value was stored
	value, _, exists, _ := mockBE.Get(ctx, "key1")
	assert.True(t, exists)
	assert.Equal(t, []byte("value1"), value)
}

func TestCircuitBreakerBackend_Set_Failure(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failSet = true

	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()
	err := cb.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	assert.Error(t, err)
}

func TestCircuitBreakerBackend_Set_CircuitOpen(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failSet = true

	config := &CircuitBreakerConfig{
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures to open circuit
	for i := 0; i < 5; i++ {
		cb.Set(ctx, "key", []byte("value"), 1*time.Minute)
	}

	// Circuit should be open now
	err := cb.Set(ctx, "key2", []byte("value2"), 1*time.Minute)
	assert.Error(t, err)
	assert.Equal(t, backends.ErrCircuitOpen, err)
}

// Get Operation Tests

func TestCircuitBreakerBackend_Get_Success(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()

	// First set a value
	mockBE.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	// Now get it through circuit breaker
	value, _, exists, err := cb.Get(ctx, "key1")

	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, []byte("value1"), value)
}

func TestCircuitBreakerBackend_Get_Failure(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failGet = true

	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()
	_, _, _, err := cb.Get(ctx, "key1")

	assert.Error(t, err)
}

func TestCircuitBreakerBackend_Get_CircuitOpen(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failGet = true

	config := &CircuitBreakerConfig{
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures
	for i := 0; i < 5; i++ {
		cb.Get(ctx, "key")
	}

	// Circuit should be open
	_, _, _, err := cb.Get(ctx, "key2")
	assert.Error(t, err)
	assert.Equal(t, backends.ErrCircuitOpen, err)
}

// Delete Operation Tests

func TestCircuitBreakerBackend_Delete_Success(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()

	// Set a value first
	mockBE.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	// Delete through circuit breaker
	deleted, err := cb.Delete(ctx, "key1")

	assert.NoError(t, err)
	assert.True(t, deleted)

	// Verify it's deleted
	exists, _ := mockBE.Exists(ctx, "key1")
	assert.False(t, exists)
}

func TestCircuitBreakerBackend_Delete_CircuitOpen(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failDelete = true

	config := &CircuitBreakerConfig{
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures
	for i := 0; i < 5; i++ {
		cb.Delete(ctx, "key")
	}

	// Circuit should be open
	_, err := cb.Delete(ctx, "key2")
	assert.Error(t, err)
	assert.Equal(t, backends.ErrCircuitOpen, err)
}

// Exists Operation Tests

func TestCircuitBreakerBackend_Exists_Success(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()

	// Set a value first
	mockBE.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	// Check existence through circuit breaker
	exists, err := cb.Exists(ctx, "key1")

	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestCircuitBreakerBackend_Exists_CircuitOpen(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failExists = true

	config := &CircuitBreakerConfig{
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures
	for i := 0; i < 5; i++ {
		cb.Exists(ctx, "key")
	}

	// Circuit should be open
	_, err := cb.Exists(ctx, "key2")
	assert.Error(t, err)
	assert.Equal(t, backends.ErrCircuitOpen, err)
}

// Clear Operation Tests

func TestCircuitBreakerBackend_Clear_Success(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()

	// Set some values
	mockBE.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	mockBE.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	// Clear through circuit breaker
	err := cb.Clear(ctx)

	assert.NoError(t, err)

	// Verify cleared
	exists1, _ := mockBE.Exists(ctx, "key1")
	exists2, _ := mockBE.Exists(ctx, "key2")
	assert.False(t, exists1)
	assert.False(t, exists2)
}

func TestCircuitBreakerBackend_Clear_CircuitOpen(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failClear = true

	config := &CircuitBreakerConfig{
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures
	for i := 0; i < 5; i++ {
		cb.Clear(ctx)
	}

	// Circuit should be open
	err := cb.Clear(ctx)
	assert.Error(t, err)
	assert.Equal(t, backends.ErrCircuitOpen, err)
}

// GetStats Tests

func TestCircuitBreakerBackend_GetStats(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()

	// Perform some operations
	cb.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	cb.Get(ctx, "key1")

	stats := cb.GetStats()

	require.NotNil(t, stats)

	// Should have circuit breaker stats
	assert.Contains(t, stats, "circuit_breaker")

	cbStats, ok := stats["circuit_breaker"].(map[string]interface{})
	require.True(t, ok)

	// Verify circuit breaker stats fields
	assert.Contains(t, cbStats, "state")
	assert.Contains(t, cbStats, "consecutive_failures")
	assert.Contains(t, cbStats, "total_requests")
	assert.Contains(t, cbStats, "total_failures")
	assert.Contains(t, cbStats, "success_rate")
}

func TestCircuitBreakerBackend_GetStats_NilBackendStats(t *testing.T) {
	// Create a mock backend that returns nil stats
	mockBE := &mockBackendNilStats{}
	cb := NewCircuitBreakerBackend(mockBE, nil)

	stats := cb.GetStats()

	require.NotNil(t, stats)
	assert.Contains(t, stats, "circuit_breaker")
}

// mockBackendNilStats returns nil from GetStats
type mockBackendNilStats struct {
	mockBackend
}

func (m *mockBackendNilStats) GetStats() map[string]interface{} {
	return nil
}

// Ping Tests

func TestCircuitBreakerBackend_Ping_Success(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	ctx := context.Background()
	err := cb.Ping(ctx)

	assert.NoError(t, err)
}

func TestCircuitBreakerBackend_Ping_CircuitOpen(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failPing = true

	config := &CircuitBreakerConfig{
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures
	for i := 0; i < 5; i++ {
		cb.Ping(ctx)
	}

	// Circuit should be open
	err := cb.Ping(ctx)
	assert.Error(t, err)
	assert.Equal(t, backends.ErrCircuitOpen, err)
}

// Close Tests

func TestCircuitBreakerBackend_Close(t *testing.T) {
	mockBE := newMockBackend()
	cb := NewCircuitBreakerBackend(mockBE, nil)

	err := cb.Close()
	assert.NoError(t, err)
}

// Circuit Recovery Test

func TestCircuitBreakerBackend_CircuitRecovery(t *testing.T) {
	mockBE := newMockBackend()
	mockBE.failSet = true

	config := &CircuitBreakerConfig{
		MaxFailures:         2,
		Timeout:             200 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreakerBackend(mockBE, config)

	ctx := context.Background()

	// Trigger failures to open circuit
	for i := 0; i < 5; i++ {
		cb.Set(ctx, "key", []byte("value"), 1*time.Minute)
	}

	// Verify circuit is open
	err := cb.Set(ctx, "key2", []byte("value2"), 1*time.Minute)
	assert.Equal(t, backends.ErrCircuitOpen, err)

	// Wait for timeout
	time.Sleep(250 * time.Millisecond)

	// Fix the backend
	mockBE.mu.Lock()
	mockBE.failSet = false
	mockBE.mu.Unlock()

	// Circuit should be in half-open state, allow a test request
	err = cb.Set(ctx, "key3", []byte("value3"), 1*time.Minute)

	// After success threshold is met, circuit should close
	if err == nil {
		// Circuit recovered
		err2 := cb.Set(ctx, "key4", []byte("value4"), 1*time.Minute)
		assert.NoError(t, err2, "Circuit should be closed after recovery")
	}
}
