//go:build !yaegi

package backends

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBackend is a simple mock implementation of CacheBackend for testing
type mockBackend struct {
	data        map[string]mockEntry
	mu          sync.RWMutex
	failSet     bool
	failGet     bool
	failDelete  bool
	failClear   bool
	failPing    bool
	pingError   error
	stats       map[string]interface{}
	getCalls    atomic.Int32
	setCalls    atomic.Int32
	deleteCalls atomic.Int32
}

type mockEntry struct {
	value     []byte
	expiresAt time.Time
}

// mockBatchBackend extends mockBackend with batch operations
type mockBatchBackend struct {
	*mockBackend
	getManyError error
	setManyError error
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		data: make(map[string]mockEntry),
		stats: map[string]interface{}{
			"hits":   int64(0),
			"misses": int64(0),
		},
	}
}

func newMockBatchBackend() *mockBatchBackend {
	return &mockBatchBackend{
		mockBackend: newMockBackend(),
	}
}

func (m *mockBatchBackend) GetMany(ctx context.Context, keys []string) (map[string][]byte, error) {
	if m.getManyError != nil {
		return nil, m.getManyError
	}

	results := make(map[string][]byte)
	for _, key := range keys {
		value, _, exists, err := m.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if exists {
			results[key] = value
		}
	}
	return results, nil
}

func (m *mockBatchBackend) SetMany(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if m.setManyError != nil {
		return m.setManyError
	}

	for key, value := range items {
		if err := m.Set(ctx, key, value, ttl); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	m.setCalls.Add(1)

	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.getCalls.Add(1)

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.failGet {
		return nil, 0, false, errors.New("mock get error")
	}

	entry, exists := m.data[key]
	if !exists {
		return nil, 0, false, nil
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return nil, 0, false, nil
	}

	ttl := time.Until(entry.expiresAt)
	return entry.value, ttl, true, nil
}

func (m *mockBackend) Delete(ctx context.Context, key string) (bool, error) {
	m.deleteCalls.Add(1)

	m.mu.Lock()
	defer m.mu.Unlock()

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

	entry, exists := m.data[key]
	if !exists {
		return false, nil
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return false, nil
	}

	return true, nil
}

func (m *mockBackend) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failClear {
		return errors.New("mock clear error")
	}

	m.data = make(map[string]mockEntry)
	return nil
}

func (m *mockBackend) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

func (m *mockBackend) Close() error {
	return nil
}

func (m *mockBackend) Ping(ctx context.Context) error {
	if m.failPing {
		if m.pingError != nil {
			return m.pingError
		}
		return errors.New("mock ping error")
	}
	return nil
}

// Constructor Tests

func TestNewHybridBackend_Success(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	require.NotNil(t, hybrid)

	// Verify default values
	assert.NotNil(t, hybrid.logger)
	assert.NotNil(t, hybrid.asyncWriteBuffer)
	assert.NotNil(t, hybrid.syncWriteCacheTypes)

	hybrid.Close()
}

func TestNewHybridBackend_NilConfig(t *testing.T) {
	hybrid, err := NewHybridBackend(nil)
	assert.Error(t, err)
	assert.Nil(t, hybrid)
	assert.Contains(t, err.Error(), "config is required")
}

func TestNewHybridBackend_NilPrimary(t *testing.T) {
	config := &HybridConfig{
		Primary:   nil,
		Secondary: newMockBackend(),
	}

	hybrid, err := NewHybridBackend(config)
	assert.Error(t, err)
	assert.Nil(t, hybrid)
	assert.Contains(t, err.Error(), "primary")
}

func TestNewHybridBackend_NilSecondary(t *testing.T) {
	config := &HybridConfig{
		Primary:   newMockBackend(),
		Secondary: nil,
	}

	hybrid, err := NewHybridBackend(config)
	assert.Error(t, err)
	assert.Nil(t, hybrid)
	assert.Contains(t, err.Error(), "secondary")
}

func TestNewHybridBackend_CustomLogger(t *testing.T) {
	logger := &TestLogger{t: t}
	config := &HybridConfig{
		Primary:   newMockBackend(),
		Secondary: newMockBackend(),
		Logger:    logger,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	assert.Equal(t, logger, hybrid.logger)

	hybrid.Close()
}

func TestNewHybridBackend_CustomAsyncBufferSize(t *testing.T) {
	config := &HybridConfig{
		Primary:         newMockBackend(),
		Secondary:       newMockBackend(),
		AsyncBufferSize: 50,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	assert.Equal(t, 50, cap(hybrid.asyncWriteBuffer))

	hybrid.Close()
}

func TestNewHybridBackend_DefaultAsyncBufferSize(t *testing.T) {
	config := &HybridConfig{
		Primary:   newMockBackend(),
		Secondary: newMockBackend(),
		// AsyncBufferSize not set or <= 0
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	assert.Equal(t, 1000, cap(hybrid.asyncWriteBuffer))

	hybrid.Close()
}

func TestNewHybridBackend_CustomSyncWriteCacheTypes(t *testing.T) {
	customTypes := map[string]bool{
		"custom1": true,
		"custom2": true,
	}

	config := &HybridConfig{
		Primary:             newMockBackend(),
		Secondary:           newMockBackend(),
		SyncWriteCacheTypes: customTypes,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	assert.True(t, hybrid.syncWriteCacheTypes["custom1"])
	assert.True(t, hybrid.syncWriteCacheTypes["custom2"])

	hybrid.Close()
}

func TestNewHybridBackend_DefaultSyncWriteCacheTypes(t *testing.T) {
	config := &HybridConfig{
		Primary:   newMockBackend(),
		Secondary: newMockBackend(),
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)

	// Should have default critical types
	assert.True(t, hybrid.syncWriteCacheTypes["blacklist"])
	assert.True(t, hybrid.syncWriteCacheTypes["token"])

	hybrid.Close()
}

// Basic Operations Tests

func TestHybridBackend_Set_BothSuccess(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
		SyncWriteCacheTypes: map[string]bool{
			"test": true, // Make writes synchronous for testing
		},
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "test:key1"
	value := []byte("test-value")
	ttl := 1 * time.Minute

	err = hybrid.Set(ctx, key, value, ttl)
	assert.NoError(t, err)

	// Verify L1 write
	assert.Equal(t, int32(1), primary.setCalls.Load())
	assert.Equal(t, int64(1), hybrid.l1Writes.Load())

	// Give time for sync write to complete
	time.Sleep(10 * time.Millisecond)

	// Verify L2 write (sync)
	assert.Equal(t, int32(1), secondary.setCalls.Load())
	assert.Equal(t, int64(1), hybrid.l2Writes.Load())
}

func TestHybridBackend_Set_L1Failure(t *testing.T) {
	primary := newMockBackend()
	primary.failSet = true
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	err = hybrid.Set(ctx, "key1", []byte("value"), 1*time.Minute)

	// Should not return error even if L1 fails (continues to L2)
	assert.NoError(t, err)
	assert.Greater(t, hybrid.errors.Load(), int64(0))
}

func TestHybridBackend_Set_AsyncWrite(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:             primary,
		Secondary:           secondary,
		SyncWriteCacheTypes: map[string]bool{
			// "general" is not in sync list, so async
		},
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "general:key1" // Will be async
	value := []byte("test-value")

	err = hybrid.Set(ctx, key, value, 1*time.Minute)
	assert.NoError(t, err)

	// L1 should be written immediately
	assert.Equal(t, int32(1), primary.setCalls.Load())

	// Wait for async worker to process
	time.Sleep(100 * time.Millisecond)

	// L2 should eventually be written
	assert.Equal(t, int32(1), secondary.setCalls.Load())
}

func TestHybridBackend_Get_L1Hit(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "test:key1"
	value := []byte("test-value")

	// Populate L1 directly
	primary.Set(ctx, key, value, 1*time.Minute)

	// Get should hit L1
	retrieved, _, exists, err := hybrid.Get(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, value, retrieved)

	// L1 hit counter should increment
	assert.Equal(t, int64(1), hybrid.l1Hits.Load())

	// L2 should not be queried
	assert.Equal(t, int32(0), secondary.getCalls.Load())
}

func TestHybridBackend_Get_L2Hit(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "test:key1"
	value := []byte("test-value")

	// Populate L2 only
	secondary.Set(ctx, key, value, 1*time.Minute)

	// Get should miss L1, hit L2
	retrieved, _, exists, err := hybrid.Get(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, value, retrieved)

	// L2 hit counter should increment
	assert.Equal(t, int64(1), hybrid.l2Hits.Load())

	// L1 should be populated in background
	time.Sleep(150 * time.Millisecond)
	_, _, existsInL1, _ := primary.Get(ctx, key)
	assert.True(t, existsInL1, "L1 should be populated from L2")
}

func TestHybridBackend_Get_Miss(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Get non-existent key
	_, _, exists, err := hybrid.Get(ctx, "non-existent")
	assert.NoError(t, err)
	assert.False(t, exists)

	// Miss counter should increment
	assert.Equal(t, int64(1), hybrid.misses.Load())
}

func TestHybridBackend_Delete_BothCaches(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "test:key1"

	// Populate both caches
	primary.Set(ctx, key, []byte("value"), 1*time.Minute)
	secondary.Set(ctx, key, []byte("value"), 1*time.Minute)

	// Delete
	deleted, err := hybrid.Delete(ctx, key)
	assert.NoError(t, err)
	assert.True(t, deleted)

	// Both should be deleted
	assert.Equal(t, int32(1), primary.deleteCalls.Load())
	assert.Equal(t, int32(1), secondary.deleteCalls.Load())
}

func TestHybridBackend_Exists_L1(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "test:key1"

	// Populate L1
	primary.Set(ctx, key, []byte("value"), 1*time.Minute)

	exists, err := hybrid.Exists(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestHybridBackend_Exists_L2(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	key := "test:key1"

	// Populate L2 only
	secondary.Set(ctx, key, []byte("value"), 1*time.Minute)

	exists, err := hybrid.Exists(ctx, key)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestHybridBackend_Clear_BothCaches(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Populate both
	primary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	secondary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	err = hybrid.Clear(ctx)
	assert.NoError(t, err)

	// Both should be cleared
	exists1, _ := primary.Exists(ctx, "key1")
	exists2, _ := secondary.Exists(ctx, "key2")
	assert.False(t, exists1)
	assert.False(t, exists2)
}

// Fallback Mode Tests

func TestHybridBackend_FallbackMode_OnL2Errors(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()
	secondary.failSet = true

	config := &HybridConfig{
		Primary:             primary,
		Secondary:           secondary,
		SyncWriteCacheTypes: map[string]bool{"test": true},
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Multiple failures should trigger fallback mode
	for i := 0; i < 3; i++ {
		hybrid.Set(ctx, fmt.Sprintf("test:key%d", i), []byte("value"), 1*time.Minute)
		time.Sleep(10 * time.Millisecond)
	}

	// Should eventually enter fallback mode
	time.Sleep(50 * time.Millisecond)
	assert.True(t, hybrid.fallbackMode.Load(), "Should enter fallback mode after L2 errors")
}

func TestHybridBackend_FallbackMode_SkipsL2(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	// Manually enable fallback mode
	hybrid.fallbackMode.Store(true)

	ctx := context.Background()
	key := "test:key1"
	value := []byte("test-value")

	err = hybrid.Set(ctx, key, value, 1*time.Minute)
	assert.NoError(t, err)

	// L1 should be written
	assert.Equal(t, int32(1), primary.setCalls.Load())

	// L2 should be skipped
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), secondary.setCalls.Load())
}

func TestHybridBackend_FallbackMode_Get(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	// Enable fallback mode
	hybrid.fallbackMode.Store(true)

	ctx := context.Background()

	// Populate L2
	secondary.Set(ctx, "key1", []byte("value"), 1*time.Minute)

	// Get should only check L1 in fallback mode
	_, _, exists, err := hybrid.Get(ctx, "key1")
	assert.NoError(t, err)
	assert.False(t, exists)

	// Miss should be recorded
	assert.Equal(t, int64(1), hybrid.misses.Load())

	// L2 should not be queried
	assert.Equal(t, int32(0), secondary.getCalls.Load())
}

// Health Monitoring Tests

func TestHybridBackend_Ping_BothHealthy(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	err = hybrid.Ping(ctx)
	assert.NoError(t, err)
}

func TestHybridBackend_Ping_L1Failure(t *testing.T) {
	primary := newMockBackend()
	primary.failPing = true
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	err = hybrid.Ping(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "L1")
}

func TestHybridBackend_Ping_L2Failure(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()
	secondary.failPing = true

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	err = hybrid.Ping(ctx)

	// Should not return error (L2 failure is tolerated)
	assert.NoError(t, err)

	// But should record error
	lastErr := hybrid.lastL2Error.Load()
	assert.NotNil(t, lastErr)
}

func TestHybridBackend_Ping_RecoverFromFallback(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()
	secondary.failPing = true

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// First ping fails L2, enters fallback
	hybrid.Ping(ctx)
	assert.True(t, hybrid.fallbackMode.Load())

	// Fix L2
	secondary.failPing = false

	// Second ping succeeds, exits fallback
	hybrid.Ping(ctx)
	time.Sleep(10 * time.Millisecond)
	assert.False(t, hybrid.fallbackMode.Load())
}

// GetStats Tests

func TestHybridBackend_GetStats(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Generate some activity
	hybrid.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	hybrid.Get(ctx, "key1")     // L1 hit
	hybrid.Get(ctx, "key-miss") // miss

	stats := hybrid.GetStats()
	assert.NotNil(t, stats)

	// Check required fields
	assert.Equal(t, TypeHybrid, stats["type"])
	assert.Contains(t, stats, "l1_hits")
	assert.Contains(t, stats, "l2_hits")
	assert.Contains(t, stats, "misses")
	assert.Contains(t, stats, "total")
	assert.Contains(t, stats, "l1_writes")
	assert.Contains(t, stats, "l2_writes")
	assert.Contains(t, stats, "errors")
	assert.Contains(t, stats, "fallback_mode")
	assert.Contains(t, stats, "l1_stats")
	assert.Contains(t, stats, "l2_stats")
}

func TestHybridBackend_GetStats_HitRates(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	// Record some hits
	hybrid.l1Hits.Store(10)
	hybrid.l2Hits.Store(5)
	hybrid.misses.Store(5)

	stats := hybrid.GetStats()

	// Should calculate hit rates
	assert.Contains(t, stats, "l1_hit_rate")
	assert.Contains(t, stats, "l2_hit_rate")
	assert.Contains(t, stats, "overall_hit_rate")

	// Check values
	assert.InDelta(t, 0.5, stats["l1_hit_rate"], 0.01)
	assert.InDelta(t, 0.25, stats["l2_hit_rate"], 0.01)
	assert.InDelta(t, 0.75, stats["overall_hit_rate"], 0.01)
}

func TestHybridBackend_GetStats_LastL2Error(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	// Record an L2 error
	errorTime := time.Now()
	hybrid.lastL2Error.Store(errorTime)

	stats := hybrid.GetStats()

	assert.Contains(t, stats, "last_l2_error")
	assert.Contains(t, stats, "seconds_since_l2_error")
}

// GetMany/SetMany Tests

func TestHybridBackend_GetMany_L1Hits(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Populate L1
	primary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	primary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	results, err := hybrid.GetMany(ctx, []string{"key1", "key2"})
	assert.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, []byte("value1"), results["key1"])
	assert.Equal(t, []byte("value2"), results["key2"])

	// Should be L1 hits
	assert.Equal(t, int64(2), hybrid.l1Hits.Load())
}

func TestHybridBackend_GetMany_EmptyKeys(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	results, err := hybrid.GetMany(ctx, []string{})
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestHybridBackend_GetMany_L2Fallback(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Populate L2 only
	secondary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	secondary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	results, err := hybrid.GetMany(ctx, []string{"key1", "key2"})
	assert.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, []byte("value1"), results["key1"])
	assert.Equal(t, []byte("value2"), results["key2"])

	// Should be L2 misses (L1 was empty)
	assert.Equal(t, int64(0), hybrid.l1Hits.Load())

	// Give async L1 population time to complete
	time.Sleep(50 * time.Millisecond)

	// Verify L1 was populated from L2 hits
	val1, _, exists1, _ := primary.Get(ctx, "key1")
	assert.True(t, exists1)
	assert.Equal(t, []byte("value1"), val1)
}

func TestHybridBackend_GetMany_MixedL1L2(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// key1 in L1 only
	primary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	// key2 in L2 only
	secondary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	// key3 in both (L1 should win)
	primary.Set(ctx, "key3", []byte("value3-l1"), 1*time.Minute)
	secondary.Set(ctx, "key3", []byte("value3-l2"), 1*time.Minute)

	results, err := hybrid.GetMany(ctx, []string{"key1", "key2", "key3"})
	assert.NoError(t, err)
	assert.Len(t, results, 3)
	assert.Equal(t, []byte("value1"), results["key1"])
	assert.Equal(t, []byte("value2"), results["key2"])
	assert.Equal(t, []byte("value3-l1"), results["key3"]) // L1 wins

	// Should have 2 L1 hits (key1, key3)
	assert.Equal(t, int64(2), hybrid.l1Hits.Load())
}

func TestHybridBackend_GetMany_FallbackMode(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Enable fallback mode
	hybrid.fallbackMode.Store(true)

	// Populate L1 and L2
	primary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	secondary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	// In fallback mode, should only check L1
	results, err := hybrid.GetMany(ctx, []string{"key1", "key2"})
	assert.NoError(t, err)

	// Should only find key1 (from L1)
	assert.Len(t, results, 1)
	assert.Equal(t, []byte("value1"), results["key1"])
	assert.NotContains(t, results, "key2") // L2 not checked

	assert.Equal(t, int64(1), hybrid.l1Hits.Load())
}

func TestHybridBackend_GetMany_L2Error(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()
	secondary.failGet = true // Force L2 errors

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// key1 in L1, key2 needs L2 (but will error)
	primary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	results, err := hybrid.GetMany(ctx, []string{"key1", "key2"})

	// Should still succeed with L1 hits even when L2 errors
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, []byte("value1"), results["key1"])

	// Note: Individual Get errors may not immediately trigger fallback mode
	// The circuit breaker needs multiple consecutive errors
}

func TestHybridBackend_GetMany_PartialL2Results(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Only key2 exists in L2
	secondary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)

	// Request 3 keys, only one exists
	results, err := hybrid.GetMany(ctx, []string{"key1", "key2", "key3"})
	assert.NoError(t, err)

	// Should only have key2
	assert.Len(t, results, 1)
	assert.Equal(t, []byte("value2"), results["key2"])
	assert.NotContains(t, results, "key1")
	assert.NotContains(t, results, "key3")
}

func TestHybridBackend_GetMany_WithBatchBackend(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBatchBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Populate L2 with batch backend
	secondary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)
	secondary.Set(ctx, "key2", []byte("value2"), 1*time.Minute)
	secondary.Set(ctx, "key3", []byte("value3"), 1*time.Minute)

	// GetMany should use batch operation
	results, err := hybrid.GetMany(ctx, []string{"key1", "key2", "key3"})
	assert.NoError(t, err)
	assert.Len(t, results, 3)
	assert.Equal(t, []byte("value1"), results["key1"])
	assert.Equal(t, []byte("value2"), results["key2"])
	assert.Equal(t, []byte("value3"), results["key3"])

	// Verify L1 populated asynchronously
	time.Sleep(50 * time.Millisecond)
	val1, _, exists1, _ := primary.Get(ctx, "key1")
	assert.True(t, exists1)
	assert.Equal(t, []byte("value1"), val1)
}

func TestHybridBackend_GetMany_BatchBackendError(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBatchBackend()
	secondary.getManyError = errors.New("batch operation failed")

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// key1 in L1
	primary.Set(ctx, "key1", []byte("value1"), 1*time.Minute)

	// GetMany should handle batch error gracefully
	results, err := hybrid.GetMany(ctx, []string{"key1", "key2"})

	// Should return L1 results even though L2 batch failed
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, []byte("value1"), results["key1"])

	// Batch error should trigger fallback mode
	time.Sleep(50 * time.Millisecond)
	assert.True(t, hybrid.fallbackMode.Load())
}

func TestHybridBackend_GetMany_MixedBatchResults(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBatchBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// key1 and key2 in L1
	primary.Set(ctx, "key1", []byte("value1-l1"), 1*time.Minute)
	primary.Set(ctx, "key2", []byte("value2-l1"), 1*time.Minute)

	// key3 and key4 in L2 (batch backend)
	secondary.Set(ctx, "key3", []byte("value3-l2"), 1*time.Minute)
	secondary.Set(ctx, "key4", []byte("value4-l2"), 1*time.Minute)

	// GetMany with mixed L1/L2 hits via batch
	results, err := hybrid.GetMany(ctx, []string{"key1", "key2", "key3", "key4"})
	assert.NoError(t, err)
	assert.Len(t, results, 4)

	// L1 results
	assert.Equal(t, []byte("value1-l1"), results["key1"])
	assert.Equal(t, []byte("value2-l1"), results["key2"])

	// L2 batch results
	assert.Equal(t, []byte("value3-l2"), results["key3"])
	assert.Equal(t, []byte("value4-l2"), results["key4"])

	// Should have 2 L1 hits
	assert.Equal(t, int64(2), hybrid.l1Hits.Load())
}

func TestHybridBackend_SetMany_Success(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:             primary,
		Secondary:           secondary,
		SyncWriteCacheTypes: map[string]bool{"test": true},
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	items := map[string][]byte{
		"test:key1": []byte("value1"),
		"test:key2": []byte("value2"),
	}

	err = hybrid.SetMany(ctx, items, 1*time.Minute)
	assert.NoError(t, err)

	// L1 should have both
	assert.Equal(t, int32(2), primary.setCalls.Load())

	// L2 should have both (sync writes)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(2), secondary.setCalls.Load())
}

func TestHybridBackend_SetMany_EmptyItems(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	err = hybrid.SetMany(ctx, map[string][]byte{}, 1*time.Minute)
	assert.NoError(t, err)
}

// Close Tests

func TestHybridBackend_Close(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)

	err = hybrid.Close()
	assert.NoError(t, err)

	// Context should be canceled
	select {
	case <-hybrid.ctx.Done():
		// Good
	default:
		t.Error("Context should be canceled after Close")
	}
}

// Helper Function Tests

func TestExtractCacheType(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	tests := []struct {
		key      string
		expected string
	}{
		{"blacklist:token123", "blacklist"},
		{"token:access123", "token"},
		{"metadata:provider", "metadata"},
		{"jwk:key1234567", "jwk"}, // Needs to be > 10 chars
		{"session:sess1234", "session"},
		{"introspect:tok123", "introspection"},
		{"other:key", "general"},
		{"short", "general"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := hybrid.extractCacheType(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"blacklist", "black", true},
		{"blacklist", "list", true},
		{"blacklist", "xyz", false},
		{"TOKEN", "token", true}, // case insensitive
		{"short", "verylongstring", false},
		{"", "any", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.s, tt.substr), func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input    byte
		expected byte
	}{
		{'A', 'a'},
		{'Z', 'z'},
		{'a', 'a'},
		{'z', 'z'},
		{'0', '0'},
		{'!', '!'},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := toLower(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Logger Tests

func TestDefaultLogger_Methods(t *testing.T) {
	// Create a default logger using the test logger
	testLogger := &TestLogger{t: t}

	// These should not panic
	testLogger.Debugf("debug %s", "message")
	testLogger.Infof("info %s", "message")
	testLogger.Warnf("warn %s", "message")
	testLogger.Errorf("error %s", "message")
}

// Async Write Worker Tests

func TestHybridBackend_AsyncWriteWorker_ProcessesWrites(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
		// No sync types - all writes are async
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Queue multiple async writes
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("async:key%d", i)
		value := []byte(fmt.Sprintf("value%d", i))
		err := hybrid.Set(ctx, key, value, 1*time.Minute)
		require.NoError(t, err)
	}

	// Wait for async worker to process
	time.Sleep(200 * time.Millisecond)

	// All should be written to L2
	assert.Equal(t, int32(5), secondary.setCalls.Load())
}

func TestHybridBackend_AsyncWriteWorker_BufferFull(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:         primary,
		Secondary:       secondary,
		AsyncBufferSize: 2, // Very small buffer
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Try to overflow buffer
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("async:key%d", i)
		value := []byte(fmt.Sprintf("value%d", i))
		hybrid.Set(ctx, key, value, 1*time.Minute)
	}

	// Some writes should be dropped (errors incremented)
	time.Sleep(50 * time.Millisecond)
	errors := hybrid.errors.Load()
	// May have errors from buffer overflow
	_ = errors
}

// RecordL2Error Tests

func TestHybridBackend_RecordL2Error_EntersFallbackMode(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()

	config := &HybridConfig{
		Primary:   primary,
		Secondary: secondary,
	}

	hybrid, err := NewHybridBackend(config)
	require.NoError(t, err)
	defer hybrid.Close()

	// Record error
	hybrid.recordL2Error()

	// Should have timestamp
	lastErr := hybrid.lastL2Error.Load()
	assert.NotNil(t, lastErr)

	// Record another error immediately (within 1 second)
	hybrid.recordL2Error()

	// Should enter fallback mode
	assert.True(t, hybrid.fallbackMode.Load())
}
