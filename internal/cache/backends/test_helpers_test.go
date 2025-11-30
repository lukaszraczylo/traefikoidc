package backends

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestLogger implements a simple logger for tests
type TestLogger struct {
	t *testing.T
}

func NewTestLogger(t *testing.T) *TestLogger {
	return &TestLogger{t: t}
}

func (l *TestLogger) Debug(format string, args ...interface{}) {
	l.t.Logf("[DEBUG] "+format, args...)
}

func (l *TestLogger) Info(format string, args ...interface{}) {
	l.t.Logf("[INFO] "+format, args...)
}

func (l *TestLogger) Error(format string, args ...interface{}) {
	l.t.Logf("[ERROR] "+format, args...)
}

func (l *TestLogger) Debugf(format string, args ...interface{}) {
	l.Debug(format, args...)
}

func (l *TestLogger) Infof(format string, args ...interface{}) {
	l.Info(format, args...)
}

func (l *TestLogger) Errorf(format string, args ...interface{}) {
	l.Error(format, args...)
}

func (l *TestLogger) Warnf(format string, args ...interface{}) {
	l.t.Logf("[WARN] "+format, args...)
}

// MiniredisServer manages a miniredis instance for testing
type MiniredisServer struct {
	server *miniredis.Miniredis
	client *redis.Client
}

// NewMiniredisServer creates a new miniredis server for testing
func NewMiniredisServer(t *testing.T) *MiniredisServer {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// Verify connection
	ctx := context.Background()
	err = client.Ping(ctx).Err()
	require.NoError(t, err, "failed to ping miniredis")

	t.Cleanup(func() {
		client.Close()
		mr.Close()
	})

	return &MiniredisServer{
		server: mr,
		client: client,
	}
}

// GetAddr returns the address of the miniredis server
func (m *MiniredisServer) GetAddr() string {
	return m.server.Addr()
}

// GetClient returns the Redis client
func (m *MiniredisServer) GetClient() *redis.Client {
	return m.client
}

// FastForward advances the miniredis server's time
func (m *MiniredisServer) FastForward(d time.Duration) {
	m.server.FastForward(d)
}

// FlushAll removes all keys from the database
func (m *MiniredisServer) FlushAll() {
	m.server.FlushAll()
}

// SetError simulates a Redis error
func (m *MiniredisServer) SetError(err string) {
	m.server.SetError(err)
}

// ClearError clears any simulated errors
func (m *MiniredisServer) ClearError() {
	m.server.SetError("")
}

// CheckKeys verifies that specific keys exist in Redis
func (m *MiniredisServer) CheckKeys() []string {
	return m.server.Keys()
}

// Close closes the miniredis server
func (m *MiniredisServer) Close() {
	m.server.Close()
}

// Restart restarts the miniredis server
func (m *MiniredisServer) Restart() {
	m.server.Restart()
}

// TestConfig provides default test configuration
type TestConfig struct {
	MaxSize         int
	DefaultTTL      time.Duration
	CleanupInterval time.Duration
	EnableMetrics   bool
}

// DefaultTestConfig returns a standard test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		MaxSize:         100,
		DefaultTTL:      5 * time.Minute,
		CleanupInterval: 1 * time.Second,
		EnableMetrics:   true,
	}
}

// GenerateTestData creates test cache data
func GenerateTestData(count int) map[string][]byte {
	data := make(map[string][]byte, count)
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("test-key-%d", i)
		value := []byte(fmt.Sprintf("test-value-%d", i))
		data[key] = value
	}
	return data
}

// GenerateLargeValue creates a large test value
func GenerateLargeValue(sizeBytes int) []byte {
	return make([]byte, sizeBytes)
}

// AssertCacheStats is a helper to verify cache statistics
func AssertCacheStats(t *testing.T, stats map[string]interface{}, expectedHits, expectedMisses int64) {
	t.Helper()

	hits, ok := stats["hits"].(int64)
	require.True(t, ok, "hits should be int64")
	require.Equal(t, expectedHits, hits, "unexpected hit count")

	misses, ok := stats["misses"].(int64)
	require.True(t, ok, "misses should be int64")
	require.Equal(t, expectedMisses, misses, "unexpected miss count")
}

// WaitForCondition waits for a condition to be true or times out
func WaitForCondition(t *testing.T, timeout time.Duration, checkInterval time.Duration, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(checkInterval)
	}
	t.Fatal("timeout waiting for condition")
}

// AssertEventuallyExpires verifies that a key eventually expires
func AssertEventuallyExpires(t *testing.T, backend CacheBackend, ctx context.Context, key string, maxWait time.Duration) {
	t.Helper()

	WaitForCondition(t, maxWait, 100*time.Millisecond, func() bool {
		_, _, exists, err := backend.Get(ctx, key)
		return err == nil && !exists
	})
}
