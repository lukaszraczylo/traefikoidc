package backends

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Pure-Go Redis client implementation
// Compatible with Yaegi interpreter (no unsafe package)
// Implements RESP protocol for basic Redis operations

var (
	ErrPoolExhausted = errors.New("connection pool exhausted")
)

// RedisBackend implements a Redis-based cache backend using pure Go
type RedisBackend struct {
	config        *Config
	pool          *ConnectionPool
	healthMonitor *HealthMonitor

	// Metrics
	hits   atomic.Int64
	misses atomic.Int64

	// Lifecycle
	closed atomic.Bool
	mu     sync.Mutex
}

// NewRedisBackend creates a new Redis cache backend with pure-Go implementation
func NewRedisBackend(config *Config) (*RedisBackend, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.RedisAddr == "" {
		return nil, fmt.Errorf("redis address is required")
	}

	// Create connection pool with health checks enabled
	poolConfig := &PoolConfig{
		Address:           config.RedisAddr,
		Password:          config.RedisPassword,
		DB:                config.RedisDB,
		MaxConnections:    config.PoolSize,
		ConnectTimeout:    5 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		EnableHealthCheck: true,
		MaxRetries:        3,
		RetryDelay:        100 * time.Millisecond,
	}

	pool, err := NewConnectionPool(poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Create health monitor
	healthConfig := DefaultHealthMonitorConfig()
	healthMonitor := NewHealthMonitor(pool, healthConfig)

	backend := &RedisBackend{
		config:        config,
		pool:          pool,
		healthMonitor: healthMonitor,
	}

	// Test connectivity
	if err := backend.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	// Start health monitoring
	healthMonitor.Start()

	return backend, nil
}

// Set stores a value in Redis with TTL
func (r *RedisBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	prefixedKey := r.prefixKey(key)

	// Execute with retry logic
	return r.executeWithRetry(ctx, func(conn *RedisConn) error {
		var err error

		// Use PSETEX for millisecond precision, SETEX for second precision
		if ttl > 0 {
			ttlMillis := ttl.Milliseconds()
			if ttlMillis < 1000 {
				// Use PSETEX for sub-second TTLs (millisecond precision)
				_, err = conn.Do("PSETEX", prefixedKey, fmt.Sprintf("%d", ttlMillis), string(value))
			} else {
				// Use SETEX for larger TTLs (second precision)
				ttlSeconds := int(ttl.Seconds())
				_, err = conn.Do("SETEX", prefixedKey, fmt.Sprintf("%d", ttlSeconds), string(value))
			}
		} else {
			_, err = conn.Do("SET", prefixedKey, string(value))
		}

		return err
	})
}

// Get retrieves a value from Redis
func (r *RedisBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	if r.closed.Load() {
		return nil, 0, false, ErrBackendClosed
	}

	prefixedKey := r.prefixKey(key)
	var resultValue []byte
	var resultTTL time.Duration
	var resultExists bool

	// Execute with retry logic
	err := r.executeWithRetry(ctx, func(conn *RedisConn) error {
		// Get value
		resp, err := conn.Do("GET", prefixedKey)
		if err != nil {
			if errors.Is(err, ErrNilResponse) {
				r.misses.Add(1)
				resultExists = false
				return nil // Not an error, key just doesn't exist
			}
			return err
		}

		value, err := RESPString(resp)
		if err != nil {
			return err
		}

		// Get TTL
		ttlResp, err := conn.Do("TTL", prefixedKey)
		if err != nil {
			// If TTL fails, still return the value
			r.hits.Add(1)
			resultValue = []byte(value)
			resultTTL = 0
			resultExists = true
			return nil
		}

		ttlSeconds, _ := RESPInt(ttlResp)
		var ttl time.Duration
		if ttlSeconds > 0 {
			ttl = time.Duration(ttlSeconds) * time.Second
		}

		r.hits.Add(1)
		resultValue = []byte(value)
		resultTTL = ttl
		resultExists = true
		return nil
	})

	return resultValue, resultTTL, resultExists, err
}

// Delete removes a key from Redis
func (r *RedisBackend) Delete(ctx context.Context, key string) (bool, error) {
	if r.closed.Load() {
		return false, ErrBackendClosed
	}

	conn, err := r.pool.Get(ctx)
	if err != nil {
		return false, err
	}
	defer r.pool.Put(conn)

	prefixedKey := r.prefixKey(key)
	resp, err := conn.Do("DEL", prefixedKey)
	if err != nil {
		return false, err
	}

	count, err := RESPInt(resp)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Exists checks if a key exists in Redis
func (r *RedisBackend) Exists(ctx context.Context, key string) (bool, error) {
	if r.closed.Load() {
		return false, ErrBackendClosed
	}

	conn, err := r.pool.Get(ctx)
	if err != nil {
		return false, err
	}
	defer r.pool.Put(conn)

	prefixedKey := r.prefixKey(key)
	resp, err := conn.Do("EXISTS", prefixedKey)
	if err != nil {
		return false, err
	}

	count, err := RESPInt(resp)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Clear removes all keys with the configured prefix
func (r *RedisBackend) Clear(ctx context.Context) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	conn, err := r.pool.Get(ctx)
	if err != nil {
		return err
	}
	defer r.pool.Put(conn)

	// Use FLUSHDB if no prefix (clear entire DB)
	if r.config.RedisPrefix == "" {
		_, err := conn.Do("FLUSHDB")
		return err
	}

	// With prefix, we need to scan and delete keys
	// For simplicity in this implementation, we'll use KEYS pattern (not recommended for production at scale)
	pattern := r.config.RedisPrefix + "*"
	resp, err := conn.Do("KEYS", pattern)
	if err != nil {
		return err
	}

	// Extract keys from array response
	keys, ok := resp.([]interface{})
	if !ok || len(keys) == 0 {
		return nil
	}

	// Delete each key
	for _, keyInterface := range keys {
		key, err := RESPString(keyInterface)
		if err != nil {
			continue
		}
		conn.Do("DEL", key) // Best effort, ignore errors
	}

	return nil
}

// GetStats returns backend statistics
func (r *RedisBackend) GetStats() map[string]interface{} {
	hits := r.hits.Load()
	misses := r.misses.Load()
	total := hits + misses

	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	stats := map[string]interface{}{
		"backend":  "redis-pure-go",
		"address":  r.config.RedisAddr,
		"hits":     hits,
		"misses":   misses,
		"hit_rate": hitRate,
		"pool":     r.pool.Stats(),
	}

	// Add health monitor stats if available
	if r.healthMonitor != nil {
		stats["health"] = r.healthMonitor.GetStats()
	}

	return stats
}

// Ping checks Redis connectivity
func (r *RedisBackend) Ping(ctx context.Context) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	conn, err := r.pool.Get(ctx)
	if err != nil {
		return err
	}
	defer r.pool.Put(conn)

	_, err = conn.Do("PING")
	return err
}

// Close closes the Redis backend and all connections
func (r *RedisBackend) Close() error {
	if r.closed.Swap(true) {
		return nil // Already closed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Stop health monitor
	if r.healthMonitor != nil {
		r.healthMonitor.Stop()
	}

	// Close connection pool
	if r.pool != nil {
		return r.pool.Close()
	}

	return nil
}

// prefixKey adds the configured prefix to a key
func (r *RedisBackend) prefixKey(key string) string {
	if r.config.RedisPrefix == "" {
		return key
	}
	return r.config.RedisPrefix + key
}

// executeWithRetry executes a Redis operation with exponential backoff retry logic
func (r *RedisBackend) executeWithRetry(ctx context.Context, operation func(*RedisConn) error) error {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, err := r.pool.Get(ctx)
		if err != nil {
			// If we can't get a connection and this is the last attempt, fail
			if attempt == maxRetries-1 {
				return fmt.Errorf("failed to get connection after %d attempts: %w", maxRetries, err)
			}

			// Wait with exponential backoff before retrying
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				continue
			}
		}

		// Execute the operation
		err = operation(conn)
		r.pool.Put(conn)

		// If successful, return
		if err == nil {
			return nil
		}

		// If error is not retryable or last attempt, fail
		if attempt == maxRetries-1 || !isRetryableError(err) {
			return err
		}

		// Wait with exponential backoff before retrying
		delay := baseDelay * time.Duration(1<<uint(attempt))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	return fmt.Errorf("operation failed after %d attempts", maxRetries)
}

// isRetryableError determines if an error is worth retrying
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Retry on connection errors, timeouts, etc.
	// Don't retry on application-level errors like wrong type
	errMsg := err.Error()
	retryablePatterns := []string{
		"connection",
		"timeout",
		"EOF",
		"broken pipe",
		"reset by peer",
	}

	for _, pattern := range retryablePatterns {
		if contains(errMsg, pattern) {
			return true
		}
	}

	return false
}

// SetMany stores multiple values in Redis (batch operation)
func (r *RedisBackend) SetMany(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	// For simplicity, execute sequentially (can be optimized with pipelining later)
	for key, value := range items {
		if err := r.Set(ctx, key, value, ttl); err != nil {
			return err
		}
	}

	return nil
}

// GetMany retrieves multiple values from Redis
func (r *RedisBackend) GetMany(ctx context.Context, keys []string) (map[string][]byte, error) {
	if r.closed.Load() {
		return nil, ErrBackendClosed
	}

	result := make(map[string][]byte)

	// For simplicity, execute sequentially
	for _, key := range keys {
		value, _, exists, err := r.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if exists {
			result[key] = value
		}
	}

	return result, nil
}
