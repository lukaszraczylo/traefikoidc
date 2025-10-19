package backends

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend implements a Redis-based cache backend
type RedisBackend struct {
	client *redis.Client
	config *Config

	// Metrics
	hits   int64
	misses int64

	// Lifecycle
	closed atomic.Bool
}

// NewRedisBackend creates a new Redis cache backend
func NewRedisBackend(config *Config) (*RedisBackend, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.RedisAddr == "" {
		return nil, fmt.Errorf("redis address is required")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
		PoolSize: config.PoolSize,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	backend := &RedisBackend{
		client: client,
		config: config,
	}

	return backend, nil
}

// Set stores a value with TTL
func (r *RedisBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	prefixedKey := r.prefixKey(key)
	return r.client.Set(ctx, prefixedKey, value, ttl).Err()
}

// Get retrieves a value
func (r *RedisBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	if r.closed.Load() {
		return nil, 0, false, ErrBackendClosed
	}

	prefixedKey := r.prefixKey(key)

	// Get value
	value, err := r.client.Get(ctx, prefixedKey).Bytes()
	if err == redis.Nil {
		atomic.AddInt64(&r.misses, 1)
		return nil, 0, false, nil
	}
	if err != nil {
		atomic.AddInt64(&r.misses, 1)
		return nil, 0, false, fmt.Errorf("failed to get key: %w", err)
	}

	// Get TTL
	ttl, err := r.client.TTL(ctx, prefixedKey).Result()
	if err != nil {
		// Value exists but couldn't get TTL
		atomic.AddInt64(&r.hits, 1)
		return value, 0, true, nil
	}

	atomic.AddInt64(&r.hits, 1)
	return value, ttl, true, nil
}

// Delete removes a key
func (r *RedisBackend) Delete(ctx context.Context, key string) (bool, error) {
	if r.closed.Load() {
		return false, ErrBackendClosed
	}

	prefixedKey := r.prefixKey(key)
	result, err := r.client.Del(ctx, prefixedKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to delete key: %w", err)
	}

	return result > 0, nil
}

// Exists checks if a key exists
func (r *RedisBackend) Exists(ctx context.Context, key string) (bool, error) {
	if r.closed.Load() {
		return false, ErrBackendClosed
	}

	prefixedKey := r.prefixKey(key)
	result, err := r.client.Exists(ctx, prefixedKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence: %w", err)
	}

	return result > 0, nil
}

// Clear removes all keys with the prefix
func (r *RedisBackend) Clear(ctx context.Context) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	// Use SCAN to find all keys with prefix
	pattern := r.config.RedisPrefix + "*"
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()

	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	// Delete in batches to avoid blocking Redis
	batchSize := 100
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}

		if err := r.client.Del(ctx, keys[i:end]...).Err(); err != nil {
			return fmt.Errorf("failed to delete keys: %w", err)
		}
	}

	return nil
}

// GetStats returns statistics
func (r *RedisBackend) GetStats() map[string]interface{} {
	hits := atomic.LoadInt64(&r.hits)
	misses := atomic.LoadInt64(&r.misses)
	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	stats := map[string]interface{}{
		"type":     "redis",
		"hits":     hits,
		"misses":   misses,
		"hit_rate": hitRate,
	}

	// Try to get Redis info (non-critical)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if info, err := r.client.Info(ctx, "memory").Result(); err == nil {
		stats["redis_info"] = info
	}

	return stats
}

// Ping checks Redis health
func (r *RedisBackend) Ping(ctx context.Context) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	return r.client.Ping(ctx).Err()
}

// Close shuts down the backend
func (r *RedisBackend) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	return r.client.Close()
}

// prefixKey adds the configured prefix to a key
func (r *RedisBackend) prefixKey(key string) string {
	if r.config.RedisPrefix == "" {
		return key
	}
	return r.config.RedisPrefix + key
}

// Pipeline operations for batch operations (future enhancement)

// SetMany stores multiple key-value pairs in a pipeline
func (r *RedisBackend) SetMany(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	pipe := r.client.Pipeline()

	for key, value := range items {
		prefixedKey := r.prefixKey(key)
		pipe.Set(ctx, prefixedKey, value, ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

// GetMany retrieves multiple values in a pipeline
func (r *RedisBackend) GetMany(ctx context.Context, keys []string) (map[string][]byte, error) {
	if r.closed.Load() {
		return nil, ErrBackendClosed
	}

	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	pipe := r.client.Pipeline()
	cmds := make(map[string]*redis.StringCmd, len(keys))

	for _, key := range keys {
		prefixedKey := r.prefixKey(key)
		cmds[key] = pipe.Get(ctx, prefixedKey)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, err
	}

	results := make(map[string][]byte)
	for key, cmd := range cmds {
		value, err := cmd.Bytes()
		if err == nil {
			results[key] = value
			atomic.AddInt64(&r.hits, 1)
		} else if err != redis.Nil {
			atomic.AddInt64(&r.misses, 1)
		}
	}

	return results, nil
}
