package backends

import (
	"context"
	"time"
)

// MemoryBackend wraps MemoryCacheBackend to implement the CacheBackend interface
type MemoryBackend struct {
	*MemoryCacheBackend
}

// NewMemoryBackend creates a new memory backend from a config
func NewMemoryBackend(config *Config) (*MemoryBackend, error) {
	maxSize := int64(config.MaxSize)
	if maxSize <= 0 {
		maxSize = 1000
	}

	cacheBackend := NewMemoryCacheBackend(maxSize, config.MaxMemoryBytes, config.CleanupInterval)
	return &MemoryBackend{
		MemoryCacheBackend: cacheBackend,
	}, nil
}

// Set stores a value in the cache with the specified TTL
func (m *MemoryBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	err := m.MemoryCacheBackend.Set(ctx, key, value, ttl)
	if err == ErrBackendUnavailable {
		return ErrBackendClosed
	}
	return err
}

// Get retrieves a value from the cache
func (m *MemoryBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	val, err := m.MemoryCacheBackend.Get(ctx, key)
	if err != nil {
		if err == ErrCacheMiss {
			return nil, 0, false, nil
		}
		if err == ErrBackendUnavailable {
			return nil, 0, false, ErrBackendClosed
		}
		return nil, 0, false, err
	}

	// Get the item directly to check TTL
	m.MemoryCacheBackend.mu.RLock()
	item, exists := m.MemoryCacheBackend.items[key]
	m.MemoryCacheBackend.mu.RUnlock()

	if !exists {
		return nil, 0, false, nil
	}

	var ttl time.Duration
	if !item.expiresAt.IsZero() {
		ttl = time.Until(item.expiresAt)
		if ttl < 0 {
			ttl = 0
		}
	}

	// Convert interface{} to []byte
	var valueBytes []byte
	if val != nil {
		if bytes, ok := val.([]byte); ok {
			valueBytes = bytes
		} else {
			// If it's not already []byte, we might need to handle other types
			// For now, we'll just return an error
			return nil, 0, false, ErrInvalidValue
		}
	}

	return valueBytes, ttl, true, nil
}

// Delete removes a key from the cache
func (m *MemoryBackend) Delete(ctx context.Context, key string) (bool, error) {
	// Check if key exists first
	exists, err := m.MemoryCacheBackend.Exists(ctx, key)
	if err != nil {
		return false, err
	}

	if !exists {
		return false, nil
	}

	err = m.MemoryCacheBackend.Delete(ctx, key)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Exists checks if a key exists in the cache
func (m *MemoryBackend) Exists(ctx context.Context, key string) (bool, error) {
	return m.MemoryCacheBackend.Exists(ctx, key)
}

// Clear removes all keys from the cache
func (m *MemoryBackend) Clear(ctx context.Context) error {
	return m.MemoryCacheBackend.Clear(ctx)
}

// GetStats returns cache statistics
func (m *MemoryBackend) GetStats() map[string]interface{} {
	stats, err := m.MemoryCacheBackend.GetStats(context.Background())
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	// Convert BackendStats to map
	hitRate := float64(0)
	total := stats.Hits + stats.Misses
	if total > 0 {
		hitRate = float64(stats.Hits) / float64(total)
	}

	return map[string]interface{}{
		"type":       stats.Type,
		"hits":       stats.Hits,
		"misses":     stats.Misses,
		"sets":       stats.Sets,
		"deletes":    stats.Deletes,
		"errors":     stats.Errors,
		"evictions":  stats.Evictions,
		"size":       stats.CurrentSize,
		"max_size":   stats.MaxSize,
		"memory":     stats.MemoryUsage,
		"hit_rate":   hitRate,
		"uptime":     stats.Uptime,
		"start_time": stats.StartTime,
	}
}

// Close shuts down the cache backend and releases resources
func (m *MemoryBackend) Close() error {
	return m.MemoryCacheBackend.Close()
}

// Ping checks if the backend is healthy and responsive
func (m *MemoryBackend) Ping(ctx context.Context) error {
	return m.MemoryCacheBackend.Ping(ctx)
}

// Ensure MemoryBackend implements CacheBackend
var _ CacheBackend = (*MemoryBackend)(nil)
