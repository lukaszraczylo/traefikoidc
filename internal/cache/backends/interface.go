// Package backend provides cache backend implementations for the Traefik OIDC plugin.
package backends

import (
	"context"
	"time"
)

// CacheBackend defines the interface for all cache backend implementations
// Implementations include: MemoryBackend, RedisBackend, and HybridBackend
type CacheBackend interface {
	// Set stores a value in the cache with the specified TTL
	// Returns an error if the operation fails
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Get retrieves a value from the cache
	// Returns: value, remaining TTL, exists flag, and error
	// If the key doesn't exist, exists will be false
	Get(ctx context.Context, key string) (value []byte, ttl time.Duration, exists bool, err error)

	// Delete removes a key from the cache
	// Returns true if the key was deleted, false if it didn't exist
	Delete(ctx context.Context, key string) (bool, error)

	// Exists checks if a key exists in the cache
	Exists(ctx context.Context, key string) (bool, error)

	// Clear removes all keys from the cache
	Clear(ctx context.Context) error

	// GetStats returns cache statistics
	// Stats include: hits, misses, size, memory usage, etc.
	GetStats() map[string]interface{}

	// Close shuts down the cache backend and releases resources
	Close() error

	// Ping checks if the backend is healthy and responsive
	Ping(ctx context.Context) error
}

// BackendStats represents statistics for a cache backend
type BackendStats struct {
	// Type is the backend type
	Type BackendType

	// Hits is the number of cache hits
	Hits int64

	// Misses is the number of cache misses
	Misses int64

	// Sets is the number of set operations
	Sets int64

	// Deletes is the number of delete operations
	Deletes int64

	// Errors is the number of errors
	Errors int64

	// Evictions is the number of evicted items
	Evictions int64

	// CurrentSize is the current number of items in cache
	CurrentSize int64

	// MaxSize is the maximum number of items (0 means unlimited)
	MaxSize int64

	// MemoryUsage is the approximate memory usage in bytes
	MemoryUsage int64

	// AverageGetLatency is the average latency for get operations
	AverageGetLatency time.Duration

	// AverageSetLatency is the average latency for set operations
	AverageSetLatency time.Duration

	// LastError is the last error encountered
	LastError string

	// LastErrorTime is when the last error occurred
	LastErrorTime time.Time

	// Uptime is how long the backend has been running
	Uptime time.Duration

	// StartTime is when the backend was started
	StartTime time.Time
}

// BackendCapabilities describes the capabilities of a cache backend
type BackendCapabilities struct {
	// Distributed indicates if the backend is distributed across multiple instances
	Distributed bool

	// Persistent indicates if the backend persists data across restarts
	Persistent bool

	// Eviction indicates if the backend supports automatic eviction
	Eviction bool

	// TTL indicates if the backend supports TTL (time-to-live)
	TTL bool

	// MaxKeySize is the maximum size of a key in bytes (0 = unlimited)
	MaxKeySize int64

	// MaxValueSize is the maximum size of a value in bytes (0 = unlimited)
	MaxValueSize int64

	// MaxKeys is the maximum number of keys (0 = unlimited)
	MaxKeys int64

	// SupportsExpire indicates if the backend supports expiration
	SupportsExpire bool

	// SupportsMultiGet indicates if the backend supports batch get operations
	SupportsMultiGet bool

	// SupportsTransaction indicates if the backend supports transactions
	SupportsTransaction bool

	// SupportsCompression indicates if the backend supports compression
	SupportsCompression bool

	// RequiresSerialize indicates if values must be serialized
	RequiresSerialize bool

	// AtomicOperations indicates if the backend supports atomic operations
	AtomicOperations bool
}
