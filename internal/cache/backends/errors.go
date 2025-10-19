package backends

import "errors"

var (
	// ErrBackendClosed is returned when operating on a closed backend
	ErrBackendClosed = errors.New("cache backend is closed")

	// ErrKeyNotFound is returned when a key doesn't exist
	ErrKeyNotFound = errors.New("key not found")

	// ErrCacheMiss indicates the requested key was not found in the cache
	ErrCacheMiss = errors.New("cache miss")

	// ErrBackendUnavailable indicates the cache backend is not available
	ErrBackendUnavailable = errors.New("cache backend unavailable")

	// ErrInvalidValue indicates the cached value is invalid or corrupted
	ErrInvalidValue = errors.New("invalid cached value")

	// ErrInvalidTTL is returned when TTL is invalid
	ErrInvalidTTL = errors.New("invalid TTL")

	// ErrConnectionFailed is returned when connection fails
	ErrConnectionFailed = errors.New("connection failed")

	// ErrCircuitOpen is returned when circuit breaker is open
	ErrCircuitOpen = errors.New("circuit breaker is open")

	// ErrTimeout is returned when operation times out
	ErrTimeout = errors.New("operation timeout")

	// ErrSerializationFailed is returned when serialization fails
	ErrSerializationFailed = errors.New("serialization failed")

	// ErrDeserializationFailed is returned when deserialization fails
	ErrDeserializationFailed = errors.New("deserialization failed")
)
