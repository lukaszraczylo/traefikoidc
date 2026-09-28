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

	// ErrSetNXUnsupported is returned by a CacheBackend wrapper's SetNX when
	// the backend it wraps does not itself implement SetNX (FIX-17 round-2).
	// Compared with == only: no errors.As, no fmt.Errorf %w — an interpreted
	// value wrapped with %w loses its type under yaegi v0.16.1, and
	// errors.As with an interpreted target type panics there.
	ErrSetNXUnsupported = errors.New("cache backend does not support atomic SetNX")

	// ErrSetNXAmbiguous is returned by RedisBackend.SetNX when the SET NX
	// command was already written to the connection but its reply could not
	// be read (timeout, EOF, connection reset): Redis may or may not have
	// applied it. Unlike Set's idempotent SETEX/PSETEX, retrying SET NX
	// blindly here would see the caller's own possible write and misreport
	// a first-ever claim as already-claimed, so SetNX surfaces the
	// ambiguity instead of guessing (FIX-17 round-2). Compared with == only,
	// for the same yaegi reason as ErrSetNXUnsupported.
	ErrSetNXAmbiguous = errors.New("SET NX outcome unknown: reply lost after the command was sent")
)
