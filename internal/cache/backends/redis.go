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

// NoExpiryTTL is the sentinel RedisBackend.Get reports for a key that has
// no associated expiry (Redis PTTL -1). It is distinct from a returned
// ttl of 0, which means the key has under a millisecond left (or vanished
// between GET and PTTL): the caller must not treat those two cases the
// same way — folding "no expiry" into 0 made a caller that repopulates a
// local copy on ttl<=0 re-cache a dying entry for its full DefaultTTL
// (FIX-31).
const NoExpiryTTL time.Duration = -1

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
	// Timeouts are kept short to prevent request pileup when Redis is slow/stalled.
	// The UniversalCache uses 200ms context timeout, so socket timeouts should be
	// shorter to allow proper context cancellation handling.
	poolConfig := &PoolConfig{
		Address:           config.RedisAddr,
		Password:          config.RedisPassword,
		TLSServerName:     config.TLSServerName,
		DB:                config.RedisDB,
		MaxConnections:    config.PoolSize,
		ConnectTimeout:    2 * time.Second,
		ReadTimeout:       500 * time.Millisecond,
		WriteTimeout:      500 * time.Millisecond,
		EnableHealthCheck: true,
		MaxRetries:        3,
		RetryDelay:        100 * time.Millisecond,
		EnableTLS:         config.EnableTLS,
		TLSSkipVerify:     config.TLSSkipVerify,
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
		_ = pool.Close()
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

	// A NEGATIVE TTL means "already expired" (the stack's convention for a
	// value whose validity has passed). Previously ttl<=0 fell through to a
	// bare SET with no expiry, silently making the entry permanent. Zero here
	// is the documented "no expiry" contract (see SetManyNoTTL), so only
	// strictly-negative TTLs are skipped.
	prefixedKey := r.prefixKey(key)
	if ttl < 0 {
		return nil
	}

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

// SetNX stores a value in Redis only if the key does not already exist,
// atomically, using Redis SET key value NX PX <ttl-ms> — one server-side
// command rather than a Get followed by a Set, so two callers racing the
// same key (e.g. two Traefik replicas racing the same backchannel-logout
// jti) can never both observe "absent". Backs UniversalCache.SetIfAbsent's
// distributed case (FIX-17): CacheBackend has no such primitive, and
// widening it would force every implementer to add an operation only this
// one caller needs, so UniversalCache reaches this through an optional
// interface type assertion instead.
//
// Returns (true, nil) when this call claimed the key, (false, nil) when the
// key already existed (someone else claimed it first — not an error),
// (false, ErrSetNXAmbiguous) when the command reached the wire but its
// reply could not be read — Redis may or may not have applied it — and
// (false, err) on any other genuine backend failure.
//
// SetNX runs its own retry loop rather than executeWithRetry (FIX-17
// round-2): Set's SETEX/PSETEX are idempotent, so retrying one after a lost
// reply just repeats the same unconditional write. SET NX is not — retrying
// it after a lost reply would see this call's OWN possible write and
// misreport a first-ever claim as already-claimed. So SetNX retries a
// failed connection acquisition (nothing was sent yet, safe to retry) but
// never re-sends SET NX once doTracked reports the command was written.
func (r *RedisBackend) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if r.closed.Load() {
		return false, ErrBackendClosed
	}

	// Mirrors Set's TTL convention: negative means "already expired", so
	// there is nothing to claim.
	prefixedKey := r.prefixKey(key)
	if ttl < 0 {
		return false, nil
	}

	var args []string
	if ttl > 0 {
		ttlMillis := ttl.Milliseconds()
		if ttlMillis < 1 {
			ttlMillis = 1
		}
		args = []string{prefixedKey, string(value), "NX", "PX", fmt.Sprintf("%d", ttlMillis)}
	} else {
		args = []string{prefixedKey, string(value), "NX"}
	}

	maxRetries := 3
	baseDelay := 50 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		conn, err := r.pool.Get(ctx)
		if err != nil {
			if attempt == maxRetries-1 {
				return false, fmt.Errorf("failed to get connection after %d attempts: %w", maxRetries, err)
			}
			delay := baseDelay * time.Duration(1<<uint(attempt))
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(delay):
				continue
			}
		}

		var (
			resp  interface{}
			sent  bool
			doErr error
		)
		func() {
			defer func() { r.pool.Put(conn) }()
			resp, sent, doErr = conn.doTracked("SET", args...)
		}()

		if doErr == nil {
			if _, strErr := RESPString(resp); strErr != nil {
				return false, strErr
			}
			return true, nil
		}

		if errors.Is(doErr, ErrNilResponse) {
			// NX condition failed: the key already existed before this
			// call. A valid protocol outcome, not an error — the
			// connection is healthy and nothing here should be retried.
			return false, nil
		}

		if sent {
			// The command reached the wire before reading its reply
			// failed (timeout, EOF, connection reset): Redis may have
			// applied it. This is checked BEFORE ctx.Err() (FIX-17
			// round-3): UniversalCache.setIfAbsentBackend gives SetNX a
			// 500ms context, and the pool's read deadline on this same
			// write is also 500ms, started strictly after the ctx
			// deadline began ticking — so when a reply is lost, ctx has
			// almost always already expired by the time this line runs.
			// Checking ctx.Err() first therefore reported
			// context.DeadlineExceeded for what is actually an ambiguous
			// outcome, and checkAndMarkLogoutJTIProcessed does not
			// special-case a plain deadline error: it fell through to the
			// mutex-guarded Get+Set fallback, whose Get saw this call's
			// own possible write and misreported a first-ever logout
			// token as a replay. Retrying here (instead of returning) would
			// see this call's own possible write and misreport a
			// first-ever claim as already-claimed, same reasoning as
			// above — surface the ambiguity instead of guessing.
			return false, ErrSetNXAmbiguous
		}

		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		if attempt == maxRetries-1 || !isRetryableError(doErr) {
			return false, doErr
		}

		delay := baseDelay * time.Duration(1<<uint(attempt))
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(delay):
			continue
		}
	}

	return false, fmt.Errorf("operation failed after %d attempts", maxRetries)
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

		// Get TTL with millisecond precision (PTTL, not TTL). TTL's second
		// precision maps both "no expiry" (-1) and "under one second left"
		// to a reported ttl of 0 once truncated to whole seconds, so a
		// caller cannot tell them apart (FIX-31). PTTL keeps "no expiry"
		// distinct via NoExpiryTTL.
		ttlResp, err := conn.Do("PTTL", prefixedKey)
		if err != nil {
			// If PTTL fails, still return the value; report no TTL info.
			r.hits.Add(1)
			resultValue = []byte(value)
			resultTTL = 0
			resultExists = true
			return nil
		}

		ttlMillis, _ := RESPInt(ttlResp)
		var ttl time.Duration
		switch {
		case ttlMillis == -1:
			// Key exists with no associated expiry.
			ttl = NoExpiryTTL
		case ttlMillis > 0:
			ttl = time.Duration(ttlMillis) * time.Millisecond
		default:
			// -2 (key vanished between GET and PTTL) or 0 (under 1ms
			// left): report "expire now", not "no expiry".
			ttl = 0
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
		_, _ = conn.Do("DEL", key) // Best effort, ignore errors
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

// executeWithRetry executes a Redis operation with exponential backoff retry logic.
// It checks context cancellation at multiple points to ensure fast abort when the
// caller's context is canceled (e.g., due to request timeout).
func (r *RedisBackend) executeWithRetry(ctx context.Context, operation func(*RedisConn) error) error {
	maxRetries := 3
	baseDelay := 50 * time.Millisecond // Reduced from 100ms to fail faster

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check context before each attempt to fail fast
		if ctx.Err() != nil {
			return ctx.Err()
		}

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

		// Execute the operation, guaranteeing the borrowed connection is
		// returned to the pool even if the operation panics (previously a
		// panic here leaked the connection and desynced the pool counters;
		// other pool call sites use defer for this).
		func() {
			defer func() { r.pool.Put(conn) }()
			err = operation(conn)
		}()

		// Check err == nil BEFORE ctx.Err(): the operation already completed
		// against the connection (op returned), so a nil error means Redis
		// applied it. Reporting ctx.Err() first would tell the caller (e.g.
		// UniversalCache.Set) that a write failed when it actually landed,
		// which previously triggered a Delete that erased the just-applied
		// value (FIX-04).
		if err == nil {
			return nil
		}

		// Check context after operation - if canceled, don't bother retrying
		if ctx.Err() != nil {
			return ctx.Err()
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

// SetMany stores multiple values in Redis using pipelining for efficiency
// This reduces N round-trips to a single round-trip
func (r *RedisBackend) SetMany(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if r.closed.Load() {
		return ErrBackendClosed
	}

	if len(items) == 0 {
		return nil
	}

	if ttl < 0 {
		// Already-expired TTL: nothing to persist (see Set's guard). Avoids
		// creating permanent entries for past-dated values via the multi path.
		// Zero retains the "no expiry" contract (see SetManyNoTTL).
		return nil
	}

	// For single items, use regular Set
	if len(items) == 1 {
		for key, value := range items {
			return r.Set(ctx, key, value, ttl)
		}
	}

	conn, err := r.pool.Get(ctx)
	if err != nil {
		return err
	}
	defer r.pool.Put(conn)

	pipeline := conn.NewPipeline()

	// Queue all SET commands
	ttlSeconds := int(ttl.Seconds())
	ttlMillis := ttl.Milliseconds()

	for key, value := range items {
		prefixedKey := r.prefixKey(key)

		if ttl > 0 {
			if ttlMillis < 1000 {
				// Use PSETEX for sub-second TTLs
				pipeline.Queue("PSETEX", prefixedKey, fmt.Sprintf("%d", ttlMillis), string(value))
			} else {
				// Use SETEX for larger TTLs
				pipeline.Queue("SETEX", prefixedKey, fmt.Sprintf("%d", ttlSeconds), string(value))
			}
		} else {
			pipeline.Queue("SET", prefixedKey, string(value))
		}
	}

	// Execute pipeline
	responses, err := pipeline.Execute()
	if err != nil {
		return fmt.Errorf("pipeline SetMany failed: %w", err)
	}

	// Check responses for errors (each should be "OK")
	for i, resp := range responses {
		if resp == nil {
			continue
		}
		if str, ok := resp.(string); ok && str == "OK" {
			continue
		}
		return fmt.Errorf("SetMany: unexpected response at index %d: %v", i, resp)
	}

	return nil
}

// GetMany retrieves multiple values from Redis using pipelining for efficiency
// This reduces N round-trips to a single round-trip
func (r *RedisBackend) GetMany(ctx context.Context, keys []string) (map[string][]byte, error) {
	if r.closed.Load() {
		return nil, ErrBackendClosed
	}

	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	// For single key, use regular Get
	if len(keys) == 1 {
		result := make(map[string][]byte)
		value, _, exists, err := r.Get(ctx, keys[0])
		if err != nil {
			return nil, err
		}
		if exists {
			result[keys[0]] = value
		}
		return result, nil
	}

	conn, err := r.pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	defer r.pool.Put(conn)

	pipeline := conn.NewPipeline()

	// Queue all GET commands
	prefixedKeys := make([]string, len(keys))
	for i, key := range keys {
		prefixedKeys[i] = r.prefixKey(key)
		pipeline.Queue("GET", prefixedKeys[i])
	}

	// Execute pipeline
	responses, err := pipeline.Execute()
	if err != nil {
		return nil, fmt.Errorf("pipeline GetMany failed: %w", err)
	}

	// Process responses
	result := make(map[string][]byte)
	var firstErr error
	for i, resp := range responses {
		if resp == nil {
			// Key doesn't exist
			r.misses.Add(1)
			continue
		}

		// A Redis command-error reply (e.g. LOADING, WRONGTYPE) is stored
		// as an error value by Pipeline.Execute. It means the key lookup
		// failed, not that the key is missing, so it must not be counted
		// as a miss.
		if respErr, ok := resp.(error); ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("GetMany: command error for key %q: %w", keys[i], respErr)
			}
			continue
		}

		value, err := RESPString(resp)
		if err != nil {
			// Invalid response, skip this key
			r.misses.Add(1)
			continue
		}

		r.hits.Add(1)
		result[keys[i]] = []byte(value)
	}

	if firstErr != nil {
		return result, firstErr
	}

	return result, nil
}
