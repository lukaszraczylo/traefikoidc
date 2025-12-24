package backends

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// SingleflightCache wraps a CacheBackend with singleflight deduplication
// to prevent thundering herd problems when multiple concurrent requests
// try to fetch the same uncached key.
type SingleflightCache struct {
	backend CacheBackend
	mu      sync.Mutex
	calls   map[string]*singleflightCall

	// Metrics
	deduplicatedCalls atomic.Int64
	totalCalls        atomic.Int64
}

// singleflightCall represents an in-flight or completed fetch call
type singleflightCall struct {
	wg   sync.WaitGroup
	val  []byte
	ttl  time.Duration
	err  error
	done bool
}

// NewSingleflightCache creates a new singleflight-wrapped cache backend
func NewSingleflightCache(backend CacheBackend) *SingleflightCache {
	return &SingleflightCache{
		backend: backend,
		calls:   make(map[string]*singleflightCall),
	}
}

// Fetcher is a function type that fetches data when cache misses
type Fetcher func(ctx context.Context) (value []byte, ttl time.Duration, err error)

// GetOrFetch retrieves a value from cache or calls the fetcher exactly once
// per key when there's a cache miss. Concurrent calls for the same key will
// wait for the first call to complete and share its result.
func (s *SingleflightCache) GetOrFetch(ctx context.Context, key string, fetcher Fetcher) ([]byte, error) {
	s.totalCalls.Add(1)

	// Try cache first
	value, _, exists, err := s.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if exists {
		return value, nil
	}

	// Cache miss - use singleflight
	s.mu.Lock()

	// Check if there's already an in-flight call for this key
	if call, ok := s.calls[key]; ok {
		s.mu.Unlock()
		s.deduplicatedCalls.Add(1)

		// Wait for the in-flight call to complete
		call.wg.Wait()

		// Check context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return call.val, call.err
	}

	// Create new call
	call := &singleflightCall{}
	call.wg.Add(1)
	s.calls[key] = call
	s.mu.Unlock()

	// Execute the fetcher
	call.val, call.ttl, call.err = fetcher(ctx)
	call.done = true

	// If successful, store in cache
	if call.err == nil && call.val != nil {
		// Use a background context for cache storage to ensure it completes
		// even if the original context is cancelled
		storeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.backend.Set(storeCtx, key, call.val, call.ttl)
		cancel()
	}

	// Signal waiting goroutines
	call.wg.Done()

	// Clean up the call from the map after a short delay
	// This allows late arrivals to still benefit from the result
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.mu.Lock()
		if c, ok := s.calls[key]; ok && c == call {
			delete(s.calls, key)
		}
		s.mu.Unlock()
	}()

	return call.val, call.err
}

// Get retrieves a value from the underlying cache backend
func (s *SingleflightCache) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	return s.backend.Get(ctx, key)
}

// Set stores a value in the underlying cache backend
func (s *SingleflightCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.backend.Set(ctx, key, value, ttl)
}

// Delete removes a key from the underlying cache backend
func (s *SingleflightCache) Delete(ctx context.Context, key string) (bool, error) {
	return s.backend.Delete(ctx, key)
}

// Exists checks if a key exists in the underlying cache backend
func (s *SingleflightCache) Exists(ctx context.Context, key string) (bool, error) {
	return s.backend.Exists(ctx, key)
}

// Clear removes all keys from the underlying cache backend
func (s *SingleflightCache) Clear(ctx context.Context) error {
	return s.backend.Clear(ctx)
}

// GetStats returns cache statistics including singleflight metrics
func (s *SingleflightCache) GetStats() map[string]interface{} {
	stats := s.backend.GetStats()

	// Add singleflight-specific stats
	totalCalls := s.totalCalls.Load()
	deduped := s.deduplicatedCalls.Load()

	stats["singleflight_total_calls"] = totalCalls
	stats["singleflight_deduplicated"] = deduped
	if totalCalls > 0 {
		stats["singleflight_dedup_rate"] = float64(deduped) / float64(totalCalls)
	} else {
		stats["singleflight_dedup_rate"] = float64(0)
	}

	s.mu.Lock()
	stats["singleflight_inflight"] = len(s.calls)
	s.mu.Unlock()

	return stats
}

// Close shuts down the cache backend
func (s *SingleflightCache) Close() error {
	return s.backend.Close()
}

// Ping checks if the backend is healthy
func (s *SingleflightCache) Ping(ctx context.Context) error {
	return s.backend.Ping(ctx)
}

// GetBackend returns the underlying cache backend
func (s *SingleflightCache) GetBackend() CacheBackend {
	return s.backend
}

// ResetStats resets the singleflight statistics
func (s *SingleflightCache) ResetStats() {
	s.totalCalls.Store(0)
	s.deduplicatedCalls.Store(0)
}

// Ensure SingleflightCache implements CacheBackend
var _ CacheBackend = (*SingleflightCache)(nil)
