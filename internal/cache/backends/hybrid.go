// Package backend provides cache backend implementations for the Traefik OIDC plugin.
package backends

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// HybridBackend implements a two-tier cache with L1 (memory) and L2 (Redis) backends
// It provides automatic failover, async writes for non-critical data, and optimized read paths
type HybridBackend struct {
	lastL2Error         atomic.Value
	secondary           CacheBackend
	primary             CacheBackend
	logger              Logger
	ctx                 context.Context
	syncWriteCacheTypes map[string]bool
	asyncWriteBuffer    chan *asyncWriteItem
	l1BackfillBuffer    chan *l1BackfillItem
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	l1Hits              atomic.Int64
	errors              atomic.Int64
	l2Writes            atomic.Int64
	l1Writes            atomic.Int64
	misses              atomic.Int64
	l2Hits              atomic.Int64
	l1BackfillDrops     atomic.Int64
	fallbackMode        atomic.Bool
}

// asyncWriteItem represents an async write operation
type asyncWriteItem struct {
	ctx   context.Context
	key   string
	value []byte
	ttl   time.Duration
}

// l1BackfillItem represents a deferred write of an L2-resolved value back into
// L1. Backfills run on a single bounded worker so a burst of L2 hits cannot
// detonate the goroutine count (issue: ~1000% CPU under sustained polling).
type l1BackfillItem struct {
	key   string
	value []byte
	ttl   time.Duration
}

// Logger interface for structured logging
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// defaultLogger provides a basic logger implementation
type defaultLogger struct {
	*log.Logger
}

func (l *defaultLogger) Debugf(format string, args ...interface{}) {
	l.Printf("[DEBUG] "+format, args...)
}

func (l *defaultLogger) Infof(format string, args ...interface{}) {
	l.Printf("[INFO] "+format, args...)
}

func (l *defaultLogger) Warnf(format string, args ...interface{}) {
	l.Printf("[WARN] "+format, args...)
}

func (l *defaultLogger) Errorf(format string, args ...interface{}) {
	l.Printf("[ERROR] "+format, args...)
}

// HybridConfig provides configuration for the hybrid backend
type HybridConfig struct {
	Primary             CacheBackend
	Secondary           CacheBackend
	Logger              Logger
	SyncWriteCacheTypes map[string]bool
	AsyncBufferSize     int
}

// NewHybridBackend creates a new hybrid cache backend with L1 (memory) and L2 (Redis) tiers
func NewHybridBackend(config *HybridConfig) (*HybridBackend, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.Primary == nil {
		return nil, fmt.Errorf("primary (L1) backend is required")
	}

	if config.Secondary == nil {
		return nil, fmt.Errorf("secondary (L2) backend is required")
	}

	if config.Logger == nil {
		config.Logger = &defaultLogger{Logger: log.New(log.Writer(), "[HybridCache] ", log.LstdFlags)}
	}

	if config.AsyncBufferSize <= 0 {
		config.AsyncBufferSize = 1000
	}

	// Default critical cache types that require synchronous writes
	if config.SyncWriteCacheTypes == nil {
		config.SyncWriteCacheTypes = map[string]bool{
			"blacklist": true, // Token blacklist must be immediately consistent
			"token":     true, // Token validation is critical
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &HybridBackend{
		primary:             config.Primary,
		secondary:           config.Secondary,
		syncWriteCacheTypes: config.SyncWriteCacheTypes,
		asyncWriteBuffer:    make(chan *asyncWriteItem, config.AsyncBufferSize),
		l1BackfillBuffer:    make(chan *l1BackfillItem, config.AsyncBufferSize),
		ctx:                 ctx,
		cancel:              cancel,
		logger:              config.Logger,
	}

	// Start async write worker
	h.wg.Add(1)
	go h.asyncWriteWorker()

	// Start L1 backfill worker (single goroutine) to bound goroutine growth on
	// L2 hits regardless of request rate.
	h.wg.Add(1)
	go h.l1BackfillWorker()

	// Start health monitoring
	h.wg.Add(1)
	go h.healthMonitor()

	h.logger.Infof("HybridBackend initialized with L1 (memory) and L2 (Redis) tiers")
	h.logger.Infof("Sync write cache types: %v", config.SyncWriteCacheTypes)
	h.logger.Infof("Async write buffer size: %d", config.AsyncBufferSize)

	return h, nil
}

// Set stores a value in both L1 and L2 caches
func (h *HybridBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	// Always write to L1 first (synchronous)
	if err := h.primary.Set(ctx, key, value, ttl); err != nil {
		h.errors.Add(1)
		h.logger.Warnf("Failed to write to L1 cache: %v", err)
		// Continue to try L2 even if L1 fails
	} else {
		h.l1Writes.Add(1)
	}

	// Check if we're in fallback mode
	if h.fallbackMode.Load() {
		h.logger.Debugf("Operating in fallback mode, skipping L2 write for key: %s", redactKey(key))
		return nil // Don't fail the operation if L2 is down
	}

	// Determine if this should be a sync or async write based on cache type
	cacheType := h.extractCacheType(key)
	requiresSync := h.syncWriteCacheTypes[cacheType]

	if requiresSync {
		// Synchronous write for critical cache types
		if err := h.secondary.Set(ctx, key, value, ttl); err != nil {
			h.errors.Add(1)
			h.logger.Warnf("Failed to write to L2 cache (sync) for key %s: %v", redactKey(key), err)
			h.recordL2Error()
			// Don't fail the operation - L1 write succeeded
			return nil
		}
		h.l2Writes.Add(1)
		h.logger.Debugf("Synchronous write to L2 completed for critical key: %s", redactKey(key))
	} else {
		// Asynchronous write for non-critical cache types
		select {
		case h.asyncWriteBuffer <- &asyncWriteItem{
			key:   key,
			value: value,
			ttl:   ttl,
			ctx:   ctx,
		}:
			h.logger.Debugf("Queued async write to L2 for key: %s", redactKey(key))
		default:
			// Buffer is full, log and continue
			h.logger.Warnf("Async write buffer full, dropping L2 write for key: %s", redactKey(key))
			h.errors.Add(1)
		}
	}

	return nil
}

// Get retrieves a value from cache, checking L1 first, then L2
func (h *HybridBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	// Try L1 first
	value, ttl, exists, err := h.primary.Get(ctx, key)
	if err != nil {
		h.errors.Add(1)
		h.logger.Debugf("L1 get error for key %s: %v", redactKey(key), err)
	}

	if exists {
		h.l1Hits.Add(1)
		return value, ttl, true, nil
	}

	// Check if we're in fallback mode
	if h.fallbackMode.Load() {
		h.misses.Add(1)
		return nil, 0, false, nil
	}

	// Try L2
	value, ttl, exists, err = h.secondary.Get(ctx, key)
	if err != nil {
		h.errors.Add(1)
		h.logger.Debugf("L2 get error for key %s: %v", redactKey(key), err)
		h.recordL2Error()
		h.misses.Add(1)
		return nil, 0, false, nil // Don't propagate L2 errors
	}

	if !exists {
		h.misses.Add(1)
		return nil, 0, false, nil
	}

	h.l2Hits.Add(1)

	// Populate L1 cache with value from L2 (write-through on read).
	// Hand off to the bounded backfill worker instead of spawning a goroutine
	// per read - under burst that would mint thousands of goroutines.
	h.queueL1Backfill(key, value, ttl)

	return value, ttl, true, nil
}

// Delete removes a key from both L1 and L2 caches
func (h *HybridBackend) Delete(ctx context.Context, key string) (bool, error) {
	var deleted bool

	// Delete from L1
	if d, err := h.primary.Delete(ctx, key); err != nil {
		h.logger.Debugf("Failed to delete from L1 cache: %v", err)
	} else if d {
		deleted = true
	}

	// Delete from L2 if not in fallback mode
	if !h.fallbackMode.Load() {
		if d, err := h.secondary.Delete(ctx, key); err != nil {
			h.logger.Debugf("Failed to delete from L2 cache: %v", err)
			h.recordL2Error()
		} else if d {
			deleted = true
		}
	}

	return deleted, nil
}

// Exists checks if a key exists in either cache
func (h *HybridBackend) Exists(ctx context.Context, key string) (bool, error) {
	// Check L1 first
	if exists, err := h.primary.Exists(ctx, key); err == nil && exists {
		return true, nil
	}

	// Check L2 if not in fallback mode
	if !h.fallbackMode.Load() {
		if exists, err := h.secondary.Exists(ctx, key); err == nil && exists {
			return true, nil
		}
	}

	return false, nil
}

// Clear removes all keys from both caches
func (h *HybridBackend) Clear(ctx context.Context) error {
	var lastErr error

	// Clear L1
	if err := h.primary.Clear(ctx); err != nil {
		h.logger.Errorf("Failed to clear L1 cache: %v", err)
		lastErr = err
	}

	// Clear L2 if not in fallback mode
	if !h.fallbackMode.Load() {
		if err := h.secondary.Clear(ctx); err != nil {
			h.logger.Errorf("Failed to clear L2 cache: %v", err)
			h.recordL2Error()
			lastErr = err
		}
	}

	return lastErr
}

// GetStats returns statistics for the hybrid cache
func (h *HybridBackend) GetStats() map[string]interface{} {
	l1Hits := h.l1Hits.Load()
	l2Hits := h.l2Hits.Load()
	misses := h.misses.Load()
	total := l1Hits + l2Hits + misses

	stats := map[string]interface{}{
		"type":          TypeHybrid,
		"l1_hits":       l1Hits,
		"l2_hits":       l2Hits,
		"misses":        misses,
		"total":         total,
		"l1_writes":     h.l1Writes.Load(),
		"l2_writes":     h.l2Writes.Load(),
		"errors":        h.errors.Load(),
		"fallback_mode": h.fallbackMode.Load(),
	}

	if total > 0 {
		stats["l1_hit_rate"] = float64(l1Hits) / float64(total)
		stats["l2_hit_rate"] = float64(l2Hits) / float64(total)
		stats["overall_hit_rate"] = float64(l1Hits+l2Hits) / float64(total)
	}

	// Add sub-backend stats
	stats["l1_stats"] = h.primary.GetStats()
	stats["l2_stats"] = h.secondary.GetStats()

	// Add last L2 error time if available
	if lastErr := h.lastL2Error.Load(); lastErr != nil {
		if t, ok := lastErr.(time.Time); ok {
			stats["last_l2_error"] = t.Format(time.RFC3339)
			stats["seconds_since_l2_error"] = time.Since(t).Seconds()
		}
	}

	return stats
}

// Ping checks if both backends are healthy
func (h *HybridBackend) Ping(ctx context.Context) error {
	// Check L1
	if err := h.primary.Ping(ctx); err != nil {
		return fmt.Errorf("L1 ping failed: %w", err)
	}

	// Check L2 (but don't fail if it's down)
	if err := h.secondary.Ping(ctx); err != nil {
		h.logger.Warnf("L2 ping failed: %v", err)
		h.recordL2Error()
		// Don't return error - we can operate with L1 only
	} else {
		// L2 is healthy, clear fallback mode if it was set
		if h.fallbackMode.CompareAndSwap(true, false) {
			h.logger.Infof("L2 backend recovered, exiting fallback mode")
		}
	}

	return nil
}

// Close shuts down the hybrid backend
func (h *HybridBackend) Close() error {
	// Cancel context to stop workers
	h.cancel()

	// Close async write channel
	close(h.asyncWriteBuffer)
	close(h.l1BackfillBuffer)

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Workers finished
	case <-time.After(5 * time.Second):
		h.logger.Warnf("Timeout waiting for workers to finish")
	}

	var lastErr error

	// Close backends
	if err := h.primary.Close(); err != nil {
		h.logger.Errorf("Failed to close L1 backend: %v", err)
		lastErr = err
	}

	if err := h.secondary.Close(); err != nil {
		h.logger.Errorf("Failed to close L2 backend: %v", err)
		lastErr = err
	}

	h.logger.Infof("HybridBackend closed")

	return lastErr
}

// GetMany retrieves multiple values efficiently
func (h *HybridBackend) GetMany(ctx context.Context, keys []string) (map[string][]byte, error) {
	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	results := make(map[string][]byte, len(keys))
	missingKeys := make([]string, 0)

	// Try L1 first for all keys
	for _, key := range keys {
		if value, _, exists, _ := h.primary.Get(ctx, key); exists {
			results[key] = value
			h.l1Hits.Add(1)
		} else {
			missingKeys = append(missingKeys, key)
		}
	}

	// If all found in L1 or in fallback mode, return
	if len(missingKeys) == 0 || h.fallbackMode.Load() {
		return results, nil
	}

	// Try L2 for missing keys using batch operation if available
	if batcher, ok := h.secondary.(interface {
		GetMany(context.Context, []string) (map[string][]byte, error)
	}); ok {
		l2Results, err := batcher.GetMany(ctx, missingKeys)
		if err != nil {
			h.logger.Debugf("L2 batch get error: %v", err)
			h.recordL2Error()
		} else {
			for key, value := range l2Results {
				results[key] = value
				h.l2Hits.Add(1)
				h.queueL1Backfill(key, value, 0) // 0 = primary backend default TTL
			}
		}
	} else {
		// Fallback to individual gets
		for _, key := range missingKeys {
			if value, ttl, exists, err := h.secondary.Get(ctx, key); err == nil && exists {
				results[key] = value
				h.l2Hits.Add(1)
				h.queueL1Backfill(key, value, ttl)
			}
		}
	}

	// Count misses for keys not found anywhere
	for _, key := range keys {
		if _, found := results[key]; !found {
			h.misses.Add(1)
		}
	}

	return results, nil
}

// SetMany stores multiple key-value pairs efficiently
func (h *HybridBackend) SetMany(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if len(items) == 0 {
		return nil
	}

	// Write to L1 first
	for key, value := range items {
		if err := h.primary.Set(ctx, key, value, ttl); err != nil {
			h.logger.Debugf("Failed to write to L1 in batch: %v", err)
		} else {
			h.l1Writes.Add(1)
		}
	}

	// Skip L2 if in fallback mode
	if h.fallbackMode.Load() {
		return nil
	}

	// Check if L2 supports batch operations
	if batcher, ok := h.secondary.(interface {
		SetMany(context.Context, map[string][]byte, time.Duration) error
	}); ok {
		if err := batcher.SetMany(ctx, items, ttl); err != nil {
			h.logger.Warnf("Failed to batch write to L2: %v", err)
			h.recordL2Error()
		} else {
			h.l2Writes.Add(int64(len(items)))
		}
	} else {
		// Fallback to individual sets
		for key, value := range items {
			cacheType := h.extractCacheType(key)
			if h.syncWriteCacheTypes[cacheType] {
				// Sync write for critical types
				if err := h.secondary.Set(ctx, key, value, ttl); err != nil {
					h.logger.Debugf("Failed to write to L2: %v", err)
					h.recordL2Error()
				} else {
					h.l2Writes.Add(1)
				}
			} else {
				// Async write for non-critical types
				select {
				case h.asyncWriteBuffer <- &asyncWriteItem{
					key:   key,
					value: value,
					ttl:   ttl,
					ctx:   ctx,
				}:
					// Queued
				default:
					h.logger.Warnf("Async buffer full for batch write")
				}
			}
		}
	}

	return nil
}

// queueL1Backfill enqueues an L2-resolved value for write-through into L1.
// Drops on full buffer to keep the read path constant-time; the next L2 hit
// for the same key simply re-queues it.
func (h *HybridBackend) queueL1Backfill(key string, value []byte, ttl time.Duration) {
	select {
	case h.l1BackfillBuffer <- &l1BackfillItem{key: key, value: value, ttl: ttl}:
	default:
		h.l1BackfillDrops.Add(1)
		h.logger.Debugf("L1 backfill buffer full, dropping for key: %s", redactKey(key))
	}
}

// l1BackfillWorker drains the backfill queue serially. Single worker is
// intentional - L1 writes are local and cheap, and serializing them keeps
// goroutine count bounded under any read rate.
func (h *HybridBackend) l1BackfillWorker() {
	defer h.wg.Done()

	for {
		select {
		case <-h.ctx.Done():
			// Drain remaining items best-effort then exit.
			for len(h.l1BackfillBuffer) > 0 {
				select {
				case item := <-h.l1BackfillBuffer:
					if h.keyStillInSecondary(item.key) {
						writeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
						_ = h.primary.Set(writeCtx, item.key, item.value, item.ttl)
						cancel()
					}
				default:
					return
				}
			}
			return

		case item, ok := <-h.l1BackfillBuffer:
			if !ok {
				return
			}
			if h.keyStillInSecondary(item.key) {
				writeCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				if err := h.primary.Set(writeCtx, item.key, item.value, item.ttl); err != nil {
					h.logger.Debugf("Failed to populate L1 cache from L2 for key %s: %v", redactKey(item.key), err)
				} else {
					h.logger.Debugf("Populated L1 cache from L2 for key: %s", redactKey(item.key))
				}
				cancel()
			}
		}
	}
}

// keyStillInSecondary reports whether the key still exists in the L2 cache.
// Used by the L1 backfill worker: the value was captured from L2 at read
// time, and a Delete may have run since. Writing it into L1 without this
// check would resurrect a key the caller just removed from both tiers.
func (h *HybridBackend) keyStillInSecondary(key string) bool {
	if h.fallbackMode.Load() {
		return true // No L2 available to check; keep behavior unchanged.
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	exists, err := h.secondary.Exists(ctx, key)
	return err != nil || exists
}

// asyncWriteWorker processes asynchronous writes to L2
func (h *HybridBackend) asyncWriteWorker() {
	defer h.wg.Done()

	for {
		select {
		case <-h.ctx.Done():
			// Drain remaining items with best effort
			for len(h.asyncWriteBuffer) > 0 {
				select {
				case item := <-h.asyncWriteBuffer:
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					_ = h.secondary.Set(ctx, item.key, item.value, item.ttl)
					cancel()
				default:
					return
				}
			}
			return

		case item, ok := <-h.asyncWriteBuffer:
			if !ok {
				return
			}

			// Skip if in fallback mode
			if h.fallbackMode.Load() {
				continue
			}

			// Perform the write with a timeout
			writeCtx, cancel := context.WithTimeout(item.ctx, 500*time.Millisecond)
			if err := h.secondary.Set(writeCtx, item.key, item.value, item.ttl); err != nil {
				h.errors.Add(1)
				h.logger.Debugf("Async write to L2 failed for key %s: %v", redactKey(item.key), err)
				h.recordL2Error()
			} else {
				h.l2Writes.Add(1)
				h.logger.Debugf("Async write to L2 completed for key: %s", redactKey(item.key))
			}
			cancel()
		}
	}
}

// healthMonitor periodically checks L2 health and manages fallback mode
func (h *HybridBackend) healthMonitor() {
	defer h.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

			if err := h.secondary.Ping(ctx); err != nil {
				if !h.fallbackMode.Load() {
					h.fallbackMode.Store(true)
					h.logger.Warnf("L2 backend unhealthy, entering fallback mode: %v", err)
				}
			} else {
				if h.fallbackMode.CompareAndSwap(true, false) {
					h.logger.Infof("L2 backend healthy, exiting fallback mode")
				}
			}

			cancel()
		}
	}
}

// recordL2Error records the timestamp of an L2 error
func (h *HybridBackend) recordL2Error() {
	now := time.Now()

	// Enter fallback only if there was a PRIOR error within the last second —
	// i.e. this is at least the second L2 error in quick succession.
	// Checking a freshly-written timestamp would always be "recent" and
	// enter fallback on a single transient L2 error (cache stampede).
	if !h.fallbackMode.Load() {
		if lastErr := h.lastL2Error.Load(); lastErr != nil {
			if t, ok := lastErr.(time.Time); ok && now.Sub(t) < time.Second {
				h.fallbackMode.Store(true)
				h.logger.Warnf("Multiple L2 errors detected, entering fallback mode")
			}
		}
	}

	h.lastL2Error.Store(now)
}

// extractCacheType attempts to determine the cache type from the key
func (h *HybridBackend) extractCacheType(key string) string {
	// Simple heuristic based on key prefixes
	// This should match the actual cache type strategy in the main application

	if len(key) > 10 {
		prefix := key[:10]
		switch {
		case contains(prefix, "blacklist"):
			return "blacklist"
		case contains(prefix, "token"):
			return "token"
		case contains(prefix, "metadata"):
			return "metadata"
		case contains(prefix, "jwk"):
			return "jwk"
		case contains(prefix, "session"):
			return "session"
		case contains(prefix, "introspect"):
			return "introspection"
		}
	}

	return "general"
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// toLower converts a byte to lowercase
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
