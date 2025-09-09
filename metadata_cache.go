package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// MetadataCacheEntry represents a single cache entry with expiration and access tracking
type MetadataCacheEntry struct {
	metadata     *ProviderMetadata
	expiresAt    time.Time
	lastAccessed time.Time
	accessCount  int64
	sizeEstimate int64
}

// MetadataCache provides thread-safe caching of OIDC provider metadata.
// It stores multiple provider metadata entries with expiration time to reduce network requests.
// The cache includes automatic expiration, LRU eviction, and memory bounds.
type MetadataCache struct {
	cache               map[string]*MetadataCacheEntry
	cleanupTask         *BackgroundTask
	logger              *Logger
	wg                  *sync.WaitGroup
	stopChan            chan struct{}
	autoCleanupInterval time.Duration
	mutex               sync.RWMutex
	ctx                 context.Context
	cancel              context.CancelFunc
	// Memory and size limits
	maxEntries         int
	maxMemoryBytes     int64
	currentMemoryBytes int64
	totalAccesses      int64
	evictionCount      int64
	// LRU tracking
	accessOrder []string // Simple LRU tracking
}

// NewMetadataCache creates a new metadata cache with default configuration.
// It initializes the cache structure and starts the background cleanup task.
func NewMetadataCache(wg *sync.WaitGroup) *MetadataCache {
	return NewMetadataCacheWithLogger(wg, nil)
}

// NewMetadataCacheWithLogger creates a new metadata cache with custom logger.
// The logger is used for debugging cache operations and cleanup activities.
// Parameters:
//   - wg: WaitGroup for tracking cleanup goroutines during shutdown
//   - logger: Logger instance for debugging (nil creates no-op logger)
func NewMetadataCacheWithLogger(wg *sync.WaitGroup, logger *Logger) *MetadataCache {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &MetadataCache{
		cache:               make(map[string]*MetadataCacheEntry),
		autoCleanupInterval: 5 * time.Minute,
		logger:              logger,
		wg:                  wg,
		stopChan:            make(chan struct{}),
		ctx:                 ctx,
		cancel:              cancel,
		maxEntries:          100,              // Maximum 100 provider metadata entries
		maxMemoryBytes:      50 * 1024 * 1024, // 50MB memory limit
		accessOrder:         make([]string, 0),
	}
	c.startAutoCleanup()
	return c
}

// Cleanup removes expired metadata from the cache.
// This is called periodically by the auto-cleanup goroutine to free memory
// when cached metadata has exceeded its time-to-live.
func (c *MetadataCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)
	totalFreed := int64(0)

	// Find expired entries
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			expiredKeys = append(expiredKeys, key)
			totalFreed += entry.sizeEstimate
		}
	}

	// Remove expired entries
	for _, key := range expiredKeys {
		c.removeEntryUnsafe(key)
	}

	// Check memory limits and enforce if necessary
	c.enforceMemoryLimitsUnsafe()

	if len(expiredKeys) > 0 && c.logger != nil {
		c.logger.Debugf("Metadata cache cleanup: removed %d expired entries, freed %d bytes",
			len(expiredKeys), totalFreed)
	}
}

// isCacheValid checks if the cached metadata is still within its expiration time.
// This method assumes the caller holds the appropriate lock.
func (c *MetadataCache) isCacheValid(providerURL string) bool {
	entry, exists := c.cache[providerURL]
	return exists && entry != nil && time.Now().Before(entry.expiresAt)
}

// estimateMetadataSize estimates the memory footprint of provider metadata
func (c *MetadataCache) estimateMetadataSize(metadata *ProviderMetadata) int64 {
	if metadata == nil {
		return 0
	}

	size := int64(200) // Base overhead for struct

	if metadata.Issuer != "" {
		size += int64(len(metadata.Issuer))
	}
	if metadata.AuthURL != "" {
		size += int64(len(metadata.AuthURL))
	}
	if metadata.TokenURL != "" {
		size += int64(len(metadata.TokenURL))
	}
	if metadata.JWKSURL != "" {
		size += int64(len(metadata.JWKSURL))
	}
	if metadata.RevokeURL != "" {
		size += int64(len(metadata.RevokeURL))
	}
	if metadata.EndSessionURL != "" {
		size += int64(len(metadata.EndSessionURL))
	}

	// Note: ProviderMetadata struct has minimal fields, so no slice size estimation needed

	return size
}

// removeEntryUnsafe removes an entry from cache without locking
func (c *MetadataCache) removeEntryUnsafe(key string) {
	entry, exists := c.cache[key]
	if !exists {
		return
	}

	// Update memory tracking
	atomic.AddInt64(&c.currentMemoryBytes, -entry.sizeEstimate)

	// Remove from cache
	delete(c.cache, key)

	// Remove from access order
	c.removeFromAccessOrderUnsafe(key)
}

// removeFromAccessOrderUnsafe removes a key from the access order slice
func (c *MetadataCache) removeFromAccessOrderUnsafe(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			// Remove by swapping with last element and truncating
			c.accessOrder[i] = c.accessOrder[len(c.accessOrder)-1]
			c.accessOrder = c.accessOrder[:len(c.accessOrder)-1]
			break
		}
	}
}

// updateAccessOrderUnsafe updates LRU access order
func (c *MetadataCache) updateAccessOrderUnsafe(key string) {
	// Remove existing entry if present
	c.removeFromAccessOrderUnsafe(key)

	// Add to end (most recently used)
	c.accessOrder = append(c.accessOrder, key)
}

// enforceMemoryLimitsUnsafe enforces cache size and memory limits
func (c *MetadataCache) enforceMemoryLimitsUnsafe() {
	// Enforce entry count limit
	if len(c.cache) > c.maxEntries {
		c.evictLRUEntries(len(c.cache) - c.maxEntries)
	}

	// Enforce memory limit
	currentMemory := atomic.LoadInt64(&c.currentMemoryBytes)
	if currentMemory > c.maxMemoryBytes {
		// Try to evict 20% of entries to get below limit
		targetEvictions := len(c.cache) / 5
		if targetEvictions < 1 {
			targetEvictions = 1
		}
		c.evictLRUEntries(targetEvictions)
	}
}

// evictLRUEntries evicts the least recently used entries
func (c *MetadataCache) evictLRUEntries(count int) {
	evicted := 0

	// Start from beginning of access order (least recently used)
	for i := 0; i < len(c.accessOrder) && evicted < count; i++ {
		key := c.accessOrder[i]
		if _, exists := c.cache[key]; exists {
			c.removeEntryUnsafe(key)
			evicted++
			atomic.AddInt64(&c.evictionCount, 1)
			i-- // Adjust index since slice was modified
		}
	}

	if evicted > 0 && c.logger != nil {
		c.logger.Debugf("Evicted %d LRU entries from metadata cache", evicted)
	}
}

// GetMetadataWithRecovery retrieves provider metadata with error recovery and fallback mechanisms.
// It uses the error recovery manager to handle transient failures and provides fallback to cached data.
// Parameters:
//   - providerURL: The OIDC provider's discovery URL
//   - httpClient: HTTP client for making requests
//   - logger: Logger for debugging and error reporting
//   - errorRecoveryManager: Manager for handling and recovering from errors
//
// Returns:
//   - *ProviderMetadata: The provider metadata (from cache or freshly fetched)
//   - An error if metadata cannot be retrieved from cache or fetched from the provider
func (c *MetadataCache) GetMetadataWithRecovery(providerURL string, httpClient *http.Client, logger *Logger, errorRecoveryManager *ErrorRecoveryManager) (*ProviderMetadata, error) {
	// Check cache first
	c.mutex.Lock()
	if entry, exists := c.cache[providerURL]; exists && c.isCacheValid(providerURL) {
		// Update access tracking - safe to do with write lock
		entry.lastAccessed = time.Now()
		atomic.AddInt64(&entry.accessCount, 1)
		atomic.AddInt64(&c.totalAccesses, 1)
		metadata := entry.metadata
		c.mutex.Unlock()

		// Update LRU order
		c.mutex.Lock()
		c.updateAccessOrderUnsafe(providerURL)
		c.mutex.Unlock()

		return metadata, nil
	}
	c.mutex.Unlock()

	// Double-check locking pattern
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, exists := c.cache[providerURL]; exists && c.isCacheValid(providerURL) {
		entry.lastAccessed = time.Now()
		atomic.AddInt64(&entry.accessCount, 1)
		atomic.AddInt64(&c.totalAccesses, 1)
		c.updateAccessOrderUnsafe(providerURL)
		return entry.metadata, nil
	}

	serviceName := fmt.Sprintf("metadata-provider-%s", providerURL)

	// Setup fallback with existing cached data (even if expired)
	errorRecoveryManager.gracefulDegradation.RegisterFallback(serviceName, func() (interface{}, error) {
		if entry, exists := c.cache[providerURL]; exists && entry.metadata != nil {
			logger.Infof("Using cached metadata as fallback for service %s", serviceName)
			// Extend expiration for emergency fallback
			entry.expiresAt = time.Now().Add(10 * time.Minute)
			return entry.metadata, nil
		}
		return nil, fmt.Errorf("no cached metadata available for fallback")
	})

	errorRecoveryManager.gracefulDegradation.RegisterHealthCheck(serviceName, func() bool {
		_, err := discoverProviderMetadata(providerURL, httpClient, logger)
		return err == nil
	})

	ctx := context.Background()
	var metadata *ProviderMetadata
	err := errorRecoveryManager.ExecuteWithRecovery(ctx, serviceName, func() error {
		var fetchErr error
		metadata, fetchErr = discoverProviderMetadata(providerURL, httpClient, logger)
		return fetchErr
	})

	if err != nil {
		fallbackResult, fallbackErr := errorRecoveryManager.gracefulDegradation.ExecuteWithFallback(serviceName, func() (interface{}, error) {
			return discoverProviderMetadata(providerURL, httpClient, logger)
		})

		if fallbackErr == nil {
			if fallbackMetadata, ok := fallbackResult.(*ProviderMetadata); ok {
				logger.Infof("Successfully used fallback metadata for service %s", serviceName)
				c.storeMetadataUnsafe(providerURL, fallbackMetadata, 10*time.Minute)
				return fallbackMetadata, nil
			}
		}

		return nil, fmt.Errorf("failed to fetch provider metadata with error recovery and fallback: %w", err)
	}

	// Store successfully fetched metadata
	c.storeMetadataUnsafe(providerURL, metadata, 1*time.Hour)
	return metadata, nil
}

// storeMetadataUnsafe stores metadata in the cache (assumes caller holds write lock)
func (c *MetadataCache) storeMetadataUnsafe(providerURL string, metadata *ProviderMetadata, ttl time.Duration) {
	if metadata == nil {
		return
	}

	// Check memory limits before storing
	sizeEstimate := c.estimateMetadataSize(metadata)

	// Remove existing entry if present
	if existingEntry, exists := c.cache[providerURL]; exists {
		atomic.AddInt64(&c.currentMemoryBytes, -existingEntry.sizeEstimate)
		c.removeFromAccessOrderUnsafe(providerURL)
	}

	// Create new entry
	entry := &MetadataCacheEntry{
		metadata:     metadata,
		expiresAt:    time.Now().Add(ttl),
		lastAccessed: time.Now(),
		accessCount:  1,
		sizeEstimate: sizeEstimate,
	}

	// Store in cache
	c.cache[providerURL] = entry
	c.updateAccessOrderUnsafe(providerURL)
	atomic.AddInt64(&c.currentMemoryBytes, sizeEstimate)
	atomic.AddInt64(&c.totalAccesses, 1)

	// Enforce limits after adding new entry
	c.enforceMemoryLimitsUnsafe()
}

// GetMetadata retrieves provider metadata from cache or fetches it from the provider.
// It uses double-checked locking to prevent concurrent fetches and provides basic
// fallback to cached data if refresh fails.
// Parameters:
//   - providerURL: The OIDC provider's discovery URL
//   - httpClient: HTTP client for making requests
//   - logger: Logger for debugging and error reporting
//
// Returns:
//   - *ProviderMetadata: The provider metadata (from cache or freshly fetched)
//   - An error if metadata cannot be retrieved from cache or fetched from the provider
func (c *MetadataCache) GetMetadata(providerURL string, httpClient *http.Client, logger *Logger) (*ProviderMetadata, error) {
	// Check cache first
	c.mutex.Lock()
	if entry, exists := c.cache[providerURL]; exists && c.isCacheValid(providerURL) {
		// Update access tracking - safe to do with write lock
		entry.lastAccessed = time.Now()
		atomic.AddInt64(&entry.accessCount, 1)
		atomic.AddInt64(&c.totalAccesses, 1)
		metadata := entry.metadata
		c.mutex.Unlock()

		// Update LRU order
		c.mutex.Lock()
		c.updateAccessOrderUnsafe(providerURL)
		c.mutex.Unlock()

		return metadata, nil
	}
	c.mutex.Unlock()

	// Double-check locking pattern
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, exists := c.cache[providerURL]; exists && c.isCacheValid(providerURL) {
		entry.lastAccessed = time.Now()
		atomic.AddInt64(&entry.accessCount, 1)
		atomic.AddInt64(&c.totalAccesses, 1)
		c.updateAccessOrderUnsafe(providerURL)
		return entry.metadata, nil
	}

	// Fetch new metadata
	metadata, err := discoverProviderMetadata(providerURL, httpClient, logger)
	if err != nil {
		// Try to use cached version even if expired
		if entry, exists := c.cache[providerURL]; exists && entry.metadata != nil {
			entry.expiresAt = time.Now().Add(5 * time.Minute)
			logger.Errorf("Failed to refresh metadata, using cached version for 5 more minutes: %v", err)
			entry.lastAccessed = time.Now()
			atomic.AddInt64(&entry.accessCount, 1)
			c.updateAccessOrderUnsafe(providerURL)
			return entry.metadata, nil
		}
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}

	// Store successfully fetched metadata
	c.storeMetadataUnsafe(providerURL, metadata, 1*time.Hour)
	return metadata, nil
}

// startAutoCleanup starts a background cleanup task that runs periodically
// to remove expired metadata from the cache and free memory.
func (c *MetadataCache) startAutoCleanup() {
	c.cleanupTask = NewBackgroundTask("metadata-cache-cleanup", c.autoCleanupInterval, c.Cleanup, c.logger, c.wg)
	c.cleanupTask.Start()
}

// Close stops the automatic cleanup task and releases resources.
// This should be called when the cache is no longer needed to prevent resource leaks.
func (c *MetadataCache) Close() {
	// Cancel context to stop background operations
	if c.cancel != nil {
		c.cancel()
	}

	// First, close the stop channel and get cleanup task reference without holding lock
	c.mutex.Lock()

	// Stop channel first
	select {
	case <-c.stopChan:
		// Already closed
		c.mutex.Unlock()
		return
	default:
		close(c.stopChan)
	}

	// Get reference to cleanup task before unlocking
	cleanupTask := c.cleanupTask
	c.mutex.Unlock()

	// Stop the cleanup task WITHOUT holding the lock to avoid deadlock
	if cleanupTask != nil {
		cleanupTask.Stop()
	}

	// Wait for background operations if WaitGroup is provided
	if c.wg != nil {
		c.wg.Wait()
	}

	// Now safely clear all cached data
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cleanupTask = nil

	// Clear all cached metadata and free memory tracking
	totalEntries := len(c.cache)
	totalMemory := atomic.LoadInt64(&c.currentMemoryBytes)

	for key, entry := range c.cache {
		atomic.AddInt64(&c.currentMemoryBytes, -entry.sizeEstimate)
		delete(c.cache, key)
	}

	// Clear access order
	c.accessOrder = c.accessOrder[:0]

	// Force garbage collection to help cleanup
	runtime.GC()

	if c.logger != nil {
		c.logger.Infof("MetadataCache closed: cleared %d entries, freed %d bytes", totalEntries, totalMemory)
	}
}

// GetCacheStats returns statistics about cache performance and memory usage
func (c *MetadataCache) GetCacheStats() map[string]interface{} {
	c.mutex.RLock()
	entryCount := len(c.cache)
	c.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["entries"] = entryCount
	stats["max_entries"] = c.maxEntries
	stats["memory_bytes"] = atomic.LoadInt64(&c.currentMemoryBytes)
	stats["max_memory_bytes"] = c.maxMemoryBytes
	stats["total_accesses"] = atomic.LoadInt64(&c.totalAccesses)
	stats["eviction_count"] = atomic.LoadInt64(&c.evictionCount)

	// Calculate cache hit ratio if we have enough data
	if entryCount > 0 {
		stats["estimated_hit_ratio"] = float64(atomic.LoadInt64(&c.totalAccesses)) / float64(entryCount+int(atomic.LoadInt64(&c.evictionCount)))
	} else {
		stats["estimated_hit_ratio"] = 0.0
	}

	return stats
}
