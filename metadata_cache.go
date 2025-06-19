package traefikoidc

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type MetadataCache struct {
	metadata            *ProviderMetadata
	expiresAt           time.Time
	mutex               sync.RWMutex
	autoCleanupInterval time.Duration
	stopCleanup         chan struct{}
}

// NewMetadataCache creates a new MetadataCache instance.
// It initializes the cache structure and starts the background cleanup goroutine.
func NewMetadataCache() *MetadataCache {
	c := &MetadataCache{
		autoCleanupInterval: 5 * time.Minute,
		stopCleanup:         make(chan struct{}),
	}
	go c.startAutoCleanup()
	return c
}

// Cleanup removes the cached provider metadata if it has expired.
// This is called periodically by the auto-cleanup goroutine.
func (c *MetadataCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	if c.metadata != nil && now.After(c.expiresAt) {
		c.metadata = nil
	}
}

// isCacheValid checks if the cached metadata is present and has not expired.
// Note: This function assumes the read lock is held or it's called from a context
// where the lock is already held (like within GetMetadata after locking).
func (c *MetadataCache) isCacheValid() bool {
	return c.metadata != nil && time.Now().Before(c.expiresAt)
}

// GetMetadata retrieves the OIDC provider metadata.
// It first checks the cache for valid, non-expired metadata. If found, it's returned immediately.
// If the cache is empty or expired, it attempts to fetch the metadata from the provider's
// well-known endpoint using discoverProviderMetadata.
// If fetching is successful, the new metadata is cached for 1 hour.
// If fetching fails but valid metadata exists in the cache (even if expired), the cache expiry
// is extended by 5 minutes, and the cached data is returned to prevent thundering herd issues.
// If fetching fails and there's no cached data, an error is returned.
// It employs double-checked locking for thread safety and performance.
//
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
//   - httpClient: The HTTP client to use for fetching metadata.
//   - logger: The logger instance for recording errors or warnings.
//
// Returns:
//   - A pointer to the ProviderMetadata struct.
//   - An error if metadata cannot be retrieved from cache or fetched from the provider.
func (c *MetadataCache) GetMetadata(providerURL string, httpClient *http.Client, logger *Logger) (*ProviderMetadata, error) {
	c.mutex.RLock()
	if c.isCacheValid() {
		defer c.mutex.RUnlock()
		return c.metadata, nil
	}
	c.mutex.RUnlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Double-check after acquiring write lock
	if c.isCacheValid() {
		return c.metadata, nil
	}

	metadata, err := discoverProviderMetadata(providerURL, httpClient, logger)
	if err != nil {
		if c.metadata != nil {
			// On error, extend current cache by 5 minutes to prevent thundering herd
			c.expiresAt = time.Now().Add(5 * time.Minute)
			logger.Errorf("Failed to refresh metadata, using cached version for 5 more minutes: %v", err)
			return c.metadata, nil
		}
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}

	c.metadata = metadata
	// Set a fixed cache lifetime (e.g., 1 hour)
	// Consider making this configurable or respecting HTTP cache headers
	c.expiresAt = time.Now().Add(1 * time.Hour)

	// End of GetMetadata
	return metadata, nil
}

// startAutoCleanup starts the background goroutine that periodically calls Cleanup
// to remove expired metadata from the cache.
func (c *MetadataCache) startAutoCleanup() {
	autoCleanupRoutine(c.autoCleanupInterval, c.stopCleanup, c.Cleanup)
}

// Close stops the automatic cleanup goroutine associated with this metadata cache.
func (c *MetadataCache) Close() {
	close(c.stopCleanup)
}
