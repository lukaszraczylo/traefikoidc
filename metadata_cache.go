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

func NewMetadataCache() *MetadataCache {
	c := &MetadataCache{
		autoCleanupInterval: 5 * time.Minute,
		stopCleanup:         make(chan struct{}),
	}
	go c.startAutoCleanup()
	return c
}

// Cleanup removes expired metadata from the cache.
func (c *MetadataCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	if c.metadata != nil && now.After(c.expiresAt) {
		c.metadata = nil
	}
}

func (c *MetadataCache) isCacheValid() bool {
	return c.metadata != nil && time.Now().Before(c.expiresAt)
}

// GetMetadata retrieves the metadata from cache or fetches it if expired
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
	// TODO: Consider making this configurable or respecting HTTP cache headers
	c.expiresAt = time.Now().Add(1 * time.Hour)

	// End of GetMetadata
	return metadata, nil
}

func (c *MetadataCache) startAutoCleanup() {
	autoCleanupRoutine(c.autoCleanupInterval, c.stopCleanup, c.Cleanup)
}

func (c *MetadataCache) Close() {
	close(c.stopCleanup)
}
