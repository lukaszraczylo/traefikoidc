package traefikoidc

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MetadataCache provides thread-safe caching for OIDC provider metadata
type MetadataCache struct {
	metadata  *ProviderMetadata
	expiresAt time.Time
	mutex     sync.RWMutex
}

// NewMetadataCache creates a new metadata cache instance
func NewMetadataCache() *MetadataCache {
	return &MetadataCache{}
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

// GetMetadata retrieves the metadata from cache or fetches it if expired
func (c *MetadataCache) GetMetadata(providerURL string, httpClient *http.Client, logger *Logger) (*ProviderMetadata, error) {
	c.mutex.RLock()
	if c.metadata != nil && time.Now().Before(c.expiresAt) {
		defer c.mutex.RUnlock()
		return c.metadata, nil
	}
	c.mutex.RUnlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Double-check after acquiring write lock
	if c.metadata != nil && time.Now().Before(c.expiresAt) {
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
	// Calculate expiration time based on usage patterns
usageCount := 0 // This should be replaced with actual usage tracking logic
if usageCount < 10 {
	c.expiresAt = time.Now().Add(30 * time.Minute)
} else if usageCount < 50 {
	c.expiresAt = time.Now().Add(1 * time.Hour)
} else {
	c.expiresAt = time.Now().Add(2 * time.Hour)
}

	return metadata, nil
}
