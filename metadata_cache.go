package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MetadataCache provides thread-safe caching for OIDC provider metadata.
// It stores provider discovery information (endpoints, issuer, etc.) to reduce
// network requests to the provider's .well-known/openid-configuration endpoint.
// The cache includes automatic expiration and periodic cleanup.
type MetadataCache struct {
	expiresAt           time.Time
	metadata            *ProviderMetadata
	cleanupTask         *BackgroundTask
	logger              *Logger
	autoCleanupInterval time.Duration
	mutex               sync.RWMutex
	wg                  *sync.WaitGroup
	stopChan            chan struct{}
}

// NewMetadataCache creates a new MetadataCache instance.
// It initializes the cache structure and starts the background cleanup task.
func NewMetadataCache(wg *sync.WaitGroup) *MetadataCache {
	return NewMetadataCacheWithLogger(wg, nil)
}

// NewMetadataCacheWithLogger creates a new MetadataCache with a specified logger.
func NewMetadataCacheWithLogger(wg *sync.WaitGroup, logger *Logger) *MetadataCache {
	if logger == nil {
		logger = newNoOpLogger()
	}

	c := &MetadataCache{
		autoCleanupInterval: 30 * time.Minute, // Increased from 5 minutes since metadata changes rarely
		logger:              logger,
		wg:                  wg,
		stopChan:            make(chan struct{}),
	}
	c.startAutoCleanup()
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
// This method assumes the caller holds the appropriate lock.
func (c *MetadataCache) isCacheValid() bool {
	return c.metadata != nil && time.Now().Before(c.expiresAt)
}

// GetMetadataWithRecovery retrieves the OIDC provider metadata with comprehensive error recovery.
// It uses circuit breaker protection and graceful degradation patterns.
// Similar to GetMetadata but with enhanced error handling capabilities.
//
// Parameters:
//   - providerURL: The base URL of the OIDC provider.
//   - httpClient: The HTTP client to use for fetching metadata.
//   - logger: The logger instance for recording errors or warnings.
//   - errorRecoveryManager: The error recovery manager for circuit breaker and retry handling.
//
// Returns:
//   - A pointer to the ProviderMetadata struct.
//   - An error if metadata cannot be retrieved from cache or fetched from the provider.
func (c *MetadataCache) GetMetadataWithRecovery(providerURL string, httpClient *http.Client, logger *Logger, errorRecoveryManager *ErrorRecoveryManager) (*ProviderMetadata, error) {
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

	// Use error recovery manager for fetching metadata with circuit breaker protection
	serviceName := fmt.Sprintf("metadata-provider-%s", providerURL)

	// Register fallback function for graceful degradation
	errorRecoveryManager.gracefulDegradation.RegisterFallback(serviceName, func() (interface{}, error) {
		if c.metadata != nil {
			logger.Infof("Using cached metadata as fallback for service %s", serviceName)
			// Extend cache by 10 minutes when using fallback
			c.expiresAt = time.Now().Add(10 * time.Minute)
			return c.metadata, nil
		}
		return nil, fmt.Errorf("no cached metadata available for fallback")
	})

	// Register health check function
	errorRecoveryManager.gracefulDegradation.RegisterHealthCheck(serviceName, func() bool {
		// Simple health check by attempting a quick metadata fetch
		_, err := discoverProviderMetadata(providerURL, httpClient, logger)
		return err == nil
	})

	// Execute metadata discovery with circuit breaker and retry protection
	ctx := context.Background()
	var metadata *ProviderMetadata
	err := errorRecoveryManager.ExecuteWithRecovery(ctx, serviceName, func() error {
		var fetchErr error
		metadata, fetchErr = discoverProviderMetadata(providerURL, httpClient, logger)
		return fetchErr
	})

	if err != nil {
		// Try graceful degradation fallback
		fallbackResult, fallbackErr := errorRecoveryManager.gracefulDegradation.ExecuteWithFallback(serviceName, func() (interface{}, error) {
			return discoverProviderMetadata(providerURL, httpClient, logger)
		})

		if fallbackErr == nil {
			if fallbackMetadata, ok := fallbackResult.(*ProviderMetadata); ok {
				logger.Infof("Successfully used fallback metadata for service %s", serviceName)
				c.metadata = fallbackMetadata
				// Cache fallback result for 10 minutes
				c.expiresAt = time.Now().Add(10 * time.Minute)
				return fallbackMetadata, nil
			}
		}

		return nil, fmt.Errorf("failed to fetch provider metadata with error recovery and fallback: %w", err)
	}

	c.metadata = metadata
	c.expiresAt = time.Now().Add(1 * time.Hour)

	return metadata, nil
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

// startAutoCleanup starts the background task that periodically calls Cleanup
// to remove expired metadata from the cache.
func (c *MetadataCache) startAutoCleanup() {
	c.cleanupTask = NewBackgroundTask("metadata-cache-cleanup", c.autoCleanupInterval, c.Cleanup, c.logger, c.wg)
	c.cleanupTask.Start()
}

// Close stops the automatic cleanup task associated with this metadata cache.
func (c *MetadataCache) Close() {
	if c.cleanupTask != nil {
		c.cleanupTask.Stop()
		c.cleanupTask = nil
	}
}
