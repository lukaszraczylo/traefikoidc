package traefikoidc

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MetadataCache provides thread-safe caching of OIDC provider metadata.
// It stores the metadata with expiration time to reduce network requests.
// The cache includes automatic expiration and periodic cleanup.
type MetadataCache struct {
	expiresAt           time.Time
	metadata            *ProviderMetadata
	providerURL         string
	cleanupTask         *BackgroundTask
	logger              *Logger
	wg                  *sync.WaitGroup
	stopChan            chan struct{}
	autoCleanupInterval time.Duration
	mutex               sync.RWMutex
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

	c := &MetadataCache{
		autoCleanupInterval: 5 * time.Minute,
		logger:              logger,
		wg:                  wg,
		stopChan:            make(chan struct{}),
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
	if c.metadata != nil && now.After(c.expiresAt) {
		c.metadata = nil
		c.providerURL = ""
	}
}

// isCacheValid checks if the cached metadata is still within its expiration time
// and matches the requested provider URL.
// This method assumes the caller holds the appropriate lock.
func (c *MetadataCache) isCacheValid(providerURL string) bool {
	return c.metadata != nil && time.Now().Before(c.expiresAt) && c.providerURL == providerURL
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
	c.mutex.RLock()
	if c.isCacheValid(providerURL) {
		defer c.mutex.RUnlock()
		return c.metadata, nil
	}
	c.mutex.RUnlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.isCacheValid(providerURL) {
		return c.metadata, nil
	}

	serviceName := fmt.Sprintf("metadata-provider-%s", providerURL)

	errorRecoveryManager.gracefulDegradation.RegisterFallback(serviceName, func() (interface{}, error) {
		if c.metadata != nil {
			logger.Infof("Using cached metadata as fallback for service %s", serviceName)
			c.expiresAt = time.Now().Add(10 * time.Minute)
			return c.metadata, nil
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
				c.metadata = fallbackMetadata
				c.providerURL = providerURL
				c.expiresAt = time.Now().Add(10 * time.Minute)
				return fallbackMetadata, nil
			}
		}

		return nil, fmt.Errorf("failed to fetch provider metadata with error recovery and fallback: %w", err)
	}

	c.metadata = metadata
	c.providerURL = providerURL
	c.expiresAt = time.Now().Add(1 * time.Hour)

	return metadata, nil
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
	c.mutex.RLock()
	if c.isCacheValid(providerURL) {
		defer c.mutex.RUnlock()
		return c.metadata, nil
	}
	c.mutex.RUnlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.isCacheValid(providerURL) {
		return c.metadata, nil
	}

	metadata, err := discoverProviderMetadata(providerURL, httpClient, logger)
	if err != nil {
		if c.metadata != nil {
			c.expiresAt = time.Now().Add(5 * time.Minute)
			logger.Errorf("Failed to refresh metadata, using cached version for 5 more minutes: %v", err)
			return c.metadata, nil
		}
		return nil, fmt.Errorf("failed to fetch provider metadata: %w", err)
	}

	c.metadata = metadata
	c.providerURL = providerURL
	c.expiresAt = time.Now().Add(1 * time.Hour)

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

	// Now safely clear the cleanup task reference
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cleanupTask = nil

	// Clear cached metadata
	c.metadata = nil
	c.providerURL = ""

	if c.logger != nil {
		c.logger.Debug("MetadataCache closed and resources cleaned up")
	}
}
