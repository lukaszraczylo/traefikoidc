package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MetadataCache wraps UniversalCache for metadata operations
type MetadataCache struct {
	cache  *UniversalCache
	logger *Logger
	wg     *sync.WaitGroup
}

// MetadataCacheEntry for compatibility
type MetadataCacheEntry struct {
}

// NewMetadataCache creates a new metadata cache
func NewMetadataCache(wg *sync.WaitGroup) *MetadataCache {
	manager := GetUniversalCacheManager(nil)
	return &MetadataCache{
		cache:  manager.GetMetadataCache(),
		logger: manager.logger,
		wg:     wg,
	}
}

// NewMetadataCacheWithLogger creates a metadata cache with specific logger
func NewMetadataCacheWithLogger(wg *sync.WaitGroup, logger *Logger) *MetadataCache {
	manager := GetUniversalCacheManager(logger)
	return &MetadataCache{
		cache:  manager.GetMetadataCache(),
		logger: logger,
		wg:     wg,
	}
}

// Set stores provider metadata with a TTL
func (mc *MetadataCache) Set(providerURL string, metadata *ProviderMetadata, ttl time.Duration) error {
	if metadata == nil {
		return fmt.Errorf("metadata cannot be nil")
	}

	mc.logger.Debugf("MetadataCache: Setting metadata for %s with TTL %v", providerURL, ttl)

	// Store as JSON for consistency
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return mc.cache.Set(providerURL, data, ttl)
}

// Get retrieves provider metadata from cache
func (mc *MetadataCache) Get(providerURL string) (*ProviderMetadata, bool) {
	value, exists := mc.cache.Get(providerURL)
	if !exists {
		mc.logger.Debugf("MetadataCache: MISS for %s", providerURL)
		return nil, false
	}

	// Handle different value types
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		mc.logger.Errorf("MetadataCache: Invalid data type for %s: %T", providerURL, value)
		return nil, false
	}

	var metadata ProviderMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		mc.logger.Errorf("MetadataCache: Failed to unmarshal metadata for %s: %v", providerURL, err)
		return nil, false
	}

	mc.logger.Debugf("MetadataCache: HIT for %s", providerURL)
	return &metadata, true
}

// GetProviderMetadata fetches metadata with automatic caching
func (mc *MetadataCache) GetProviderMetadata(ctx context.Context, providerURL string, httpClient *http.Client) (*ProviderMetadata, error) {
	// Check cache first
	if metadata, exists := mc.Get(providerURL); exists {
		return metadata, nil
	}

	// Fetch from provider
	metadataURL := providerURL + "/.well-known/openid-configuration"
	mc.logger.Infof("Fetching provider metadata from: %s", metadataURL)

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch returned status %d", resp.StatusCode)
	}

	var metadata ProviderMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	// Cache for 1 hour by default
	if err := mc.Set(providerURL, &metadata, 1*time.Hour); err != nil {
		mc.logger.Errorf("Failed to cache metadata: %v", err)
	}

	return &metadata, nil
}

// Clear removes all cached metadata
func (mc *MetadataCache) Clear() {
	mc.cache.Clear()
	mc.logger.Info("MetadataCache: Cleared all entries")
}

// Close shuts down the cache
func (mc *MetadataCache) Close() {
	// Cache is managed globally, so we don't close it here
	mc.logger.Debug("MetadataCache: Close called (managed by global cache manager)")
}

// GetMetrics returns cache metrics
func (mc *MetadataCache) GetMetrics() map[string]interface{} {
	return mc.cache.GetMetrics()
}

// Size returns the number of cached entries
func (mc *MetadataCache) Size() int {
	return mc.cache.Size()
}

// GetMetadata fetches metadata with HTTP client and logger
func (mc *MetadataCache) GetMetadata(providerURL string, httpClient *http.Client, logger *Logger) (*ProviderMetadata, error) {
	// Check cache first
	if metadata, exists := mc.Get(providerURL); exists {
		return metadata, nil
	}

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return mc.GetProviderMetadata(ctx, providerURL, httpClient)
}

// GetMetadataWithRecovery fetches metadata with recovery support
func (mc *MetadataCache) GetMetadataWithRecovery(providerURL string, httpClient *http.Client, logger *Logger, errorRecoveryManager *ErrorRecoveryManager) (*ProviderMetadata, error) {
	// For now, just use regular GetMetadata
	// Recovery would be handled by ErrorRecoveryManager if needed
	return mc.GetMetadata(providerURL, httpClient, logger)
}

// GetStats returns cache statistics for testing
func (mc *MetadataCache) GetStats() map[string]interface{} {
	return mc.cache.GetMetrics()
}

// CleanupExpired triggers cleanup of expired entries
func (mc *MetadataCache) CleanupExpired() {
	mc.cache.Cleanup()
}

// Delete removes an entry from the cache
func (mc *MetadataCache) Delete(key string) {
	mc.cache.Delete(key)
}

// Mutex returns the cache mutex for testing
func (mc *MetadataCache) Mutex() *sync.RWMutex {
	return &mc.cache.mu
}
