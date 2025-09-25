package providers

import (
	"net/url"
	"strings"
	"sync"
)

// ProviderRegistry manages a collection of OIDC provider implementations.
// It provides thread-safe access to provider instances and caches detection results.
type ProviderRegistry struct {
	cache     map[string]OIDCProvider
	typeMap   map[ProviderType]OIDCProvider
	providers []OIDCProvider
	mu        sync.RWMutex
	// Bounded cache configuration to prevent memory leaks
	maxCacheSize int
	cacheCount   int
}

// NewProviderRegistry creates and initializes a new ProviderRegistry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers:    make([]OIDCProvider, 0),
		cache:        make(map[string]OIDCProvider),
		typeMap:      make(map[ProviderType]OIDCProvider),
		maxCacheSize: 1000, // Prevent unbounded cache growth
		cacheCount:   0,
	}
}

// RegisterProvider adds a new provider to the registry.
// It maintains both a list of providers and a type-to-provider mapping for efficient lookups.
func (r *ProviderRegistry) RegisterProvider(provider OIDCProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, provider)
	r.typeMap[provider.GetType()] = provider
}

// GetProviderByType retrieves a provider instance by its type.
// Returns nil if the provider type is not registered.
func (r *ProviderRegistry) GetProviderByType(providerType ProviderType) OIDCProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.typeMap[providerType]
}

// GetRegisteredProviders returns a slice of all registered provider types.
func (r *ProviderRegistry) GetRegisteredProviders() []ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]ProviderType, 0, len(r.typeMap))
	for providerType := range r.typeMap {
		types = append(types, providerType)
	}
	return types
}

// ClearCache removes all cached provider detection results.
// This can be useful for testing or when provider configuration changes.
func (r *ProviderRegistry) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]OIDCProvider)
	r.cacheCount = 0
}

// evictOldestCacheEntry removes the first cache entry when cache is full
// This is a simple eviction strategy - in production, LRU might be preferred
func (r *ProviderRegistry) evictOldestCacheEntry() {
	// Simple eviction: remove first entry found
	for key := range r.cache {
		delete(r.cache, key)
		r.cacheCount--
		break
	}
}

// DetectProvider identifies the appropriate OIDC provider for an issuer URL.
// Uses double-checked locking pattern to avoid race conditions while caching results.
func (r *ProviderRegistry) DetectProvider(issuerURL string) OIDCProvider {
	r.mu.RLock()
	if provider, found := r.cache[issuerURL]; found {
		r.mu.RUnlock()
		return provider
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	if provider, found := r.cache[issuerURL]; found {
		return provider
	}

	detectedProvider := r.detectProviderUnsafe(issuerURL)

	// Check if cache is full and evict if necessary
	if r.cacheCount >= r.maxCacheSize {
		r.evictOldestCacheEntry()
	}

	r.cache[issuerURL] = detectedProvider
	r.cacheCount++

	return detectedProvider
}

// detectProviderUnsafe performs the actual provider detection logic.
// This method assumes the caller holds the appropriate lock and should not be called directly.
func (r *ProviderRegistry) detectProviderUnsafe(issuerURL string) OIDCProvider {
	normalizedURL, err := url.Parse(issuerURL)
	if err != nil {
		return nil
	}

	// Check if the URL has a valid scheme and host
	if normalizedURL.Scheme == "" || normalizedURL.Host == "" {
		return nil
	}

	// Convert host to lowercase for case-insensitive matching
	host := strings.ToLower(normalizedURL.Host)

	for _, p := range r.providers {
		switch p.GetType() {
		case ProviderTypeGoogle:
			if strings.Contains(host, "accounts.google.com") {
				return p
			}
		case ProviderTypeAzure:
			if strings.Contains(host, "login.microsoftonline.com") || strings.Contains(host, "sts.windows.net") {
				return p
			}
		}
	}

	for _, p := range r.providers {
		if p.GetType() == ProviderTypeGeneric {
			return p
		}
	}

	return nil
}
