package providers

import (
	"net/url"
	"strings"
	"sync"
)

// ProviderRegistry holds and manages the available OIDC provider implementations.
// It provides thread-safe access to provider instances and caches detection results.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers []OIDCProvider
	cache     map[string]OIDCProvider
	typeMap   map[ProviderType]OIDCProvider // Maps provider type to instance
}

// NewProviderRegistry creates and initializes a new ProviderRegistry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make([]OIDCProvider, 0),
		cache:     make(map[string]OIDCProvider),
		typeMap:   make(map[ProviderType]OIDCProvider),
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

// GetProviderByType returns a provider instance for the specified type.
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
}

// DetectProvider determines the most appropriate provider for a given issuer URL.
// It iterates through the registered providers and returns the first one that matches.
// Detection is based on URL patterns and other provider-specific criteria.
func (r *ProviderRegistry) DetectProvider(issuerURL string) OIDCProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check cache first for performance
	if provider, found := r.cache[issuerURL]; found {
		return provider
	}

	// Normalize issuer URL for consistent matching
	normalizedURL, err := url.Parse(issuerURL)
	if err != nil {
		// Log error or handle it appropriately
		return nil
	}
	host := normalizedURL.Host

	// Iterate through registered providers to find a match
	for _, p := range r.providers {
		switch p.GetType() {
		case ProviderTypeGoogle:
			if strings.Contains(host, "accounts.google.com") {
				r.cache[issuerURL] = p
				return p
			}
		case ProviderTypeAzure:
			if strings.Contains(host, "login.microsoftonline.com") || strings.Contains(host, "sts.windows.net") {
				r.cache[issuerURL] = p
				return p
			}
		}
	}

	// Fallback to the generic provider if no specific provider is detected
	for _, p := range r.providers {
		if p.GetType() == ProviderTypeGeneric {
			r.cache[issuerURL] = p
			return p
		}
	}

	return nil
}
