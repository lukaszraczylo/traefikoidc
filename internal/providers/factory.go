package providers

import (
	"fmt"
	"net/url"
	"strings"
)

// ProviderFactory encapsulates the logic for creating and configuring OIDC providers.
type ProviderFactory struct {
	registry *ProviderRegistry
}

// NewProviderFactory creates a new factory with a pre-configured registry.
func NewProviderFactory() *ProviderFactory {
	registry := NewProviderRegistry()

	registry.RegisterProvider(NewGenericProvider())
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())

	return &ProviderFactory{
		registry: registry,
	}
}

// CreateProvider creates an OIDC provider based on the issuer URL.
// It automatically detects the provider type and returns a configured instance.
func (f *ProviderFactory) CreateProvider(issuerURL string) (OIDCProvider, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuer URL cannot be empty")
	}

	parsedURL, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL format: %w", err)
	}

	// Check if the URL has a valid scheme and host
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid issuer URL format: URL must have a valid scheme and host")
	}

	provider := f.registry.DetectProvider(issuerURL)
	if provider == nil {
		return nil, fmt.Errorf("unable to detect provider for issuer URL: %s", issuerURL)
	}

	if err := provider.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("provider configuration validation failed: %w", err)
	}

	return provider, nil
}

// CreateProviderByType creates a provider instance of the specified type.
// This is useful when you want to force a specific provider type regardless of URL.
func (f *ProviderFactory) CreateProviderByType(providerType ProviderType) (OIDCProvider, error) {
	var provider OIDCProvider

	switch providerType {
	case ProviderTypeGeneric:
		provider = NewGenericProvider()
	case ProviderTypeGoogle:
		provider = NewGoogleProvider()
	case ProviderTypeAzure:
		provider = NewAzureProvider()
	default:
		return nil, fmt.Errorf("unsupported provider type: %d", providerType)
	}

	if err := provider.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("provider configuration validation failed: %w", err)
	}

	return provider, nil
}

// GetSupportedProviders returns a list of all supported provider types and their detection patterns.
func (f *ProviderFactory) GetSupportedProviders() map[ProviderType][]string {
	return map[ProviderType][]string{
		ProviderTypeGeneric: {"*"},
		ProviderTypeGoogle:  {"accounts.google.com"},
		ProviderTypeAzure:   {"login.microsoftonline.com", "sts.windows.net"},
	}
}

// DetectProviderType determines the provider type for a given issuer URL.
// This is useful for diagnostic purposes or UI display.
func (f *ProviderFactory) DetectProviderType(issuerURL string) (ProviderType, error) {
	provider, err := f.CreateProvider(issuerURL)
	if err != nil {
		return ProviderTypeGeneric, err
	}
	return provider.GetType(), nil
}

// IsProviderSupported checks if a given issuer URL is supported by any registered provider.
func (f *ProviderFactory) IsProviderSupported(issuerURL string) bool {
	if issuerURL == "" {
		return false
	}

	normalizedURL, err := url.Parse(issuerURL)
	if err != nil {
		return false
	}

	// Check if the URL has a valid scheme and host
	if normalizedURL.Scheme == "" || normalizedURL.Host == "" {
		return false
	}

	host := strings.ToLower(normalizedURL.Host)
	supportedProviders := f.GetSupportedProviders()

	for _, patterns := range supportedProviders {
		for _, pattern := range patterns {
			if pattern == "*" || strings.Contains(host, strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}
