package providers

import (
	"net/url"
)

// GoogleProvider encapsulates Google-specific OIDC logic.
type GoogleProvider struct {
	*BaseProvider
}

// NewGoogleProvider creates a new instance of the GoogleProvider.
func NewGoogleProvider() *GoogleProvider {
	return &GoogleProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *GoogleProvider) GetType() ProviderType {
	return ProviderTypeGoogle
}

// GetCapabilities returns the specific capabilities of the Google provider.
func (p *GoogleProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,  // Google DOES support refresh tokens
		RequiresOfflineAccessScope: false, // Google uses access_type=offline instead
		RequiresPromptConsent:      true,
		PreferredTokenValidation:   "id",
	}
}

// BuildAuthParams configures Google-specific authentication parameters.
func (p *GoogleProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	baseParams.Set("access_type", "offline")
	baseParams.Set("prompt", "consent")

	// Google does not use the "offline_access" scope, so we remove it if present.
	var filteredScopes []string
	for _, scope := range scopes {
		if scope != "offline_access" {
			filteredScopes = append(filteredScopes, scope)
		}
	}

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    filteredScopes,
	}, nil
}

// Google requires specific scopes and client configuration for proper operation.
func (p *GoogleProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
