package providers

import (
	"net/url"
)

// Auth0Provider encapsulates Auth0-specific OIDC logic.
type Auth0Provider struct {
	*BaseProvider
}

// NewAuth0Provider creates a new instance of the Auth0Provider.
func NewAuth0Provider() *Auth0Provider {
	return &Auth0Provider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *Auth0Provider) GetType() ProviderType {
	return ProviderTypeAuth0
}

// GetCapabilities returns the specific capabilities of the Auth0 provider.
func (p *Auth0Provider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		RequiresPromptConsent:      false,
		PreferredTokenValidation:   "id", // Auth0 typically uses ID tokens
	}
}

// BuildAuthParams configures Auth0-specific authentication parameters.
func (p *Auth0Provider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// Auth0 supports various response types and connection parameters
	baseParams.Set("response_type", "code")

	// Ensure offline_access scope is present for refresh tokens
	hasOfflineAccess := false
	for _, scope := range scopes {
		if scope == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}
	if !hasOfflineAccess {
		scopes = append(scopes, "offline_access")
	}

	// Ensure openid scope is present
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append(scopes, "openid")
	}

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    scopes,
	}, nil
}

// Auth0 requires specific tenant configuration and connection handling.
func (p *Auth0Provider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
