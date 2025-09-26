package providers

import (
	"net/url"
)

// OktaProvider encapsulates Okta-specific OIDC logic.
type OktaProvider struct {
	*BaseProvider
}

// NewOktaProvider creates a new instance of the OktaProvider.
func NewOktaProvider() *OktaProvider {
	return &OktaProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *OktaProvider) GetType() ProviderType {
	return ProviderTypeOkta
}

// GetCapabilities returns the specific capabilities of the Okta provider.
func (p *OktaProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		RequiresPromptConsent:      false,
		PreferredTokenValidation:   "id", // Okta primarily uses ID tokens
	}
}

// BuildAuthParams configures Okta-specific authentication parameters.
func (p *OktaProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// Okta supports various response types
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

// Okta requires specific domain configuration and application setup.
func (p *OktaProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
