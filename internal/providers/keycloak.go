package providers

import (
	"net/url"
)

// KeycloakProvider encapsulates Keycloak-specific OIDC logic.
type KeycloakProvider struct {
	*BaseProvider
}

// NewKeycloakProvider creates a new instance of the KeycloakProvider.
func NewKeycloakProvider() *KeycloakProvider {
	return &KeycloakProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *KeycloakProvider) GetType() ProviderType {
	return ProviderTypeKeycloak
}

// GetCapabilities returns the specific capabilities of the Keycloak provider.
func (p *KeycloakProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		RequiresPromptConsent:      false,
		PreferredTokenValidation:   "id", // Keycloak typically uses ID tokens
	}
}

// BuildAuthParams configures Keycloak-specific authentication parameters.
func (p *KeycloakProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// Keycloak supports standard OIDC parameters
	baseParams.Set("response_type", "code")

	// Ensure offline_access scope is present for refresh tokens
	hasOfflineAccess := false
	for _, scope := range scopes {
		if scope == ScopeOfflineAccess {
			hasOfflineAccess = true
			break
		}
	}
	if !hasOfflineAccess {
		scopes = append(scopes, ScopeOfflineAccess)
	}

	// Ensure openid scope is present
	hasOpenID := false
	for _, scope := range scopes {
		if scope == ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append(scopes, ScopeOpenID)
	}

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    deduplicateScopes(scopes),
	}, nil
}

// Keycloak requires realm and server configuration.
func (p *KeycloakProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
