package providers

import (
	"net/url"
)

// GitHubProvider encapsulates GitHub-specific OIDC logic.
type GitHubProvider struct {
	*BaseProvider
}

// NewGitHubProvider creates a new instance of the GitHubProvider.
func NewGitHubProvider() *GitHubProvider {
	return &GitHubProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *GitHubProvider) GetType() ProviderType {
	return ProviderTypeGitHub
}

// GetCapabilities returns the specific capabilities of the GitHub provider.
// WARNING: GitHub does NOT support OpenID Connect - it's OAuth 2.0 only.
// This provider should only be used for OAuth flows, not OIDC authentication.
func (p *GitHubProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      false, // GitHub OAuth apps don't support refresh tokens
		RequiresOfflineAccessScope: false, // GitHub doesn't use offline_access
		RequiresPromptConsent:      false,
		PreferredTokenValidation:   "access", // GitHub only provides access tokens, no ID tokens
	}
}

// BuildAuthParams configures GitHub-specific authentication parameters.
func (p *GitHubProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// GitHub doesn't use offline_access scope, so remove it if present
	var filteredScopes []string
	for _, scope := range scopes {
		if scope != ScopeOfflineAccess {
			filteredScopes = append(filteredScopes, scope)
		}
	}

	// If no scopes specified, use default GitHub scopes for OAuth
	// Note: GitHub doesn't support 'openid' scope as it's not an OIDC provider
	if len(filteredScopes) == 0 {
		filteredScopes = []string{"user:email", "read:user"}
	}

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    deduplicateScopes(filteredScopes),
	}, nil
}

// GitHub requires specific configuration for proper operation.
func (p *GitHubProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
