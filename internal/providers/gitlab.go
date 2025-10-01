package providers

import (
	"net/url"
)

// GitLabProvider encapsulates GitLab-specific OIDC logic.
type GitLabProvider struct {
	*BaseProvider
}

// NewGitLabProvider creates a new instance of the GitLabProvider.
func NewGitLabProvider() *GitLabProvider {
	return &GitLabProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *GitLabProvider) GetType() ProviderType {
	return ProviderTypeGitLab
}

// GetCapabilities returns the specific capabilities of the GitLab provider.
func (p *GitLabProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: false, // GitLab doesn't use offline_access scope
		RequiresPromptConsent:      false,
		PreferredTokenValidation:   "id", // GitLab typically uses ID tokens
	}
}

// BuildAuthParams configures GitLab-specific authentication parameters.
func (p *GitLabProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// GitLab supports standard OAuth 2.0 parameters
	baseParams.Set("response_type", "code")

	// Remove offline_access scope as GitLab doesn't use it
	var filteredScopes []string
	for _, scope := range scopes {
		if scope != "offline_access" {
			filteredScopes = append(filteredScopes, scope)
		}
	}

	// Ensure openid scope is present for OIDC
	hasOpenID := false
	for _, scope := range filteredScopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		filteredScopes = append(filteredScopes, "openid")
	}

	// Default GitLab scopes if none specified
	if len(filteredScopes) == 1 && filteredScopes[0] == "openid" {
		filteredScopes = append(filteredScopes, "profile", "email")
	}

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    deduplicateScopes(filteredScopes),
	}, nil
}

// GitLab requires application configuration and proper redirect URIs.
func (p *GitLabProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
