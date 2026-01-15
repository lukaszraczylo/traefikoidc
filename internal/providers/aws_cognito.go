package providers

import (
	"net/url"
	"strings"
)

// AWSCognitoProvider encapsulates AWS Cognito-specific OIDC logic.
type AWSCognitoProvider struct {
	*BaseProvider
}

// NewAWSCognitoProvider creates a new instance of the AWSCognitoProvider.
func NewAWSCognitoProvider() *AWSCognitoProvider {
	return &AWSCognitoProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *AWSCognitoProvider) GetType() ProviderType {
	return ProviderTypeAWSCognito
}

// GetCapabilities returns the specific capabilities of the AWS Cognito provider.
func (p *AWSCognitoProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: false, // Cognito doesn't use offline_access scope
		RequiresPromptConsent:      false,
		PreferredTokenValidation:   "id", // Cognito typically uses ID tokens
	}
}

// BuildAuthParams configures AWS Cognito-specific authentication parameters.
func (p *AWSCognitoProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// AWS Cognito supports standard OIDC parameters
	baseParams.Set("response_type", "code")

	// Remove offline_access scope as Cognito doesn't use it (case-insensitive)
	var filteredScopes []string
	for _, scope := range scopes {
		if !strings.EqualFold(scope, ScopeOfflineAccess) {
			filteredScopes = append(filteredScopes, scope)
		}
	}

	// Ensure openid scope is present
	hasOpenID := false
	for _, scope := range filteredScopes {
		if scope == ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		filteredScopes = append(filteredScopes, ScopeOpenID)
	}

	// Default Cognito scopes if none specified
	if len(filteredScopes) == 1 && filteredScopes[0] == ScopeOpenID {
		filteredScopes = append(filteredScopes, ScopeEmail, ScopeProfile)
	}

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    deduplicateScopes(filteredScopes),
	}, nil
}

// AWS Cognito requires user pool and domain configuration.
func (p *AWSCognitoProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig()
}
