package providers

import (
	"net/url"
	"strings"
	"time"
)

// AzureProvider encapsulates Azure AD-specific OIDC logic.
type AzureProvider struct {
	*BaseProvider
}

// NewAzureProvider creates a new instance of the AzureProvider.
func NewAzureProvider() *AzureProvider {
	return &AzureProvider{
		BaseProvider: NewBaseProvider(),
	}
}

// GetType returns the provider's type.
func (p *AzureProvider) GetType() ProviderType {
	return ProviderTypeAzure
}

// GetCapabilities returns the specific capabilities of the Azure provider.
func (p *AzureProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		PreferredTokenValidation:   "access", // Azure AD prefers access token validation
	}
}

// BuildAuthParams configures Azure-specific authentication parameters.
func (p *AzureProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	baseParams.Set("response_mode", "query")

	// Ensure "offline_access" scope is present for refresh tokens
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

	return &AuthParams{
		URLValues: baseParams,
		Scopes:    scopes,
	}, nil
}

// ValidateTokens overrides the default token validation to implement Azure-specific logic.
// Azure may use access tokens for validation, and this method ensures that behavior is preserved.
func (p *AzureProvider) ValidateTokens(session Session, verifier TokenVerifier, tokenCache TokenCache, refreshGracePeriod time.Duration) (*ValidationResult, error) {
	if !session.GetAuthenticated() {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{NeedsRefresh: true}, nil
		}
		return &ValidationResult{IsExpired: true}, nil
	}

	accessToken := session.GetAccessToken()
	idToken := session.GetIDToken()

	if accessToken != "" {
		if strings.Count(accessToken, ".") == 2 {
			if err := verifier.VerifyToken(accessToken); err != nil {
				if idToken != "" {
					return p.ValidateTokenExpiry(session, idToken, tokenCache, refreshGracePeriod)
				}
				if session.GetRefreshToken() != "" {
					return &ValidationResult{NeedsRefresh: true}, nil
				}
				return &ValidationResult{IsExpired: true}, nil
			}
			return p.ValidateTokenExpiry(session, accessToken, tokenCache, refreshGracePeriod)
		}
		if idToken != "" {
			return p.ValidateTokenExpiry(session, idToken, tokenCache, refreshGracePeriod)
		}
		return &ValidationResult{Authenticated: true}, nil
	}

	if idToken != "" {
		if err := verifier.VerifyToken(idToken); err != nil {
			if session.GetRefreshToken() != "" {
				return &ValidationResult{NeedsRefresh: true}, nil
			}
			return &ValidationResult{IsExpired: true}, nil
		}
		return p.ValidateTokenExpiry(session, idToken, tokenCache, refreshGracePeriod)
	}

	if session.GetRefreshToken() != "" {
		return &ValidationResult{NeedsRefresh: true}, nil
	}
	return &ValidationResult{IsExpired: true}, nil
}

// ValidateConfig validates Azure-specific configuration requirements.
// Azure requires specific tenant configuration and scope handling.
func (p *AzureProvider) ValidateConfig() error {
	// Azure provider validation - ensure we have the necessary configuration
	// In a real implementation, this might check for tenant ID, proper issuer URL format, etc.
	return p.BaseProvider.ValidateConfig()
}
