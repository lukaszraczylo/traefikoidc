package providers

import (
	"net/url"
	"strings"
	"time"
)

// BaseProvider provides common functionality for all OIDC provider implementations.
// It defines default behaviors that can be overridden by specific providers.
// It can be embedded in specific provider structs to share common logic.
type BaseProvider struct {
}

// GetType returns the default provider type (generic).
// This should be overridden by specific provider implementations.
func (p *BaseProvider) GetType() ProviderType {
	return ProviderTypeGeneric
}

// GetCapabilities returns default provider capabilities.
// This can be overridden by specific providers to declare their unique features.
func (p *BaseProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		PreferredTokenValidation:   "id",
	}
}

// ValidateTokens performs basic token validation logic common to all providers.
// It checks authentication state, token presence, and determines if refresh is needed.
// This method can be extended or replaced by specific providers.
func (p *BaseProvider) ValidateTokens(session Session, verifier TokenVerifier, tokenCache TokenCache, refreshGracePeriod time.Duration) (*ValidationResult, error) {
	if !session.GetAuthenticated() {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{NeedsRefresh: true}, nil
		}
		return &ValidationResult{}, nil
	}

	accessToken := session.GetAccessToken()
	if accessToken == "" {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{NeedsRefresh: true}, nil
		}
		return &ValidationResult{IsExpired: true}, nil
	}

	idToken := session.GetIDToken()
	if idToken == "" {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{Authenticated: true, NeedsRefresh: true}, nil
		}
		return &ValidationResult{Authenticated: true}, nil
	}

	if err := verifier.VerifyToken(idToken); err != nil {
		if strings.Contains(err.Error(), "token has expired") {
			if session.GetRefreshToken() != "" {
				return &ValidationResult{NeedsRefresh: true}, nil
			}
			return &ValidationResult{IsExpired: true}, nil
		}
		if session.GetRefreshToken() != "" {
			return &ValidationResult{NeedsRefresh: true}, nil
		}
		return &ValidationResult{IsExpired: true}, nil
	}

	return p.ValidateTokenExpiry(session, idToken, tokenCache, refreshGracePeriod)
}

// ValidateTokenExpiry checks if a token is expired or needs refresh based on cached claims.
// This method is now exported so provider implementations can reuse this logic without duplication.
func (p *BaseProvider) ValidateTokenExpiry(session Session, token string, tokenCache TokenCache, refreshGracePeriod time.Duration) (*ValidationResult, error) {
	cachedClaims, found := tokenCache.Get(token)
	if !found {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{NeedsRefresh: true}, nil
		}
		return &ValidationResult{IsExpired: true}, nil
	}

	expClaim, ok := cachedClaims["exp"].(float64)
	if !ok {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{NeedsRefresh: true}, nil
		}
		return &ValidationResult{IsExpired: true}, nil
	}

	expTime := time.Unix(int64(expClaim), 0)
	if expTime.Before(time.Now().Add(refreshGracePeriod)) {
		if session.GetRefreshToken() != "" {
			return &ValidationResult{Authenticated: true, NeedsRefresh: true}, nil
		}
		return &ValidationResult{Authenticated: true}, nil
	}

	return &ValidationResult{Authenticated: true}, nil
}

// BuildAuthParams constructs authorization parameters for the provider.
// It includes the "offline_access" scope by default for refresh token support.
func (p *BaseProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
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
		Scopes:    deduplicateScopes(scopes),
	}, nil
}

// HandleTokenRefresh processes provider-specific token refresh logic.
// By default, it does nothing and assumes the standard token response is sufficient.
func (p *BaseProvider) HandleTokenRefresh(tokenData *TokenResult) error {
	return nil
}

// deduplicateScopes removes duplicate scopes from a slice while preserving order.
func deduplicateScopes(scopes []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}

	return result
}

// ValidateConfig checks provider-specific configuration requirements.
// By default, it assumes the configuration is valid.
func (p *BaseProvider) ValidateConfig() error {
	return nil
}

// NewBaseProvider creates a new BaseProvider instance.
// This can be used when a generic OIDC provider is sufficient.
func NewBaseProvider() *BaseProvider {
	return &BaseProvider{}
}
