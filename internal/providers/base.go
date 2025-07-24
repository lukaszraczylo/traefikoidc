package providers

import (
	"net/url"
	"strings"
	"time"
)

// BaseProvider provides a common foundation for OIDC provider implementations.
// It can be embedded in specific provider structs to share common logic.
type BaseProvider struct {
	// Common configuration or dependencies can be added here.
}

// GetType returns the default provider type, which is Generic.
// This should be overridden by specific provider implementations.
func (p *BaseProvider) GetType() ProviderType {
	return ProviderTypeGeneric
}

// GetCapabilities returns a default set of capabilities for a generic OIDC provider.
// This can be overridden by specific providers to declare their unique features.
func (p *BaseProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		PreferredTokenValidation:   "id",
	}
}

// ValidateTokens provides a default token validation implementation.
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

// ValidateTokenExpiry provides common token expiry validation logic that can be used by all providers.
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

// BuildAuthParams provides a default implementation for building authorization parameters.
// It includes the "offline_access" scope by default.
func (p *BaseProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	// Ensure offline_access is included if not already present
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

// HandleTokenRefresh provides a default implementation for token refresh handling.
// By default, it does nothing and assumes the standard token response is sufficient.
func (p *BaseProvider) HandleTokenRefresh(tokenData *TokenResult) error {
	// No provider-specific refresh handling by default.
	return nil
}

// ValidateConfig provides a default implementation for configuration validation.
// By default, it assumes the configuration is valid.
func (p *BaseProvider) ValidateConfig() error {
	// No provider-specific config validation by default.
	return nil
}

// NewBaseProvider creates a new BaseProvider.
func NewBaseProvider() *BaseProvider {
	return &BaseProvider{}
}
