// Package providers implements a universal OIDC provider abstraction system.
// It provides a clean interface for different OIDC providers (Google, Azure, Generic)
// with provider-specific logic encapsulated in separate implementations.
package providers

import (
	"net/url"
	"time"
)

// TokenVerifier defines the interface for token verification.
type TokenVerifier interface {
	VerifyToken(token string) error
}

// TokenCache defines the interface for a token cache.
type TokenCache interface {
	Get(key string) (map[string]interface{}, bool)
}

// ProviderType is an enumeration for identifying different OIDC providers.
type ProviderType int

const (
	// ProviderTypeGeneric represents a standard, compliant OIDC provider.
	ProviderTypeGeneric ProviderType = iota
	// ProviderTypeGoogle represents Google as the OIDC provider.
	ProviderTypeGoogle
	// ProviderTypeAzure represents Microsoft Azure AD as the OIDC provider.
	ProviderTypeAzure
)

// ProviderCapabilities defines the specific features and behaviors of an OIDC provider.
type ProviderCapabilities struct {
	// SupportsRefreshTokens indicates if the provider issues refresh tokens.
	SupportsRefreshTokens bool
	// RequiresOfflineAccessScope indicates if the "offline_access" scope is needed for refresh tokens.
	RequiresOfflineAccessScope bool
	// RequiresPromptConsent indicates if "prompt=consent" is needed to ensure a refresh token is issued.
	RequiresPromptConsent bool
	// PreferredTokenValidation specifies the recommended token type to validate (e.g., "access" or "id").
	PreferredTokenValidation string
}

// ValidationResult holds the outcome of a token validation check.
type ValidationResult struct {
	// Authenticated is true if the token is valid and the user is authenticated.
	Authenticated bool
	// NeedsRefresh is true if the token is approaching its expiry and should be refreshed.
	NeedsRefresh bool
	// IsExpired is true if the token has expired or is invalid.
	IsExpired bool
}

// AuthParams contains the provider-specific parameters for building the authorization URL.
type AuthParams struct {
	// URLValues are the query parameters to be added to the authorization URL.
	URLValues url.Values
	// Scopes is the list of scopes to be requested.
	Scopes []string
}

// TokenResult holds the tokens returned by the provider.
type TokenResult struct {
	// IDToken is the OIDC ID token.
	IDToken string
	// AccessToken is the OAuth2 access token.
	AccessToken string
	// RefreshToken is the OAuth2 refresh token.
	RefreshToken string
}

// OIDCProvider defines the interface for an OIDC provider implementation.
// This abstraction allows for provider-specific logic to be encapsulated.
type OIDCProvider interface {
	// GetType returns the type of the provider (e.g., Google, Azure, Generic).
	GetType() ProviderType

	// GetCapabilities returns the feature set of the provider.
	GetCapabilities() ProviderCapabilities

	// ValidateTokens performs token validation according to the provider's specific rules.
	// It should check the validity of the access and/or ID tokens from the session.
	ValidateTokens(session Session, verifier TokenVerifier, tokenCache TokenCache, refreshGracePeriod time.Duration) (*ValidationResult, error)

	// BuildAuthParams modifies the authorization URL parameters for the provider.
	// This can be used to add provider-specific parameters like "access_type" for Google.
	BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error)

	// HandleTokenRefresh manages the token refresh process for the provider.
	// It can modify the token request or handle the response as needed.
	HandleTokenRefresh(tokenData *TokenResult) error

	// ValidateConfig checks if the user's configuration is valid for this provider.
	ValidateConfig() error
}

// Session represents the session data required by providers for validation.
// This interface decouples the providers from the main session management implementation.
type Session interface {
	GetIDToken() string
	GetAccessToken() string
	GetRefreshToken() string
	GetAuthenticated() bool
}
