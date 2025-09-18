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
	ProviderTypeGeneric ProviderType = iota
	ProviderTypeGoogle
	ProviderTypeAzure
)

// ProviderCapabilities defines the specific features and behaviors of an OIDC provider.
type ProviderCapabilities struct {
	PreferredTokenValidation   string
	SupportsRefreshTokens      bool
	RequiresOfflineAccessScope bool
	RequiresPromptConsent      bool
}

// ValidationResult holds the outcome of a token validation check.
type ValidationResult struct {
	Authenticated bool
	NeedsRefresh  bool
	IsExpired     bool
}

// AuthParams contains the provider-specific parameters for building the authorization URL.
type AuthParams struct {
	URLValues url.Values
	Scopes    []string
}

// TokenResult holds the tokens returned by the provider.
type TokenResult struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

// This abstraction allows for provider-specific logic to be encapsulated.
type OIDCProvider interface {
	GetType() ProviderType

	GetCapabilities() ProviderCapabilities

	ValidateTokens(session Session, verifier TokenVerifier, tokenCache TokenCache, refreshGracePeriod time.Duration) (*ValidationResult, error)

	BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error)

	HandleTokenRefresh(tokenData *TokenResult) error

	ValidateConfig() error
}

// This interface decouples the providers from the main session management implementation.
type Session interface {
	GetIDToken() string
	GetAccessToken() string
	GetRefreshToken() string
	GetAuthenticated() bool
}
