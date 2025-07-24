package providers

import (
	"net/url"
	"strings"
	"time"
)

// Adapter facilitates communication between the legacy TraefikOIDC struct and the new provider system.
type Adapter struct {
	provider       OIDCProvider
	legacySettings LegacySettings
	tokenVerifier  TokenVerifier
	tokenCache     TokenCache
}

// LegacySettings provides the adapter with access to the original configuration values.
type LegacySettings interface {
	GetIssuerURL() string
	GetAuthURL() string
	GetScopes() []string
	IsPKCEEnabled() bool
	GetClientID() string
	GetRefreshGracePeriod() time.Duration
	IsOverrideScopes() bool
}

// NewAdapter creates a new adapter for a given provider and legacy settings.
func NewAdapter(provider OIDCProvider, settings LegacySettings, tokenVerifier TokenVerifier, tokenCache TokenCache) *Adapter {
	return &Adapter{
		provider:       provider,
		legacySettings: settings,
		tokenVerifier:  tokenVerifier,
		tokenCache:     tokenCache,
	}
}

// BuildAuthURL constructs the authentication URL using the adapted provider.
func (a *Adapter) BuildAuthURL(redirectURL, state, nonce, codeChallenge string) string {
	params := url.Values{}
	params.Set("client_id", a.legacySettings.GetClientID())
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirectURL)
	params.Set("state", state)
	params.Set("nonce", nonce)

	if a.legacySettings.IsPKCEEnabled() && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	scopes := a.legacySettings.GetScopes()

	// When overrideScopes is true, use exactly the scopes provided without modification
	if a.legacySettings.IsOverrideScopes() {
		// Use scopes as-is, don't let provider add anything
		finalParams := params
		finalParams.Set("scope", strings.Join(scopes, " "))

		// For provider-specific parameters, we still need to check the provider type
		switch a.provider.GetType() {
		case ProviderTypeGoogle:
			// Google-specific parameters
			finalParams.Set("access_type", "offline")
			finalParams.Set("prompt", "consent")
		case ProviderTypeAzure:
			// Azure-specific parameters
			finalParams.Set("response_mode", "query")
		}

		return a.buildURLWithParams(a.legacySettings.GetAuthURL(), finalParams)
	}

	// When overrideScopes is false, let the provider add necessary scopes
	authParams, err := a.provider.BuildAuthParams(params, scopes)
	if err != nil {
		// Log the error appropriately
		return ""
	}

	finalParams := authParams.URLValues
	finalParams.Set("scope", strings.Join(authParams.Scopes, " "))

	// Build the full URL with params
	return a.buildURLWithParams(a.legacySettings.GetAuthURL(), finalParams)
}

// buildURLWithParams takes a base URL and query parameters and constructs a full URL string.
// If the baseURL is relative (doesn't start with http/https), it prepends the scheme and host
// from the configured issuerURL.
func (a *Adapter) buildURLWithParams(baseURL string, params url.Values) string {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		// Relative URL - resolve against issuer URL
		issuerURLParsed, err := url.Parse(a.legacySettings.GetIssuerURL())
		if err != nil {
			return ""
		}

		baseURLParsed, err := url.Parse(baseURL)
		if err != nil {
			return ""
		}

		resolvedURL := issuerURLParsed.ResolveReference(baseURLParsed)
		resolvedURL.RawQuery = params.Encode()
		return resolvedURL.String()
	}

	// Absolute URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	u.RawQuery = params.Encode()
	return u.String()
}

// ValidateTokens validates tokens using the adapted provider.
func (a *Adapter) ValidateTokens(session Session) (*ValidationResult, error) {
	return a.provider.ValidateTokens(session, a.tokenVerifier, a.tokenCache, a.legacySettings.GetRefreshGracePeriod())
}

// GetType returns the underlying provider's type.
func (a *Adapter) GetType() ProviderType {
	return a.provider.GetType()
}
