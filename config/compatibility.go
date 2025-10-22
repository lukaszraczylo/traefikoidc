// Package config provides backward compatibility for legacy configuration
package config

import (
	"fmt"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/compat"
	"github.com/lukaszraczylo/traefikoidc/internal/features"
)

// LegacyAdapter provides backward compatibility for old Config struct
type LegacyAdapter struct {
	unified *UnifiedConfig
	adapter *compat.ConfigAdapter
}

// NewLegacyAdapter creates a new legacy adapter from unified config
func NewLegacyAdapter(unified *UnifiedConfig) *LegacyAdapter {
	adapter := compat.NewConfigAdapter(unified)

	// Register getters for commonly used fields
	adapter.RegisterGetter("ProviderURL", func() interface{} {
		return unified.Provider.IssuerURL
	})
	adapter.RegisterGetter("ClientID", func() interface{} {
		return unified.Provider.ClientID
	})
	adapter.RegisterGetter("ClientSecret", func() interface{} {
		return unified.Provider.ClientSecret
	})
	adapter.RegisterGetter("CallbackURL", func() interface{} {
		return unified.Provider.RedirectURL
	})
	adapter.RegisterGetter("LogoutURL", func() interface{} {
		return unified.Provider.LogoutURL
	})
	adapter.RegisterGetter("PostLogoutRedirectURI", func() interface{} {
		return unified.Provider.PostLogoutRedirectURI
	})
	adapter.RegisterGetter("SessionEncryptionKey", func() interface{} {
		return unified.Session.EncryptionKey
	})
	adapter.RegisterGetter("ForceHTTPS", func() interface{} {
		return unified.Security.ForceHTTPS
	})
	adapter.RegisterGetter("LogLevel", func() interface{} {
		return unified.Logging.Level
	})
	adapter.RegisterGetter("Scopes", func() interface{} {
		return unified.Provider.Scopes
	})
	adapter.RegisterGetter("OverrideScopes", func() interface{} {
		return unified.Provider.OverrideScopes
	})
	adapter.RegisterGetter("AllowedUsers", func() interface{} {
		return unified.Security.AllowedUsers
	})
	adapter.RegisterGetter("AllowedUserDomains", func() interface{} {
		return unified.Security.AllowedUserDomains
	})
	adapter.RegisterGetter("AllowedRolesAndGroups", func() interface{} {
		return unified.Security.AllowedRolesAndGroups
	})
	adapter.RegisterGetter("ExcludedURLs", func() interface{} {
		return unified.Security.ExcludedURLs
	})
	adapter.RegisterGetter("EnablePKCE", func() interface{} {
		return unified.Security.EnablePKCE
	})
	adapter.RegisterGetter("RateLimit", func() interface{} {
		return unified.RateLimit.RequestsPerSecond
	})
	adapter.RegisterGetter("RefreshGracePeriodSeconds", func() interface{} {
		return int(unified.Token.RefreshGracePeriod.Seconds())
	})
	adapter.RegisterGetter("CookieDomain", func() interface{} {
		return unified.Session.Domain
	})
	adapter.RegisterGetter("SecurityHeaders", func() interface{} {
		return unified.Security.Headers
	})

	return &LegacyAdapter{
		unified: unified,
		adapter: adapter,
	}
}

// ToOldConfig converts unified config to old Config struct format
func (la *LegacyAdapter) ToOldConfig() *Config {
	// Use feature flags to determine behavior
	if !features.IsUnifiedConfigEnabled() {
		// Return existing Config if unified config not enabled
		return CreateConfig()
	}

	cfg := &Config{
		ProviderURL:               la.unified.Provider.IssuerURL,
		ClientID:                  la.unified.Provider.ClientID,
		ClientSecret:              la.unified.Provider.ClientSecret,
		CallbackURL:               la.unified.Provider.RedirectURL,
		LogoutURL:                 la.unified.Provider.LogoutURL,
		PostLogoutRedirectURI:     la.unified.Provider.PostLogoutRedirectURI,
		SessionEncryptionKey:      la.unified.Session.EncryptionKey,
		ForceHTTPS:                la.unified.Security.ForceHTTPS,
		LogLevel:                  la.unified.Logging.Level,
		Scopes:                    la.unified.Provider.Scopes,
		OverrideScopes:            la.unified.Provider.OverrideScopes,
		AllowedUsers:              la.unified.Security.AllowedUsers,
		AllowedUserDomains:        la.unified.Security.AllowedUserDomains,
		AllowedRolesAndGroups:     la.unified.Security.AllowedRolesAndGroups,
		ExcludedURLs:              la.unified.Security.ExcludedURLs,
		EnablePKCE:                la.unified.Security.EnablePKCE,
		RateLimit:                 la.unified.RateLimit.RequestsPerSecond,
		RefreshGracePeriodSeconds: int(la.unified.Token.RefreshGracePeriod.Seconds()),
		Headers:                   la.convertHeaders(),
		CookieDomain:              la.unified.Session.Domain,
		SecurityHeaders:           la.unified.Security.Headers,
	}

	return cfg
}

// convertHeaders converts unified header config to old format
func (la *LegacyAdapter) convertHeaders() []HeaderConfig {
	headers := make([]HeaderConfig, 0)

	for name, value := range la.unified.Middleware.CustomHeaders {
		headers = append(headers, HeaderConfig{
			Name:  name,
			Value: value,
		})
	}

	return headers
}

// FromOldConfig creates unified config from old Config struct
func FromOldConfig(old *Config) *UnifiedConfig {
	unified := NewUnifiedConfig()

	// Map provider settings
	unified.Provider.IssuerURL = old.ProviderURL
	unified.Provider.ClientID = old.ClientID
	unified.Provider.ClientSecret = old.ClientSecret
	unified.Provider.RedirectURL = old.CallbackURL
	unified.Provider.LogoutURL = old.LogoutURL
	unified.Provider.PostLogoutRedirectURI = old.PostLogoutRedirectURI
	unified.Provider.Scopes = old.Scopes
	unified.Provider.OverrideScopes = old.OverrideScopes

	// Map session settings
	unified.Session.EncryptionKey = old.SessionEncryptionKey
	unified.Session.Domain = old.CookieDomain

	// Map security settings
	unified.Security.ForceHTTPS = old.ForceHTTPS
	unified.Security.EnablePKCE = old.EnablePKCE
	unified.Security.AllowedUsers = old.AllowedUsers
	unified.Security.AllowedUserDomains = old.AllowedUserDomains
	unified.Security.AllowedRolesAndGroups = old.AllowedRolesAndGroups
	unified.Security.ExcludedURLs = old.ExcludedURLs
	unified.Security.Headers = old.SecurityHeaders

	// Map rate limiting
	unified.RateLimit.RequestsPerSecond = old.RateLimit
	unified.RateLimit.Enabled = old.RateLimit > 0

	// Map token settings
	unified.Token.RefreshGracePeriod = timeSecondsToDuration(old.RefreshGracePeriodSeconds)

	// Map logging
	unified.Logging.Level = old.LogLevel

	// Map custom headers
	if len(old.Headers) > 0 {
		unified.Middleware.CustomHeaders = make(map[string]string)
		for _, header := range old.Headers {
			unified.Middleware.CustomHeaders[header.Name] = header.Value
		}
	}

	// Store original config in legacy field for reference
	unified.Legacy["original"] = old

	return unified
}

// timeSecondsToDuration converts seconds to time.Duration
func timeSecondsToDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

// GetConfigInterface returns appropriate config based on feature flag
func GetConfigInterface() interface{} {
	if features.IsUnifiedConfigEnabled() {
		return NewUnifiedConfig()
	}
	return CreateConfig()
}

// ValidateConfig validates config based on feature flag
func ValidateConfig(cfg interface{}) error {
	if features.IsUnifiedConfigEnabled() {
		if unified, ok := cfg.(*UnifiedConfig); ok {
			return unified.Validate()
		}
	}

	// Fall back to old validation if available
	if old, ok := cfg.(*Config); ok {
		return old.Validate()
	}

	return nil
}

// Add Validate method to old Config for compatibility
func (c *Config) Validate() error {
	var errors ValidationErrors

	// Basic validation for old config
	if c.ProviderURL == "" {
		errors = append(errors, ValidationError{
			Field:   "ProviderURL",
			Message: "provider URL is required",
		})
	}

	if c.ClientID == "" {
		errors = append(errors, ValidationError{
			Field:   "ClientID",
			Message: "client ID is required",
		})
	}

	if c.ClientSecret == "" && !c.EnablePKCE {
		errors = append(errors, ValidationError{
			Field:   "ClientSecret",
			Message: "client secret is required (or enable PKCE)",
		})
	}

	if c.SessionEncryptionKey != "" && len(c.SessionEncryptionKey) < minEncryptionKeyLength {
		errors = append(errors, ValidationError{
			Field:   "SessionEncryptionKey",
			Message: fmt.Sprintf("encryption key must be at least %d characters", minEncryptionKeyLength),
			Value:   len(c.SessionEncryptionKey),
		})
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}
