package traefikoidc

import (
	"strings"
)

// ScopeFilterLogger interface for dependency injection
type ScopeFilterLogger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ScopeFilter handles OAuth scope validation and filtering based on provider capabilities.
type ScopeFilter struct {
	logger ScopeFilterLogger
}

// NewScopeFilter creates a new ScopeFilter instance.
func NewScopeFilter(logger ScopeFilterLogger) *ScopeFilter {
	return &ScopeFilter{
		logger: logger,
	}
}

// FilterSupportedScopes returns the intersection of requested and supported scopes.
// It preserves the order of requested scopes and returns all requested scopes
// if supportedScopes is empty (fallback for providers without scopes_supported).
//
// Parameters:
//   - requestedScopes: Scopes the application wants to request
//   - supportedScopes: Scopes advertised by the provider (from discovery doc)
//   - providerURL: Provider URL for logging purposes
//
// Returns:
//   - Filtered list of scopes safe to request from the provider
func (sf *ScopeFilter) FilterSupportedScopes(requestedScopes, supportedScopes []string, providerURL string) []string {
	// If no supported scopes declared, return all requested (backward compatibility)
	if len(supportedScopes) == 0 {
		sf.logger.Debugf("ScopeFilter: Provider %s has no scopes_supported in discovery doc, using all requested scopes", providerURL)
		return requestedScopes
	}

	// Build lookup map for efficient checking
	supportedMap := make(map[string]bool, len(supportedScopes))
	for _, scope := range supportedScopes {
		supportedMap[strings.TrimSpace(scope)] = true
	}

	// Filter requested scopes
	filtered := make([]string, 0, len(requestedScopes))
	removed := make([]string, 0)

	for _, scope := range requestedScopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed == "" {
			continue
		}

		if supportedMap[trimmed] {
			filtered = append(filtered, trimmed)
		} else {
			removed = append(removed, trimmed)
		}
	}

	// Log filtering results
	if len(removed) > 0 {
		sf.logger.Infof("ScopeFilter: Filtered unsupported scopes for %s: %v (not in provider's scopes_supported)",
			providerURL, removed)
		sf.logger.Debugf("ScopeFilter: Provider %s supported scopes: %v", providerURL, supportedScopes)
		sf.logger.Debugf("ScopeFilter: Final filtered scopes: %v", filtered)
	} else {
		sf.logger.Debugf("ScopeFilter: All requested scopes are supported by %s", providerURL)
	}

	// If all scopes were filtered out, return at least "openid"
	if len(filtered) == 0 {
		sf.logger.Infof("ScopeFilter: All scopes filtered out for %s, falling back to 'openid'", providerURL)
		return []string{"openid"}
	}

	return filtered
}

// EnsureOpenIDScope ensures "openid" scope is present in the scope list.
// This is required for OIDC compliance.
func (sf *ScopeFilter) EnsureOpenIDScope(scopes []string) []string {
	for _, scope := range scopes {
		if scope == "openid" {
			return scopes
		}
	}

	sf.logger.Debugf("ScopeFilter: Adding required 'openid' scope")
	return append([]string{"openid"}, scopes...)
}
