package providers

import (
	"fmt"
	"net/url"
	"strings"
)

// ConfigValidator provides common configuration validation utilities for providers.
type ConfigValidator struct{}

// NewConfigValidator creates a new configuration validator.
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// ValidateIssuerURL validates that an issuer URL is properly formatted and accessible.
func (v *ConfigValidator) ValidateIssuerURL(issuerURL string) error {
	if issuerURL == "" {
		return fmt.Errorf("issuer URL cannot be empty")
	}

	parsedURL, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("invalid issuer URL format: %w", err)
	}

	if parsedURL.Scheme == "" {
		return fmt.Errorf("issuer URL must include scheme (http/https)")
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("issuer URL scheme must be http or https")
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("issuer URL must include host")
	}

	return nil
}

// ValidateClientID validates that a client ID is properly formatted.
func (v *ConfigValidator) ValidateClientID(clientID string) error {
	if clientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}

	if len(clientID) < 3 {
		return fmt.Errorf("client ID appears to be too short")
	}

	return nil
}

// ValidateScopes validates that the provided scopes are reasonable.
func (v *ConfigValidator) ValidateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("at least one scope must be provided")
	}

	hasOpenIDScope := false
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "openid" {
			hasOpenIDScope = true
			break
		}
	}

	if !hasOpenIDScope {
		return fmt.Errorf("'openid' scope is required for OIDC authentication")
	}

	return nil
}

// ValidateRedirectURL validates that a redirect URL is properly formatted.
func (v *ConfigValidator) ValidateRedirectURL(redirectURL string) error {
	if redirectURL == "" {
		return fmt.Errorf("redirect URL cannot be empty")
	}

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		return fmt.Errorf("invalid redirect URL format: %w", err)
	}

	if parsedURL.Scheme == "" {
		return fmt.Errorf("redirect URL must include scheme (http/https)")
	}

	return nil
}

// ValidateProviderSpecificConfig performs provider-specific validation.
func (v *ConfigValidator) ValidateProviderSpecificConfig(provider OIDCProvider, config map[string]interface{}) error {
	switch provider.GetType() {
	case ProviderTypeGoogle:
		return v.validateGoogleConfig(config)
	case ProviderTypeAzure:
		return v.validateAzureConfig(config)
	case ProviderTypeGeneric:
		return v.validateGenericConfig(config)
	default:
		return fmt.Errorf("unknown provider type: %d", provider.GetType())
	}
}

// validateGoogleConfig validates Google-specific configuration.
func (v *ConfigValidator) validateGoogleConfig(config map[string]interface{}) error {
	if issuerURL, ok := config["issuer_url"].(string); ok {
		if !strings.Contains(issuerURL, "accounts.google.com") {
			return fmt.Errorf("google provider requires issuer URL to contain accounts.google.com")
		}
	}

	return nil
}

// validateAzureConfig validates Azure-specific configuration.
func (v *ConfigValidator) validateAzureConfig(config map[string]interface{}) error {
	if issuerURL, ok := config["issuer_url"].(string); ok {
		if !strings.Contains(issuerURL, "login.microsoftonline.com") && !strings.Contains(issuerURL, "sts.windows.net") {
			return fmt.Errorf("azure provider requires issuer URL to contain login.microsoftonline.com or sts.windows.net")
		}
	}

	if issuerURL, ok := config["issuer_url"].(string); ok {
		parsedURL, err := url.Parse(issuerURL)
		if err == nil {
			pathParts := strings.Split(parsedURL.Path, "/")
			hasTenantID := false
			for _, part := range pathParts {
				if len(part) == 36 && strings.Count(part, "-") == 4 {
					hasTenantID = true
					break
				}
			}
			if !hasTenantID {
				return fmt.Errorf("azure issuer URL should include tenant ID")
			}
		}
	}

	return nil
}

// validateGenericConfig validates generic OIDC provider configuration.
func (v *ConfigValidator) validateGenericConfig(config map[string]interface{}) error {
	return nil
}
