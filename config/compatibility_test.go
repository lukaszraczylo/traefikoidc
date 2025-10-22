//go:build !yaegi

package config

import (
	"testing"

	"github.com/lukaszraczylo/traefikoidc/internal/features"
)

// NewLegacyAdapter Tests
func TestNewLegacyAdapter(t *testing.T) {
	unified := NewUnifiedConfig()
	unified.Provider.IssuerURL = "https://provider.example.com"
	unified.Provider.ClientID = "test-client"
	unified.Provider.ClientSecret = "test-secret"

	adapter := NewLegacyAdapter(unified)

	if adapter == nil {
		t.Fatal("Expected NewLegacyAdapter to return non-nil")
	}

	if adapter.unified != unified {
		t.Error("Expected adapter to reference the unified config")
	}

	if adapter.adapter == nil {
		t.Error("Expected internal adapter to be initialized")
	}
}

// ToOldConfig Tests
func TestLegacyAdapter_ToOldConfig(t *testing.T) {
	unified := NewUnifiedConfig()
	unified.Provider.IssuerURL = "https://issuer.example.com"
	unified.Provider.ClientID = "client-123"
	unified.Provider.ClientSecret = "secret-456"
	unified.Provider.RedirectURL = "https://app.example.com/callback"
	unified.Provider.LogoutURL = "/logout"
	unified.Provider.PostLogoutRedirectURI = "https://app.example.com"
	unified.Provider.Scopes = []string{"openid", "profile"}
	unified.Provider.OverrideScopes = true
	unified.Session.EncryptionKey = "test-encryption-key-32-chars!!"
	unified.Session.Domain = "example.com"
	unified.Security.ForceHTTPS = true
	unified.Security.EnablePKCE = true
	unified.Security.AllowedUsers = []string{"user@example.com"}
	unified.Security.AllowedUserDomains = []string{"example.com"}
	unified.Security.AllowedRolesAndGroups = []string{"admin"}
	unified.Security.ExcludedURLs = []string{"/health"}
	unified.RateLimit.RequestsPerSecond = 100
	unified.Logging.Level = "debug"
	unified.Middleware.CustomHeaders = map[string]string{
		"X-Header-1": "value1",
		"X-Header-2": "value2",
	}

	adapter := NewLegacyAdapter(unified)
	oldConfig := adapter.ToOldConfig()

	if oldConfig == nil {
		t.Fatal("Expected ToOldConfig to return non-nil")
	}

	// ToOldConfig behavior depends on feature flag
	if !features.IsUnifiedConfigEnabled() {
		// When feature is disabled, returns default config
		if oldConfig.ProviderURL == "" {
			t.Log("Feature flag disabled - ToOldConfig returns default config")
		}
		return
	}

	// When feature is enabled, verify all fields were correctly mapped
	if oldConfig.ProviderURL != unified.Provider.IssuerURL {
		t.Errorf("Expected ProviderURL '%s', got '%s'", unified.Provider.IssuerURL, oldConfig.ProviderURL)
	}

	if oldConfig.ClientID != unified.Provider.ClientID {
		t.Errorf("Expected ClientID '%s', got '%s'", unified.Provider.ClientID, oldConfig.ClientID)
	}

	if oldConfig.ClientSecret != unified.Provider.ClientSecret {
		t.Errorf("Expected ClientSecret '%s', got '%s'", unified.Provider.ClientSecret, oldConfig.ClientSecret)
	}

	if oldConfig.CallbackURL != unified.Provider.RedirectURL {
		t.Error("Expected CallbackURL to match RedirectURL")
	}

	if oldConfig.LogoutURL != unified.Provider.LogoutURL {
		t.Error("Expected LogoutURL to match")
	}

	if oldConfig.ForceHTTPS != unified.Security.ForceHTTPS {
		t.Error("Expected ForceHTTPS to match")
	}

	if oldConfig.EnablePKCE != unified.Security.EnablePKCE {
		t.Error("Expected EnablePKCE to match")
	}

	if oldConfig.RateLimit != unified.RateLimit.RequestsPerSecond {
		t.Errorf("Expected RateLimit %d, got %d", unified.RateLimit.RequestsPerSecond, oldConfig.RateLimit)
	}

	if len(oldConfig.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(oldConfig.Headers))
	}
}

// convertHeaders Tests
func TestLegacyAdapter_convertHeaders(t *testing.T) {
	unified := NewUnifiedConfig()
	unified.Middleware.CustomHeaders = map[string]string{
		"X-Custom-Header-1": "value1",
		"X-Custom-Header-2": "value2",
		"X-Custom-Header-3": "value3",
	}

	adapter := NewLegacyAdapter(unified)
	headers := adapter.convertHeaders()

	if len(headers) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(headers))
	}

	// Check that headers were converted
	headerMap := make(map[string]string)
	for _, h := range headers {
		headerMap[h.Name] = h.Value
	}

	if headerMap["X-Custom-Header-1"] != "value1" {
		t.Error("Expected X-Custom-Header-1 to have value 'value1'")
	}

	if headerMap["X-Custom-Header-2"] != "value2" {
		t.Error("Expected X-Custom-Header-2 to have value 'value2'")
	}
}

func TestLegacyAdapter_convertHeaders_Empty(t *testing.T) {
	unified := NewUnifiedConfig()
	// No custom headers

	adapter := NewLegacyAdapter(unified)
	headers := adapter.convertHeaders()

	if len(headers) != 0 {
		t.Errorf("Expected 0 headers, got %d", len(headers))
	}
}

// GetConfigInterface Tests
func TestGetConfigInterface(t *testing.T) {
	cfg := GetConfigInterface()

	if cfg == nil {
		t.Fatal("Expected GetConfigInterface to return non-nil")
	}

	// Should return either UnifiedConfig or Config depending on feature flag
	_, isUnified := cfg.(*UnifiedConfig)
	_, isOld := cfg.(*Config)

	if !isUnified && !isOld {
		t.Error("Expected either *UnifiedConfig or *Config")
	}

	// Verify consistency with feature flag
	if features.IsUnifiedConfigEnabled() {
		if !isUnified {
			t.Error("Expected *UnifiedConfig when unified config is enabled")
		}
	} else {
		if !isOld {
			t.Error("Expected *Config when unified config is disabled")
		}
	}
}

// ValidateConfig Tests
func TestValidateConfig_UnifiedConfig(t *testing.T) {
	unified := NewUnifiedConfig()
	unified.Provider.IssuerURL = "https://provider.example.com"
	unified.Provider.ClientID = "client-id"
	unified.Provider.ClientSecret = "client-secret"
	unified.Session.EncryptionKey = "encryption-key-32-characters!!"

	err := ValidateConfig(unified)
	// Should succeed regardless of feature flag since we're passing the right type
	if err != nil {
		t.Errorf("Expected valid unified config to pass validation, got: %v", err)
	}
}

func TestValidateConfig_OldConfig(t *testing.T) {
	old := CreateConfig()
	old.ProviderURL = "https://provider.example.com"
	old.ClientID = "client-id"
	old.ClientSecret = "client-secret"
	old.SessionEncryptionKey = "encryption-key-32-characters!!"

	err := ValidateConfig(old)
	if err != nil {
		t.Errorf("Expected valid old config to pass validation, got: %v", err)
	}
}

func TestValidateConfig_InvalidType(t *testing.T) {
	// Pass something that's not a config
	err := ValidateConfig("not a config")
	if err != nil {
		t.Errorf("Expected nil for unknown type, got: %v", err)
	}
}

// Config.Validate Tests
func TestConfig_Validate_Valid(t *testing.T) {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://provider.example.com"
	cfg.ClientID = "client-id"
	cfg.ClientSecret = "client-secret"
	cfg.SessionEncryptionKey = "encryption-key-32-characters!!"

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected valid config to pass, got: %v", err)
	}
}

func TestConfig_Validate_MissingProviderURL(t *testing.T) {
	cfg := CreateConfig()
	cfg.ClientID = "client-id"
	cfg.ClientSecret = "client-secret"

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for missing ProviderURL")
	}

	// Check if it's a ValidationErrors type
	if verrs, ok := err.(ValidationErrors); ok {
		found := false
		for _, verr := range verrs {
			if verr.Field == "ProviderURL" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected ProviderURL validation error")
		}
	}
}

func TestConfig_Validate_MissingClientID(t *testing.T) {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://provider.example.com"
	cfg.ClientSecret = "client-secret"

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for missing ClientID")
	}

	if verrs, ok := err.(ValidationErrors); ok {
		found := false
		for _, verr := range verrs {
			if verr.Field == "ClientID" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected ClientID validation error")
		}
	}
}

func TestConfig_Validate_MissingClientSecret_NoPKCE(t *testing.T) {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://provider.example.com"
	cfg.ClientID = "client-id"
	cfg.EnablePKCE = false

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for missing ClientSecret without PKCE")
	}

	if verrs, ok := err.(ValidationErrors); ok {
		found := false
		for _, verr := range verrs {
			if verr.Field == "ClientSecret" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected ClientSecret validation error")
		}
	}
}

func TestConfig_Validate_MissingClientSecret_WithPKCE(t *testing.T) {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://provider.example.com"
	cfg.ClientID = "client-id"
	cfg.EnablePKCE = true // PKCE enabled, so ClientSecret not required

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error with PKCE enabled and no ClientSecret, got: %v", err)
	}
}

func TestConfig_Validate_ShortEncryptionKey(t *testing.T) {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://provider.example.com"
	cfg.ClientID = "client-id"
	cfg.ClientSecret = "client-secret"
	cfg.SessionEncryptionKey = "short" // Too short

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for short encryption key")
	}

	if verrs, ok := err.(ValidationErrors); ok {
		found := false
		for _, verr := range verrs {
			if verr.Field == "SessionEncryptionKey" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected SessionEncryptionKey validation error")
		}
	}
}

func TestConfig_Validate_MultipleErrors(t *testing.T) {
	cfg := CreateConfig()
	// Missing ProviderURL, ClientID, and ClientSecret

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Expected validation errors")
	}

	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatal("Expected ValidationErrors type")
	}

	if len(verrs) < 2 {
		t.Errorf("Expected at least 2 validation errors, got %d", len(verrs))
	}
}
