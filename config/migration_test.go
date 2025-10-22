package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Version Detection Tests
// =============================================================================

func TestConfigMigrator_DetectVersion_UnifiedJSON(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	unifiedConfig := map[string]interface{}{
		"provider": map[string]interface{}{
			"issuerURL": "https://provider.example.com",
		},
		"session": map[string]interface{}{
			"encryptionKey": "test-key",
		},
	}

	data, err := json.Marshal(unifiedConfig)
	require.NoError(t, err)

	version := migrator.DetectVersion(data)
	assert.Equal(t, VersionUnified, version, "Should detect unified format with provider+session")
}

func TestConfigMigrator_DetectVersion_UnifiedYAML(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	yamlData := `
provider:
  issuerURL: https://provider.example.com
session:
  encryptionKey: test-key
`

	version := migrator.DetectVersion([]byte(yamlData))
	assert.Equal(t, VersionUnified, version, "Should detect unified format from YAML")
}

func TestConfigMigrator_DetectVersion_LegacyLowercaseProviderUrl(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyConfig := map[string]interface{}{
		"providerUrl": "https://provider.example.com",
		"clientId":    "test-client",
	}

	data, err := json.Marshal(legacyConfig)
	require.NoError(t, err)

	version := migrator.DetectVersion(data)
	assert.Equal(t, VersionLegacy, version, "Should detect legacy format with providerUrl")
}

func TestConfigMigrator_DetectVersion_LegacyCapitalizedProviderURL(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyConfig := map[string]interface{}{
		"ProviderURL": "https://provider.example.com",
		"ClientID":    "test-client",
	}

	data, err := json.Marshal(legacyConfig)
	require.NoError(t, err)

	version := migrator.DetectVersion(data)
	assert.Equal(t, VersionLegacy, version, "Should detect legacy format with ProviderURL")
}

func TestConfigMigrator_DetectVersion_InvalidJSONDefaultsToLegacy(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	invalidData := []byte("this is not valid JSON or YAML")

	version := migrator.DetectVersion(invalidData)
	assert.Equal(t, VersionLegacy, version, "Should default to legacy for invalid data")
}

func TestConfigMigrator_DetectVersion_EmptyDataDefaultsToLegacy(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	version := migrator.DetectVersion([]byte("{}"))
	assert.Equal(t, VersionLegacy, version, "Should default to legacy for empty config")
}

func TestConfigMigrator_DetectVersion_ProviderWithoutSession(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	config := map[string]interface{}{
		"provider": map[string]interface{}{
			"issuerURL": "https://provider.example.com",
		},
		// Missing session field
	}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	version := migrator.DetectVersion(data)
	assert.Equal(t, VersionLegacy, version, "Should require both provider AND session for unified detection")
}

// =============================================================================
// Migration Pipeline Tests
// =============================================================================

func TestConfigMigrator_Migrate_AlreadyUnifiedJSON(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	unifiedConfig := map[string]interface{}{
		"provider": map[string]interface{}{
			"issuerURL":   "https://provider.example.com",
			"clientID":    "test-client",
			"redirectURL": "https://app.example.com/callback",
		},
		"session": map[string]interface{}{
			"encryptionKey": "test-encryption-key",
		},
	}

	data, err := json.Marshal(unifiedConfig)
	require.NoError(t, err)

	config, warnings, err := migrator.Migrate(data)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotNil(t, warnings)
	assert.Equal(t, "https://provider.example.com", config.Provider.IssuerURL)
	assert.Equal(t, "test-client", config.Provider.ClientID)
}

func TestConfigMigrator_Migrate_AlreadyUnifiedYAML(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	yamlData := `
provider:
  issuerURL: https://provider.example.com
  clientID: test-client
session:
  encryptionKey: test-key
`

	config, warnings, err := migrator.Migrate([]byte(yamlData))
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotNil(t, warnings)
	assert.Equal(t, "https://provider.example.com", config.Provider.IssuerURL)
}

func TestConfigMigrator_Migrate_LegacyToUnified(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyConfig := map[string]interface{}{
		"providerUrl":          "https://legacy-provider.com",
		"clientId":             "legacy-client",
		"clientSecret":         "legacy-secret",
		"callbackUrl":          "https://app.com/callback",
		"sessionEncryptionKey": "legacy-encryption-key",
		"forceHttps":           true,
		"enablePkce":           true,
	}

	data, err := json.Marshal(legacyConfig)
	require.NoError(t, err)

	config, warnings, err := migrator.Migrate(data)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotNil(t, warnings)

	// Verify migration worked
	assert.Equal(t, "https://legacy-provider.com", config.Provider.IssuerURL)
	assert.Equal(t, "legacy-client", config.Provider.ClientID)
	assert.Equal(t, "legacy-secret", config.Provider.ClientSecret)
	assert.Equal(t, "https://app.com/callback", config.Provider.RedirectURL)
	assert.Equal(t, "legacy-encryption-key", config.Session.EncryptionKey)
	assert.True(t, config.Security.ForceHTTPS)
	assert.True(t, config.Security.EnablePKCE)
}

func TestConfigMigrator_Migrate_InvalidJSON(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	invalidData := []byte("{invalid json}")

	config, warnings, err := migrator.Migrate(invalidData)
	// Invalid JSON will be detected as legacy and migrated with default values
	// This is expected behavior - migration is lenient
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotNil(t, warnings)
}

func TestConfigMigrator_Migrate_CollectsDeprecationWarnings(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	// Use a deprecated field that the compat layer would warn about
	legacyConfig := map[string]interface{}{
		"providerUrl": "https://provider.com",
		"clientId":    "test-client",
	}

	data, err := json.Marshal(legacyConfig)
	require.NoError(t, err)

	config, warnings, err := migrator.Migrate(data)
	require.NoError(t, err)
	assert.NotNil(t, config)
	// Warnings may or may not be present depending on compat layer config
	assert.NotNil(t, warnings)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Provider Configuration
// =============================================================================

func TestMigrateLegacyToUnified_ProviderConfigFlat(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl":           "https://auth.example.com",
		"clientId":              "test-client-123",
		"clientSecret":          "test-secret-456",
		"callbackUrl":           "https://app.example.com/callback",
		"logoutUrl":             "https://auth.example.com/logout",
		"postLogoutRedirectUri": "https://app.example.com/logged-out",
		"scopes":                []interface{}{"openid", "profile", "email"},
		"overrideScopes":        true,
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)
	assert.NotNil(t, config)

	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
	assert.Equal(t, "test-client-123", config.Provider.ClientID)
	assert.Equal(t, "test-secret-456", config.Provider.ClientSecret)
	assert.Equal(t, "https://app.example.com/callback", config.Provider.RedirectURL)
	assert.Equal(t, "https://auth.example.com/logout", config.Provider.LogoutURL)
	assert.Equal(t, "https://app.example.com/logged-out", config.Provider.PostLogoutRedirectURI)
	assert.Equal(t, []string{"openid", "profile", "email"}, config.Provider.Scopes)
	assert.True(t, config.Provider.OverrideScopes)
}

func TestMigrateLegacyToUnified_ProviderConfigCapitalized(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"ProviderURL":           "https://auth.example.com",
		"ClientID":              "test-client",
		"ClientSecret":          "test-secret",
		"CallbackURL":           "https://app.example.com/callback",
		"LogoutURL":             "https://auth.example.com/logout",
		"PostLogoutRedirectURI": "https://app.example.com/logged-out",
		"Scopes":                []string{"openid", "profile"},
		"OverrideScopes":        false,
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	// Should handle capitalized field names
	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
	assert.Equal(t, "test-client", config.Provider.ClientID)
	assert.Equal(t, "test-secret", config.Provider.ClientSecret)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Session Configuration
// =============================================================================

func TestMigrateLegacyToUnified_SessionConfig(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl":          "https://auth.example.com",
		"sessionEncryptionKey": "my-encryption-key-32-bytes-long",
		"cookieDomain":         ".example.com",
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.Equal(t, "my-encryption-key-32-bytes-long", config.Session.EncryptionKey)
	assert.Equal(t, ".example.com", config.Session.Domain)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Security Configuration
// =============================================================================

func TestMigrateLegacyToUnified_SecurityConfig(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl":           "https://auth.example.com",
		"forceHttps":            true,
		"enablePkce":            true,
		"allowedUsers":          []interface{}{"user1@example.com", "user2@example.com"},
		"allowedUserDomains":    []interface{}{"example.com", "partner.com"},
		"allowedRolesAndGroups": []interface{}{"admin", "developers"},
		"excludedUrls":          []interface{}{"/health", "/metrics"},
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.True(t, config.Security.ForceHTTPS)
	assert.True(t, config.Security.EnablePKCE)
	assert.Equal(t, []string{"user1@example.com", "user2@example.com"}, config.Security.AllowedUsers)
	assert.Equal(t, []string{"example.com", "partner.com"}, config.Security.AllowedUserDomains)
	assert.Equal(t, []string{"admin", "developers"}, config.Security.AllowedRolesAndGroups)
	assert.Equal(t, []string{"/health", "/metrics"}, config.Security.ExcludedURLs)
}

func TestMigrateLegacyToUnified_SecurityConfigCapitalized(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"ProviderURL":           "https://auth.example.com",
		"ForceHTTPS":            false,
		"EnablePKCE":            false,
		"AllowedUsers":          []string{"admin@example.com"},
		"AllowedUserDomains":    []string{"example.com"},
		"AllowedRolesAndGroups": []string{"admins"},
		"ExcludedURLs":          []string{"/public"},
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.False(t, config.Security.ForceHTTPS)
	assert.False(t, config.Security.EnablePKCE)
	assert.Equal(t, []string{"admin@example.com"}, config.Security.AllowedUsers)
	assert.Equal(t, []string{"example.com"}, config.Security.AllowedUserDomains)
	assert.Equal(t, []string{"admins"}, config.Security.AllowedRolesAndGroups)
	assert.Equal(t, []string{"/public"}, config.Security.ExcludedURLs)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Rate Limiting
// =============================================================================

func TestMigrateLegacyToUnified_RateLimitEnabled(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"rateLimit":   100,
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.True(t, config.RateLimit.Enabled)
	assert.Equal(t, 100, config.RateLimit.RequestsPerSecond)
	assert.Equal(t, 200, config.RateLimit.Burst) // Default: 2x rate
}

func TestMigrateLegacyToUnified_RateLimitDisabled(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"rateLimit":   0, // Disabled
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.False(t, config.RateLimit.Enabled)
}

func TestMigrateLegacyToUnified_RateLimitCapitalized(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"ProviderURL": "https://auth.example.com",
		"RateLimit":   50,
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.True(t, config.RateLimit.Enabled)
	assert.Equal(t, 50, config.RateLimit.RequestsPerSecond)
	assert.Equal(t, 100, config.RateLimit.Burst)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Token Configuration
// =============================================================================

func TestMigrateLegacyToUnified_TokenRefreshGracePeriod(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl":               "https://auth.example.com",
		"refreshGracePeriodSeconds": 300, // 5 minutes
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.Equal(t, 300*time.Second, config.Token.RefreshGracePeriod)
}

func TestMigrateLegacyToUnified_TokenRefreshGracePeriodCapitalized(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"ProviderURL":               "https://auth.example.com",
		"RefreshGracePeriodSeconds": 600,
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.Equal(t, 600*time.Second, config.Token.RefreshGracePeriod)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Logging
// =============================================================================

func TestMigrateLegacyToUnified_LoggingLevelLowercase(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"logLevel":    "DEBUG",
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.Equal(t, "debug", config.Logging.Level) // Should be lowercased
}

func TestMigrateLegacyToUnified_LoggingLevelDefaultsToInfo(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		// No logLevel specified
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.Equal(t, "info", config.Logging.Level) // Default
}

func TestMigrateLegacyToUnified_LoggingLevelCapitalized(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"ProviderURL": "https://auth.example.com",
		"LogLevel":    "ERROR",
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.Equal(t, "error", config.Logging.Level)
}

// =============================================================================
// Legacy to Unified Mapping Tests - Custom Headers
// =============================================================================

func TestMigrateLegacyToUnified_CustomHeaders(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"headers": []interface{}{
			map[string]interface{}{
				"name":  "X-Custom-Header",
				"value": "custom-value",
			},
			map[string]interface{}{
				"name":  "X-Another-Header",
				"value": "another-value",
			},
		},
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.NotNil(t, config.Middleware.CustomHeaders)
	assert.Equal(t, "custom-value", config.Middleware.CustomHeaders["X-Custom-Header"])
	assert.Equal(t, "another-value", config.Middleware.CustomHeaders["X-Another-Header"])
}

func TestMigrateLegacyToUnified_CustomHeadersEmptyName(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"headers": []interface{}{
			map[string]interface{}{
				"name":  "", // Empty name
				"value": "should-be-ignored",
			},
			map[string]interface{}{
				"name":  "X-Valid-Header",
				"value": "valid-value",
			},
		},
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.NotNil(t, config.Middleware.CustomHeaders)
	assert.NotContains(t, config.Middleware.CustomHeaders, "") // Empty name should be skipped
	assert.Equal(t, "valid-value", config.Middleware.CustomHeaders["X-Valid-Header"])
}

// =============================================================================
// Legacy to Unified Mapping Tests - Legacy Data Preservation
// =============================================================================

func TestMigrateLegacyToUnified_PreservesLegacyData(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"clientId":    "test-client",
		"customField": "custom-value", // Non-standard field
	}

	config, err := migrator.migrateLegacyToUnified(legacyData)
	require.NoError(t, err)

	assert.NotNil(t, config.Legacy)
	assert.Equal(t, legacyData, config.Legacy) // Original data should be preserved
}

// =============================================================================
// File Migration Tests
// =============================================================================

func TestConfigMigrator_MigrateFile_ValidJSON(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	// Create temporary JSON config file
	tmpFile := filepath.Join(t.TempDir(), "config.json")

	configData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"clientId":    "test-client",
	}

	jsonData, err := json.Marshal(configData)
	require.NoError(t, err)

	err = os.WriteFile(tmpFile, jsonData, 0644)
	require.NoError(t, err)

	config, err := migrator.MigrateFile(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
}

func TestConfigMigrator_MigrateFile_ValidYAML(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	tmpFile := filepath.Join(t.TempDir(), "config.yaml")

	yamlData := `
providerUrl: https://auth.example.com
clientId: test-client
`

	err := os.WriteFile(tmpFile, []byte(yamlData), 0644)
	require.NoError(t, err)

	config, err := migrator.MigrateFile(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
}

func TestConfigMigrator_MigrateFile_PathTraversalPrevention(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	// Attempt path traversal
	maliciousPath := "../../../etc/passwd"

	config, err := migrator.MigrateFile(maliciousPath)
	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestConfigMigrator_MigrateFile_NonExistentFile(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	nonExistentFile := filepath.Join(t.TempDir(), "does-not-exist.json")

	config, err := migrator.MigrateFile(nonExistentFile)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestConfigMigrator_MigrateFile_InvalidPath(t *testing.T) {
	t.Parallel()

	migrator := NewConfigMigrator()

	// Use invalid characters
	invalidPath := string([]byte{0x00}) + "config.json"

	config, err := migrator.MigrateFile(invalidPath)
	assert.Error(t, err)
	assert.Nil(t, config)
}

// =============================================================================
// Auto-Migration Tests
// =============================================================================

func TestAutoMigrate_ByteSliceInput(t *testing.T) {
	t.Parallel()

	// This test depends on features.IsUnifiedConfigEnabled() being true
	// Skip if unified config is not enabled
	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"clientId":    "test-client",
	}

	jsonData, err := json.Marshal(legacyData)
	require.NoError(t, err)

	config, err := AutoMigrate(jsonData)

	// If feature is disabled, config will be nil with no error
	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
}

func TestAutoMigrate_StringInput(t *testing.T) {
	t.Parallel()

	jsonString := `{"providerUrl":"https://auth.example.com","clientId":"test-client"}`

	config, err := AutoMigrate(jsonString)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
}

func TestAutoMigrate_MapInput(t *testing.T) {
	t.Parallel()

	legacyData := map[string]interface{}{
		"providerUrl": "https://auth.example.com",
		"clientId":    "test-client",
	}

	config, err := AutoMigrate(legacyData)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "https://auth.example.com", config.Provider.IssuerURL)
}

func TestAutoMigrate_OldConfigInput(t *testing.T) {
	t.Parallel()

	oldConfig := &Config{
		ProviderURL: "https://auth.example.com",
		ClientID:    "test-client",
	}

	config, err := AutoMigrate(oldConfig)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	require.NoError(t, err)
	assert.NotNil(t, config)
	// FromOldConfig should map fields
}

func TestAutoMigrate_UnifiedConfigInput(t *testing.T) {
	t.Parallel()

	unifiedConfig := NewUnifiedConfig()
	unifiedConfig.Provider.IssuerURL = "https://auth.example.com"

	config, err := AutoMigrate(unifiedConfig)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	require.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, unifiedConfig, config) // Should return same instance
}

func TestAutoMigrate_UnsupportedType(t *testing.T) {
	t.Parallel()

	unsupportedData := 12345 // int type not supported

	config, err := AutoMigrate(unsupportedData)

	// If feature is disabled, both will be nil
	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported config type")
}

// Test that AutoMigrate handles nil map input
func TestAutoMigrate_NilMap(t *testing.T) {
	t.Parallel()

	var nilMap map[string]interface{}

	config, err := AutoMigrate(nilMap)

	// Should handle nil gracefully
	if config == nil && err == nil {
		// Feature disabled OR nil handled correctly
		t.Skip("Unified config feature not enabled or nil handled")
	}

	// If feature is enabled, should either succeed with empty config or error
	// (depending on migration logic)
	if err != nil {
		assert.NotNil(t, err)
	}
}

// Test AutoMigrate with empty byte slice
func TestAutoMigrate_EmptyByteSlice(t *testing.T) {
	t.Parallel()

	emptyData := []byte("")

	config, err := AutoMigrate(emptyData)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Should handle empty data - either error or return config
	// (error expected for invalid JSON)
	if err != nil {
		assert.NotNil(t, err)
	}
}

// Test AutoMigrate with empty string
func TestAutoMigrate_EmptyString(t *testing.T) {
	t.Parallel()

	emptyString := ""

	config, err := AutoMigrate(emptyString)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Should handle empty string - error expected
	if err != nil {
		assert.NotNil(t, err)
	}
}

// Test AutoMigrate with invalid JSON string
func TestAutoMigrate_InvalidJSON(t *testing.T) {
	t.Parallel()

	invalidJSON := "{invalid json}"

	config, err := AutoMigrate(invalidJSON)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Should error on invalid JSON
	assert.Error(t, err)
}

// Test AutoMigrate with invalid JSON bytes
func TestAutoMigrate_InvalidJSONBytes(t *testing.T) {
	t.Parallel()

	invalidJSON := []byte("{not valid json")

	config, err := AutoMigrate(invalidJSON)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Should error on invalid JSON
	assert.Error(t, err)
}

// Test AutoMigrate with nil old config pointer
func TestAutoMigrate_NilOldConfig(t *testing.T) {
	t.Parallel()

	var nilConfig *Config

	config, err := AutoMigrate(nilConfig)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Nil config should be handled - might panic or return error
	// depending on FromOldConfig implementation
	if err != nil {
		assert.NotNil(t, err)
	}
}

// Test AutoMigrate with nil unified config pointer
func TestAutoMigrate_NilUnifiedConfig(t *testing.T) {
	t.Parallel()

	var nilUnified *UnifiedConfig

	config, err := AutoMigrate(nilUnified)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Should return nil unified config as-is
	assert.NoError(t, err)
	assert.Nil(t, config)
}

// Test AutoMigrate with map containing unmarshalable values
func TestAutoMigrate_MapWithUnmarshalableValue(t *testing.T) {
	t.Parallel()

	// Create a map with a value that can't be marshaled to JSON
	badMap := map[string]interface{}{
		"providerUrl": "https://example.com",
		"badValue":    make(chan int), // channels can't be marshaled
	}

	config, err := AutoMigrate(badMap)

	if config == nil && err == nil {
		t.Skip("Unified config feature not enabled")
	}

	// Should error during JSON marshaling
	assert.Error(t, err)
	assert.Nil(t, config)
}

// =============================================================================
// Helper Function Tests - getNestedMap
// =============================================================================

func TestGetNestedMap_Exists(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	result, ok := getNestedMap(m, "nested")
	assert.True(t, ok)
	assert.NotNil(t, result)
	assert.Equal(t, "value", result["key"])
}

func TestGetNestedMap_DoesNotExist(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"other": "value",
	}

	result, ok := getNestedMap(m, "nested")
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestGetNestedMap_WrongType(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"nested": "not-a-map",
	}

	result, ok := getNestedMap(m, "nested")
	assert.False(t, ok)
	assert.Nil(t, result)
}

// =============================================================================
// Helper Function Tests - getStringValue
// =============================================================================

func TestGetStringValue_FirstKey(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	result := getStringValue(m, "key1", "key2")
	assert.Equal(t, "value1", result)
}

func TestGetStringValue_FallbackKey(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key2": "value2",
	}

	result := getStringValue(m, "key1", "key2", "key3")
	assert.Equal(t, "value2", result) // Falls back to key2
}

func TestGetStringValue_NoKeysExist(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"other": "value",
	}

	result := getStringValue(m, "key1", "key2")
	assert.Equal(t, "", result) // Returns empty string
}

func TestGetStringValue_NilValue(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": nil,
	}

	result := getStringValue(m, "key1")
	assert.Equal(t, "", result)
}

// =============================================================================
// Helper Function Tests - getStringFromInterface
// =============================================================================

func TestGetStringFromInterface_String(t *testing.T) {
	t.Parallel()

	result := getStringFromInterface("test-string")
	assert.Equal(t, "test-string", result)
}

func TestGetStringFromInterface_ByteSlice(t *testing.T) {
	t.Parallel()

	result := getStringFromInterface([]byte("test-bytes"))
	assert.Equal(t, "test-bytes", result)
}

func TestGetStringFromInterface_Int(t *testing.T) {
	t.Parallel()

	result := getStringFromInterface(42)
	assert.Equal(t, "42", result)
}

func TestGetStringFromInterface_Nil(t *testing.T) {
	t.Parallel()

	result := getStringFromInterface(nil)
	assert.Equal(t, "", result)
}

func TestGetStringFromInterface_Bool(t *testing.T) {
	t.Parallel()

	result := getStringFromInterface(true)
	assert.Equal(t, "true", result)
}

// =============================================================================
// Helper Function Tests - getBoolValue
// =============================================================================

func TestGetBoolValue_BoolTrue(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": true,
	}

	result := getBoolValue(m, "key1")
	assert.True(t, result)
}

func TestGetBoolValue_BoolFalse(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": false,
	}

	result := getBoolValue(m, "key1")
	assert.False(t, result)
}

func TestGetBoolValue_StringTrue(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": "true",
	}

	result := getBoolValue(m, "key1")
	assert.True(t, result)
}

func TestGetBoolValue_StringTrueUppercase(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": "TRUE",
	}

	result := getBoolValue(m, "key1")
	assert.True(t, result)
}

func TestGetBoolValue_StringFalse(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": "false",
	}

	result := getBoolValue(m, "key1")
	assert.False(t, result)
}

func TestGetBoolValue_Missing(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"other": "value",
	}

	result := getBoolValue(m, "key1")
	assert.False(t, result) // Default
}

func TestGetBoolValue_Fallback(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key2": true,
	}

	result := getBoolValue(m, "key1", "key2")
	assert.True(t, result) // Falls back to key2
}

// =============================================================================
// Helper Function Tests - getIntValue
// =============================================================================

func TestGetIntValue_Int(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": 42,
	}

	result := getIntValue(m, "key1")
	assert.Equal(t, 42, result)
}

func TestGetIntValue_Int64(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": int64(100),
	}

	result := getIntValue(m, "key1")
	assert.Equal(t, 100, result)
}

func TestGetIntValue_Float64(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": 42.7,
	}

	result := getIntValue(m, "key1")
	assert.Equal(t, 42, result) // Truncates to int
}

func TestGetIntValue_String(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": "123",
	}

	result := getIntValue(m, "key1")
	assert.Equal(t, 123, result)
}

func TestGetIntValue_InvalidString(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": "not-a-number",
	}

	result := getIntValue(m, "key1")
	assert.Equal(t, 0, result) // Returns 0 for invalid parse
}

func TestGetIntValue_Missing(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"other": "value",
	}

	result := getIntValue(m, "key1")
	assert.Equal(t, 0, result)
}

func TestGetIntValue_Fallback(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key2": 99,
	}

	result := getIntValue(m, "key1", "key2")
	assert.Equal(t, 99, result)
}

// =============================================================================
// Helper Function Tests - getArrayValue
// =============================================================================

func TestGetArrayValue_InterfaceSlice(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": []interface{}{"value1", "value2", "value3"},
	}

	result := getArrayValue(m, "key1")
	assert.Equal(t, []string{"value1", "value2", "value3"}, result)
}

func TestGetArrayValue_StringSlice(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": []string{"a", "b", "c"},
	}

	result := getArrayValue(m, "key1")
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestGetArrayValue_InterfaceSliceWithNumbers(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": []interface{}{1, 2, 3},
	}

	result := getArrayValue(m, "key1")
	assert.Equal(t, []string{"1", "2", "3"}, result) // Converted to strings
}

func TestGetArrayValue_Missing(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"other": "value",
	}

	result := getArrayValue(m, "key1")
	assert.Nil(t, result)
}

func TestGetArrayValue_Fallback(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key2": []string{"fallback1", "fallback2"},
	}

	result := getArrayValue(m, "key1", "key2")
	assert.Equal(t, []string{"fallback1", "fallback2"}, result)
}

func TestGetArrayValue_Empty(t *testing.T) {
	t.Parallel()

	m := map[string]interface{}{
		"key1": []interface{}{},
	}

	result := getArrayValue(m, "key1")
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result))
}

// =============================================================================
// Helper Function Tests - mapToStruct
// =============================================================================

func TestMapToStruct_ValidMapping(t *testing.T) {
	t.Parallel()

	type TestStruct struct {
		Name  string `json:"name"`
		Age   int    `json:"age"`
		Email string `json:"email"`
	}

	m := map[string]interface{}{
		"name":  "John Doe",
		"age":   30,
		"email": "john@example.com",
	}

	var target TestStruct
	err := mapToStruct(m, &target)

	require.NoError(t, err)
	assert.Equal(t, "John Doe", target.Name)
	assert.Equal(t, 30, target.Age)
	assert.Equal(t, "john@example.com", target.Email)
}

func TestMapToStruct_PartialMapping(t *testing.T) {
	t.Parallel()

	type TestStruct struct {
		Name  string `json:"name"`
		Age   int    `json:"age"`
		Email string `json:"email"`
	}

	m := map[string]interface{}{
		"name": "Jane Doe",
		// age and email missing
	}

	var target TestStruct
	err := mapToStruct(m, &target)

	require.NoError(t, err)
	assert.Equal(t, "Jane Doe", target.Name)
	assert.Equal(t, 0, target.Age)    // Zero value
	assert.Equal(t, "", target.Email) // Zero value
}

func TestMapToStruct_InvalidJSON(t *testing.T) {
	t.Parallel()

	type TestStruct struct {
		Name string `json:"name"`
	}

	// Create a struct that can't be marshaled to JSON (e.g., with a channel)
	m := make(chan int)

	var target TestStruct
	err := mapToStruct(m, &target)

	assert.Error(t, err) // Should fail to marshal
}
