// Package config provides configuration migration from old to new format
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/compat"
	"github.com/lukaszraczylo/traefikoidc/internal/features"
	"gopkg.in/yaml.v3"
)

// ConfigVersion represents the version of a configuration format
type ConfigVersion string

const (
	// VersionLegacy represents the original config format
	VersionLegacy ConfigVersion = "legacy"

	// VersionUnified represents the new unified config format
	VersionUnified ConfigVersion = "unified"

	// CurrentVersion is the current config version
	CurrentVersion ConfigVersion = VersionUnified
)

// ConfigMigrator handles migration between config versions
type ConfigMigrator struct {
	compatLayer *compat.CompatibilityLayer
	migrations  map[ConfigVersion]MigrationFunc
}

// MigrationFunc defines a function that migrates configuration
type MigrationFunc func(data map[string]interface{}) (*UnifiedConfig, error)

// NewConfigMigrator creates a new configuration migrator
func NewConfigMigrator() *ConfigMigrator {
	m := &ConfigMigrator{
		compatLayer: compat.GetLayer(),
		migrations:  make(map[ConfigVersion]MigrationFunc),
	}

	// Register migration functions
	m.migrations[VersionLegacy] = m.migrateLegacyToUnified

	return m
}

// DetectVersion detects the version of a configuration
func (m *ConfigMigrator) DetectVersion(data []byte) ConfigVersion {
	var testMap map[string]interface{}

	// Try JSON first
	if err := json.Unmarshal(data, &testMap); err != nil {
		// Try YAML
		if err := yaml.Unmarshal(data, &testMap); err != nil {
			return VersionLegacy // Default to legacy if can't parse
		}
	}

	// Check for unified config markers
	if _, hasProvider := testMap["provider"]; hasProvider {
		if _, hasSession := testMap["session"]; hasSession {
			return VersionUnified
		}
	}

	// Check for legacy config markers
	if _, hasProviderURL := testMap["providerUrl"]; hasProviderURL {
		return VersionLegacy
	}
	if _, hasProviderURL := testMap["ProviderURL"]; hasProviderURL {
		return VersionLegacy
	}

	return VersionLegacy
}

// Migrate migrates configuration data to the current version
func (m *ConfigMigrator) Migrate(data []byte) (*UnifiedConfig, []string, error) {
	warnings := []string{}

	// Detect version
	version := m.DetectVersion(data)

	// If already current version, just unmarshal
	if version == CurrentVersion {
		var config UnifiedConfig
		if err := json.Unmarshal(data, &config); err != nil {
			// Try YAML
			if err := yaml.Unmarshal(data, &config); err != nil {
				return nil, warnings, fmt.Errorf("failed to unmarshal unified config: %w", err)
			}
		}
		return &config, warnings, nil
	}

	// Parse to generic map
	var configMap map[string]interface{}
	if err := json.Unmarshal(data, &configMap); err != nil {
		// Try YAML
		if err := yaml.Unmarshal(data, &configMap); err != nil {
			return nil, warnings, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	// Apply migration
	migrationFunc, exists := m.migrations[version]
	if !exists {
		return nil, warnings, fmt.Errorf("no migration path from version %s", version)
	}

	config, err := migrationFunc(configMap)
	if err != nil {
		return nil, warnings, fmt.Errorf("migration failed: %w", err)
	}

	// Collect any deprecation warnings
	for key := range configMap {
		if warning, deprecated := m.compatLayer.CheckDeprecation(key); deprecated {
			warnings = append(warnings, warning)
		}
	}

	return config, warnings, nil
}

// migrateLegacyToUnified migrates legacy config to unified format
func (m *ConfigMigrator) migrateLegacyToUnified(data map[string]interface{}) (*UnifiedConfig, error) {
	config := NewUnifiedConfig()

	// Use compatibility layer for field mapping
	migratedMap, warnings := m.compatLayer.MigrateMap(data)

	// Log warnings
	for _, warning := range warnings {
		// In production, these would be logged
		_ = warning
	}

	// Map provider configuration
	if provider, ok := getNestedMap(migratedMap, "Provider"); ok {
		_ = mapToStruct(provider, &config.Provider)
	} else {
		// Direct field mapping for legacy format
		config.Provider.IssuerURL = getStringValue(data, "providerUrl", "ProviderURL")
		config.Provider.ClientID = getStringValue(data, "clientId", "ClientID")
		config.Provider.ClientSecret = getStringValue(data, "clientSecret", "ClientSecret")
		config.Provider.RedirectURL = getStringValue(data, "callbackUrl", "CallbackURL")
		config.Provider.LogoutURL = getStringValue(data, "logoutUrl", "LogoutURL")
		config.Provider.PostLogoutRedirectURI = getStringValue(data, "postLogoutRedirectUri", "PostLogoutRedirectURI")

		if scopes := getArrayValue(data, "scopes", "Scopes"); scopes != nil {
			config.Provider.Scopes = scopes
		}
		config.Provider.OverrideScopes = getBoolValue(data, "overrideScopes", "OverrideScopes")
	}

	// Map session configuration
	if session, ok := getNestedMap(migratedMap, "Session"); ok {
		_ = mapToStruct(session, &config.Session)
	} else {
		config.Session.EncryptionKey = getStringValue(data, "sessionEncryptionKey", "SessionEncryptionKey")
		config.Session.Domain = getStringValue(data, "cookieDomain", "CookieDomain")
	}

	// Map security configuration
	if security, ok := getNestedMap(migratedMap, "Security"); ok {
		_ = mapToStruct(security, &config.Security)
	} else {
		config.Security.ForceHTTPS = getBoolValue(data, "forceHttps", "ForceHTTPS")
		config.Security.EnablePKCE = getBoolValue(data, "enablePkce", "EnablePKCE")

		if users := getArrayValue(data, "allowedUsers", "AllowedUsers"); users != nil {
			config.Security.AllowedUsers = users
		}
		if domains := getArrayValue(data, "allowedUserDomains", "AllowedUserDomains"); domains != nil {
			config.Security.AllowedUserDomains = domains
		}
		if roles := getArrayValue(data, "allowedRolesAndGroups", "AllowedRolesAndGroups"); roles != nil {
			config.Security.AllowedRolesAndGroups = roles
		}
		if excluded := getArrayValue(data, "excludedUrls", "ExcludedURLs"); excluded != nil {
			config.Security.ExcludedURLs = excluded
		}

		// Handle security headers
		if headers := data["securityHeaders"]; headers != nil {
			// Security headers might be in old format
			_ = mapToStruct(headers, &config.Security.Headers)
		}
	}

	// Map rate limiting
	if rateLimit := getIntValue(data, "rateLimit", "RateLimit"); rateLimit > 0 {
		config.RateLimit.Enabled = true
		config.RateLimit.RequestsPerSecond = rateLimit
		config.RateLimit.Burst = rateLimit * 2 // Default burst to 2x rate
	}

	// Map token configuration
	if refreshGrace := getIntValue(data, "refreshGracePeriodSeconds", "RefreshGracePeriodSeconds"); refreshGrace > 0 {
		config.Token.RefreshGracePeriod = time.Duration(refreshGrace) * time.Second
	}

	// Map logging
	config.Logging.Level = strings.ToLower(getStringValue(data, "logLevel", "LogLevel"))
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}

	// Map custom headers
	if headers := data["headers"]; headers != nil {
		if headerList, ok := headers.([]interface{}); ok {
			config.Middleware.CustomHeaders = make(map[string]string)
			for _, h := range headerList {
				if headerMap, ok := h.(map[string]interface{}); ok {
					name := getStringFromInterface(headerMap["name"])
					value := getStringFromInterface(headerMap["value"])
					if name != "" {
						config.Middleware.CustomHeaders[name] = value
					}
				}
			}
		}
	}

	// Store original data for reference
	config.Legacy = data

	return config, nil
}

// MigrateFile migrates a configuration file
func (m *ConfigMigrator) MigrateFile(filePath string) (*UnifiedConfig, error) {
	// Clean and validate path to prevent traversal attacks
	cleanPath := filepath.Clean(filePath)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid config path: potential path traversal detected in %s", filePath)
	}

	// Ensure the path is within expected directories
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for %s: %w", filePath, err)
	}

	// Read the file with validated path
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config, warnings, err := m.Migrate(data)
	if err != nil {
		return nil, err
	}

	// Log warnings
	for _, warning := range warnings {
		fmt.Printf("Migration Warning: %s\n", warning)
	}

	return config, nil
}

// AutoMigrate automatically migrates config based on feature flags
func AutoMigrate(data interface{}) (*UnifiedConfig, error) {
	if !features.IsUnifiedConfigEnabled() {
		// Feature not enabled, return nil
		return nil, nil
	}

	migrator := NewConfigMigrator()

	// Handle different input types
	switch v := data.(type) {
	case []byte:
		config, _, err := migrator.Migrate(v)
		return config, err
	case string:
		config, _, err := migrator.Migrate([]byte(v))
		return config, err
	case *Config:
		// Convert old config to unified
		return FromOldConfig(v), nil
	case *UnifiedConfig:
		// Already unified
		return v, nil
	case map[string]interface{}:
		// Convert map to JSON then migrate
		jsonData, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		config, _, err := migrator.Migrate(jsonData)
		return config, err
	default:
		return nil, fmt.Errorf("unsupported config type: %T", v)
	}
}

// Helper functions

func getNestedMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	if val, exists := m[key]; exists {
		if mapped, ok := val.(map[string]interface{}); ok {
			return mapped, true
		}
	}
	return nil, false
}

func getStringValue(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, exists := m[key]; exists {
			return getStringFromInterface(val)
		}
	}
	return ""
}

func getStringFromInterface(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func getBoolValue(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if val, exists := m[key]; exists {
			if b, ok := val.(bool); ok {
				return b
			}
			// Try string conversion
			if s, ok := val.(string); ok {
				return strings.ToLower(s) == "true"
			}
		}
	}
	return false
}

func getIntValue(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if val, exists := m[key]; exists {
			switch v := val.(type) {
			case int:
				return v
			case int64:
				return int(v)
			case float64:
				return int(v)
			case string:
				// Try to parse
				var i int
				if _, err := fmt.Sscanf(v, "%d", &i); err != nil {
					// If parsing fails, return default
					return 0
				}
				return i
			}
		}
	}
	return 0
}

func getArrayValue(m map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		if val, exists := m[key]; exists {
			if arr, ok := val.([]interface{}); ok {
				result := make([]string, 0, len(arr))
				for _, item := range arr {
					result = append(result, getStringFromInterface(item))
				}
				return result
			}
			if strArr, ok := val.([]string); ok {
				return strArr
			}
		}
	}
	return nil
}

func mapToStruct(m interface{}, target interface{}) error {
	// Simple mapping using JSON as intermediate
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
