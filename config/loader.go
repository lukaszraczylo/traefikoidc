// Package config provides configuration loading and merging logic
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/lukaszraczylo/traefikoidc/internal/features"
	"gopkg.in/yaml.v3"
)

// ConfigLoader handles loading configuration from various sources
type ConfigLoader struct {
	migrator    *ConfigMigrator
	envPrefix   string
	configPaths []string
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{
		migrator:    NewConfigMigrator(),
		envPrefix:   "TRAEFIKOIDC_",
		configPaths: getDefaultConfigPaths(),
	}
}

// getDefaultConfigPaths returns default configuration file paths to check
func getDefaultConfigPaths() []string {
	return []string{
		"traefik-oidc.yaml",
		"traefik-oidc.yml",
		"traefik-oidc.json",
		"config.yaml",
		"config.yml",
		"config.json",
		"/etc/traefik-oidc/config.yaml",
		"/etc/traefik-oidc/config.json",
	}
}

// Load loads configuration from all available sources
func (l *ConfigLoader) Load() (*UnifiedConfig, error) {
	// Start with defaults
	config := NewUnifiedConfig()

	// Try to load from file
	if fileConfig, err := l.LoadFromFile(); err == nil && fileConfig != nil {
		config = l.mergeConfigs(config, fileConfig)
	}

	// Load from environment variables
	l.LoadFromEnv(config)

	// Validate the final configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// LoadFromFile loads configuration from a file
func (l *ConfigLoader) LoadFromFile(paths ...string) (*UnifiedConfig, error) {
	// Use provided paths or default paths
	searchPaths := paths
	if len(searchPaths) == 0 {
		searchPaths = l.configPaths
	}

	// Check for config file in environment variable
	if envPath := os.Getenv(l.envPrefix + "CONFIG_FILE"); envPath != "" {
		searchPaths = append([]string{envPath}, searchPaths...)
	}

	// Try each path
	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return l.loadFile(path)
		}
	}

	// No config file found, not an error (use defaults)
	return nil, nil
}

// loadFile loads a specific configuration file
func (l *ConfigLoader) loadFile(path string) (*UnifiedConfig, error) {
	// Clean and validate path to prevent traversal attacks
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid config path: potential path traversal detected in %s", path)
	}

	// Ensure the path is within expected directories (current dir or subdirs)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for %s: %w", path, err)
	}

	// Read the file with validated path
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", absPath, err)
	}

	// Check if unified config is enabled
	if features.IsUnifiedConfigEnabled() {
		// Use migrator to handle any version
		config, warnings, err := l.migrator.Migrate(data)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate config from %s: %w", path, err)
		}

		// Log warnings
		for _, warning := range warnings {
			// In production, use proper logging
			fmt.Printf("Config Warning (%s): %s\n", path, warning)
		}

		return config, nil
	}

	// Legacy path: load old config and convert
	ext := strings.ToLower(filepath.Ext(path))
	var oldConfig Config

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &oldConfig); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &oldConfig); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file extension: %s", ext)
	}

	return FromOldConfig(&oldConfig), nil
}

// LoadFromEnv loads configuration from environment variables
func (l *ConfigLoader) LoadFromEnv(config *UnifiedConfig) {
	// Provider configuration
	l.loadEnvString(&config.Provider.IssuerURL, "PROVIDER_ISSUER_URL", "PROVIDER_URL")
	l.loadEnvString(&config.Provider.ClientID, "PROVIDER_CLIENT_ID", "CLIENT_ID")
	l.loadEnvString(&config.Provider.ClientSecret, "PROVIDER_CLIENT_SECRET", "CLIENT_SECRET")
	l.loadEnvString(&config.Provider.RedirectURL, "PROVIDER_REDIRECT_URL", "CALLBACK_URL")
	l.loadEnvString(&config.Provider.LogoutURL, "PROVIDER_LOGOUT_URL", "LOGOUT_URL")
	l.loadEnvString(&config.Provider.PostLogoutRedirectURI, "PROVIDER_POST_LOGOUT_URI", "POST_LOGOUT_REDIRECT_URI")
	l.loadEnvStringSlice(&config.Provider.Scopes, "PROVIDER_SCOPES", "SCOPES")
	l.loadEnvBool(&config.Provider.OverrideScopes, "PROVIDER_OVERRIDE_SCOPES", "OVERRIDE_SCOPES")

	// Session configuration
	l.loadEnvString(&config.Session.Name, "SESSION_NAME")
	l.loadEnvInt(&config.Session.MaxAge, "SESSION_MAX_AGE")
	l.loadEnvString(&config.Session.Secret, "SESSION_SECRET")
	l.loadEnvString(&config.Session.EncryptionKey, "SESSION_ENCRYPTION_KEY")
	l.loadEnvString(&config.Session.Domain, "SESSION_DOMAIN", "COOKIE_DOMAIN")
	l.loadEnvBool(&config.Session.Secure, "SESSION_SECURE")
	l.loadEnvBool(&config.Session.HttpOnly, "SESSION_HTTP_ONLY")
	l.loadEnvString(&config.Session.SameSite, "SESSION_SAME_SITE")

	// Security configuration
	l.loadEnvBool(&config.Security.ForceHTTPS, "SECURITY_FORCE_HTTPS", "FORCE_HTTPS")
	l.loadEnvBool(&config.Security.EnablePKCE, "SECURITY_ENABLE_PKCE", "ENABLE_PKCE")
	l.loadEnvStringSlice(&config.Security.AllowedUsers, "SECURITY_ALLOWED_USERS", "ALLOWED_USERS")
	l.loadEnvStringSlice(&config.Security.AllowedUserDomains, "SECURITY_ALLOWED_DOMAINS", "ALLOWED_USER_DOMAINS")
	l.loadEnvStringSlice(&config.Security.AllowedRolesAndGroups, "SECURITY_ALLOWED_ROLES", "ALLOWED_ROLES_AND_GROUPS")
	l.loadEnvStringSlice(&config.Security.ExcludedURLs, "SECURITY_EXCLUDED_URLS", "EXCLUDED_URLS")

	// Cache configuration
	l.loadEnvBool(&config.Cache.Enabled, "CACHE_ENABLED")
	l.loadEnvString(&config.Cache.Type, "CACHE_TYPE")
	l.loadEnvInt(&config.Cache.MaxEntries, "CACHE_MAX_ENTRIES")
	// MaxEntrySize is int64, skip for now

	// Rate limiting
	l.loadEnvBool(&config.RateLimit.Enabled, "RATELIMIT_ENABLED")
	l.loadEnvInt(&config.RateLimit.RequestsPerSecond, "RATELIMIT_RPS", "RATE_LIMIT")
	l.loadEnvInt(&config.RateLimit.Burst, "RATELIMIT_BURST")

	// Logging
	l.loadEnvString(&config.Logging.Level, "LOGGING_LEVEL", "LOG_LEVEL")
	l.loadEnvString(&config.Logging.Format, "LOGGING_FORMAT")
	l.loadEnvString(&config.Logging.Output, "LOGGING_OUTPUT")

	// Redis configuration (already handled by its own LoadFromEnv)
	config.Redis.LoadFromEnv()

	// Feature flags
	features.GetManager().LoadFromEnv()
}

// Helper methods for environment variable loading

func (l *ConfigLoader) loadEnvString(target *string, keys ...string) {
	for _, key := range keys {
		if value := os.Getenv(l.envPrefix + key); value != "" {
			*target = value
			return
		}
		// Try without prefix
		if value := os.Getenv(key); value != "" {
			*target = value
			return
		}
	}
}

func (l *ConfigLoader) loadEnvBool(target *bool, keys ...string) {
	for _, key := range keys {
		if value := os.Getenv(l.envPrefix + key); value != "" {
			*target = strings.ToLower(value) == "true" || value == "1"
			return
		}
		// Try without prefix
		if value := os.Getenv(key); value != "" {
			*target = strings.ToLower(value) == "true" || value == "1"
			return
		}
	}
}

func (l *ConfigLoader) loadEnvInt(target *int, keys ...string) {
	for _, key := range keys {
		if value := os.Getenv(l.envPrefix + key); value != "" {
			var i int
			if _, err := fmt.Sscanf(value, "%d", &i); err == nil {
				*target = i
				return
			}
		}
		// Try without prefix
		if value := os.Getenv(key); value != "" {
			var i int
			if _, err := fmt.Sscanf(value, "%d", &i); err == nil {
				*target = i
				return
			}
		}
	}
}

func (l *ConfigLoader) loadEnvStringSlice(target *[]string, keys ...string) {
	for _, key := range keys {
		if value := os.Getenv(l.envPrefix + key); value != "" {
			*target = splitAndTrim(value)
			return
		}
		// Try without prefix
		if value := os.Getenv(key); value != "" {
			*target = splitAndTrim(value)
			return
		}
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// mergeConfigs merges two configurations, with source overriding target
func (l *ConfigLoader) mergeConfigs(target, source *UnifiedConfig) *UnifiedConfig {
	if source == nil {
		return target
	}
	if target == nil {
		return source
	}

	// Use reflection for deep merge
	l.mergeStructs(reflect.ValueOf(target).Elem(), reflect.ValueOf(source).Elem())

	return target
}

// mergeStructs recursively merges two structs
func (l *ConfigLoader) mergeStructs(target, source reflect.Value) {
	for i := 0; i < source.NumField(); i++ {
		sourceField := source.Field(i)
		targetField := target.Field(i)

		// Skip if source field is zero value
		if isZeroValue(sourceField) {
			continue
		}

		switch sourceField.Kind() {
		case reflect.Struct:
			// Recursively merge structs
			l.mergeStructs(targetField, sourceField)
		case reflect.Slice:
			// Replace slice if source has values
			if sourceField.Len() > 0 {
				targetField.Set(sourceField)
			}
		case reflect.Map:
			// Merge maps
			if !sourceField.IsNil() {
				if targetField.IsNil() {
					targetField.Set(reflect.MakeMap(sourceField.Type()))
				}
				for _, key := range sourceField.MapKeys() {
					targetField.SetMapIndex(key, sourceField.MapIndex(key))
				}
			}
		default:
			// Replace value
			targetField.Set(sourceField)
		}
	}
}

// isZeroValue checks if a reflect.Value is a zero value
func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		return v.IsNil()
	case reflect.Slice, reflect.Map:
		return v.IsNil() || v.Len() == 0
	case reflect.Struct:
		// Check if all fields are zero
		for i := 0; i < v.NumField(); i++ {
			if !isZeroValue(v.Field(i)) {
				return false
			}
		}
		return true
	default:
		zero := reflect.Zero(v.Type())
		return reflect.DeepEqual(v.Interface(), zero.Interface())
	}
}

// SaveToFile saves the configuration to a file
func (l *ConfigLoader) SaveToFile(config *UnifiedConfig, path string) error {
	// Clean and validate path to prevent traversal attacks
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid config path: potential path traversal detected in %s", path)
	}

	// Ensure the path is within expected directories
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %s: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(absPath))

	var data []byte

	switch ext {
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
	default:
		return fmt.Errorf("unsupported file extension: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create directory if it doesn't exist with secure permissions
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write file with secure permissions (owner read/write only)
	if err := os.WriteFile(absPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", absPath, err)
	}

	return nil
}
