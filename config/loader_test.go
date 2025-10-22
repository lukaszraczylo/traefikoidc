//go:build !yaegi

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigLoader tests the config loader functionality
func TestConfigLoader(t *testing.T) {
	loader := NewConfigLoader()

	if loader == nil {
		t.Fatal("NewConfigLoader should not return nil")
	}

	if loader.migrator == nil {
		t.Error("ConfigLoader should have a migrator")
	}

	if loader.envPrefix != "TRAEFIKOIDC_" {
		t.Errorf("Expected envPrefix to be 'TRAEFIKOIDC_', got %s", loader.envPrefix)
	}

	if len(loader.configPaths) == 0 {
		t.Error("ConfigLoader should have default config paths")
	}
}

// TestLoadFromEnv tests loading configuration from environment variables
func TestLoadFromEnv(t *testing.T) {
	// Set up test environment variables
	testEnvVars := map[string]string{
		"TRAEFIKOIDC_PROVIDER_ISSUER_URL":    "https://test.example.com",
		"TRAEFIKOIDC_PROVIDER_CLIENT_ID":     "test-client-id",
		"TRAEFIKOIDC_PROVIDER_CLIENT_SECRET": "test-secret",
		"TRAEFIKOIDC_SESSION_ENCRYPTION_KEY": "32-character-encryption-key-12345",
		"TRAEFIKOIDC_SESSION_CHUNKED":        "true",
		"TRAEFIKOIDC_REDIS_ENABLED":          "true",
		"TRAEFIKOIDC_REDIS_ADDR":             "redis.example.com:6379",
		"TRAEFIKOIDC_SECURITY_FORCE_HTTPS":   "true",
		"TRAEFIKOIDC_CACHE_ENABLED":          "true",
		"TRAEFIKOIDC_CACHE_TYPE":             "redis",
		"TRAEFIKOIDC_RATELIMIT_ENABLED":      "true",
		"TRAEFIKOIDC_RATELIMIT_RPS":          "100",
	}

	// Set environment variables
	for key, value := range testEnvVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	loader := NewConfigLoader()
	config := &UnifiedConfig{}
	loader.LoadFromEnv(config)

	// Verify values were loaded
	if config.Provider.IssuerURL != "https://test.example.com" {
		t.Errorf("Expected IssuerURL to be 'https://test.example.com', got %s", config.Provider.IssuerURL)
	}
	if config.Provider.ClientID != "test-client-id" {
		t.Errorf("Expected ClientID to be 'test-client-id', got %s", config.Provider.ClientID)
	}
	if config.Provider.ClientSecret != "test-secret" {
		t.Errorf("Expected ClientSecret to be 'test-secret', got %s", config.Provider.ClientSecret)
	}
	if config.Session.EncryptionKey != "32-character-encryption-key-12345" {
		t.Errorf("Expected EncryptionKey to be set, got %s", config.Session.EncryptionKey)
	}
	if !config.Security.ForceHTTPS {
		t.Error("Expected ForceHTTPS to be true")
	}
	if !config.Cache.Enabled {
		t.Error("Expected Cache to be enabled")
	}
	if config.Cache.Type != "redis" {
		t.Errorf("Expected Cache.Type to be 'redis', got %s", config.Cache.Type)
	}
	if !config.RateLimit.Enabled {
		t.Error("Expected RateLimit to be enabled")
	}
	if config.RateLimit.RequestsPerSecond != 100 {
		t.Errorf("Expected RequestsPerSecond to be 100, got %d", config.RateLimit.RequestsPerSecond)
	}
}

// TestSaveToFile tests saving configuration to files
func TestSaveToFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	loader := NewConfigLoader()
	config := &UnifiedConfig{
		Provider: ProviderConfig{
			IssuerURL:    "https://auth.example.com",
			ClientID:     "test-client",
			ClientSecret: "secret",
		},
		Session: SessionConfig{
			EncryptionKey: "32-character-encryption-key-12345",
		},
	}

	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "save as JSON",
			filename: "config.json",
			wantErr:  false,
		},
		{
			name:     "save as YAML",
			filename: "config.yaml",
			wantErr:  false,
		},
		{
			name:     "save as YML",
			filename: "config.yml",
			wantErr:  false,
		},
		{
			name:     "unsupported extension",
			filename: "config.txt",
			wantErr:  true,
		},
		{
			name:     "path traversal attempt",
			filename: "../../../etc/config.json",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tmpDir, tt.filename)
			err := loader.SaveToFile(config, filePath)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify file was created with correct permissions
			info, err := os.Stat(filePath)
			if err != nil {
				t.Errorf("Failed to stat saved file: %v", err)
				return
			}

			// Check file permissions (should be 0600)
			mode := info.Mode().Perm()
			if mode != 0600 {
				t.Errorf("Expected file permissions 0600, got %o", mode)
			}

			// Verify content can be read back
			data, err := os.ReadFile(filePath)
			if err != nil {
				t.Errorf("Failed to read saved file: %v", err)
				return
			}

			// Verify secrets are redacted
			content := string(data)
			if strings.Contains(content, "secret") && !strings.Contains(content, "[REDACTED]") {
				t.Error("Secrets should be redacted in saved file")
			}
		})
	}
}

// TestLoadFile tests loading configuration from files
func TestLoadFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test data - using old config format since unified config is not enabled by default
	jsonConfig := `{
		"providerURL": "https://auth.example.com",
		"clientID": "test-client",
		"clientSecret": "secret",
		"sessionEncryptionKey": "32-character-encryption-key-12345"
	}`

	yamlConfig := `
providerurl: https://auth.example.com
clientid: test-client
clientsecret: secret
sessionencryptionkey: 32-character-encryption-key-12345
`

	tests := []struct {
		name     string
		filename string
		content  string
		wantErr  bool
	}{
		{
			name:     "load JSON config",
			filename: "config.json",
			content:  jsonConfig,
			wantErr:  false,
		},
		{
			name:     "load YAML config",
			filename: "config.yaml",
			content:  yamlConfig,
			wantErr:  false,
		},
		{
			name:     "path traversal attempt",
			filename: "../../../etc/passwd",
			content:  "",
			wantErr:  true,
		},
		{
			name:     "non-existent file",
			filename: "does-not-exist.json",
			content:  "",
			wantErr:  true,
		},
	}

	loader := NewConfigLoader()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filePath string
			if tt.content != "" {
				filePath = filepath.Join(tmpDir, tt.filename)
				err := os.WriteFile(filePath, []byte(tt.content), 0600)
				if err != nil {
					t.Fatalf("Failed to write test file: %v", err)
					return
				}
			} else {
				filePath = tt.filename
			}

			config, err := loader.loadFile(filePath)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				if !os.IsNotExist(err) && !strings.Contains(err.Error(), "no such file") {
					t.Errorf("Unexpected error: %v", err)
				}
				return
			}

			// Verify loaded config
			if config == nil {
				t.Error("Expected config to be loaded")
				return
			}

			if config.Provider.IssuerURL != "https://auth.example.com" {
				t.Errorf("Expected IssuerURL to be 'https://auth.example.com', got %s", config.Provider.IssuerURL)
			}
			if config.Provider.ClientID != "test-client" {
				t.Errorf("Expected ClientID to be 'test-client', got %s", config.Provider.ClientID)
			}
		})
	}
}
