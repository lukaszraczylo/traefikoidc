//go:build !yaegi

package config

import (
	"os"
	"path/filepath"
	"reflect"
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

// ====================================================================================
// Tests for untested functions (0% coverage)
// ====================================================================================

// TestConfigLoader_Load tests the full Load pipeline
func TestConfigLoader_Load(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-load-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test config file
	configPath := filepath.Join(tmpDir, "traefik-oidc.json")
	configData := `{
		"providerURL": "https://auth.example.com",
		"clientID": "test-client",
		"clientSecret": "test-secret",
		"sessionEncryptionKey": "32-character-encryption-key-12345"
	}`
	err = os.WriteFile(configPath, []byte(configData), 0600)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Change to temp directory so loader can find the config
	oldDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldDir)

	// Set some environment variables to test merging
	os.Setenv("TRAEFIKOIDC_SECURITY_FORCE_HTTPS", "true")
	defer os.Unsetenv("TRAEFIKOIDC_SECURITY_FORCE_HTTPS")

	loader := NewConfigLoader()
	config, err := loader.Load()

	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if config == nil {
		t.Fatal("Load() returned nil config")
	}

	// Verify file was loaded
	if config.Provider.IssuerURL != "https://auth.example.com" {
		t.Errorf("Expected IssuerURL from file, got %s", config.Provider.IssuerURL)
	}

	// Verify env vars were loaded
	if !config.Security.ForceHTTPS {
		t.Error("Expected ForceHTTPS from env var to be true")
	}
}

// TestConfigLoader_LoadFromFile tests the LoadFromFile function
func TestConfigLoader_LoadFromFile(t *testing.T) {
	t.Run("NoConfigFile", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-nofile-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		oldDir, _ := os.Getwd()
		os.Chdir(tmpDir)
		defer os.Chdir(oldDir)

		loader := NewConfigLoader()
		config, err := loader.LoadFromFile()

		// Should not error when no config file found
		if err != nil {
			t.Errorf("LoadFromFile() should not error when no file found: %v", err)
		}

		// Should return nil config
		if config != nil {
			t.Error("LoadFromFile() should return nil config when no file found")
		}
	})

	t.Run("LoadFromEnvPath", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-envpath-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create config file
		configPath := filepath.Join(tmpDir, "custom-config.json")
		configData := `{
			"providerURL": "https://custom.example.com",
			"clientID": "custom-client"
		}`
		err = os.WriteFile(configPath, []byte(configData), 0600)
		if err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		// Set env variable pointing to config
		os.Setenv("TRAEFIKOIDC_CONFIG_FILE", configPath)
		defer os.Unsetenv("TRAEFIKOIDC_CONFIG_FILE")

		loader := NewConfigLoader()
		config, err := loader.LoadFromFile()

		if err != nil {
			t.Fatalf("LoadFromFile() failed: %v", err)
		}

		if config == nil {
			t.Fatal("LoadFromFile() returned nil config")
		}

		if config.Provider.IssuerURL != "https://custom.example.com" {
			t.Errorf("Expected IssuerURL 'https://custom.example.com', got %s", config.Provider.IssuerURL)
		}
	})

	t.Run("LoadWithProvidedPaths", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config-provided-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create config file
		configPath := filepath.Join(tmpDir, "specific.json")
		configData := `{
			"providerURL": "https://specific.example.com",
			"clientID": "specific-client"
		}`
		err = os.WriteFile(configPath, []byte(configData), 0600)
		if err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		loader := NewConfigLoader()
		config, err := loader.LoadFromFile(configPath)

		if err != nil {
			t.Fatalf("LoadFromFile() with path failed: %v", err)
		}

		if config == nil {
			t.Fatal("LoadFromFile() returned nil config")
		}

		if config.Provider.IssuerURL != "https://specific.example.com" {
			t.Errorf("Expected IssuerURL 'https://specific.example.com', got %s", config.Provider.IssuerURL)
		}
	})
}

// TestSplitAndTrim tests the splitAndTrim helper function
func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Simple comma-separated",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "With spaces",
			input:    "a, b , c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Empty strings filtered out",
			input:    "a,,b, ,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Leading and trailing spaces",
			input:    "  a  ,  b  ,  c  ",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "Single value",
			input:    "single",
			expected: []string{"single"},
		},
		{
			name:     "Empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "Only commas and spaces",
			input:    " , , , ",
			expected: []string{},
		},
		{
			name:     "Complex real-world example",
			input:    "openid, profile, email, groups",
			expected: []string{"openid", "profile", "email", "groups"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d items, got %d: %v", len(tt.expected), len(result), result)
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("At index %d: expected %q, got %q", i, expected, result[i])
				}
			}
		})
	}
}

// TestConfigLoader_MergeConfigs tests the mergeConfigs function
func TestConfigLoader_MergeConfigs(t *testing.T) {
	loader := NewConfigLoader()

	t.Run("MergeNilSource", func(t *testing.T) {
		target := &UnifiedConfig{
			Provider: ProviderConfig{
				IssuerURL: "https://target.example.com",
			},
		}

		result := loader.mergeConfigs(target, nil)

		if result != target {
			t.Error("mergeConfigs should return target when source is nil")
		}
	})

	t.Run("MergeNilTarget", func(t *testing.T) {
		source := &UnifiedConfig{
			Provider: ProviderConfig{
				IssuerURL: "https://source.example.com",
			},
		}

		result := loader.mergeConfigs(nil, source)

		if result != source {
			t.Error("mergeConfigs should return source when target is nil")
		}
	})

	t.Run("MergeSimpleFields", func(t *testing.T) {
		target := &UnifiedConfig{
			Provider: ProviderConfig{
				IssuerURL: "https://target.example.com",
				ClientID:  "",
			},
		}

		source := &UnifiedConfig{
			Provider: ProviderConfig{
				IssuerURL: "https://source.example.com",
				ClientID:  "source-client",
			},
		}

		result := loader.mergeConfigs(target, source)

		if result.Provider.IssuerURL != "https://source.example.com" {
			t.Errorf("Expected IssuerURL to be overridden, got %s", result.Provider.IssuerURL)
		}

		if result.Provider.ClientID != "source-client" {
			t.Errorf("Expected ClientID to be set, got %s", result.Provider.ClientID)
		}
	})

	t.Run("MergeSlices", func(t *testing.T) {
		target := &UnifiedConfig{
			Provider: ProviderConfig{
				Scopes: []string{"openid", "profile"},
			},
		}

		source := &UnifiedConfig{
			Provider: ProviderConfig{
				Scopes: []string{"email", "groups"},
			},
		}

		result := loader.mergeConfigs(target, source)

		// Source slice should replace target slice
		if len(result.Provider.Scopes) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(result.Provider.Scopes))
		}

		if result.Provider.Scopes[0] != "email" {
			t.Errorf("Expected first scope 'email', got %s", result.Provider.Scopes[0])
		}
	})

	t.Run("MergeMaps", func(t *testing.T) {
		target := &UnifiedConfig{
			Middleware: MiddlewareConfig{
				CustomHeaders: map[string]string{
					"X-Target-Header": "target-value",
				},
			},
		}

		source := &UnifiedConfig{
			Middleware: MiddlewareConfig{
				CustomHeaders: map[string]string{
					"X-Source-Header": "source-value",
					"X-Target-Header": "overridden-value",
				},
			},
		}

		result := loader.mergeConfigs(target, source)

		if len(result.Middleware.CustomHeaders) != 2 {
			t.Errorf("Expected 2 headers, got %d", len(result.Middleware.CustomHeaders))
		}

		if result.Middleware.CustomHeaders["X-Target-Header"] != "overridden-value" {
			t.Errorf("Expected X-Target-Header to be overridden")
		}

		if result.Middleware.CustomHeaders["X-Source-Header"] != "source-value" {
			t.Errorf("Expected X-Source-Header to be added")
		}
	})
}

// TestConfigLoader_MergeStructs tests the mergeStructs function indirectly
func TestConfigLoader_MergeStructs(t *testing.T) {
	loader := NewConfigLoader()

	t.Run("NestedStructMerge", func(t *testing.T) {
		target := &UnifiedConfig{
			Provider: ProviderConfig{
				IssuerURL: "https://target.example.com",
				ClientID:  "target-client",
			},
			Session: SessionConfig{
				Name:   "target-session",
				MaxAge: 3600,
			},
		}

		source := &UnifiedConfig{
			Provider: ProviderConfig{
				ClientID:     "source-client",
				ClientSecret: "source-secret",
			},
			Session: SessionConfig{
				MaxAge: 7200,
			},
		}

		result := loader.mergeConfigs(target, source)

		// Provider.IssuerURL should remain (zero value in source)
		if result.Provider.IssuerURL != "https://target.example.com" {
			t.Errorf("Expected IssuerURL to remain, got %s", result.Provider.IssuerURL)
		}

		// Provider.ClientID should be overridden
		if result.Provider.ClientID != "source-client" {
			t.Errorf("Expected ClientID to be overridden, got %s", result.Provider.ClientID)
		}

		// Provider.ClientSecret should be added
		if result.Provider.ClientSecret != "source-secret" {
			t.Errorf("Expected ClientSecret to be added, got %s", result.Provider.ClientSecret)
		}

		// Session.Name should remain (zero value in source)
		if result.Session.Name != "target-session" {
			t.Errorf("Expected Session.Name to remain, got %s", result.Session.Name)
		}

		// Session.MaxAge should be overridden
		if result.Session.MaxAge != 7200 {
			t.Errorf("Expected Session.MaxAge to be overridden, got %d", result.Session.MaxAge)
		}
	})
}

// TestIsZeroValue tests the isZeroValue helper function
func TestIsZeroValue(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{
			name:     "Zero string",
			value:    "",
			expected: true,
		},
		{
			name:     "Non-zero string",
			value:    "hello",
			expected: false,
		},
		{
			name:     "Zero int",
			value:    0,
			expected: true,
		},
		{
			name:     "Non-zero int",
			value:    42,
			expected: false,
		},
		{
			name:     "Zero bool",
			value:    false,
			expected: true,
		},
		{
			name:     "Non-zero bool",
			value:    true,
			expected: false,
		},
		{
			name:     "Nil pointer",
			value:    (*string)(nil),
			expected: true,
		},
		{
			name:     "Non-nil pointer",
			value:    stringPtr("test"),
			expected: false,
		},
		{
			name:     "Nil slice",
			value:    ([]string)(nil),
			expected: true,
		},
		{
			name:     "Empty slice",
			value:    []string{},
			expected: true,
		},
		{
			name:     "Non-empty slice",
			value:    []string{"a"},
			expected: false,
		},
		{
			name:     "Nil map",
			value:    (map[string]string)(nil),
			expected: true,
		},
		{
			name:     "Empty map",
			value:    map[string]string{},
			expected: true,
		},
		{
			name:     "Non-empty map",
			value:    map[string]string{"key": "value"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := reflect.ValueOf(tt.value)
			result := isZeroValue(v)

			if result != tt.expected {
				t.Errorf("Expected isZeroValue to be %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsZeroValue_Struct tests isZeroValue with struct types
func TestIsZeroValue_Struct(t *testing.T) {
	type TestStruct struct {
		Field1 string
		Field2 int
	}

	t.Run("Zero struct", func(t *testing.T) {
		s := TestStruct{}
		v := reflect.ValueOf(s)
		result := isZeroValue(v)

		if !result {
			t.Error("Expected zero struct to return true")
		}
	})

	t.Run("Non-zero struct - Field1 set", func(t *testing.T) {
		s := TestStruct{Field1: "test"}
		v := reflect.ValueOf(s)
		result := isZeroValue(v)

		if result {
			t.Error("Expected non-zero struct to return false")
		}
	})

	t.Run("Non-zero struct - Field2 set", func(t *testing.T) {
		s := TestStruct{Field2: 42}
		v := reflect.ValueOf(s)
		result := isZeroValue(v)

		if result {
			t.Error("Expected non-zero struct to return false")
		}
	})

	t.Run("Non-zero struct - Both fields set", func(t *testing.T) {
		s := TestStruct{Field1: "test", Field2: 42}
		v := reflect.ValueOf(s)
		result := isZeroValue(v)

		if result {
			t.Error("Expected non-zero struct to return false")
		}
	})
}

// Helper function for pointer tests
func stringPtr(s string) *string {
	return &s
}
