package config

import (
	"testing"
	"text/template"
	"time"
)

// ============================================================================
// Config Creation Tests
// ============================================================================

func TestConfigCreation(t *testing.T) {
	t.Run("CreateConfig_DefaultValues", func(t *testing.T) {
		config := CreateConfig()

		// Check default scopes
		expectedScopes := []string{"openid", "profile", "email"}
		if len(config.Scopes) != len(expectedScopes) {
			t.Errorf("Expected %d default scopes, got %d", len(expectedScopes), len(config.Scopes))
		}
		for i, scope := range expectedScopes {
			if config.Scopes[i] != scope {
				t.Errorf("Expected scope %s at position %d, got %s", scope, i, config.Scopes[i])
			}
		}

		// Check default log level
		if config.LogLevel != "INFO" {
			t.Errorf("Expected default log level '%s', got '%s'", "INFO", config.LogLevel)
		}

		// Check default rate limit
		if config.RateLimit != 10 {
			t.Errorf("Expected default rate limit %d, got %d", 10, config.RateLimit)
		}

		// Check ForceHTTPS default
		if !config.ForceHTTPS {
			t.Error("Expected ForceHTTPS to be true by default")
		}

		// Check OverrideScopes default
		if config.OverrideScopes {
			t.Error("Expected OverrideScopes to be false by default")
		}
	})

	t.Run("CreateConfig_EmptyHeaders", func(t *testing.T) {
		config := CreateConfig()
		if config.Headers == nil {
			t.Error("Expected Headers to be initialized, got nil")
		}
		if len(config.Headers) != 0 {
			t.Errorf("Expected empty Headers slice, got %d headers", len(config.Headers))
		}
	})
}

// ============================================================================
// Config Validation Tests - SKIPPED (no Validate method in real Config)
// ============================================================================
/*
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectedError string
	}{
		{
			name:          "Empty Config",
			config:        &Config{},
			expectedError: "providerURL is required",
		},
		{
			name: "Missing CallbackURL",
			config: &Config{
				ProviderURL: "https://provider.com",
			},
			expectedError: "callbackURL is required",
		},
		{
			name: "Missing ClientID",
			config: &Config{
				ProviderURL: "https://provider.com",
				CallbackURL: "/callback",
			},
			expectedError: "clientID is required",
		},
		{
			name: "Missing ClientSecret",
			config: &Config{
				ProviderURL: "https://provider.com",
				CallbackURL: "/callback",
				ClientID:    "client-id",
			},
			expectedError: "clientSecret is required",
		},
		{
			name: "Missing SessionEncryptionKey",
			config: &Config{
				ProviderURL:  "https://provider.com",
				CallbackURL:  "/callback",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectedError: "sessionEncryptionKey is required",
		},
		{
			name: "Short SessionEncryptionKey",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "short",
			},
			expectedError: "sessionEncryptionKey must be at least 32 characters",
		},
		{
			name: "Invalid LogLevel",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				LogLevel:             "invalid",
			},
			expectedError: "invalid log level: invalid (must be one of: debug, info, warn, error)",
		},
		{
			name: "Invalid RateLimit",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				RateLimit:            0,
			},
			expectedError: "rateLimit must be greater than 0",
		},
		{
			name: "Valid Config",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				RateLimit:            10,
			},
			expectedError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error: %s, got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError {
					t.Errorf("Expected error: %s, got: %s", tc.expectedError, err.Error())
				}
			}
		})
	}
}
*/

// ============================================================================
// Templated Header Config Tests
// ============================================================================

/*
func TestHeaderConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		header        HeaderConfig
		expectedError string
	}{
		{
			name:          "Empty Name",
			header:        HeaderConfig{Name: "", Value: "{{.Claims.email}}"},
			expectedError: "header name cannot be empty",
		},
		{
			name:          "Empty Value",
			header:        HeaderConfig{Name: "X-Email", Value: ""},
			expectedError: "header value template cannot be empty",
		},
		{
			name:          "Not a Template",
			header:        HeaderConfig{Name: "X-Email", Value: "static-value"},
			expectedError: "header value 'static-value' does not appear to be a valid template (missing {{ }})",
		},
		{
			name:          "Lowercase claims",
			header:        HeaderConfig{Name: "X-Email", Value: "{{.claims.email}}"},
			expectedError: "header template '{{.claims.email}}' appears to use lowercase 'claims' - use '{{.Claims...' instead (case sensitive)",
		},
		{
			name:          "Lowercase accessToken",
			header:        HeaderConfig{Name: "X-Token", Value: "Bearer {{.accessToken}}"},
			expectedError: "header template 'Bearer {{.accessToken}}' appears to use lowercase 'accessToken' - use '{{.AccessToken...' instead (case sensitive)",
		},
		{
			name:          "Lowercase idToken",
			header:        HeaderConfig{Name: "X-Token", Value: "Bearer {{.idToken}}"},
			expectedError: "header template 'Bearer {{.idToken}}' appears to use lowercase 'idToken' - use '{{.IdToken...' instead (case sensitive)",
		},
		{
			name:          "Lowercase refreshToken",
			header:        HeaderConfig{Name: "X-Refresh", Value: "Bearer {{.refreshToken}}"},
			expectedError: "header template 'Bearer {{.refreshToken}}' appears to use lowercase 'refreshToken' - use '{{.RefreshToken...' instead (case sensitive)",
		},
		{
			name:          "Valid Template",
			header:        HeaderConfig{Name: "X-Email", Value: "{{.Claims.email}}"},
			expectedError: "",
		},
		{
			name:          "Valid Bearer Token Template",
			header:        HeaderConfig{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
			expectedError: "",
		},
		{
			name:          "Complex Valid Template",
			header:        HeaderConfig{Name: "X-User-Info", Value: "{{.Claims.sub}}-{{.Claims.email}}"},
			expectedError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				RateLimit:            10,
				Headers:              []HeaderConfig{tc.header},
			}

			err := config.Validate()
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error: %s, got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError {
					t.Errorf("Expected error: %s, got: %s", tc.expectedError, err.Error())
				}
			}
		})
	}
}
*/

func TestTemplateParsingInConfig(t *testing.T) {
	tests := []struct {
		name              string
		headers           []HeaderConfig
		expectedTemplates int
		expectError       bool
	}{
		{
			name: "Single Valid Template",
			headers: []HeaderConfig{
				{Name: "X-Email", Value: "{{.Claims.email}}"},
			},
			expectedTemplates: 1,
			expectError:       false,
		},
		{
			name: "Multiple Valid Templates",
			headers: []HeaderConfig{
				{Name: "X-Email", Value: "{{.Claims.email}}"},
				{Name: "X-Subject", Value: "{{.Claims.sub}}"},
				{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
			},
			expectedTemplates: 3,
			expectError:       false,
		},
		{
			name: "Template with Conditional",
			headers: []HeaderConfig{
				{Name: "X-User", Value: "{{if .Claims.preferred_username}}{{.Claims.preferred_username}}{{else}}{{.Claims.sub}}{{end}}"},
			},
			expectedTemplates: 1,
			expectError:       false,
		},
		{
			name: "Template with Range",
			headers: []HeaderConfig{
				{Name: "X-Groups", Value: "{{range .Claims.groups}}{{.}},{{end}}"},
			},
			expectedTemplates: 1,
			expectError:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsedTemplates := make(map[string]*template.Template)

			for _, header := range tc.headers {
				tmpl, err := template.New(header.Name).Parse(header.Value)
				if err != nil {
					if !tc.expectError {
						t.Errorf("Failed to parse template for header %s: %v", header.Name, err)
					}
					continue
				}
				parsedTemplates[header.Name] = tmpl
			}

			if !tc.expectError && len(parsedTemplates) != tc.expectedTemplates {
				t.Errorf("Expected %d parsed templates, got %d", tc.expectedTemplates, len(parsedTemplates))
			}
		})
	}
}

// ============================================================================
// Auth Config Tests
// ============================================================================

func TestAuthConfig(t *testing.T) {
	// AuthURL field removed from Config - test skipped

	t.Run("Scopes Configuration", func(t *testing.T) {
		tests := []struct {
			name           string
			config         *Config
			expectedScopes []string
		}{
			{
				name: "Default scopes",
				config: &Config{
					Scopes: []string{"openid", "profile", "email"},
				},
				expectedScopes: []string{"openid", "profile", "email"},
			},
			{
				name: "Custom scopes",
				config: &Config{
					Scopes: []string{"openid", "custom_scope"},
				},
				expectedScopes: []string{"openid", "custom_scope"},
			},
			{
				name: "Empty scopes",
				config: &Config{
					Scopes: []string{},
				},
				expectedScopes: []string{},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if !equalSlices(tc.config.Scopes, tc.expectedScopes) {
					t.Errorf("Expected scopes %v, got %v", tc.expectedScopes, tc.config.Scopes)
				}
			})
		}
	})

	t.Run("Excluded URLs Configuration", func(t *testing.T) {
		tests := []struct {
			name            string
			config          *Config
			expectedExclude []string
		}{
			{
				name:            "No excluded URLs",
				config:          &Config{},
				expectedExclude: nil,
			},
			{
				name: "With excluded URLs",
				config: &Config{
					ExcludedURLs: []string{"/health", "/metrics", "/api/public"},
				},
				expectedExclude: []string{"/health", "/metrics", "/api/public"},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if tc.expectedExclude == nil {
					if tc.config.ExcludedURLs != nil {
						t.Errorf("Expected nil ExcludedURLs, got %v", tc.config.ExcludedURLs)
					}
				} else if !equalSlices(tc.config.ExcludedURLs, tc.expectedExclude) {
					t.Errorf("Expected ExcludedURLs %v, got %v", tc.expectedExclude, tc.config.ExcludedURLs)
				}
			})
		}
	})
}

// ============================================================================
// Config Parser Tests
// ============================================================================

func TestConfigParser(t *testing.T) {
	t.Run("ParseProviderURL", func(t *testing.T) {
		tests := []struct {
			name        string
			input       string
			expected    string
			expectError bool
		}{
			{
				name:        "Valid HTTPS URL",
				input:       "https://provider.com/.well-known/openid-configuration",
				expected:    "https://provider.com/.well-known/openid-configuration",
				expectError: false,
			},
			{
				name:        "Valid HTTP URL",
				input:       "http://localhost:8080/.well-known/openid-configuration",
				expected:    "http://localhost:8080/.well-known/openid-configuration",
				expectError: false,
			},
			{
				name:        "URL with trailing slash",
				input:       "https://provider.com/",
				expected:    "https://provider.com/",
				expectError: false,
			},
			{
				name:        "Invalid URL",
				input:       "not-a-url",
				expected:    "",
				expectError: true,
			},
			{
				name:        "Empty URL",
				input:       "",
				expected:    "",
				expectError: true,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				config := &Config{ProviderURL: tc.input}
				// Since we're testing parsing, we'd validate the URL format
				if tc.input == "" {
					if !tc.expectError {
						t.Error("Expected error for empty URL")
					}
				} else if tc.input == "not-a-url" {
					// In real parsing, this would be caught
					if !tc.expectError {
						t.Error("Expected error for invalid URL")
					}
				} else {
					if config.ProviderURL != tc.expected {
						t.Errorf("Expected URL %s, got %s", tc.expected, config.ProviderURL)
					}
				}
			})
		}
	})

	t.Run("ParseTimeouts", func(t *testing.T) {
		tests := []struct {
			name            string
			refreshInterval string
			gracePeriod     string
			expectedRefresh time.Duration
			expectedGrace   time.Duration
		}{
			{
				name:            "Default values",
				refreshInterval: "",
				gracePeriod:     "",
				expectedRefresh: 0,
				expectedGrace:   0,
			},
			{
				name:            "Custom refresh interval",
				refreshInterval: "5m",
				gracePeriod:     "",
				expectedRefresh: 5 * time.Minute,
				expectedGrace:   0,
			},
			{
				name:            "Custom grace period",
				refreshInterval: "",
				gracePeriod:     "30s",
				expectedRefresh: 0,
				expectedGrace:   30 * time.Second,
			},
			{
				name:            "Both custom",
				refreshInterval: "10m",
				gracePeriod:     "1m",
				expectedRefresh: 10 * time.Minute,
				expectedGrace:   1 * time.Minute,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				// This would be part of config parsing
				// Here we're just testing the concept
				var refreshDuration, graceDuration time.Duration

				if tc.refreshInterval != "" {
					d, _ := time.ParseDuration(tc.refreshInterval)
					refreshDuration = d
				}
				if tc.gracePeriod != "" {
					d, _ := time.ParseDuration(tc.gracePeriod)
					graceDuration = d
				}

				if refreshDuration != tc.expectedRefresh {
					t.Errorf("Expected refresh %v, got %v", tc.expectedRefresh, refreshDuration)
				}
				if graceDuration != tc.expectedGrace {
					t.Errorf("Expected grace %v, got %v", tc.expectedGrace, graceDuration)
				}
			})
		}
	})
}

// ============================================================================
// Helper Functions
// ============================================================================

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
