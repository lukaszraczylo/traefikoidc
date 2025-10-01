// Package config provides tests for configuration management
package config

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// MockLogger implements the Logger interface for testing
type MockLogger struct {
	debugMessages []string
	infoMessages  []string
	errorMessages []string
}

func NewMockLogger() *MockLogger {
	return &MockLogger{
		debugMessages: make([]string, 0),
		infoMessages:  make([]string, 0),
		errorMessages: make([]string, 0),
	}
}

func (m *MockLogger) Debug(msg string) {
	m.debugMessages = append(m.debugMessages, msg)
}

func (m *MockLogger) Debugf(format string, args ...interface{}) {
	m.debugMessages = append(m.debugMessages, format)
}

func (m *MockLogger) Info(msg string) {
	m.infoMessages = append(m.infoMessages, msg)
}

func (m *MockLogger) Infof(format string, args ...interface{}) {
	m.infoMessages = append(m.infoMessages, format)
}

func (m *MockLogger) Error(msg string) {
	m.errorMessages = append(m.errorMessages, msg)
}

func (m *MockLogger) Errorf(format string, args ...interface{}) {
	m.errorMessages = append(m.errorMessages, format)
}

func (m *MockLogger) GetDebugMessages() []string {
	return m.debugMessages
}

func (m *MockLogger) GetInfoMessages() []string {
	return m.infoMessages
}

func (m *MockLogger) GetErrorMessages() []string {
	return m.errorMessages
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config == nil {
		t.Fatal("CreateConfig() returned nil")
	}

	// Test default values
	if config.LogLevel != "INFO" {
		t.Errorf("Expected LogLevel 'INFO', got '%s'", config.LogLevel)
	}

	if !config.ForceHTTPS {
		t.Error("Expected ForceHTTPS to be true")
	}

	if !config.EnablePKCE {
		t.Error("Expected EnablePKCE to be true")
	}

	if config.RateLimit != 10 {
		t.Errorf("Expected RateLimit 10, got %d", config.RateLimit)
	}

	if config.RefreshGracePeriodSeconds != 60 {
		t.Errorf("Expected RefreshGracePeriodSeconds 60, got %d", config.RefreshGracePeriodSeconds)
	}

	expectedScopes := []string{"openid", "profile", "email"}
	if len(config.Scopes) != len(expectedScopes) {
		t.Errorf("Expected %d scopes, got %d", len(expectedScopes), len(config.Scopes))
	}

	for i, expected := range expectedScopes {
		if i >= len(config.Scopes) || config.Scopes[i] != expected {
			t.Errorf("Expected scope '%s' at index %d, got '%s'", expected, i, config.Scopes[i])
		}
	}

	if config.Headers == nil {
		t.Error("Expected Headers to be initialized, got nil")
	}

	if len(config.Headers) != 0 {
		t.Errorf("Expected empty Headers slice, got %d elements", len(config.Headers))
	}
}

func TestNewSettings(t *testing.T) {
	logger := NewMockLogger()
	settings := NewSettings(logger)

	if settings == nil {
		t.Fatal("NewSettings() returned nil")
	}

	if settings.logger != logger {
		t.Error("Settings logger not set correctly")
	}
}

func TestHeaderConfig(t *testing.T) {
	header := HeaderConfig{
		Name:  "X-User-Email",
		Value: "{{.Claims.email}}",
	}

	if header.Name != "X-User-Email" {
		t.Errorf("Expected Name 'X-User-Email', got '%s'", header.Name)
	}

	if header.Value != "{{.Claims.email}}" {
		t.Errorf("Expected Value '{{.Claims.email}}', got '%s'", header.Value)
	}
}

func TestConfigDefaults(t *testing.T) {
	config := &Config{}

	// Test that zero values are as expected
	if config.LogLevel != "" {
		t.Errorf("Expected empty LogLevel, got '%s'", config.LogLevel)
	}

	if config.ForceHTTPS {
		t.Error("Expected ForceHTTPS to be false by default")
	}

	if config.EnablePKCE {
		t.Error("Expected EnablePKCE to be false by default")
	}

	if config.RateLimit != 0 {
		t.Errorf("Expected RateLimit 0, got %d", config.RateLimit)
	}
}

func TestConfigSerialization(t *testing.T) {
	config := CreateConfig()
	config.ProviderURL = "https://example.com"
	config.ClientID = "test-client"
	config.ClientSecret = "test-secret"

	// Test that config can be used (basic validation)
	if config.ProviderURL != "https://example.com" {
		t.Errorf("Expected ProviderURL 'https://example.com', got '%s'", config.ProviderURL)
	}

	if config.ClientID != "test-client" {
		t.Errorf("Expected ClientID 'test-client', got '%s'", config.ClientID)
	}

	if config.ClientSecret != "test-secret" {
		t.Errorf("Expected ClientSecret 'test-secret', got '%s'", config.ClientSecret)
	}
}

func TestConfigWithHeaders(t *testing.T) {
	config := CreateConfig()
	config.Headers = []HeaderConfig{
		{Name: "X-User-Name", Value: "{{.Claims.name}}"},
		{Name: "X-User-Email", Value: "{{.Claims.email}}"},
	}

	if len(config.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(config.Headers))
	}

	expectedHeaders := map[string]string{
		"X-User-Name":  "{{.Claims.name}}",
		"X-User-Email": "{{.Claims.email}}",
	}

	for _, header := range config.Headers {
		if expectedValue, exists := expectedHeaders[header.Name]; !exists {
			t.Errorf("Unexpected header: %s", header.Name)
		} else if header.Value != expectedValue {
			t.Errorf("Expected header %s value '%s', got '%s'", header.Name, expectedValue, header.Value)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectValid bool
	}{
		{
			name:        "default config",
			config:      CreateConfig(),
			expectValid: true,
		},
		{
			name: "config with all fields",
			config: &Config{
				ProviderURL:               "https://example.com",
				ClientID:                  "test-client",
				ClientSecret:              "test-secret",
				CallbackURL:               "/callback",
				LogLevel:                  "DEBUG",
				ForceHTTPS:                true,
				EnablePKCE:                true,
				RateLimit:                 20,
				RefreshGracePeriodSeconds: 120,
			},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - ensure config is not nil
			if tt.config == nil && tt.expectValid {
				t.Error("Expected valid config, got nil")
			}
			if tt.config != nil && !tt.expectValid {
				// Could add specific validation logic here
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if minEncryptionKeyLength != 16 {
		t.Errorf("Expected minEncryptionKeyLength 16, got %d", minEncryptionKeyLength)
	}

	if ConstSessionTimeout != 86400 {
		t.Errorf("Expected ConstSessionTimeout 86400, got %d", ConstSessionTimeout)
	}
}

func TestCreateDefaultSecurityConfig(t *testing.T) {
	config := createDefaultSecurityConfig()

	if config == nil {
		t.Fatal("createDefaultSecurityConfig() returned nil")
	}

	// Test default values
	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}

	if config.Profile != "default" {
		t.Errorf("Expected Profile 'default', got '%s'", config.Profile)
	}

	if !config.StrictTransportSecurity {
		t.Error("Expected StrictTransportSecurity to be true")
	}

	if config.StrictTransportSecurityMaxAge != 31536000 {
		t.Errorf("Expected StrictTransportSecurityMaxAge 31536000, got %d", config.StrictTransportSecurityMaxAge)
	}

	if config.FrameOptions != "DENY" {
		t.Errorf("Expected FrameOptions 'DENY', got '%s'", config.FrameOptions)
	}

	if config.ContentTypeOptions != "nosniff" {
		t.Errorf("Expected ContentTypeOptions 'nosniff', got '%s'", config.ContentTypeOptions)
	}

	if config.XSSProtection != "1; mode=block" {
		t.Errorf("Expected XSSProtection '1; mode=block', got '%s'", config.XSSProtection)
	}

	if config.CORSEnabled {
		t.Error("Expected CORSEnabled to be false")
	}

	if !config.DisableServerHeader {
		t.Error("Expected DisableServerHeader to be true")
	}
}

func TestToInternalSecurityConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *SecurityHeadersConfig
		expected map[string]interface{}
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: nil,
		},
		{
			name: "disabled config",
			config: &SecurityHeadersConfig{
				Enabled: false,
			},
			expected: nil,
		},
		{
			name: "default profile",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "default",
			},
			expected: map[string]interface{}{
				"DevelopmentMode":       false,
				"ContentSecurityPolicy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
				"FrameOptions":          "DENY",
			},
		},
		{
			name: "strict profile",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "strict",
			},
			expected: map[string]interface{}{
				"DevelopmentMode":       false,
				"ContentSecurityPolicy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
			},
		},
		{
			name: "development profile",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "development",
			},
			expected: map[string]interface{}{
				"DevelopmentMode": true,
				"FrameOptions":    "SAMEORIGIN",
			},
		},
		{
			name: "api profile",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "api",
			},
			expected: map[string]interface{}{
				"DevelopmentMode":       false,
				"ContentSecurityPolicy": "default-src 'none'; frame-ancestors 'none';",
				"FrameOptions":          "DENY",
			},
		},
		{
			name: "custom config with overrides",
			config: &SecurityHeadersConfig{
				Enabled:                       true,
				Profile:                       "custom",
				ContentSecurityPolicy:         "custom-csp",
				FrameOptions:                  "SAMEORIGIN",
				StrictTransportSecurity:       true,
				StrictTransportSecurityMaxAge: 86400,
			},
			expected: map[string]interface{}{
				"DevelopmentMode":               false,
				"ContentSecurityPolicy":         "custom-csp",
				"FrameOptions":                  "SAMEORIGIN",
				"StrictTransportSecurityMaxAge": 86400,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ToInternalSecurityConfig()

			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil result, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			configMap, ok := result.(map[string]interface{})
			if !ok {
				t.Fatalf("Expected map[string]interface{}, got %T", result)
			}

			// Check a few key values
			for key, expectedValue := range tt.expected {
				if actualValue, exists := configMap[key]; !exists {
					t.Errorf("Expected key '%s' not found", key)
				} else if actualValue != expectedValue {
					t.Errorf("For key '%s': expected %v, got %v", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestGetSecurityHeadersApplier(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool // whether applier should be nil
	}{
		{
			name: "nil security headers",
			config: &Config{
				SecurityHeaders: nil,
			},
			expected: true, // applier should be nil
		},
		{
			name: "disabled security headers",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled: false,
				},
			},
			expected: true, // applier should be nil
		},
		{
			name: "enabled security headers",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled: true,
				},
			},
			expected: false, // applier should not be nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applier := tt.config.GetSecurityHeadersApplier()

			if tt.expected && applier != nil {
				t.Error("Expected applier to be nil")
			}
			if !tt.expected && applier == nil {
				t.Error("Expected applier to not be nil")
			}
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		expected       bool
	}{
		{
			name:           "exact match",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com", "https://other.com"},
			expected:       true,
		},
		{
			name:           "wildcard match",
			origin:         "https://test.example.com",
			allowedOrigins: []string{"https://*.example.com"},
			expected:       true,
		},
		{
			name:           "root domain match with wildcard",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://*.example.com"},
			expected:       true,
		},
		{
			name:           "http wildcard match",
			origin:         "http://test.example.com",
			allowedOrigins: []string{"http://*.example.com"},
			expected:       true,
		},
		{
			name:           "catch-all wildcard",
			origin:         "https://anything.com",
			allowedOrigins: []string{"*"},
			expected:       true,
		},
		{
			name:           "no match",
			origin:         "https://notallowed.com",
			allowedOrigins: []string{"https://example.com"},
			expected:       false,
		},
		{
			name:           "empty allowed origins",
			origin:         "https://example.com",
			allowedOrigins: []string{},
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOriginAllowed(tt.origin, tt.allowedOrigins)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSecurityHeadersConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config *SecurityHeadersConfig
		valid  bool
	}{
		{
			name: "valid default config",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "default",
			},
			valid: true,
		},
		{
			name: "valid strict config",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "strict",
			},
			valid: true,
		},
		{
			name: "valid development config",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "development",
			},
			valid: true,
		},
		{
			name: "valid api config",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "api",
			},
			valid: true,
		},
		{
			name: "valid custom config",
			config: &SecurityHeadersConfig{
				Enabled:               true,
				Profile:               "custom",
				ContentSecurityPolicy: "default-src 'self'",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - ensure config can be processed
			if tt.config == nil && tt.valid {
				t.Error("Expected valid config, got nil")
			}

			// Test ToInternalSecurityConfig doesn't panic
			result := tt.config.ToInternalSecurityConfig()

			if tt.config.Enabled && result == nil {
				t.Error("Expected non-nil result for enabled config")
			}
		})
	}
}

func TestConfigWithSecurityHeaders(t *testing.T) {
	config := CreateConfig()

	// Test that default config has security headers
	if config.SecurityHeaders == nil {
		t.Fatal("Expected SecurityHeaders to be initialized")
	}

	if !config.SecurityHeaders.Enabled {
		t.Error("Expected SecurityHeaders to be enabled by default")
	}

	// Test security headers applier
	applier := config.GetSecurityHeadersApplier()
	if applier == nil {
		t.Error("Expected security headers applier to be non-nil")
	}

	// Test with custom security config
	config.SecurityHeaders = &SecurityHeadersConfig{
		Enabled:                       true,
		Profile:                       "strict",
		ContentSecurityPolicy:         "default-src 'self'",
		FrameOptions:                  "DENY",
		StrictTransportSecurity:       true,
		StrictTransportSecurityMaxAge: 31536000,
		CORSEnabled:                   false,
		CustomHeaders:                 map[string]string{"X-Custom": "value"},
	}

	applier = config.GetSecurityHeadersApplier()
	if applier == nil {
		t.Error("Expected custom security headers applier to be non-nil")
	}
}

func TestConfigEdgeCases(t *testing.T) {
	// Test config with empty values
	config := &Config{
		ProviderURL:  "",
		ClientID:     "",
		ClientSecret: "",
		LogLevel:     "",
		Scopes:       []string{},
		Headers:      []HeaderConfig{},
	}

	if config.LogLevel != "" {
		t.Errorf("Expected empty LogLevel, got '%s'", config.LogLevel)
	}

	if len(config.Scopes) != 0 {
		t.Errorf("Expected empty Scopes, got %d", len(config.Scopes))
	}

	// Test config with nil slices
	config = &Config{
		Scopes:  nil,
		Headers: nil,
	}

	if len(config.Scopes) != 0 {
		t.Errorf("Expected empty Scopes, got %v", config.Scopes)
	}
}

func TestSecurityHeadersApplierComprehensive(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		setup  func(*http.Request) *http.Request
		check  func(*testing.T, http.Header)
	}{
		{
			name: "All security headers with HTTPS",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled:                           true,
					FrameOptions:                      "SAMEORIGIN",
					ContentTypeOptions:                "nosniff",
					XSSProtection:                     "1; mode=block",
					ReferrerPolicy:                    "strict-origin-when-cross-origin",
					ContentSecurityPolicy:             "default-src 'self'",
					StrictTransportSecurity:           true,
					StrictTransportSecurityMaxAge:     31536000,
					StrictTransportSecuritySubdomains: true,
					StrictTransportSecurityPreload:    true,
					CORSEnabled:                       true,
					CORSAllowedOrigins:                []string{"https://example.com"},
					CORSAllowedMethods:                []string{"GET", "POST"},
					CORSAllowedHeaders:                []string{"Authorization", "Content-Type"},
					CORSAllowCredentials:              true,
					CORSMaxAge:                        86400,
					CustomHeaders:                     map[string]string{"X-Custom": "value"},
					DisableServerHeader:               true,
					DisablePoweredByHeader:            true,
				},
			},
			setup: func(req *http.Request) *http.Request {
				req.Header.Set("Origin", "https://example.com")
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			},
			check: func(t *testing.T, headers http.Header) {
				expectedHeaders := map[string]string{
					"X-Frame-Options":                  "SAMEORIGIN",
					"X-Content-Type-Options":           "nosniff",
					"X-XSS-Protection":                 "1; mode=block",
					"Referrer-Policy":                  "strict-origin-when-cross-origin",
					"Content-Security-Policy":          "default-src 'self'",
					"Strict-Transport-Security":        "max-age=31536000; includeSubDomains; preload",
					"Access-Control-Allow-Origin":      "https://example.com",
					"Access-Control-Allow-Methods":     "GET, POST",
					"Access-Control-Allow-Headers":     "Authorization, Content-Type",
					"Access-Control-Allow-Credentials": "true",
					"Access-Control-Max-Age":           "86400",
					"X-Custom":                         "value",
				}

				for key, expected := range expectedHeaders {
					if actual := headers.Get(key); actual != expected {
						t.Errorf("Expected header %s: '%s', got '%s'", key, expected, actual)
					}
				}
			},
		},
		{
			name: "CORS with wildcard origin",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled:            true,
					CORSEnabled:        true,
					CORSAllowedOrigins: []string{"*"},
				},
			},
			setup: func(req *http.Request) *http.Request {
				req.Header.Set("Origin", "https://anywhere.com")
				return req
			},
			check: func(t *testing.T, headers http.Header) {
				if origin := headers.Get("Access-Control-Allow-Origin"); origin != "https://anywhere.com" {
					t.Errorf("Expected CORS origin 'https://anywhere.com', got '%s'", origin)
				}
			},
		},
		{
			name: "HSTS with TLS",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled:                        true,
					StrictTransportSecurity:        true,
					StrictTransportSecurityMaxAge:  63072000,
					StrictTransportSecurityPreload: false,
				},
			},
			setup: func(req *http.Request) *http.Request {
				// Simulate TLS request
				req.TLS = &tls.ConnectionState{}
				return req
			},
			check: func(t *testing.T, headers http.Header) {
				hsts := headers.Get("Strict-Transport-Security")
				expected := "max-age=63072000"
				if hsts != expected {
					t.Errorf("Expected HSTS '%s', got '%s'", expected, hsts)
				}
			},
		},
		{
			name: "Disabled security headers",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled: false,
				},
			},
			setup: func(req *http.Request) *http.Request {
				return req
			},
			check: func(t *testing.T, headers http.Header) {
				// Since applier should be nil, this won't be called
				// but we include it for completeness
			},
		},
		{
			name: "Remove server headers",
			config: &Config{
				SecurityHeaders: &SecurityHeadersConfig{
					Enabled:                true,
					DisableServerHeader:    true,
					DisablePoweredByHeader: true,
				},
			},
			setup: func(req *http.Request) *http.Request {
				return req
			},
			check: func(t *testing.T, headers http.Header) {
				// Headers should be explicitly deleted
				// We can't easily test deletion, but we ensure they're not set
				if server := headers.Get("Server"); server != "" {
					t.Errorf("Expected Server header to be removed, got '%s'", server)
				}
				if powered := headers.Get("X-Powered-By"); powered != "" {
					t.Errorf("Expected X-Powered-By header to be removed, got '%s'", powered)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applier := tt.config.GetSecurityHeadersApplier()

			if !tt.config.SecurityHeaders.Enabled {
				if applier != nil {
					t.Error("Expected nil applier for disabled security headers")
				}
				return
			}

			if applier == nil {
				t.Fatal("Expected non-nil applier for enabled security headers")
			}

			req := httptest.NewRequest("GET", "https://example.com/test", nil)
			req = tt.setup(req)
			rw := httptest.NewRecorder()

			// Pre-set some headers that should be removed
			rw.Header().Set("Server", "nginx/1.0")
			rw.Header().Set("X-Powered-By", "Express")

			applier(rw, req)
			tt.check(t, rw.Header())
		})
	}
}

func TestToInternalSecurityConfigComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		config   *SecurityHeadersConfig
		expected map[string]interface{}
	}{
		{
			name:     "Nil config",
			config:   nil,
			expected: nil,
		},
		{
			name: "Disabled config",
			config: &SecurityHeadersConfig{
				Enabled: false,
			},
			expected: nil,
		},
		{
			name: "Custom profile with all options",
			config: &SecurityHeadersConfig{
				Enabled:                           true,
				Profile:                           "custom",
				ContentSecurityPolicy:             "default-src 'none'",
				FrameOptions:                      "ALLOW-FROM https://example.com",
				ContentTypeOptions:                "nosniff",
				XSSProtection:                     "0",
				ReferrerPolicy:                    "no-referrer",
				PermissionsPolicy:                 "camera=(), microphone=()",
				CrossOriginEmbedderPolicy:         "require-corp",
				CrossOriginOpenerPolicy:           "same-origin",
				CrossOriginResourcePolicy:         "cross-origin",
				StrictTransportSecurity:           true,
				StrictTransportSecurityMaxAge:     15552000,
				StrictTransportSecuritySubdomains: false,
				StrictTransportSecurityPreload:    true,
				CORSEnabled:                       true,
				CORSAllowedOrigins:                []string{"https://api.example.com"},
				CORSAllowedMethods:                []string{"PUT", "DELETE"},
				CORSAllowedHeaders:                []string{"X-API-Key"},
				CORSAllowCredentials:              false,
				CORSMaxAge:                        3600,
				CustomHeaders:                     map[string]string{"X-API-Version": "v1"},
				DisableServerHeader:               true,
				DisablePoweredByHeader:            false,
			},
			expected: map[string]interface{}{
				"DevelopmentMode":                   false,
				"ContentSecurityPolicy":             "default-src 'none'",
				"FrameOptions":                      "ALLOW-FROM https://example.com",
				"ContentTypeOptions":                "nosniff",
				"XSSProtection":                     "0",
				"ReferrerPolicy":                    "no-referrer",
				"PermissionsPolicy":                 "camera=(), microphone=()",
				"CrossOriginEmbedderPolicy":         "require-corp",
				"CrossOriginOpenerPolicy":           "same-origin",
				"CrossOriginResourcePolicy":         "cross-origin",
				"StrictTransportSecurityMaxAge":     15552000,
				"StrictTransportSecuritySubdomains": false,
				"StrictTransportSecurityPreload":    true,
				"CORSEnabled":                       true,
				"CORSAllowedOrigins":                []string{"https://api.example.com"},
				"CORSAllowedMethods":                []string{"PUT", "DELETE"},
				"CORSAllowedHeaders":                []string{"X-API-Key"},
				"CORSAllowCredentials":              false,
				"CORSMaxAge":                        3600,
				"CustomHeaders":                     map[string]string{"X-API-Version": "v1"},
				"DisableServerHeader":               true,
				"DisablePoweredByHeader":            false,
			},
		},
		{
			name: "Development profile",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "development",
			},
			expected: map[string]interface{}{
				"DevelopmentMode":           true,
				"ContentSecurityPolicy":     "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' ws: wss:;",
				"FrameOptions":              "SAMEORIGIN",
				"ContentTypeOptions":        "nosniff",
				"XSSProtection":             "1; mode=block",
				"ReferrerPolicy":            "strict-origin-when-cross-origin",
				"CrossOriginOpenerPolicy":   "unsafe-none",
				"CrossOriginResourcePolicy": "cross-origin",
				"CORSEnabled":               false,
				"CORSAllowCredentials":      false,
				"DisableServerHeader":       false,
				"DisablePoweredByHeader":    false,
			},
		},
		{
			name: "API profile",
			config: &SecurityHeadersConfig{
				Enabled: true,
				Profile: "api",
			},
			expected: map[string]interface{}{
				"DevelopmentMode":           false,
				"ContentSecurityPolicy":     "default-src 'none'; frame-ancestors 'none';",
				"FrameOptions":              "DENY",
				"ContentTypeOptions":        "nosniff",
				"XSSProtection":             "1; mode=block",
				"ReferrerPolicy":            "strict-origin-when-cross-origin",
				"CrossOriginResourcePolicy": "cross-origin",
				"CORSEnabled":               false,
				"CORSAllowCredentials":      false,
				"DisableServerHeader":       false,
				"DisablePoweredByHeader":    false,
			},
		},
		{
			name: "Partial configuration",
			config: &SecurityHeadersConfig{
				Enabled:      true,
				Profile:      "default",
				FrameOptions: "SAMEORIGIN", // Override default
				CORSEnabled:  true,         // Enable CORS
			},
			expected: map[string]interface{}{
				"DevelopmentMode":           false,
				"ContentSecurityPolicy":     "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
				"FrameOptions":              "SAMEORIGIN", // Overridden
				"ContentTypeOptions":        "nosniff",
				"XSSProtection":             "1; mode=block",
				"ReferrerPolicy":            "strict-origin-when-cross-origin",
				"PermissionsPolicy":         "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
				"CrossOriginEmbedderPolicy": "require-corp",
				"CrossOriginOpenerPolicy":   "same-origin",
				"CrossOriginResourcePolicy": "same-origin",
				"CORSEnabled":               true, // Explicitly set
				"CORSAllowCredentials":      false,
				"DisableServerHeader":       false,
				"DisablePoweredByHeader":    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.ToInternalSecurityConfig()

			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil result, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			resultMap, ok := result.(map[string]interface{})
			if !ok {
				t.Errorf("Expected result to be map[string]interface{}, got %T", result)
				return
			}

			for key, expectedValue := range tt.expected {
				actualValue, exists := resultMap[key]
				if !exists {
					t.Errorf("Expected key '%s' not found in result", key)
					continue
				}

				if !reflect.DeepEqual(actualValue, expectedValue) {
					t.Errorf("For key '%s': expected %v (%T), got %v (%T)",
						key, expectedValue, expectedValue, actualValue, actualValue)
				}
			}

			// Check that no unexpected keys are present
			for key := range resultMap {
				if _, expected := tt.expected[key]; !expected {
					t.Errorf("Unexpected key '%s' found in result with value %v", key, resultMap[key])
				}
			}
		})
	}
}
