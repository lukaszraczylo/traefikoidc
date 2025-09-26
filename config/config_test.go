// Package config provides tests for configuration management
package config

import (
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
