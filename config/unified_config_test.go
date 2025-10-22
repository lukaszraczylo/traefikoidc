//go:build !yaegi

package config

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestUnifiedConfigJSONMarshalling tests JSON marshalling with secret redaction
func TestUnifiedConfigJSONMarshalling(t *testing.T) {
	config := &UnifiedConfig{
		Provider: ProviderConfig{
			IssuerURL:    "https://auth.example.com",
			ClientID:     "test-client",
			ClientSecret: "super-secret-value",
		},
		Session: SessionConfig{
			Secret:        "session-secret",
			EncryptionKey: "32-character-encryption-key-here",
			SigningKey:    "signing-key-secret",
		},
		Redis: RedisConfig{
			Password:         "redis-password",
			SentinelPassword: "sentinel-password",
		},
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config to JSON: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Verify secrets are redacted
	if !contains(jsonStr, `"clientSecret":"[REDACTED]"`) {
		t.Error("ClientSecret should be redacted in JSON output")
	}
	if !contains(jsonStr, `"secret":"[REDACTED]"`) {
		t.Error("Session.Secret should be redacted in JSON output")
	}
	if !contains(jsonStr, `"encryptionKey":"[REDACTED]"`) {
		t.Error("Session.EncryptionKey should be redacted in JSON output")
	}
	if !contains(jsonStr, `"signingKey":"[REDACTED]"`) {
		t.Error("Session.SigningKey should be redacted in JSON output")
	}
	if !contains(jsonStr, `"password":"[REDACTED]"`) {
		t.Error("Redis.Password should be redacted in JSON output")
	}
	if !contains(jsonStr, `"sentinelPassword":"[REDACTED]"`) {
		t.Error("Redis.SentinelPassword should be redacted in JSON output")
	}

	// Verify non-secret fields are preserved
	if !contains(jsonStr, `"issuerURL":"https://auth.example.com"`) {
		t.Error("IssuerURL should be preserved in JSON output")
	}
	if !contains(jsonStr, `"clientID":"test-client"`) {
		t.Error("ClientID should be preserved in JSON output")
	}
}

// TestUnifiedConfigYAMLMarshalling tests YAML marshalling with secret redaction
func TestUnifiedConfigYAMLMarshalling(t *testing.T) {
	config := &UnifiedConfig{
		Provider: ProviderConfig{
			IssuerURL:    "https://auth.example.com",
			ClientID:     "test-client",
			ClientSecret: "super-secret-value",
		},
		Session: SessionConfig{
			Secret:        "session-secret",
			EncryptionKey: "32-character-encryption-key-here",
			SigningKey:    "signing-key-secret",
		},
		Redis: RedisConfig{
			Password:         "redis-password",
			SentinelPassword: "sentinel-password",
		},
	}

	// Marshal to YAML
	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config to YAML: %v", err)
	}

	yamlStr := string(yamlBytes)

	// Verify secrets are redacted
	if !contains(yamlStr, "clientSecret: '[REDACTED]'") {
		t.Error("ClientSecret should be redacted in YAML output")
	}
	if !contains(yamlStr, "secret: '[REDACTED]'") {
		t.Error("Session.Secret should be redacted in YAML output")
	}
	if !contains(yamlStr, "encryptionKey: '[REDACTED]'") {
		t.Error("Session.EncryptionKey should be redacted in YAML output")
	}
	if !contains(yamlStr, "signingKey: '[REDACTED]'") {
		t.Error("Session.SigningKey should be redacted in YAML output")
	}
	if !contains(yamlStr, "password: '[REDACTED]'") {
		t.Error("Redis.Password should be redacted in YAML output")
	}
	if !contains(yamlStr, "sentinelPassword: '[REDACTED]'") {
		t.Error("Redis.SentinelPassword should be redacted in YAML output")
	}

	// Verify non-secret fields are preserved
	if !contains(yamlStr, "issuerURL: https://auth.example.com") {
		t.Error("IssuerURL should be preserved in YAML output")
	}
	if !contains(yamlStr, "clientID: test-client") {
		t.Error("ClientID should be preserved in YAML output")
	}
}

// TestProviderConfigMarshalling tests individual struct marshalling
func TestProviderConfigMarshalling(t *testing.T) {
	provider := ProviderConfig{
		IssuerURL:    "https://auth.example.com",
		ClientID:     "test-client",
		ClientSecret: "super-secret-value",
	}

	// Test JSON marshalling
	jsonBytes, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("Failed to marshal ProviderConfig to JSON: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !contains(jsonStr, `"clientSecret":"[REDACTED]"`) {
		t.Error("ClientSecret should be redacted in JSON output")
	}
	if !contains(jsonStr, `"clientID":"test-client"`) {
		t.Error("ClientID should be preserved in JSON output")
	}

	// Test YAML marshalling
	yamlBytes, err := yaml.Marshal(provider)
	if err != nil {
		t.Fatalf("Failed to marshal ProviderConfig to YAML: %v", err)
	}

	yamlStr := string(yamlBytes)
	if !contains(yamlStr, "clientSecret: '[REDACTED]'") {
		t.Error("ClientSecret should be redacted in YAML output")
	}
	if !contains(yamlStr, "clientID: test-client") {
		t.Error("ClientID should be preserved in YAML output")
	}
}

// TestSessionConfigMarshalling tests session config marshalling
func TestSessionConfigMarshalling(t *testing.T) {
	session := SessionConfig{
		Name:          "session-cookie",
		Secret:        "session-secret",
		EncryptionKey: "32-character-encryption-key-here",
		SigningKey:    "signing-key-secret",
		Domain:        "example.com",
		Secure:        true,
	}

	// Test JSON marshalling
	jsonBytes, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Failed to marshal SessionConfig to JSON: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !contains(jsonStr, `"secret":"[REDACTED]"`) {
		t.Error("Secret should be redacted in JSON output")
	}
	if !contains(jsonStr, `"encryptionKey":"[REDACTED]"`) {
		t.Error("EncryptionKey should be redacted in JSON output")
	}
	if !contains(jsonStr, `"signingKey":"[REDACTED]"`) {
		t.Error("SigningKey should be redacted in JSON output")
	}
	if !contains(jsonStr, `"name":"session-cookie"`) {
		t.Error("Name should be preserved in JSON output")
	}
	if !contains(jsonStr, `"domain":"example.com"`) {
		t.Error("Domain should be preserved in JSON output")
	}
}

// TestRedisConfigMarshalling tests Redis config marshalling
func TestRedisConfigMarshalling(t *testing.T) {
	redis := RedisConfig{
		Enabled:          true,
		Mode:             RedisModeCluster,
		Password:         "redis-password",
		SentinelPassword: "sentinel-password",
		Addr:             "localhost:6379",
		DB:               1,
	}

	// Test JSON marshalling
	jsonBytes, err := json.Marshal(redis)
	if err != nil {
		t.Fatalf("Failed to marshal RedisConfig to JSON: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !contains(jsonStr, `"password":"[REDACTED]"`) {
		t.Error("Password should be redacted in JSON output")
	}
	if !contains(jsonStr, `"sentinelPassword":"[REDACTED]"`) {
		t.Error("SentinelPassword should be redacted in JSON output")
	}
	if !contains(jsonStr, `"addr":"localhost:6379"`) {
		t.Error("Addr should be preserved in JSON output")
	}
	if !contains(jsonStr, `"db":1`) {
		t.Error("DB should be preserved in JSON output")
	}
}

// TestEmptySecretsNotRedacted tests that empty secrets are not shown as redacted
func TestEmptySecretsNotRedacted(t *testing.T) {
	config := &UnifiedConfig{
		Provider: ProviderConfig{
			IssuerURL:    "https://auth.example.com",
			ClientID:     "test-client",
			ClientSecret: "", // Empty secret
		},
		Session: SessionConfig{
			Secret:        "", // Empty secret
			EncryptionKey: "", // Empty secret
		},
		Redis: RedisConfig{
			Password: "", // Empty secret
		},
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config to JSON: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Verify empty secrets are not shown as redacted
	if contains(jsonStr, "[REDACTED]") {
		t.Error("Empty secrets should not be shown as [REDACTED]")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
