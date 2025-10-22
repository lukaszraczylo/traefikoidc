//go:build !yaegi

package config

import (
	"strings"
	"testing"
	"time"
)

// TestValidateUnifiedConfig tests the validation of UnifiedConfig
func TestValidateUnifiedConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *UnifiedConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config with minimum requirements",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientID:     "test-client",
					ClientSecret: "secret",
					Scopes:       []string{"openid", "profile", "email"},
				},
				Session: SessionConfig{
					Name:          "oidc_session",
					EncryptionKey: "this-is-a-32-character-key-12345",
					ChunkSize:     4000,
					MaxChunks:     5,
					StorageType:   "cookie",
				},
				Token: TokenConfig{
					AccessTokenTTL:  time.Hour,
					RefreshTokenTTL: 24 * time.Hour,
					ValidationMode:  "jwt",
				},
				Middleware: MiddlewareConfig{
					MaxRequestSize: 10 * 1024 * 1024,
					RequestTimeout: 30 * time.Second,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: "json",
					Output: "stdout",
				},
			},
			expectError: false,
		},
		{
			name: "missing provider URL",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					ClientID:     "test-client",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "this-is-a-32-character-key-12345",
				},
			},
			expectError: true,
			errorField:  "Provider.IssuerURL",
		},
		{
			name: "missing client ID",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "this-is-a-32-character-key-12345",
				},
			},
			expectError: true,
			errorField:  "Provider.ClientID",
		},
		{
			name: "encryption key too short",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientID:     "test-client",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "too-short",
				},
			},
			expectError: true,
			errorField:  "Session.EncryptionKey",
		},
		{
			name: "invalid chunk size",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientID:     "test-client",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "this-is-a-32-character-key-12345",
					ChunkSize:     500, // Too small
				},
			},
			expectError: true,
			errorField:  "Session.ChunkSize",
		},
		{
			name: "invalid max chunks",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientID:     "test-client",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "this-is-a-32-character-key-12345",
					ChunkSize:     4000,
					MaxChunks:     0, // Too small
				},
			},
			expectError: true,
			errorField:  "Session.MaxChunks",
		},
		{
			name: "invalid TLS min version",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientID:     "test-client",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "this-is-a-32-character-key-12345",
				},
				Transport: TransportConfig{
					TLSMinVersion: "1.0", // Too old
				},
			},
			expectError: true,
			errorField:  "Transport.TLSMinVersion",
		},
		{
			name: "invalid circuit breaker failure ratio",
			config: &UnifiedConfig{
				Provider: ProviderConfig{
					IssuerURL:    "https://auth.example.com",
					ClientID:     "test-client",
					ClientSecret: "secret",
				},
				Session: SessionConfig{
					EncryptionKey: "this-is-a-32-character-key-12345",
				},
				Circuit: CircuitConfig{
					Enabled:      true,
					FailureRatio: 1.5, // Too high
				},
			},
			expectError: true,
			errorField:  "Circuit.FailureRatio",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected validation error for field %s, but got none", tt.errorField)
				} else if validationErrs, ok := err.(ValidationErrors); ok {
					found := false
					for _, e := range validationErrs {
						if e.Field == tt.errorField {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected validation error for field %s, but got errors for: %v",
							tt.errorField, validationErrs)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no validation error, but got: %v", err)
				}
			}
		})
	}
}

// TestValidationErrorMessage tests validation error formatting
func TestValidationErrorMessage(t *testing.T) {
	errs := ValidationErrors{
		{
			Field:   "Provider.IssuerURL",
			Message: "is required",
			Value:   nil,
		},
		{
			Field:   "Session.EncryptionKey",
			Message: "must be at least 32 characters",
			Value:   16,
		},
	}

	errMsg := errs.Error()

	if !strings.Contains(errMsg, "Provider.IssuerURL") {
		t.Error("Error message should contain field name Provider.IssuerURL")
	}
	if !strings.Contains(errMsg, "is required") {
		t.Error("Error message should contain 'is required'")
	}
	if !strings.Contains(errMsg, "Session.EncryptionKey") {
		t.Error("Error message should contain field name Session.EncryptionKey")
	}
	if !strings.Contains(errMsg, "must be at least 32 characters") {
		t.Error("Error message should contain 'must be at least 32 characters'")
	}
}

// TestValidateRedisConfig tests Redis configuration validation
func TestValidateRedisConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *RedisConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid standalone config",
			config: &RedisConfig{
				Enabled: true,
				Mode:    RedisModeStandalone,
				Addr:    "localhost:6379",
			},
			expectError: false,
		},
		{
			name: "missing address for standalone",
			config: &RedisConfig{
				Enabled: true,
				Mode:    RedisModeStandalone,
				Addr:    "",
			},
			expectError: true,
			errorMsg:    "Redis address is required",
		},
		{
			name: "valid cluster config",
			config: &RedisConfig{
				Enabled:      true,
				Mode:         RedisModeCluster,
				ClusterAddrs: []string{"localhost:7000", "localhost:7001"},
			},
			expectError: false,
		},
		{
			name: "missing cluster addresses",
			config: &RedisConfig{
				Enabled:      true,
				Mode:         RedisModeCluster,
				ClusterAddrs: []string{},
			},
			expectError: true,
			errorMsg:    "cluster address is required",
		},
		{
			name: "valid sentinel config",
			config: &RedisConfig{
				Enabled:       true,
				Mode:          RedisModeSentinel,
				MasterName:    "mymaster",
				SentinelAddrs: []string{"localhost:26379"},
			},
			expectError: false,
		},
		{
			name: "missing master name for sentinel",
			config: &RedisConfig{
				Enabled:       true,
				Mode:          RedisModeSentinel,
				MasterName:    "",
				SentinelAddrs: []string{"localhost:26379"},
			},
			expectError: true,
			errorMsg:    "Master name is required",
		},
		{
			name: "missing sentinel addresses",
			config: &RedisConfig{
				Enabled:       true,
				Mode:          RedisModeSentinel,
				MasterName:    "mymaster",
				SentinelAddrs: []string{},
			},
			expectError: true,
			errorMsg:    "sentinel address is required",
		},
		{
			name: "disabled redis needs no validation",
			config: &RedisConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "invalid redis mode",
			config: &RedisConfig{
				Enabled: true,
				Mode:    "invalid-mode",
			},
			expectError: true,
			errorMsg:    "Invalid Redis mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected validation error containing '%s', but got none", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', but got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no validation error, but got: %v", err)
				}
			}
		})
	}
}
