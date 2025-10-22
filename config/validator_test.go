//go:build !yaegi

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// ============================================================================
// validateRateLimit Tests
// ============================================================================

func TestValidateRateLimit_Disabled(t *testing.T) {
	config := NewUnifiedConfig()
	config.RateLimit.Enabled = false

	errors := config.validateRateLimit()

	assert.Empty(t, errors, "Should have no errors when rate limiting is disabled")
}

func TestValidateRateLimit_ValidConfig(t *testing.T) {
	config := NewUnifiedConfig()
	config.RateLimit.Enabled = true
	config.RateLimit.RequestsPerSecond = 100
	config.RateLimit.Burst = 200
	config.RateLimit.KeyType = "ip"

	errors := config.validateRateLimit()

	assert.Empty(t, errors, "Should have no errors for valid rate limit config")
}

func TestValidateRateLimit_RequestsPerSecondTooLow(t *testing.T) {
	config := NewUnifiedConfig()
	config.RateLimit.Enabled = true
	config.RateLimit.RequestsPerSecond = 0
	config.RateLimit.Burst = 100
	config.RateLimit.KeyType = "ip"

	errors := config.validateRateLimit()

	require.Len(t, errors, 1)
	assert.Equal(t, "RateLimit.RequestsPerSecond", errors[0].Field)
	assert.Contains(t, errors[0].Message, "between 1 and 10000")
}

func TestValidateRateLimit_RequestsPerSecondTooHigh(t *testing.T) {
	config := NewUnifiedConfig()
	config.RateLimit.Enabled = true
	config.RateLimit.RequestsPerSecond = 15000
	config.RateLimit.Burst = 20000
	config.RateLimit.KeyType = "ip"

	errors := config.validateRateLimit()

	require.Len(t, errors, 1)
	assert.Equal(t, "RateLimit.RequestsPerSecond", errors[0].Field)
	assert.Contains(t, errors[0].Message, "between 1 and 10000")
}

func TestValidateRateLimit_BurstTooSmall(t *testing.T) {
	config := NewUnifiedConfig()
	config.RateLimit.Enabled = true
	config.RateLimit.RequestsPerSecond = 100
	config.RateLimit.Burst = 50 // Less than RequestsPerSecond
	config.RateLimit.KeyType = "ip"

	errors := config.validateRateLimit()

	require.Len(t, errors, 1)
	assert.Equal(t, "RateLimit.Burst", errors[0].Field)
	assert.Contains(t, errors[0].Message, "at least as large as requests per second")
}

func TestValidateRateLimit_InvalidKeyType(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
	}{
		{"empty key type", ""},
		{"invalid key type", "invalid"},
		{"random string", "foobar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewUnifiedConfig()
			config.RateLimit.Enabled = true
			config.RateLimit.RequestsPerSecond = 100
			config.RateLimit.Burst = 200
			config.RateLimit.KeyType = tt.keyType

			errors := config.validateRateLimit()

			require.Len(t, errors, 1)
			assert.Equal(t, "RateLimit.KeyType", errors[0].Field)
			assert.Contains(t, errors[0].Message, "invalid key type")
		})
	}
}

func TestValidateRateLimit_ValidKeyTypes(t *testing.T) {
	validKeyTypes := []string{"ip", "user", "token", "custom"}

	for _, keyType := range validKeyTypes {
		t.Run(keyType, func(t *testing.T) {
			config := NewUnifiedConfig()
			config.RateLimit.Enabled = true
			config.RateLimit.RequestsPerSecond = 100
			config.RateLimit.Burst = 200
			config.RateLimit.KeyType = keyType

			errors := config.validateRateLimit()

			assert.Empty(t, errors, "Should have no errors for valid key type: %s", keyType)
		})
	}
}

func TestValidateRateLimit_MultipleErrors(t *testing.T) {
	config := NewUnifiedConfig()
	config.RateLimit.Enabled = true
	config.RateLimit.RequestsPerSecond = 0 // Too low
	config.RateLimit.Burst = 50            // Will pass (0 < 50)
	config.RateLimit.KeyType = "invalid"   // Invalid

	errors := config.validateRateLimit()

	// Should have 2 errors (rps and keyType)
	assert.Len(t, errors, 2)

	// Check each error is present
	fields := make(map[string]bool)
	for _, err := range errors {
		fields[err.Field] = true
	}
	assert.True(t, fields["RateLimit.RequestsPerSecond"])
	assert.True(t, fields["RateLimit.KeyType"])
}

// ============================================================================
// validateMetrics Tests
// ============================================================================

func TestValidateMetrics_Disabled(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = false

	errors := config.validateMetrics()

	assert.Empty(t, errors, "Should have no errors when metrics are disabled")
}

func TestValidateMetrics_ValidPrometheus(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = true
	config.Metrics.Provider = "prometheus"
	config.Metrics.Endpoint = "" // Prometheus doesn't require endpoint

	errors := config.validateMetrics()

	assert.Empty(t, errors, "Should have no errors for valid prometheus config")
}

func TestValidateMetrics_ValidStatsd(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = true
	config.Metrics.Provider = "statsd"
	config.Metrics.Endpoint = "localhost:8125"

	errors := config.validateMetrics()

	assert.Empty(t, errors, "Should have no errors for valid statsd config")
}

func TestValidateMetrics_ValidOTLP(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = true
	config.Metrics.Provider = "otlp"
	config.Metrics.Endpoint = "localhost:4317"

	errors := config.validateMetrics()

	assert.Empty(t, errors, "Should have no errors for valid otlp config")
}

func TestValidateMetrics_InvalidProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
	}{
		{"empty provider", ""},
		{"invalid provider", "invalid"},
		{"datadog", "datadog"},
		{"influx", "influx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewUnifiedConfig()
			config.Metrics.Enabled = true
			config.Metrics.Provider = tt.provider
			config.Metrics.Endpoint = "localhost:8080"

			errors := config.validateMetrics()

			require.Len(t, errors, 1)
			assert.Equal(t, "Metrics.Provider", errors[0].Field)
			assert.Contains(t, errors[0].Message, "invalid metrics provider")
		})
	}
}

func TestValidateMetrics_StatsdMissingEndpoint(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = true
	config.Metrics.Provider = "statsd"
	config.Metrics.Endpoint = "" // Missing required endpoint

	errors := config.validateMetrics()

	require.Len(t, errors, 1)
	assert.Equal(t, "Metrics.Endpoint", errors[0].Field)
	assert.Contains(t, errors[0].Message, "endpoint is required for statsd provider")
}

func TestValidateMetrics_OTLPMissingEndpoint(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = true
	config.Metrics.Provider = "otlp"
	config.Metrics.Endpoint = "" // Missing required endpoint

	errors := config.validateMetrics()

	require.Len(t, errors, 1)
	assert.Equal(t, "Metrics.Endpoint", errors[0].Field)
	assert.Contains(t, errors[0].Message, "endpoint is required for otlp provider")
}

func TestValidateMetrics_MultipleErrors(t *testing.T) {
	config := NewUnifiedConfig()
	config.Metrics.Enabled = true
	config.Metrics.Provider = "invalid" // Invalid provider
	config.Metrics.Endpoint = ""        // Would be missing if provider was statsd/otlp

	errors := config.validateMetrics()

	// Should have at least 1 error for invalid provider
	assert.NotEmpty(t, errors)
	assert.Equal(t, "Metrics.Provider", errors[0].Field)
}
