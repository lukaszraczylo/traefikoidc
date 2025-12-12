package traefikoidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCProviderHTTPClientConfigUnit tests OIDCProviderHTTPClientConfig function
func TestOIDCProviderHTTPClientConfigUnit(t *testing.T) {
	config := OIDCProviderHTTPClientConfig()

	// Verify OIDC-specific settings
	assert.Equal(t, 15*time.Second, config.Timeout, "OIDC provider should have 15s timeout")
	assert.Equal(t, 100, config.MaxIdleConns, "OIDC provider should have 100 max idle conns")
	assert.Equal(t, 25, config.MaxIdleConnsPerHost, "OIDC provider should have 25 max idle conns per host")
	assert.Equal(t, 50, config.MaxConnsPerHost, "OIDC provider should have 50 max conns per host")
	assert.Equal(t, 90*time.Second, config.IdleConnTimeout, "OIDC provider should have 90s idle conn timeout")
	assert.True(t, config.UseCookieJar, "OIDC provider should have cookie jar enabled")
}

// TestCreateDefaultClientUnit tests CreateDefaultClient function
func TestCreateDefaultClientUnit(t *testing.T) {
	factory := NewHTTPClientFactory()
	client := factory.CreateDefaultClient()

	require.NotNil(t, client)
	assert.NotNil(t, client.Transport, "client should have transport")
	assert.Equal(t, 10*time.Second, client.Timeout, "default client should have 10s timeout")
}

// TestCreateTokenClientUnit tests CreateTokenClient function
func TestCreateTokenClientUnit(t *testing.T) {
	factory := NewHTTPClientFactory()
	client := factory.CreateTokenClient()

	require.NotNil(t, client)
	assert.NotNil(t, client.Transport, "client should have transport")
	assert.NotNil(t, client.Jar, "token client should have cookie jar")
	assert.Equal(t, 10*time.Second, client.Timeout, "token client should have 10s timeout")
}

// TestCreateHTTPClientWithConfigUnit tests CreateHTTPClientWithConfig function
func TestCreateHTTPClientWithConfigUnit(t *testing.T) {
	config := HTTPClientConfig{
		Timeout:             5 * time.Second,
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 5,
		UseCookieJar:        true,
	}

	client := CreateHTTPClientWithConfig(config)

	require.NotNil(t, client)
	assert.Equal(t, 5*time.Second, client.Timeout)
	assert.NotNil(t, client.Jar, "client should have cookie jar when configured")
}

// TestHTTPClientFactoryCreateHTTPClientValidation tests validation in CreateHTTPClient
func TestHTTPClientFactoryCreateHTTPClientValidation(t *testing.T) {
	factory := NewHTTPClientFactory()

	t.Run("zero values get defaults", func(t *testing.T) {
		config := HTTPClientConfig{
			// All zero values
		}

		client := factory.CreateHTTPClient(config)

		require.NotNil(t, client)
		// Verify defaults were applied
		assert.Equal(t, 30*time.Second, client.Timeout)
	})

	t.Run("custom values preserved", func(t *testing.T) {
		config := HTTPClientConfig{
			Timeout:           15 * time.Second,
			MaxIdleConns:      50,
			MaxRedirects:      3,
			UseCookieJar:      true,
			ForceHTTP2:        true,
			DisableKeepAlives: true,
		}

		client := factory.CreateHTTPClient(config)

		require.NotNil(t, client)
		assert.Equal(t, 15*time.Second, client.Timeout)
		assert.NotNil(t, client.Jar)
	})

	t.Run("invalid timeout gets default", func(t *testing.T) {
		config := HTTPClientConfig{
			Timeout: -1 * time.Second, // Invalid
		}

		client := factory.CreateHTTPClient(config)

		require.NotNil(t, client)
		// Should get default due to validation failure
		assert.Equal(t, 30*time.Second, client.Timeout)
	})
}

// TestHTTPClientFactoryValidateHTTPClientConfig tests ValidateHTTPClientConfig
func TestHTTPClientFactoryValidateHTTPClientConfig(t *testing.T) {
	factory := NewHTTPClientFactory()

	tests := []struct {
		name      string
		errorMsg  string
		config    HTTPClientConfig
		wantError bool
	}{
		{
			name: "valid config",
			config: HTTPClientConfig{
				Timeout:             10 * time.Second,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				MaxConnsPerHost:     20,
			},
			wantError: false,
		},
		{
			name: "negative MaxIdleConns",
			config: HTTPClientConfig{
				Timeout:             10 * time.Second,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
				MaxIdleConns:        -1,
			},
			wantError: true,
			errorMsg:  "MaxIdleConns cannot be negative",
		},
		{
			name: "MaxIdleConns too high",
			config: HTTPClientConfig{
				Timeout:             10 * time.Second,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
				MaxIdleConns:        1500,
			},
			wantError: true,
			errorMsg:  "MaxIdleConns too high",
		},
		{
			name: "negative MaxIdleConnsPerHost",
			config: HTTPClientConfig{
				Timeout:             10 * time.Second,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
				MaxIdleConnsPerHost: -1,
			},
			wantError: true,
			errorMsg:  "MaxIdleConnsPerHost cannot be negative",
		},
		{
			name: "timeout too high",
			config: HTTPClientConfig{
				Timeout:             10 * time.Minute,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
			},
			wantError: true,
			errorMsg:  "timeout too high",
		},
		{
			name: "negative timeout",
			config: HTTPClientConfig{
				Timeout:             -1 * time.Second,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
			},
			wantError: true,
			errorMsg:  "timeout must be positive",
		},
		{
			name: "MaxIdleConnsPerHost exceeds MaxConnsPerHost",
			config: HTTPClientConfig{
				Timeout:             10 * time.Second,
				DialTimeout:         5 * time.Second,
				TLSHandshakeTimeout: 2 * time.Second,
				MaxIdleConnsPerHost: 50,
				MaxConnsPerHost:     10,
			},
			wantError: true,
			errorMsg:  "MaxIdleConnsPerHost (50) cannot exceed MaxConnsPerHost (10)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateHTTPClientConfig(&tt.config)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
