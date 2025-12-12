package providers

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestNewConfigValidator tests the creation of a ConfigValidator
func TestNewConfigValidator(t *testing.T) {
	validator := NewConfigValidator()
	if validator == nil {
		t.Error("expected non-nil validator")
	}
}

// TestValidateIssuerURL tests the ValidateIssuerURL function
func TestValidateIssuerURL(t *testing.T) {
	tests := []struct {
		name      string
		issuerURL string
		errMsg    string
		wantErr   bool
	}{
		{
			name:      "valid https URL",
			issuerURL: "https://accounts.google.com",
			wantErr:   false,
		},
		{
			name:      "valid http URL",
			issuerURL: "http://localhost:8080",
			wantErr:   false,
		},
		{
			name:      "valid URL with path",
			issuerURL: "https://login.microsoftonline.com/tenant-id/v2.0",
			wantErr:   false,
		},
		{
			name:      "empty URL",
			issuerURL: "",
			wantErr:   true,
			errMsg:    "issuer URL cannot be empty",
		},
		{
			name:      "URL without scheme",
			issuerURL: "accounts.google.com",
			wantErr:   true,
			errMsg:    "issuer URL must include scheme",
		},
		{
			name:      "URL with invalid scheme",
			issuerURL: "ftp://example.com",
			wantErr:   true,
			errMsg:    "issuer URL scheme must be http or https",
		},
		{
			name:      "URL without host",
			issuerURL: "https://",
			wantErr:   true,
			errMsg:    "issuer URL must include host",
		},
		{
			name:      "malformed URL",
			issuerURL: "ht!tp://[invalid",
			wantErr:   true,
			errMsg:    "invalid issuer URL format",
		},
		{
			name:      "URL with port",
			issuerURL: "https://auth.example.com:443/oauth",
			wantErr:   false,
		},
		{
			name:      "URL with query parameters",
			issuerURL: "https://auth.example.com?tenant=123",
			wantErr:   false,
		},
	}

	validator := NewConfigValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIssuerURL(tt.issuerURL)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateClientID tests the ValidateClientID function
func TestValidateClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		errMsg   string
		wantErr  bool
	}{
		{
			name:     "valid client ID",
			clientID: "my-application-client",
			wantErr:  false,
		},
		{
			name:     "valid UUID client ID",
			clientID: "123e4567-e89b-12d3-a456-426614174000",
			wantErr:  false,
		},
		{
			name:     "empty client ID",
			clientID: "",
			wantErr:  true,
			errMsg:   "client ID cannot be empty",
		},
		{
			name:     "too short client ID",
			clientID: "ab",
			wantErr:  true,
			errMsg:   "client ID appears to be too short",
		},
		{
			name:     "minimum length client ID",
			clientID: "abc",
			wantErr:  false,
		},
		{
			name:     "client ID with special characters",
			clientID: "client-id_123.app",
			wantErr:  false,
		},
		{
			name:     "long client ID",
			clientID: strings.Repeat("a", 255),
			wantErr:  false,
		},
	}

	validator := NewConfigValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateClientID(tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateScopes tests the ValidateScopes function
func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		scopes  []string
		wantErr bool
	}{
		{
			name:    "valid scopes with openid",
			scopes:  []string{"openid", "email", "profile"},
			wantErr: false,
		},
		{
			name:    "only openid scope",
			scopes:  []string{"openid"},
			wantErr: false,
		},
		{
			name:    "openid with whitespace",
			scopes:  []string{" openid ", "email"},
			wantErr: false,
		},
		{
			name:    "empty scopes",
			scopes:  []string{},
			wantErr: true,
			errMsg:  "at least one scope must be provided",
		},
		{
			name:    "nil scopes",
			scopes:  nil,
			wantErr: true,
			errMsg:  "at least one scope must be provided",
		},
		{
			name:    "missing openid scope",
			scopes:  []string{"email", "profile"},
			wantErr: true,
			errMsg:  "'openid' scope is required",
		},
		{
			name:    "duplicate openid scope",
			scopes:  []string{"openid", "openid", "email"},
			wantErr: false,
		},
		{
			name:    "custom scopes with openid",
			scopes:  []string{"openid", "api:read", "api:write"},
			wantErr: false,
		},
	}

	validator := NewConfigValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateScopes(tt.scopes)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateRedirectURL tests the ValidateRedirectURL function
func TestValidateRedirectURL(t *testing.T) {
	tests := []struct {
		name        string
		redirectURL string
		errMsg      string
		wantErr     bool
	}{
		{
			name:        "valid https redirect URL",
			redirectURL: "https://example.com/callback",
			wantErr:     false,
		},
		{
			name:        "valid http redirect URL",
			redirectURL: "http://localhost:3000/auth/callback",
			wantErr:     false,
		},
		{
			name:        "empty redirect URL",
			redirectURL: "",
			wantErr:     true,
			errMsg:      "redirect URL cannot be empty",
		},
		{
			name:        "redirect URL without scheme",
			redirectURL: "example.com/callback",
			wantErr:     true,
			errMsg:      "redirect URL must include scheme",
		},
		{
			name:        "malformed redirect URL",
			redirectURL: "ht!tp://[invalid",
			wantErr:     true,
			errMsg:      "invalid redirect URL format",
		},
		{
			name:        "redirect URL with query parameters",
			redirectURL: "https://example.com/callback?state=abc",
			wantErr:     false,
		},
		{
			name:        "redirect URL with fragment",
			redirectURL: "https://example.com/callback#section",
			wantErr:     false,
		},
	}

	validator := NewConfigValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRedirectURL(tt.redirectURL)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateProviderSpecificConfig tests provider-specific configuration validation
func TestValidateProviderSpecificConfig(t *testing.T) {
	tests := []struct {
		provider OIDCProvider
		config   map[string]interface{}
		name     string
		errMsg   string
		wantErr  bool
	}{
		{
			name:     "valid Google config",
			provider: NewGoogleProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://accounts.google.com",
			},
			wantErr: false,
		},
		{
			name:     "invalid Google config - wrong issuer",
			provider: NewGoogleProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://example.com",
			},
			wantErr: true,
			errMsg:  "google provider requires issuer URL to contain accounts.google.com",
		},
		{
			name:     "valid Azure config with tenant ID",
			provider: NewAzureProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
			},
			wantErr: false,
		},
		{
			name:     "invalid Azure config - wrong domain",
			provider: NewAzureProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://example.com/tenant",
			},
			wantErr: true,
			errMsg:  "azure provider requires issuer URL to contain login.microsoftonline.com",
		},
		{
			name:     "Azure config with sts.windows.net",
			provider: NewAzureProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://sts.windows.net/12345678-1234-1234-1234-123456789012",
			},
			wantErr: false,
		},
		{
			name:     "Azure config without tenant ID",
			provider: NewAzureProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://login.microsoftonline.com/common",
			},
			wantErr: true,
			errMsg:  "azure issuer URL should include tenant ID",
		},
		{
			name:     "valid generic provider config",
			provider: NewGenericProvider(),
			config: map[string]interface{}{
				"issuer_url": "https://auth.example.com",
			},
			wantErr: false,
		},
		{
			name:     "empty config for generic provider",
			provider: NewGenericProvider(),
			config:   map[string]interface{}{},
			wantErr:  false,
		},
	}

	validator := NewConfigValidator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateProviderSpecificConfig(tt.provider, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateProviderSpecificConfig_UnknownProvider tests handling of unknown provider types
func TestValidateProviderSpecificConfig_UnknownProvider(t *testing.T) {
	validator := NewConfigValidator()

	// Create a mock provider with invalid type
	mockProvider := &mockUnknownProvider{}

	err := validator.ValidateProviderSpecificConfig(mockProvider, map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown provider type")
	}
	if !strings.Contains(err.Error(), "unknown provider type") {
		t.Errorf("expected 'unknown provider type' error, got: %v", err)
	}
}

// mockUnknownProvider is a test provider with an invalid type
type mockUnknownProvider struct{}

func (m *mockUnknownProvider) GetType() ProviderType {
	return ProviderType(999) // Invalid type
}

func (m *mockUnknownProvider) GetCapabilities() ProviderCapabilities {
	return ProviderCapabilities{}
}

func (m *mockUnknownProvider) ValidateTokens(session Session, verifier TokenVerifier, tokenCache TokenCache, refreshGracePeriod time.Duration) (*ValidationResult, error) {
	return &ValidationResult{}, nil
}

func (m *mockUnknownProvider) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	return &AuthParams{}, nil
}

func (m *mockUnknownProvider) HandleTokenRefresh(tokenData *TokenResult) error {
	return nil
}

func (m *mockUnknownProvider) ValidateConfig() error {
	return nil
}

// TestValidateGoogleConfig_EdgeCases tests edge cases for Google config validation
func TestValidateGoogleConfig_EdgeCases(t *testing.T) {
	validator := NewConfigValidator()
	googleProvider := NewGoogleProvider()

	tests := []struct {
		config  map[string]interface{}
		name    string
		wantErr bool
	}{
		{
			name:    "config without issuer_url",
			config:  map[string]interface{}{},
			wantErr: false, // Should pass as issuer_url is not present
		},
		{
			name: "config with non-string issuer_url",
			config: map[string]interface{}{
				"issuer_url": 123,
			},
			wantErr: false, // Should pass as type assertion fails
		},
		{
			name: "config with accounts.google.com in path",
			config: map[string]interface{}{
				"issuer_url": "https://example.com/accounts.google.com",
			},
			wantErr: false, // Should pass as it contains the required string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateProviderSpecificConfig(googleProvider, tt.config)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateAzureConfig_EdgeCases tests edge cases for Azure config validation
func TestValidateAzureConfig_EdgeCases(t *testing.T) {
	validator := NewConfigValidator()
	azureProvider := NewAzureProvider()

	tests := []struct {
		config  map[string]interface{}
		name    string
		errMsg  string
		wantErr bool
	}{
		{
			name: "valid tenant ID format",
			config: map[string]interface{}{
				"issuer_url": "https://login.microsoftonline.com/a1b2c3d4-e5f6-7890-abcd-ef1234567890/v2.0",
			},
			wantErr: false,
		},
		{
			name: "tenant ID in different position",
			config: map[string]interface{}{
				"issuer_url": "https://login.microsoftonline.com/v2.0/a1b2c3d4-e5f6-7890-abcd-ef1234567890/oauth",
			},
			wantErr: false,
		},
		{
			name: "malformed URL for parsing",
			config: map[string]interface{}{
				"issuer_url": "https://login.microsoftonline.com/[invalid",
			},
			wantErr: true,
			errMsg:  "azure issuer URL should include tenant ID",
		},
		{
			name:    "config without issuer_url",
			config:  map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "config with non-string issuer_url",
			config: map[string]interface{}{
				"issuer_url": []string{"https://login.microsoftonline.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateProviderSpecificConfig(azureProvider, tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
