package traefikoidc

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestAudienceConfiguration tests the custom audience configuration feature
func TestAudienceConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		configAudience   string
		clientID         string
		expectedAudience string
	}{
		{
			name:             "no custom audience - uses clientID",
			configAudience:   "",
			clientID:         "test-client-id",
			expectedAudience: "test-client-id",
		},
		{
			name:             "custom audience specified",
			configAudience:   "api://custom-audience",
			clientID:         "test-client-id",
			expectedAudience: "api://custom-audience",
		},
		{
			name:             "auth0 style custom audience",
			configAudience:   "https://api.example.com",
			clientID:         "test-client-id",
			expectedAudience: "https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config with custom audience
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = tt.clientID
			config.ClientSecret = "test-secret"
			config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			config.CallbackURL = "/callback"
			config.Audience = tt.configAudience

			// Create middleware instance
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			traefikOidc, err := NewWithContext(context.Background(), config, next, "test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			// Verify audience is set correctly
			if traefikOidc.audience != tt.expectedAudience {
				t.Errorf("Expected audience %s, got %s", tt.expectedAudience, traefikOidc.audience)
			}

			// Cleanup
			traefikOidc.Close()
		})
	}
}

// TestAudienceValidation tests the audience validation in Config.Validate()
func TestAudienceValidation(t *testing.T) {
	tests := []struct {
		name          string
		audience      string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid custom audience URL",
			audience:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "valid azure style audience",
			audience:    "api://12345678-1234-1234-1234-123456789012",
			expectError: false,
		},
		{
			name:        "empty audience is valid (uses clientID)",
			audience:    "",
			expectError: false,
		},
		{
			name:          "http URL not allowed",
			audience:      "http://api.example.com",
			expectError:   true,
			errorContains: "audience URL must use HTTPS",
		},
		{
			name:          "wildcard not allowed",
			audience:      "https://*.example.com",
			expectError:   true,
			errorContains: "audience must not contain wildcards",
		},
		{
			name:          "too long audience",
			audience:      "https://" + string(make([]byte, 250)) + ".com",
			expectError:   true,
			errorContains: "audience must not exceed 256 characters",
		},
		{
			name:          "invalid characters",
			audience:      "api://test\ninjection",
			expectError:   true,
			errorContains: "audience contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CreateConfig()
			config.ProviderURL = "https://provider.example.com"
			config.ClientID = "test-client"
			config.ClientSecret = "test-secret"
			config.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			config.CallbackURL = "/callback"
			config.Audience = tt.audience

			err := config.Validate()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
