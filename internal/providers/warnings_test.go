package providers

import (
	"strings"
	"testing"
)

// TestGetProviderWarnings tests that warnings are provided for providers with limitations
func TestGetProviderWarnings(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		expectCount  int
		checkContent string
	}{
		{
			name:         "GitHub has OAuth 2.0 warning",
			providerType: ProviderTypeGitHub,
			expectCount:  2,
			checkContent: "OAuth 2.0",
		},
		{
			name:         "Auth0 has offline_access info",
			providerType: ProviderTypeAuth0,
			expectCount:  1,
			checkContent: "offline_access",
		},
		{
			name:         "Okta has configuration info",
			providerType: ProviderTypeOkta,
			expectCount:  1,
			checkContent: "admin console",
		},
		{
			name:         "AWS Cognito has regional endpoint info",
			providerType: ProviderTypeAWSCognito,
			expectCount:  1,
			checkContent: "regional endpoints",
		},
		{
			name:         "Generic provider has no warnings",
			providerType: ProviderTypeGeneric,
			expectCount:  0,
			checkContent: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := GetProviderWarnings(tt.providerType)

			if len(warnings) != tt.expectCount {
				t.Errorf("Expected %d warnings, got %d", tt.expectCount, len(warnings))
			}

			if tt.checkContent != "" {
				found := false
				for _, warning := range warnings {
					if strings.Contains(strings.ToLower(warning.Message), strings.ToLower(tt.checkContent)) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning content '%s' not found", tt.checkContent)
				}
			}
		})
	}
}

// TestValidateProviderCompatibility tests OIDC compatibility validation
func TestValidateProviderCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		requiresOIDC bool
		expectError  bool
	}{
		{
			name:         "GitHub with OIDC requirement should error",
			providerType: ProviderTypeGitHub,
			requiresOIDC: true,
			expectError:  true,
		},
		{
			name:         "GitHub without OIDC requirement should pass",
			providerType: ProviderTypeGitHub,
			requiresOIDC: false,
			expectError:  false,
		},
		{
			name:         "Auth0 with OIDC requirement should pass",
			providerType: ProviderTypeAuth0,
			requiresOIDC: true,
			expectError:  false,
		},
		{
			name:         "Google with OIDC requirement should pass",
			providerType: ProviderTypeGoogle,
			requiresOIDC: true,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderCompatibility(tt.providerType, tt.requiresOIDC)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestGetProviderRecommendations tests that recommendations are provided
func TestGetProviderRecommendations(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		expectMin    int
	}{
		{
			name:         "GitHub recommendations",
			providerType: ProviderTypeGitHub,
			expectMin:    3,
		},
		{
			name:         "Auth0 recommendations",
			providerType: ProviderTypeAuth0,
			expectMin:    3,
		},
		{
			name:         "AWS Cognito recommendations",
			providerType: ProviderTypeAWSCognito,
			expectMin:    3,
		},
		{
			name:         "Generic provider no recommendations",
			providerType: ProviderTypeGeneric,
			expectMin:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendations := GetProviderRecommendations(tt.providerType)

			if len(recommendations) < tt.expectMin {
				t.Errorf("Expected at least %d recommendations, got %d", tt.expectMin, len(recommendations))
			}
		})
	}
}

// TestFormatProviderWarnings tests warning formatting
func TestFormatProviderWarnings(t *testing.T) {
	warnings := []ProviderWarning{
		{
			ProviderType: ProviderTypeGitHub,
			Level:        "warning",
			Message:      "Test warning message",
		},
		{
			ProviderType: ProviderTypeGitHub,
			Level:        "info",
			Message:      "Test info message",
		},
	}

	formatted := FormatProviderWarnings(warnings)

	if !strings.Contains(formatted, "[WARNING]") {
		t.Error("Expected formatted output to contain [WARNING]")
	}

	if !strings.Contains(formatted, "[INFO]") {
		t.Error("Expected formatted output to contain [INFO]")
	}

	if !strings.Contains(formatted, "Test warning message") {
		t.Error("Expected formatted output to contain warning message")
	}

	// Test empty warnings
	emptyFormatted := FormatProviderWarnings([]ProviderWarning{})
	if emptyFormatted != "" {
		t.Error("Expected empty string for no warnings")
	}
}
