package providers

import (
	"net/url"
	"testing"
)

// TestGitHubProvider_NewGitHubProvider tests the constructor
func TestGitHubProvider_NewGitHubProvider(t *testing.T) {
	provider := NewGitHubProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestGitHubProvider_GetType tests provider type
func TestGitHubProvider_GetType(t *testing.T) {
	provider := NewGitHubProvider()

	if provider.GetType() != ProviderTypeGitHub {
		t.Errorf("Expected ProviderTypeGitHub, got %v", provider.GetType())
	}
}

// TestGitHubProvider_GetCapabilities tests GitHub-specific capabilities
func TestGitHubProvider_GetCapabilities(t *testing.T) {
	provider := NewGitHubProvider()
	capabilities := provider.GetCapabilities()

	if capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be false for GitHub")
	}

	if capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be false for GitHub")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for GitHub")
	}

	if capabilities.PreferredTokenValidation != "access" {
		t.Errorf("Expected PreferredTokenValidation 'access', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestGitHubProvider_BuildAuthParams tests GitHub-specific auth params
func TestGitHubProvider_BuildAuthParams(t *testing.T) {
	provider := NewGitHubProvider()
	baseParams := url.Values{}
	baseParams.Set("client_id", "test_client")

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "Remove offline_access scope",
			scopes:         []string{"user:email", "offline_access", "read:user"},
			expectedScopes: []string{"user:email", "read:user"},
		},
		{
			name:           "Default scopes when none provided",
			scopes:         []string{},
			expectedScopes: []string{"user:email", "read:user"},
		},
		{
			name:           "Keep other scopes",
			scopes:         []string{"user", "repo"},
			expectedScopes: []string{"user", "repo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authParams, err := provider.BuildAuthParams(baseParams, tt.scopes)
			if err != nil {
				t.Errorf("BuildAuthParams failed: %v", err)
				return
			}

			if len(authParams.Scopes) != len(tt.expectedScopes) {
				t.Errorf("Expected %d scopes, got %d", len(tt.expectedScopes), len(authParams.Scopes))
				return
			}

			for i, scope := range tt.expectedScopes {
				if authParams.Scopes[i] != scope {
					t.Errorf("Expected scope '%s', got '%s'", scope, authParams.Scopes[i])
				}
			}
		})
	}
}

// TestGitHubProvider_ValidateConfig tests config validation
func TestGitHubProvider_ValidateConfig(t *testing.T) {
	provider := NewGitHubProvider()

	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}
