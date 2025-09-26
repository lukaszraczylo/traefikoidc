package providers

import (
	"net/url"
	"testing"
)

// TestAuth0Provider_NewAuth0Provider tests the constructor
func TestAuth0Provider_NewAuth0Provider(t *testing.T) {
	provider := NewAuth0Provider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestAuth0Provider_GetType tests provider type
func TestAuth0Provider_GetType(t *testing.T) {
	provider := NewAuth0Provider()

	if provider.GetType() != ProviderTypeAuth0 {
		t.Errorf("Expected ProviderTypeAuth0, got %v", provider.GetType())
	}
}

// TestAuth0Provider_GetCapabilities tests Auth0-specific capabilities
func TestAuth0Provider_GetCapabilities(t *testing.T) {
	provider := NewAuth0Provider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true for Auth0")
	}

	if !capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be true for Auth0")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for Auth0")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestAuth0Provider_BuildAuthParams tests Auth0-specific auth params
func TestAuth0Provider_BuildAuthParams(t *testing.T) {
	provider := NewAuth0Provider()
	baseParams := url.Values{}
	baseParams.Set("client_id", "test_client")

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "Add offline_access and openid scopes",
			scopes:         []string{"profile", "email"},
			expectedScopes: []string{"profile", "email", "offline_access", "openid"},
		},
		{
			name:           "Keep existing offline_access and openid",
			scopes:         []string{"openid", "profile", "offline_access", "email"},
			expectedScopes: []string{"openid", "profile", "offline_access", "email"},
		},
		{
			name:           "Add both scopes when none provided",
			scopes:         []string{},
			expectedScopes: []string{"offline_access", "openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authParams, err := provider.BuildAuthParams(baseParams, tt.scopes)
			if err != nil {
				t.Errorf("BuildAuthParams failed: %v", err)
				return
			}

			// Check that response_type is set
			if authParams.URLValues.Get("response_type") != "code" {
				t.Errorf("Expected response_type 'code', got '%s'", authParams.URLValues.Get("response_type"))
			}

			if len(authParams.Scopes) != len(tt.expectedScopes) {
				t.Errorf("Expected %d scopes, got %d. Expected: %v, Got: %v",
					len(tt.expectedScopes), len(authParams.Scopes), tt.expectedScopes, authParams.Scopes)
				return
			}

			// Check that all expected scopes are present
			for _, expectedScope := range tt.expectedScopes {
				found := false
				for _, actualScope := range authParams.Scopes {
					if actualScope == expectedScope {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected scope '%s' not found in %v", expectedScope, authParams.Scopes)
				}
			}
		})
	}
}

// TestAuth0Provider_ValidateConfig tests config validation
func TestAuth0Provider_ValidateConfig(t *testing.T) {
	provider := NewAuth0Provider()

	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}
