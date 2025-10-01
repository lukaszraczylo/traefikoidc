package providers

import (
	"net/url"
	"testing"
)

// TestOktaProvider_NewOktaProvider tests the constructor
func TestOktaProvider_NewOktaProvider(t *testing.T) {
	provider := NewOktaProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestOktaProvider_GetType tests provider type
func TestOktaProvider_GetType(t *testing.T) {
	provider := NewOktaProvider()

	if provider.GetType() != ProviderTypeOkta {
		t.Errorf("Expected ProviderTypeOkta, got %v", provider.GetType())
	}
}

// TestOktaProvider_GetCapabilities tests Okta-specific capabilities
func TestOktaProvider_GetCapabilities(t *testing.T) {
	provider := NewOktaProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true for Okta")
	}

	if !capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be true for Okta")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for Okta")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestOktaProvider_BuildAuthParams tests Okta-specific auth params
func TestOktaProvider_BuildAuthParams(t *testing.T) {
	provider := NewOktaProvider()
	baseParams := url.Values{}
	baseParams.Set("client_id", "test_client")

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "Add offline_access and openid scopes",
			scopes:         []string{"groups", "profile"},
			expectedScopes: []string{"groups", "profile", "offline_access", "openid"},
		},
		{
			name:           "Keep existing offline_access and openid",
			scopes:         []string{"openid", "groups", "offline_access", "profile"},
			expectedScopes: []string{"openid", "groups", "offline_access", "profile"},
		},
		{
			name:           "Add both scopes when none provided",
			scopes:         []string{},
			expectedScopes: []string{"offline_access", "openid"},
		},
		{
			name:           "Add openid when only offline_access present",
			scopes:         []string{"offline_access"},
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

// TestOktaProvider_ValidateConfig tests config validation
func TestOktaProvider_ValidateConfig(t *testing.T) {
	provider := NewOktaProvider()

	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}

// TestOktaProvider_InterfaceCompliance tests that Okta provider implements the OIDCProvider interface
func TestOktaProvider_InterfaceCompliance(t *testing.T) {
	var _ OIDCProvider = NewOktaProvider()
}

// TestOktaProvider_BaseProviderInheritance tests that Okta provider inherits from BaseProvider correctly
func TestOktaProvider_BaseProviderInheritance(t *testing.T) {
	provider := NewOktaProvider()

	// Test that it has access to BaseProvider methods
	if provider.BaseProvider == nil {
		t.Error("Expected BaseProvider to be initialized")
	}

	// Test HandleTokenRefresh (inherited from BaseProvider)
	err := provider.HandleTokenRefresh(&TokenResult{
		IDToken:      "test-id-token",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	})
	if err != nil {
		t.Errorf("HandleTokenRefresh failed: %v", err)
	}
}

// TestOktaProvider_ScopeHandling tests Okta-specific scope handling
func TestOktaProvider_ScopeHandling(t *testing.T) {
	provider := NewOktaProvider()
	baseParams := url.Values{}

	tests := []struct {
		name     string
		scopes   []string
		checkFor []string
	}{
		{
			name:     "Groups scope handling",
			scopes:   []string{"groups", "profile"},
			checkFor: []string{"groups", "profile", "offline_access", "openid"},
		},
		{
			name:     "Custom Okta scopes",
			scopes:   []string{"okta.users.read", "okta.groups.read"},
			checkFor: []string{"okta.users.read", "okta.groups.read", "offline_access", "openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authParams, err := provider.BuildAuthParams(baseParams, tt.scopes)
			if err != nil {
				t.Errorf("BuildAuthParams failed: %v", err)
				return
			}

			for _, expectedScope := range tt.checkFor {
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
