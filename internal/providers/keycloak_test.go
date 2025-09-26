package providers

import (
	"net/url"
	"testing"
)

// TestKeycloakProvider_NewKeycloakProvider tests the constructor
func TestKeycloakProvider_NewKeycloakProvider(t *testing.T) {
	provider := NewKeycloakProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestKeycloakProvider_GetType tests provider type
func TestKeycloakProvider_GetType(t *testing.T) {
	provider := NewKeycloakProvider()

	if provider.GetType() != ProviderTypeKeycloak {
		t.Errorf("Expected ProviderTypeKeycloak, got %v", provider.GetType())
	}
}

// TestKeycloakProvider_GetCapabilities tests Keycloak-specific capabilities
func TestKeycloakProvider_GetCapabilities(t *testing.T) {
	provider := NewKeycloakProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true for Keycloak")
	}

	if !capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be true for Keycloak")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for Keycloak")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestKeycloakProvider_BuildAuthParams tests Keycloak-specific auth params
func TestKeycloakProvider_BuildAuthParams(t *testing.T) {
	provider := NewKeycloakProvider()
	baseParams := url.Values{}
	baseParams.Set("client_id", "test_client")

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "Add offline_access and openid scopes",
			scopes:         []string{"roles", "groups"},
			expectedScopes: []string{"roles", "groups", "offline_access", "openid"},
		},
		{
			name:           "Keep existing offline_access and openid",
			scopes:         []string{"openid", "roles", "offline_access", "groups"},
			expectedScopes: []string{"openid", "roles", "offline_access", "groups"},
		},
		{
			name:           "Add both scopes when none provided",
			scopes:         []string{},
			expectedScopes: []string{"offline_access", "openid"},
		},
		{
			name:           "Keycloak custom scopes",
			scopes:         []string{"realm-roles", "account"},
			expectedScopes: []string{"realm-roles", "account", "offline_access", "openid"},
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

// TestKeycloakProvider_ValidateConfig tests config validation
func TestKeycloakProvider_ValidateConfig(t *testing.T) {
	provider := NewKeycloakProvider()

	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}

// TestKeycloakProvider_InterfaceCompliance tests that Keycloak provider implements the OIDCProvider interface
func TestKeycloakProvider_InterfaceCompliance(t *testing.T) {
	var _ OIDCProvider = NewKeycloakProvider()
}

// TestKeycloakProvider_BaseProviderInheritance tests that Keycloak provider inherits from BaseProvider correctly
func TestKeycloakProvider_BaseProviderInheritance(t *testing.T) {
	provider := NewKeycloakProvider()

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

// TestKeycloakProvider_RealmSpecificScopes tests Keycloak realm-specific scopes
func TestKeycloakProvider_RealmSpecificScopes(t *testing.T) {
	provider := NewKeycloakProvider()
	baseParams := url.Values{}

	tests := []struct {
		name     string
		scopes   []string
		checkFor []string
	}{
		{
			name:     "Keycloak standard scopes",
			scopes:   []string{"roles", "groups", "profile", "email"},
			checkFor: []string{"roles", "groups", "profile", "email", "offline_access", "openid"},
		},
		{
			name:     "Keycloak realm roles",
			scopes:   []string{"realm-roles", "client-roles"},
			checkFor: []string{"realm-roles", "client-roles", "offline_access", "openid"},
		},
		{
			name:     "Keycloak account service",
			scopes:   []string{"account"},
			checkFor: []string{"account", "offline_access", "openid"},
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

// TestKeycloakProvider_ScopeDeduplication tests that duplicate scopes are handled correctly
func TestKeycloakProvider_ScopeDeduplication(t *testing.T) {
	provider := NewKeycloakProvider()
	baseParams := url.Values{}

	// Test with duplicate scopes
	scopes := []string{"openid", "profile", "offline_access", "roles", "openid", "profile"}
	authParams, err := provider.BuildAuthParams(baseParams, scopes)
	if err != nil {
		t.Errorf("BuildAuthParams failed: %v", err)
		return
	}

	// Count occurrences of each scope
	scopeCounts := make(map[string]int)
	for _, scope := range authParams.Scopes {
		scopeCounts[scope]++
	}

	// Check that no scope appears more than once
	for scope, count := range scopeCounts {
		if count > 1 {
			t.Errorf("Scope '%s' appears %d times, expected 1", scope, count)
		}
	}
}
