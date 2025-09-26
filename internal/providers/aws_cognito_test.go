package providers

import (
	"net/url"
	"testing"
)

// TestAWSCognitoProvider_NewAWSCognitoProvider tests the constructor
func TestAWSCognitoProvider_NewAWSCognitoProvider(t *testing.T) {
	provider := NewAWSCognitoProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestAWSCognitoProvider_GetType tests provider type
func TestAWSCognitoProvider_GetType(t *testing.T) {
	provider := NewAWSCognitoProvider()

	if provider.GetType() != ProviderTypeAWSCognito {
		t.Errorf("Expected ProviderTypeAWSCognito, got %v", provider.GetType())
	}
}

// TestAWSCognitoProvider_GetCapabilities tests AWS Cognito-specific capabilities
func TestAWSCognitoProvider_GetCapabilities(t *testing.T) {
	provider := NewAWSCognitoProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true for AWS Cognito")
	}

	if capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be false for AWS Cognito")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for AWS Cognito")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestAWSCognitoProvider_BuildAuthParams tests AWS Cognito-specific auth params
func TestAWSCognitoProvider_BuildAuthParams(t *testing.T) {
	provider := NewAWSCognitoProvider()
	baseParams := url.Values{}
	baseParams.Set("client_id", "test_client")

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "Remove offline_access scope and ensure openid",
			scopes:         []string{"email", "profile", "offline_access"},
			expectedScopes: []string{"email", "profile", "openid"},
		},
		{
			name:           "Keep existing openid, remove offline_access",
			scopes:         []string{"openid", "email", "offline_access", "profile"},
			expectedScopes: []string{"openid", "email", "profile"},
		},
		{
			name:           "Add default scopes when only openid",
			scopes:         []string{"openid"},
			expectedScopes: []string{"openid", "email", "profile"},
		},
		{
			name:           "Add openid and defaults when empty",
			scopes:         []string{},
			expectedScopes: []string{"openid", "email", "profile"},
		},
		{
			name:           "Cognito-specific scopes",
			scopes:         []string{"aws.cognito.signin.user.admin", "phone"},
			expectedScopes: []string{"aws.cognito.signin.user.admin", "phone", "openid"},
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

			// Ensure offline_access is NOT present
			for _, actualScope := range authParams.Scopes {
				if actualScope == "offline_access" {
					t.Error("offline_access scope should be filtered out for AWS Cognito")
				}
			}
		})
	}
}

// TestAWSCognitoProvider_ValidateConfig tests config validation
func TestAWSCognitoProvider_ValidateConfig(t *testing.T) {
	provider := NewAWSCognitoProvider()

	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}

// TestAWSCognitoProvider_InterfaceCompliance tests that AWS Cognito provider implements the OIDCProvider interface
func TestAWSCognitoProvider_InterfaceCompliance(t *testing.T) {
	var _ OIDCProvider = NewAWSCognitoProvider()
}

// TestAWSCognitoProvider_BaseProviderInheritance tests that AWS Cognito provider inherits from BaseProvider correctly
func TestAWSCognitoProvider_BaseProviderInheritance(t *testing.T) {
	provider := NewAWSCognitoProvider()

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

// TestAWSCognitoProvider_OfflineAccessFiltering tests that offline_access scope is always filtered out
func TestAWSCognitoProvider_OfflineAccessFiltering(t *testing.T) {
	provider := NewAWSCognitoProvider()
	baseParams := url.Values{}

	tests := []struct {
		name   string
		scopes []string
	}{
		{
			name:   "Single offline_access",
			scopes: []string{"offline_access"},
		},
		{
			name:   "Multiple offline_access occurrences",
			scopes: []string{"offline_access", "email", "offline_access", "profile"},
		},
		{
			name:   "Mixed case",
			scopes: []string{"OFFLINE_ACCESS", "email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authParams, err := provider.BuildAuthParams(baseParams, tt.scopes)
			if err != nil {
				t.Errorf("BuildAuthParams failed: %v", err)
				return
			}

			// Ensure offline_access is NOT present in any form
			for _, actualScope := range authParams.Scopes {
				if actualScope == "offline_access" || actualScope == "OFFLINE_ACCESS" {
					t.Errorf("offline_access scope should be filtered out, but found: %s", actualScope)
				}
			}
		})
	}
}

// TestAWSCognitoProvider_CognitoSpecificScopes tests AWS Cognito-specific scopes
func TestAWSCognitoProvider_CognitoSpecificScopes(t *testing.T) {
	provider := NewAWSCognitoProvider()
	baseParams := url.Values{}

	tests := []struct {
		name     string
		scopes   []string
		checkFor []string
	}{
		{
			name:     "Cognito admin scope",
			scopes:   []string{"aws.cognito.signin.user.admin"},
			checkFor: []string{"aws.cognito.signin.user.admin", "openid"},
		},
		{
			name:     "Phone scope",
			scopes:   []string{"phone"},
			checkFor: []string{"phone", "openid"},
		},
		{
			name:     "Address scope",
			scopes:   []string{"address"},
			checkFor: []string{"address", "openid"},
		},
		{
			name:     "Multiple Cognito scopes",
			scopes:   []string{"aws.cognito.signin.user.admin", "phone", "address"},
			checkFor: []string{"aws.cognito.signin.user.admin", "phone", "address", "openid"},
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

// TestAWSCognitoProvider_DefaultScopeHandling tests default scope behavior
func TestAWSCognitoProvider_DefaultScopeHandling(t *testing.T) {
	provider := NewAWSCognitoProvider()
	baseParams := url.Values{}

	// Test with only openid scope - should add defaults
	authParams, err := provider.BuildAuthParams(baseParams, []string{"openid"})
	if err != nil {
		t.Errorf("BuildAuthParams failed: %v", err)
		return
	}

	expectedScopes := []string{"openid", "email", "profile"}
	if len(authParams.Scopes) != len(expectedScopes) {
		t.Errorf("Expected %d scopes, got %d", len(expectedScopes), len(authParams.Scopes))
		return
	}

	for _, expectedScope := range expectedScopes {
		found := false
		for _, actualScope := range authParams.Scopes {
			if actualScope == expectedScope {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected default scope '%s' not found in %v", expectedScope, authParams.Scopes)
		}
	}
}
