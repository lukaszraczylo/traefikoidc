package providers

import (
	"net/url"
	"testing"
)

// TestGitLabProvider_NewGitLabProvider tests the constructor
func TestGitLabProvider_NewGitLabProvider(t *testing.T) {
	provider := NewGitLabProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestGitLabProvider_GetType tests provider type
func TestGitLabProvider_GetType(t *testing.T) {
	provider := NewGitLabProvider()

	if provider.GetType() != ProviderTypeGitLab {
		t.Errorf("Expected ProviderTypeGitLab, got %v", provider.GetType())
	}
}

// TestGitLabProvider_GetCapabilities tests GitLab-specific capabilities
func TestGitLabProvider_GetCapabilities(t *testing.T) {
	provider := NewGitLabProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true for GitLab")
	}

	if capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be false for GitLab")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for GitLab")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestGitLabProvider_BuildAuthParams tests GitLab-specific auth params
func TestGitLabProvider_BuildAuthParams(t *testing.T) {
	provider := NewGitLabProvider()
	baseParams := url.Values{}
	baseParams.Set("client_id", "test_client")

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "Remove offline_access scope and ensure openid",
			scopes:         []string{"read_user", "read_api", "offline_access"},
			expectedScopes: []string{"read_user", "read_api", "openid"},
		},
		{
			name:           "Keep existing openid, remove offline_access",
			scopes:         []string{"openid", "read_user", "offline_access", "profile"},
			expectedScopes: []string{"openid", "read_user", "profile"},
		},
		{
			name:           "Add default scopes when only openid",
			scopes:         []string{"openid"},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "Add openid and defaults when empty",
			scopes:         []string{},
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "GitLab-specific scopes",
			scopes:         []string{"read_user", "read_api", "read_repository"},
			expectedScopes: []string{"read_user", "read_api", "read_repository", "openid"},
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
					t.Error("offline_access scope should be filtered out for GitLab")
				}
			}
		})
	}
}

// TestGitLabProvider_ValidateConfig tests config validation
func TestGitLabProvider_ValidateConfig(t *testing.T) {
	provider := NewGitLabProvider()

	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("ValidateConfig failed: %v", err)
	}
}

// TestGitLabProvider_InterfaceCompliance tests that GitLab provider implements the OIDCProvider interface
func TestGitLabProvider_InterfaceCompliance(t *testing.T) {
	var _ OIDCProvider = NewGitLabProvider()
}

// TestGitLabProvider_BaseProviderInheritance tests that GitLab provider inherits from BaseProvider correctly
func TestGitLabProvider_BaseProviderInheritance(t *testing.T) {
	provider := NewGitLabProvider()

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

// TestGitLabProvider_OfflineAccessFiltering tests that offline_access scope is always filtered out
func TestGitLabProvider_OfflineAccessFiltering(t *testing.T) {
	provider := NewGitLabProvider()
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
			scopes: []string{"offline_access", "read_user", "offline_access", "profile"},
		},
		{
			name:   "Mixed with other scopes",
			scopes: []string{"read_api", "offline_access", "read_user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authParams, err := provider.BuildAuthParams(baseParams, tt.scopes)
			if err != nil {
				t.Errorf("BuildAuthParams failed: %v", err)
				return
			}

			// Ensure offline_access is NOT present
			for _, actualScope := range authParams.Scopes {
				if actualScope == "offline_access" {
					t.Error("offline_access scope should be filtered out for GitLab")
				}
			}
		})
	}
}

// TestGitLabProvider_GitLabSpecificScopes tests GitLab-specific scopes
func TestGitLabProvider_GitLabSpecificScopes(t *testing.T) {
	provider := NewGitLabProvider()
	baseParams := url.Values{}

	tests := []struct {
		name     string
		scopes   []string
		checkFor []string
	}{
		{
			name:     "GitLab API scopes",
			scopes:   []string{"read_api", "read_user"},
			checkFor: []string{"read_api", "read_user", "openid"},
		},
		{
			name:     "GitLab repository scopes",
			scopes:   []string{"read_repository", "write_repository"},
			checkFor: []string{"read_repository", "write_repository", "openid"},
		},
		{
			name:     "GitLab admin scopes",
			scopes:   []string{"api", "sudo"},
			checkFor: []string{"api", "sudo", "openid"},
		},
		{
			name:     "GitLab registry scopes",
			scopes:   []string{"read_registry", "write_registry"},
			checkFor: []string{"read_registry", "write_registry", "openid"},
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

// TestGitLabProvider_DefaultScopeHandling tests default scope behavior
func TestGitLabProvider_DefaultScopeHandling(t *testing.T) {
	provider := NewGitLabProvider()
	baseParams := url.Values{}

	// Test with only openid scope - should add defaults
	authParams, err := provider.BuildAuthParams(baseParams, []string{"openid"})
	if err != nil {
		t.Errorf("BuildAuthParams failed: %v", err)
		return
	}

	expectedScopes := []string{"openid", "profile", "email"}
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

// TestGitLabProvider_ScopeDeduplication tests that duplicate scopes are handled correctly
func TestGitLabProvider_ScopeDeduplication(t *testing.T) {
	provider := NewGitLabProvider()
	baseParams := url.Values{}

	// Test with duplicate scopes
	scopes := []string{"openid", "read_user", "openid", "profile", "read_user"}
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
