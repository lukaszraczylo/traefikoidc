package providers

import (
	"net/url"
	"testing"
)

// TestGoogleProvider_NewGoogleProvider tests the constructor
func TestGoogleProvider_NewGoogleProvider(t *testing.T) {
	provider := NewGoogleProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestGoogleProvider_GetType tests provider type
func TestGoogleProvider_GetType(t *testing.T) {
	provider := NewGoogleProvider()

	if provider.GetType() != ProviderTypeGoogle {
		t.Errorf("Expected ProviderTypeGoogle, got %v", provider.GetType())
	}
}

// TestGoogleProvider_GetCapabilities tests Google-specific capabilities
func TestGoogleProvider_GetCapabilities(t *testing.T) {
	provider := NewGoogleProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true")
	}

	if capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be false for Google")
	}

	if !capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be true for Google")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestGoogleProvider_BuildAuthParams tests Google-specific auth parameters
func TestGoogleProvider_BuildAuthParams(t *testing.T) {
	provider := NewGoogleProvider()

	tests := []struct {
		name                 string
		inputScopes          []string
		expectedScopes       []string
		shouldHaveAccessType bool
		shouldHavePrompt     bool
	}{
		{
			name:                 "Basic scopes without offline_access",
			inputScopes:          []string{"openid", "profile", "email"},
			expectedScopes:       []string{"openid", "profile", "email"},
			shouldHaveAccessType: true,
			shouldHavePrompt:     true,
		},
		{
			name:                 "Scopes with offline_access (should be filtered out)",
			inputScopes:          []string{"openid", "profile", "offline_access", "email"},
			expectedScopes:       []string{"openid", "profile", "email"},
			shouldHaveAccessType: true,
			shouldHavePrompt:     true,
		},
		{
			name:                 "Only offline_access scope (should be filtered out)",
			inputScopes:          []string{"offline_access"},
			expectedScopes:       []string{},
			shouldHaveAccessType: true,
			shouldHavePrompt:     true,
		},
		{
			name:                 "Empty scopes",
			inputScopes:          []string{},
			expectedScopes:       []string{},
			shouldHaveAccessType: true,
			shouldHavePrompt:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseParams := make(url.Values)
			baseParams.Set("client_id", "test-client")

			result, err := provider.BuildAuthParams(baseParams, tt.inputScopes)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check Google-specific parameters
			if tt.shouldHaveAccessType {
				if result.URLValues.Get("access_type") != "offline" {
					t.Errorf("Expected access_type 'offline', got '%s'", result.URLValues.Get("access_type"))
				}
			}

			if tt.shouldHavePrompt {
				if result.URLValues.Get("prompt") != "consent" {
					t.Errorf("Expected prompt 'consent', got '%s'", result.URLValues.Get("prompt"))
				}
			}

			// Check filtered scopes
			if len(result.Scopes) != len(tt.expectedScopes) {
				t.Errorf("Expected %d scopes, got %d", len(tt.expectedScopes), len(result.Scopes))
			}

			for _, expectedScope := range tt.expectedScopes {
				found := false
				for _, actualScope := range result.Scopes {
					if actualScope == expectedScope {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected scope '%s' not found in result", expectedScope)
				}
			}

			// Ensure offline_access is not in the result scopes
			for _, scope := range result.Scopes {
				if scope == "offline_access" {
					t.Error("offline_access scope should be filtered out for Google")
				}
			}

			// Verify original base parameters are preserved
			if result.URLValues.Get("client_id") != "test-client" {
				t.Errorf("Expected client_id 'test-client', got '%s'", result.URLValues.Get("client_id"))
			}
		})
	}
}

// TestGoogleProvider_ValidateConfig tests configuration validation
func TestGoogleProvider_ValidateConfig(t *testing.T) {
	provider := NewGoogleProvider()

	err := provider.ValidateConfig()

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestGoogleProvider_InterfaceCompliance tests that Google provider implements OIDCProvider
func TestGoogleProvider_InterfaceCompliance(t *testing.T) {
	provider := NewGoogleProvider()

	// Verify it implements the OIDCProvider interface
	var _ OIDCProvider = provider
}

// TestGoogleProvider_OfflineAccessFiltering tests comprehensive offline_access filtering
func TestGoogleProvider_OfflineAccessFiltering(t *testing.T) {
	provider := NewGoogleProvider()

	tests := []struct {
		name        string
		inputScopes []string
		description string
	}{
		{
			name:        "Multiple offline_access occurrences",
			inputScopes: []string{"openid", "offline_access", "profile", "offline_access", "email"},
			description: "Should remove all instances of offline_access",
		},
		{
			name:        "Case sensitive filtering",
			inputScopes: []string{"openid", "OFFLINE_ACCESS", "profile", "offline_access"},
			description: "Should only remove exact case matches",
		},
		{
			name:        "Similar but different scopes",
			inputScopes: []string{"openid", "offline_access_extended", "profile", "offline_access"},
			description: "Should only remove exact offline_access matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseParams := make(url.Values)
			result, err := provider.BuildAuthParams(baseParams, tt.inputScopes)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Count offline_access occurrences in result
			offlineAccessCount := 0
			for _, scope := range result.Scopes {
				if scope == "offline_access" {
					offlineAccessCount++
				}
			}

			if offlineAccessCount != 0 {
				t.Errorf("Expected 0 offline_access scopes in result, got %d", offlineAccessCount)
			}

			// Verify other scopes are preserved
			for _, originalScope := range tt.inputScopes {
				if originalScope == "offline_access" {
					continue // Skip the filtered scope
				}

				found := false
				for _, resultScope := range result.Scopes {
					if resultScope == originalScope {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected scope '%s' to be preserved", originalScope)
				}
			}
		})
	}
}

// TestGoogleProvider_BaseProviderInheritance tests inherited functionality from BaseProvider
func TestGoogleProvider_BaseProviderInheritance(t *testing.T) {
	provider := NewGoogleProvider()

	// Test ValidateTokens (inherited from BaseProvider)
	session := &mockSession{
		authenticated: true,
		idToken:       "test-token",
		accessToken:   "access-token", // Add access token for proper validation
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		claims: map[string]map[string]interface{}{
			"test-token": {
				"exp": float64(9999999999), // Far future
				"sub": "user123",
			},
		},
	}

	result, err := provider.ValidateTokens(session, verifier, cache, 0)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !result.Authenticated {
		t.Error("Expected result to be authenticated")
	}

	// Test HandleTokenRefresh (inherited from BaseProvider)
	tokenData := &TokenResult{IDToken: "new-token"}
	err = provider.HandleTokenRefresh(tokenData)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestGoogleProvider_AuthParamsPreservation tests that base parameters are not overwritten
func TestGoogleProvider_AuthParamsPreservation(t *testing.T) {
	provider := NewGoogleProvider()

	baseParams := make(url.Values)
	baseParams.Set("client_id", "test-client")
	baseParams.Set("redirect_uri", "https://example.com/callback")
	baseParams.Set("response_type", "code")
	baseParams.Set("state", "test-state")
	baseParams.Set("nonce", "test-nonce")

	scopes := []string{"openid", "profile"}

	result, err := provider.BuildAuthParams(baseParams, scopes)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Verify all original parameters are preserved
	expectedParams := map[string]string{
		"client_id":     "test-client",
		"redirect_uri":  "https://example.com/callback",
		"response_type": "code",
		"state":         "test-state",
		"nonce":         "test-nonce",
		"access_type":   "offline", // Added by Google provider
		"prompt":        "consent", // Added by Google provider
	}

	for key, expectedValue := range expectedParams {
		actualValue := result.URLValues.Get(key)
		if actualValue != expectedValue {
			t.Errorf("Expected %s '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify scopes
	if len(result.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(result.Scopes))
	}

	expectedScopes := []string{"openid", "profile"}
	for _, expectedScope := range expectedScopes {
		found := false
		for _, actualScope := range result.Scopes {
			if actualScope == expectedScope {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected scope '%s' not found", expectedScope)
		}
	}
}

// Benchmark tests
func BenchmarkGoogleProvider_BuildAuthParams(b *testing.B) {
	provider := NewGoogleProvider()
	baseParams := make(url.Values)
	baseParams.Set("client_id", "test-client")
	scopes := []string{"openid", "profile", "email", "offline_access"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.BuildAuthParams(baseParams, scopes)
	}
}

func BenchmarkGoogleProvider_GetCapabilities(b *testing.B) {
	provider := NewGoogleProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetCapabilities()
	}
}
