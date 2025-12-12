package providers

import (
	"testing"
)

// TestGenericProvider_NewGenericProvider tests the constructor
func TestGenericProvider_NewGenericProvider(t *testing.T) {
	provider := NewGenericProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestGenericProvider_GetType tests provider type
func TestGenericProvider_GetType(t *testing.T) {
	provider := NewGenericProvider()

	if provider.GetType() != ProviderTypeGeneric {
		t.Errorf("Expected ProviderTypeGeneric, got %v", provider.GetType())
	}
}

// TestGenericProvider_GetCapabilities tests that it inherits BaseProvider capabilities
func TestGenericProvider_GetCapabilities(t *testing.T) {
	provider := NewGenericProvider()
	capabilities := provider.GetCapabilities()

	// Should have the same capabilities as BaseProvider
	baseProvider := NewBaseProvider()
	baseCapabilities := baseProvider.GetCapabilities()

	if capabilities.SupportsRefreshTokens != baseCapabilities.SupportsRefreshTokens {
		t.Errorf("Expected SupportsRefreshTokens %v, got %v",
			baseCapabilities.SupportsRefreshTokens, capabilities.SupportsRefreshTokens)
	}

	if capabilities.RequiresOfflineAccessScope != baseCapabilities.RequiresOfflineAccessScope {
		t.Errorf("Expected RequiresOfflineAccessScope %v, got %v",
			baseCapabilities.RequiresOfflineAccessScope, capabilities.RequiresOfflineAccessScope)
	}

	if capabilities.PreferredTokenValidation != baseCapabilities.PreferredTokenValidation {
		t.Errorf("Expected PreferredTokenValidation %v, got %v",
			baseCapabilities.PreferredTokenValidation, capabilities.PreferredTokenValidation)
	}

	if capabilities.RequiresPromptConsent != baseCapabilities.RequiresPromptConsent {
		t.Errorf("Expected RequiresPromptConsent %v, got %v",
			baseCapabilities.RequiresPromptConsent, capabilities.RequiresPromptConsent)
	}
}

// TestGenericProvider_InterfaceCompliance tests that Generic provider implements OIDCProvider
func TestGenericProvider_InterfaceCompliance(t *testing.T) {
	provider := NewGenericProvider()

	// Verify it implements the OIDCProvider interface
	var _ OIDCProvider = provider
}

// TestGenericProvider_InheritsBaseProviderBehavior tests inherited functionality
func TestGenericProvider_InheritsBaseProviderBehavior(t *testing.T) {
	provider := NewGenericProvider()
	baseProvider := NewBaseProvider()

	// Test BuildAuthParams behavior is the same
	scopes := []string{"openid", "profile", "email"}
	baseParams := make(map[string][]string)
	baseParams["client_id"] = []string{"test-client"}

	genericResult, genericErr := provider.BuildAuthParams(baseParams, scopes)
	baseResult, baseErr := baseProvider.BuildAuthParams(baseParams, scopes)

	if (genericErr == nil) != (baseErr == nil) {
		t.Errorf("BuildAuthParams error mismatch: generic=%v, base=%v", genericErr, baseErr)
	}

	if genericErr == nil && baseErr == nil {
		// Compare scopes length (offline_access should be added)
		if len(genericResult.Scopes) != len(baseResult.Scopes) {
			t.Errorf("BuildAuthParams scope count mismatch: generic=%d, base=%d",
				len(genericResult.Scopes), len(baseResult.Scopes))
		}

		// Verify offline_access is added in both cases
		genericHasOffline := false
		baseHasOffline := false

		for _, scope := range genericResult.Scopes {
			if scope == "offline_access" {
				genericHasOffline = true
				break
			}
		}

		for _, scope := range baseResult.Scopes {
			if scope == "offline_access" {
				baseHasOffline = true
				break
			}
		}

		if genericHasOffline != baseHasOffline {
			t.Errorf("offline_access scope handling mismatch: generic=%v, base=%v",
				genericHasOffline, baseHasOffline)
		}
	}

	// Test ValidateConfig behavior is the same
	genericConfigErr := provider.ValidateConfig()
	baseConfigErr := baseProvider.ValidateConfig()

	if (genericConfigErr == nil) != (baseConfigErr == nil) {
		t.Errorf("ValidateConfig error mismatch: generic=%v, base=%v", genericConfigErr, baseConfigErr)
	}

	// Test HandleTokenRefresh behavior is the same
	tokenData := &TokenResult{IDToken: "test-token"}
	genericRefreshErr := provider.HandleTokenRefresh(tokenData)
	baseRefreshErr := baseProvider.HandleTokenRefresh(tokenData)

	if (genericRefreshErr == nil) != (baseRefreshErr == nil) {
		t.Errorf("HandleTokenRefresh error mismatch: generic=%v, base=%v",
			genericRefreshErr, baseRefreshErr)
	}
}

// TestGenericProvider_ValidateTokens tests token validation inheritance
func TestGenericProvider_ValidateTokens(t *testing.T) {
	provider := NewGenericProvider()

	tests := []struct {
		verifierError  error
		session        *mockSession
		name           string
		expectedResult ValidationResult
	}{
		{
			name: "Unauthenticated with refresh token",
			session: &mockSession{
				authenticated: false,
				refreshToken:  "refresh-token",
			},
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name: "Authenticated with valid tokens",
			session: &mockSession{
				authenticated: true,
				idToken:       "valid-token",
				accessToken:   "access-token",
				refreshToken:  "refresh-token",
			},
			verifierError: nil,
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name: "Authenticated with invalid token, has refresh",
			session: &mockSession{
				authenticated: true,
				idToken:       "invalid-token",
				refreshToken:  "refresh-token",
			},
			verifierError: &testError{"token expired"},
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &mockTokenVerifier{error: tt.verifierError}
			cache := &mockTokenCache{
				claims: map[string]map[string]interface{}{
					"valid-token": {
						"exp": float64(9999999999), // Far future
						"sub": "user123",
					},
				},
			}

			result, err := provider.ValidateTokens(tt.session, verifier, cache, 0)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result.Authenticated != tt.expectedResult.Authenticated {
				t.Errorf("Expected Authenticated %v, got %v", tt.expectedResult.Authenticated, result.Authenticated)
			}

			if result.NeedsRefresh != tt.expectedResult.NeedsRefresh {
				t.Errorf("Expected NeedsRefresh %v, got %v", tt.expectedResult.NeedsRefresh, result.NeedsRefresh)
			}

			if result.IsExpired != tt.expectedResult.IsExpired {
				t.Errorf("Expected IsExpired %v, got %v", tt.expectedResult.IsExpired, result.IsExpired)
			}
		})
	}
}

// Benchmark tests
func BenchmarkGenericProvider_GetType(b *testing.B) {
	provider := NewGenericProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetType()
	}
}

func BenchmarkGenericProvider_GetCapabilities(b *testing.B) {
	provider := NewGenericProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetCapabilities()
	}
}

// Test error type for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
