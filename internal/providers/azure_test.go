package providers

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestAzureProvider_NewAzureProvider tests the constructor
func TestAzureProvider_NewAzureProvider(t *testing.T) {
	provider := NewAzureProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	if provider.BaseProvider == nil {
		t.Error("BaseProvider should be initialized")
	}
}

// TestAzureProvider_GetType tests provider type
func TestAzureProvider_GetType(t *testing.T) {
	provider := NewAzureProvider()

	if provider.GetType() != ProviderTypeAzure {
		t.Errorf("Expected ProviderTypeAzure, got %v", provider.GetType())
	}
}

// TestAzureProvider_GetCapabilities tests Azure-specific capabilities
func TestAzureProvider_GetCapabilities(t *testing.T) {
	provider := NewAzureProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true")
	}

	if !capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be true for Azure")
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false for Azure")
	}

	if capabilities.PreferredTokenValidation != "access" {
		t.Errorf("Expected PreferredTokenValidation 'access', got '%s'", capabilities.PreferredTokenValidation)
	}
}

// TestAzureProvider_BuildAuthParams tests Azure-specific auth parameters
func TestAzureProvider_BuildAuthParams(t *testing.T) {
	provider := NewAzureProvider()

	tests := []struct {
		name                   string
		inputScopes            []string
		expectedScopes         []string
		shouldHaveResponseMode bool
		shouldAddOfflineAccess bool
	}{
		{
			name:                   "Basic scopes without offline_access",
			inputScopes:            []string{"openid", "profile", "email"},
			expectedScopes:         []string{"openid", "profile", "email", "offline_access"},
			shouldHaveResponseMode: true,
			shouldAddOfflineAccess: true,
		},
		{
			name:                   "Scopes with offline_access already present",
			inputScopes:            []string{"openid", "profile", "offline_access", "email"},
			expectedScopes:         []string{"openid", "profile", "offline_access", "email"},
			shouldHaveResponseMode: true,
			shouldAddOfflineAccess: false,
		},
		{
			name:                   "Only offline_access scope",
			inputScopes:            []string{"offline_access"},
			expectedScopes:         []string{"offline_access"},
			shouldHaveResponseMode: true,
			shouldAddOfflineAccess: false,
		},
		{
			name:                   "Empty scopes (should add offline_access)",
			inputScopes:            []string{},
			expectedScopes:         []string{"offline_access"},
			shouldHaveResponseMode: true,
			shouldAddOfflineAccess: true,
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

			// Check Azure-specific parameters
			if tt.shouldHaveResponseMode {
				if result.URLValues.Get("response_mode") != "query" {
					t.Errorf("Expected response_mode 'query', got '%s'", result.URLValues.Get("response_mode"))
				}
			}

			// Check scopes
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

			// Verify offline_access is present
			hasOfflineAccess := false
			for _, scope := range result.Scopes {
				if scope == "offline_access" {
					hasOfflineAccess = true
					break
				}
			}
			if !hasOfflineAccess {
				t.Error("Azure provider should always include offline_access scope")
			}

			// Verify original base parameters are preserved
			if result.URLValues.Get("client_id") != "test-client" {
				t.Errorf("Expected client_id 'test-client', got '%s'", result.URLValues.Get("client_id"))
			}
		})
	}
}

// TestAzureProvider_ValidateTokens tests Azure-specific token validation logic
func TestAzureProvider_ValidateTokens(t *testing.T) {
	provider := NewAzureProvider()

	tests := []struct {
		name           string
		session        *mockSession
		verifierError  error
		cacheData      map[string]interface{}
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
			name: "Unauthenticated without refresh token",
			session: &mockSession{
				authenticated: false,
			},
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     true,
			},
		},
		{
			name: "JWT access token valid",
			session: &mockSession{
				authenticated: true,
				accessToken:   "valid.jwt.token",
				refreshToken:  "refresh-token",
			},
			verifierError: nil,
			cacheData: map[string]interface{}{
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name: "JWT access token invalid, valid ID token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "invalid.jwt.token",
				idToken:       "valid.id.token",
				refreshToken:  "refresh-token",
			},
			verifierError: errors.New("invalid token"),
			cacheData: map[string]interface{}{
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name: "Opaque access token with valid ID token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "opaque-token-no-dots",
				idToken:       "valid.id.token",
				refreshToken:  "refresh-token",
			},
			cacheData: map[string]interface{}{
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name: "Opaque access token without ID token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "opaque-token-no-dots",
				refreshToken:  "refresh-token",
			},
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name: "No access token, valid ID token",
			session: &mockSession{
				authenticated: true,
				idToken:       "valid.id.token",
				refreshToken:  "refresh-token",
			},
			verifierError: nil,
			cacheData: map[string]interface{}{
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name: "No access token, invalid ID token, with refresh token",
			session: &mockSession{
				authenticated: true,
				idToken:       "invalid.id.token",
				refreshToken:  "refresh-token",
			},
			verifierError: errors.New("invalid token"),
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name: "No tokens, with refresh token",
			session: &mockSession{
				authenticated: true,
				refreshToken:  "refresh-token",
			},
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name: "No tokens, no refresh token",
			session: &mockSession{
				authenticated: true,
			},
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &mockTokenVerifier{error: tt.verifierError}
			cache := &mockTokenCache{claims: make(map[string]map[string]interface{})}

			// Set up cache data
			if tt.cacheData != nil {
				if tt.session.accessToken != "" && strings.Count(tt.session.accessToken, ".") == 2 {
					cache.claims[tt.session.accessToken] = tt.cacheData
				}
				if tt.session.idToken != "" {
					cache.claims[tt.session.idToken] = tt.cacheData
				}
			}

			result, err := provider.ValidateTokens(tt.session, verifier, cache, time.Minute)

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

// TestAzureProvider_ValidateConfig tests configuration validation
func TestAzureProvider_ValidateConfig(t *testing.T) {
	provider := NewAzureProvider()

	err := provider.ValidateConfig()

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestAzureProvider_InterfaceCompliance tests that Azure provider implements OIDCProvider
func TestAzureProvider_InterfaceCompliance(t *testing.T) {
	provider := NewAzureProvider()

	// Verify it implements the OIDCProvider interface
	var _ OIDCProvider = provider
}

// TestAzureProvider_OfflineAccessHandling tests comprehensive offline_access handling
func TestAzureProvider_OfflineAccessHandling(t *testing.T) {
	provider := NewAzureProvider()

	tests := []struct {
		name          string
		inputScopes   []string
		expectedCount int // Expected number of offline_access scopes (should be 1)
		description   string
	}{
		{
			name:          "No offline_access - should add one",
			inputScopes:   []string{"openid", "profile", "email"},
			expectedCount: 1,
			description:   "Should add offline_access when not present",
		},
		{
			name:          "One offline_access - should preserve",
			inputScopes:   []string{"openid", "offline_access", "profile"},
			expectedCount: 1,
			description:   "Should preserve existing offline_access",
		},
		{
			name:          "Multiple offline_access - should preserve all",
			inputScopes:   []string{"openid", "offline_access", "profile", "offline_access"},
			expectedCount: 2,
			description:   "Should preserve all offline_access scopes if multiple exist",
		},
		{
			name:          "Only offline_access",
			inputScopes:   []string{"offline_access"},
			expectedCount: 1,
			description:   "Should preserve when only offline_access is present",
		},
		{
			name:          "Empty scopes - should add offline_access",
			inputScopes:   []string{},
			expectedCount: 1,
			description:   "Should add offline_access when no scopes provided",
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

			if offlineAccessCount != tt.expectedCount {
				t.Errorf("Expected %d offline_access scopes in result, got %d", tt.expectedCount, offlineAccessCount)
			}

			// Ensure at least one offline_access is always present
			if offlineAccessCount == 0 {
				t.Error("Azure provider should always have at least one offline_access scope")
			}

			// Verify other scopes are preserved (except for the empty case)
			if len(tt.inputScopes) > 0 {
				for _, originalScope := range tt.inputScopes {
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
			}
		})
	}
}

// TestAzureProvider_TokenValidationPriority tests access token vs ID token priority
func TestAzureProvider_TokenValidationPriority(t *testing.T) {
	provider := NewAzureProvider()

	// Test that Azure prefers access tokens over ID tokens when both are JWT
	session := &mockSession{
		authenticated: true,
		accessToken:   "valid.access.token",
		idToken:       "valid.id.token",
		refreshToken:  "refresh-token",
	}

	verifier := &mockTokenVerifier{} // Valid tokens
	cache := &mockTokenCache{
		claims: map[string]map[string]interface{}{
			"valid.access.token": {
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
			"valid.id.token": {
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
		},
	}

	result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !result.Authenticated {
		t.Error("Should be authenticated with valid access token")
	}

	if result.NeedsRefresh {
		t.Error("Should not need refresh with valid access token")
	}
}

// TestAzureProvider_AuthParamsPreservation tests that base parameters are not overwritten
func TestAzureProvider_AuthParamsPreservation(t *testing.T) {
	provider := NewAzureProvider()

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
		"response_mode": "query", // Added by Azure provider
	}

	for key, expectedValue := range expectedParams {
		actualValue := result.URLValues.Get(key)
		if actualValue != expectedValue {
			t.Errorf("Expected %s '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify scopes (should include offline_access)
	if len(result.Scopes) != 3 {
		t.Errorf("Expected 3 scopes (including offline_access), got %d", len(result.Scopes))
	}

	expectedScopes := []string{"openid", "profile", "offline_access"}
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
func BenchmarkAzureProvider_BuildAuthParams(b *testing.B) {
	provider := NewAzureProvider()
	baseParams := make(url.Values)
	baseParams.Set("client_id", "test-client")
	scopes := []string{"openid", "profile", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.BuildAuthParams(baseParams, scopes)
	}
}

func BenchmarkAzureProvider_ValidateTokens(b *testing.B) {
	provider := NewAzureProvider()
	session := &mockSession{
		authenticated: true,
		accessToken:   "valid.access.token",
		idToken:       "valid.id.token",
		refreshToken:  "refresh-token",
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		claims: map[string]map[string]interface{}{
			"valid.access.token": {
				"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
				"sub": "user123",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.ValidateTokens(session, verifier, cache, time.Minute)
	}
}
