package providers

import (
	"errors"
	"testing"
	"time"
)

// Mock implementations for testing
type mockSession struct {
	authenticated bool
	idToken       string
	accessToken   string
	refreshToken  string
}

func (s *mockSession) GetIDToken() string      { return s.idToken }
func (s *mockSession) GetAccessToken() string  { return s.accessToken }
func (s *mockSession) GetRefreshToken() string { return s.refreshToken }
func (s *mockSession) GetAuthenticated() bool  { return s.authenticated }

type mockTokenVerifier struct {
	error error
}

func (v *mockTokenVerifier) VerifyToken(token string) error {
	return v.error
}

type mockTokenCache struct {
	claims map[string]map[string]interface{}
}

func (c *mockTokenCache) Get(key string) (map[string]interface{}, bool) {
	claims, exists := c.claims[key]
	return claims, exists
}

// TestBaseProvider_GetType tests the default provider type
func TestBaseProvider_GetType(t *testing.T) {
	provider := NewBaseProvider()

	if provider.GetType() != ProviderTypeGeneric {
		t.Errorf("Expected ProviderTypeGeneric, got %v", provider.GetType())
	}
}

// TestBaseProvider_GetCapabilities tests the default capabilities
func TestBaseProvider_GetCapabilities(t *testing.T) {
	provider := NewBaseProvider()
	capabilities := provider.GetCapabilities()

	if !capabilities.SupportsRefreshTokens {
		t.Error("Expected SupportsRefreshTokens to be true")
	}

	if !capabilities.RequiresOfflineAccessScope {
		t.Error("Expected RequiresOfflineAccessScope to be true")
	}

	if capabilities.PreferredTokenValidation != "id" {
		t.Errorf("Expected PreferredTokenValidation 'id', got '%s'", capabilities.PreferredTokenValidation)
	}

	if capabilities.RequiresPromptConsent {
		t.Error("Expected RequiresPromptConsent to be false")
	}
}

// TestBaseProvider_ValidateTokens_Unauthenticated tests validation when not authenticated
func TestBaseProvider_ValidateTokens_Unauthenticated(t *testing.T) {
	provider := NewBaseProvider()
	session := &mockSession{authenticated: false}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}

	tests := []struct {
		name           string
		refreshToken   string
		expectedResult ValidationResult
	}{
		{
			name:         "No refresh token",
			refreshToken: "",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name:         "Has refresh token",
			refreshToken: "refresh-token",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session.refreshToken = tt.refreshToken

			result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

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

// TestBaseProvider_ValidateTokens_AuthenticatedNoAccessToken tests authenticated session without access token
func TestBaseProvider_ValidateTokens_AuthenticatedNoAccessToken(t *testing.T) {
	provider := NewBaseProvider()
	session := &mockSession{
		authenticated: true,
		accessToken:   "", // No access token
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}

	tests := []struct {
		name           string
		refreshToken   string
		expectedResult ValidationResult
	}{
		{
			name:         "No access token, no refresh token",
			refreshToken: "",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     true,
			},
		},
		{
			name:         "No access token, has refresh token",
			refreshToken: "refresh-token",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session.refreshToken = tt.refreshToken

			result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

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

// TestBaseProvider_ValidateTokens_AuthenticatedNoIDToken tests authenticated session without ID token
func TestBaseProvider_ValidateTokens_AuthenticatedNoIDToken(t *testing.T) {
	provider := NewBaseProvider()
	session := &mockSession{
		authenticated: true,
		accessToken:   "access-token",
		idToken:       "", // No ID token
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}

	tests := []struct {
		name           string
		refreshToken   string
		expectedResult ValidationResult
	}{
		{
			name:         "No ID token, no refresh token",
			refreshToken: "",
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
		{
			name:         "No ID token, has refresh token",
			refreshToken: "refresh-token",
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session.refreshToken = tt.refreshToken

			result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

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

// TestBaseProvider_ValidateTokens_TokenVerificationFailure tests token verification failures
func TestBaseProvider_ValidateTokens_TokenVerificationFailure(t *testing.T) {
	provider := NewBaseProvider()
	session := &mockSession{
		authenticated: true,
		accessToken:   "access-token",
		idToken:       "id-token",
	}
	cache := &mockTokenCache{}

	tests := []struct {
		name           string
		verifierError  error
		refreshToken   string
		expectedResult ValidationResult
	}{
		{
			name:          "Token expired, has refresh token",
			verifierError: errors.New("token has expired"),
			refreshToken:  "refresh-token",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name:          "Token expired, no refresh token",
			verifierError: errors.New("token has expired"),
			refreshToken:  "",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     true,
			},
		},
		{
			name:          "Other verification error, has refresh token",
			verifierError: errors.New("invalid signature"),
			refreshToken:  "refresh-token",
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name:          "Other verification error, no refresh token",
			verifierError: errors.New("invalid signature"),
			refreshToken:  "",
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
			session.refreshToken = tt.refreshToken

			result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

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

// TestBaseProvider_ValidateTokenExpiry tests token expiry validation logic
func TestBaseProvider_ValidateTokenExpiry(t *testing.T) {
	provider := NewBaseProvider()
	session := &mockSession{refreshToken: "refresh-token"}

	now := time.Now()
	gracePeriod := 5 * time.Minute

	tests := []struct {
		name           string
		claims         map[string]interface{}
		cacheFound     bool
		expectedResult ValidationResult
	}{
		{
			name:       "Token not found in cache, has refresh token",
			claims:     nil,
			cacheFound: false,
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name:       "Claims without exp, has refresh token",
			claims:     map[string]interface{}{"sub": "user123"},
			cacheFound: true,
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name: "Token expired (beyond grace period), has refresh token",
			claims: map[string]interface{}{
				"exp": float64(now.Add(-10 * time.Minute).Unix()),
			},
			cacheFound: true,
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name: "Token expires within grace period, has refresh token",
			claims: map[string]interface{}{
				"exp": float64(now.Add(2 * time.Minute).Unix()),
			},
			cacheFound: true,
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  true,
				IsExpired:     false,
			},
		},
		{
			name: "Token valid (beyond grace period)",
			claims: map[string]interface{}{
				"exp": float64(now.Add(10 * time.Minute).Unix()),
			},
			cacheFound: true,
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &mockTokenCache{claims: make(map[string]map[string]interface{})}
			if tt.cacheFound {
				cache.claims["test-token"] = tt.claims
			}

			result, err := provider.ValidateTokenExpiry(session, "test-token", cache, gracePeriod)

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

// TestBaseProvider_ValidateTokenExpiry_NoRefreshToken tests expiry validation without refresh token
func TestBaseProvider_ValidateTokenExpiry_NoRefreshToken(t *testing.T) {
	provider := NewBaseProvider()
	session := &mockSession{refreshToken: ""} // No refresh token

	now := time.Now()
	gracePeriod := 5 * time.Minute

	tests := []struct {
		name           string
		claims         map[string]interface{}
		cacheFound     bool
		expectedResult ValidationResult
	}{
		{
			name:       "Token not found in cache, no refresh token",
			claims:     nil,
			cacheFound: false,
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     true,
			},
		},
		{
			name:       "Claims without exp, no refresh token",
			claims:     map[string]interface{}{"sub": "user123"},
			cacheFound: true,
			expectedResult: ValidationResult{
				Authenticated: false,
				NeedsRefresh:  false,
				IsExpired:     true,
			},
		},
		{
			name: "Token expires within grace period, no refresh token",
			claims: map[string]interface{}{
				"exp": float64(now.Add(2 * time.Minute).Unix()),
			},
			cacheFound: true,
			expectedResult: ValidationResult{
				Authenticated: true,
				NeedsRefresh:  false,
				IsExpired:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &mockTokenCache{claims: make(map[string]map[string]interface{})}
			if tt.cacheFound {
				cache.claims["test-token"] = tt.claims
			}

			result, err := provider.ValidateTokenExpiry(session, "test-token", cache, gracePeriod)

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

// TestBaseProvider_BuildAuthParams tests authorization parameter building
func TestBaseProvider_BuildAuthParams(t *testing.T) {
	provider := NewBaseProvider()

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "No existing offline_access scope",
			scopes:         []string{"openid", "profile", "email"},
			expectedScopes: []string{"openid", "profile", "email", "offline_access"},
		},
		{
			name:           "Existing offline_access scope",
			scopes:         []string{"openid", "profile", "offline_access", "email"},
			expectedScopes: []string{"openid", "profile", "offline_access", "email"},
		},
		{
			name:           "Empty scopes",
			scopes:         []string{},
			expectedScopes: []string{"offline_access"},
		},
		{
			name:           "Only offline_access",
			scopes:         []string{"offline_access"},
			expectedScopes: []string{"offline_access"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseParams := make(map[string][]string)
			baseParams["client_id"] = []string{"test-client"}

			result, err := provider.BuildAuthParams(baseParams, tt.scopes)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if len(result.Scopes) != len(tt.expectedScopes) {
				t.Errorf("Expected %d scopes, got %d", len(tt.expectedScopes), len(result.Scopes))
			}

			// Check that all expected scopes are present
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

			// Verify base parameters are preserved
			if result.URLValues.Get("client_id") != "test-client" {
				t.Errorf("Expected client_id 'test-client', got '%s'", result.URLValues.Get("client_id"))
			}
		})
	}
}

// TestBaseProvider_HandleTokenRefresh tests token refresh handling
func TestBaseProvider_HandleTokenRefresh(t *testing.T) {
	provider := NewBaseProvider()
	tokenData := &TokenResult{
		IDToken:      "new-id-token",
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
	}

	// Base provider should do nothing and return no error
	err := provider.HandleTokenRefresh(tokenData)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestBaseProvider_ValidateConfig tests configuration validation
func TestBaseProvider_ValidateConfig(t *testing.T) {
	provider := NewBaseProvider()

	// Base provider should always return valid configuration
	err := provider.ValidateConfig()

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestNewBaseProvider tests the constructor
func TestNewBaseProvider(t *testing.T) {
	provider := NewBaseProvider()

	if provider == nil {
		t.Fatal("Expected provider to be created, got nil")
	}

	// Verify it implements the OIDCProvider interface
	var _ OIDCProvider = provider
}

// Benchmark tests
func BenchmarkBaseProvider_ValidateTokens(b *testing.B) {
	provider := NewBaseProvider()
	session := &mockSession{
		authenticated: true,
		idToken:       "test-token",
		accessToken:   "access-token",
		refreshToken:  "refresh-token",
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		claims: map[string]map[string]interface{}{
			"test-token": {
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

func BenchmarkBaseProvider_BuildAuthParams(b *testing.B) {
	provider := NewBaseProvider()
	baseParams := make(map[string][]string)
	baseParams["client_id"] = []string{"test-client"}
	scopes := []string{"openid", "profile", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.BuildAuthParams(baseParams, scopes)
	}
}
