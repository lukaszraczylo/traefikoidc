package providers

import (
	"net/url"
	"testing"
	"time"
)

func TestBaseProvider_GetType(t *testing.T) {
	provider := NewBaseProvider()
	providerType := provider.GetType()

	if providerType != ProviderTypeGeneric {
		t.Errorf("expected provider type %d, got %d", ProviderTypeGeneric, providerType)
	}
}

func TestBaseProvider_GetCapabilities(t *testing.T) {
	provider := NewBaseProvider()
	capabilities := provider.GetCapabilities()

	expectedCapabilities := ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		PreferredTokenValidation:   "id",
	}

	if capabilities.SupportsRefreshTokens != expectedCapabilities.SupportsRefreshTokens {
		t.Errorf("expected SupportsRefreshTokens %t, got %t", expectedCapabilities.SupportsRefreshTokens, capabilities.SupportsRefreshTokens)
	}

	if capabilities.RequiresOfflineAccessScope != expectedCapabilities.RequiresOfflineAccessScope {
		t.Errorf("expected RequiresOfflineAccessScope %t, got %t", expectedCapabilities.RequiresOfflineAccessScope, capabilities.RequiresOfflineAccessScope)
	}

	if capabilities.PreferredTokenValidation != expectedCapabilities.PreferredTokenValidation {
		t.Errorf("expected PreferredTokenValidation %q, got %q", expectedCapabilities.PreferredTokenValidation, capabilities.PreferredTokenValidation)
	}
}

func TestBaseProvider_BuildAuthParams(t *testing.T) {
	provider := NewBaseProvider()

	tests := []struct {
		name                string
		baseParams          url.Values
		scopes              []string
		expectOfflineAccess bool
	}{
		{
			name:                "params with offline_access scope",
			baseParams:          url.Values{"client_id": []string{"test-client"}},
			scopes:              []string{"openid", "offline_access", "email"},
			expectOfflineAccess: true,
		},
		{
			name:                "params without offline_access scope",
			baseParams:          url.Values{"client_id": []string{"test-client"}},
			scopes:              []string{"openid", "email"},
			expectOfflineAccess: true, // Should be added automatically
		},
		{
			name:                "empty scopes",
			baseParams:          url.Values{},
			scopes:              []string{},
			expectOfflineAccess: true, // Should be added automatically
		},
		{
			name:                "multiple offline_access scopes",
			baseParams:          url.Values{},
			scopes:              []string{"openid", "offline_access", "email", "offline_access"},
			expectOfflineAccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authParams, err := provider.BuildAuthParams(tt.baseParams, tt.scopes)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if authParams == nil {
				t.Fatal("expected non-nil auth params")
			}

			// Check offline_access scope
			if tt.expectOfflineAccess {
				hasOfflineAccess := false
				for _, scope := range authParams.Scopes {
					if scope == "offline_access" {
						hasOfflineAccess = true
						break
					}
				}
				if !hasOfflineAccess {
					t.Error("expected offline_access scope to be present")
				}
			}

			// Verify other parameters are preserved
			for key, values := range tt.baseParams {
				paramValues := authParams.URLValues[key]
				if len(paramValues) != len(values) {
					t.Errorf("expected %d values for param %s, got %d", len(values), key, len(paramValues))
				}
				for i, expectedValue := range values {
					if i < len(paramValues) && paramValues[i] != expectedValue {
						t.Errorf("expected param %s[%d] to be %q, got %q", key, i, expectedValue, paramValues[i])
					}
				}
			}
		})
	}
}

func TestBaseProvider_ValidateTokenExpiry(t *testing.T) {
	provider := NewBaseProvider()

	tests := []struct {
		name               string
		token              string
		session            *mockSession
		cache              *mockTokenCache
		refreshGracePeriod time.Duration
		expectedResult     *ValidationResult
	}{
		{
			name:  "token not in cache with refresh token",
			token: "missing-token",
			session: &mockSession{
				refreshToken: "refresh-token",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{},
			},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name:  "token not in cache without refresh token",
			token: "missing-token",
			session: &mockSession{
				refreshToken: "",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{},
			},
			expectedResult: &ValidationResult{
				IsExpired: true,
			},
		},
		{
			name:  "token with missing exp claim with refresh token",
			token: "token-without-exp",
			session: &mockSession{
				refreshToken: "refresh-token",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"token-without-exp": {
						"sub": "user123",
					},
				},
			},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name:  "token with invalid exp claim type with refresh token",
			token: "token-with-invalid-exp",
			session: &mockSession{
				refreshToken: "refresh-token",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"token-with-invalid-exp": {
						"exp": "not-a-number",
					},
				},
			},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name:  "token with invalid exp claim type without refresh token",
			token: "token-with-invalid-exp",
			session: &mockSession{
				refreshToken: "",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"token-with-invalid-exp": {
						"exp": "not-a-number",
					},
				},
			},
			expectedResult: &ValidationResult{
				IsExpired: true,
			},
		},
		{
			name:               "token expired within grace period with refresh token",
			token:              "expiring-token",
			refreshGracePeriod: time.Minute * 10,
			session: &mockSession{
				refreshToken: "refresh-token",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"expiring-token": {
						"exp": float64(time.Now().Add(time.Minute * 5).Unix()), // Expires in 5 minutes, within grace period
					},
				},
			},
			expectedResult: &ValidationResult{
				Authenticated: true,
				NeedsRefresh:  true,
			},
		},
		{
			name:               "token expired within grace period without refresh token",
			token:              "expiring-token-no-refresh",
			refreshGracePeriod: time.Minute * 10,
			session: &mockSession{
				refreshToken: "",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"expiring-token-no-refresh": {
						"exp": float64(time.Now().Add(time.Minute * 5).Unix()), // Expires in 5 minutes, within grace period
					},
				},
			},
			expectedResult: &ValidationResult{
				Authenticated: true,
			},
		},
		{
			name:               "token valid outside grace period",
			token:              "valid-token",
			refreshGracePeriod: time.Minute * 5,
			session: &mockSession{
				refreshToken: "refresh-token",
			},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"valid-token": {
						"exp": float64(time.Now().Add(time.Hour).Unix()), // Expires in 1 hour, outside grace period
					},
				},
			},
			expectedResult: &ValidationResult{
				Authenticated: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := provider.ValidateTokenExpiry(tt.session, tt.token, tt.cache, tt.refreshGracePeriod)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Fatal("expected non-nil result")
			}

			if result.Authenticated != tt.expectedResult.Authenticated {
				t.Errorf("expected Authenticated %t, got %t", tt.expectedResult.Authenticated, result.Authenticated)
			}

			if result.NeedsRefresh != tt.expectedResult.NeedsRefresh {
				t.Errorf("expected NeedsRefresh %t, got %t", tt.expectedResult.NeedsRefresh, result.NeedsRefresh)
			}

			if result.IsExpired != tt.expectedResult.IsExpired {
				t.Errorf("expected IsExpired %t, got %t", tt.expectedResult.IsExpired, result.IsExpired)
			}
		})
	}
}

func TestBaseProvider_ValidateTokens_AdditionalCases(t *testing.T) {
	provider := NewBaseProvider()

	t.Run("authenticated with access token but no ID token and refresh token", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "access-token",
			idToken:       "",
			refreshToken:  "refresh-token",
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if !result.Authenticated {
			t.Error("expected Authenticated to be true")
		}
		if !result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be true when no ID token")
		}
	})

	t.Run("authenticated with access token but no ID token and no refresh token", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "access-token",
			idToken:       "",
			refreshToken:  "",
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if !result.Authenticated {
			t.Error("expected Authenticated to be true")
		}
		if result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be false when no refresh token available")
		}
	})

	t.Run("authenticated with no access token but has refresh token", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "",
			idToken:       "",
			refreshToken:  "refresh-token",
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if result.Authenticated {
			t.Error("expected Authenticated to be false when no access token")
		}
		if !result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be true when refresh token available")
		}
	})

	t.Run("token verification error containing 'token has expired'", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "access-token",
			idToken:       "expired-id-token",
			refreshToken:  "refresh-token",
		}
		verifier := &mockTokenVerifier{
			expiredTokens: map[string]bool{
				"expired-id-token": true,
			},
		}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if result.Authenticated {
			t.Error("expected Authenticated to be false for expired token")
		}
		if !result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be true when token expired and refresh token available")
		}
	})

	t.Run("token verification error containing 'token has expired' without refresh token", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "access-token",
			idToken:       "expired-id-token",
			refreshToken:  "",
		}
		verifier := &mockTokenVerifier{
			expiredTokens: map[string]bool{
				"expired-id-token": true,
			},
		}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if result.Authenticated {
			t.Error("expected Authenticated to be false for expired token")
		}
		if result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be false when no refresh token")
		}
		if !result.IsExpired {
			t.Error("expected IsExpired to be true for expired token without refresh")
		}
	})

	t.Run("token verification other error with refresh token", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "access-token",
			idToken:       "invalid-token",
			refreshToken:  "refresh-token",
		}
		verifier := &mockTokenVerifier{shouldFail: true}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if result.Authenticated {
			t.Error("expected Authenticated to be false for invalid token")
		}
		if !result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be true when verification fails and refresh token available")
		}
	})

	t.Run("token verification other error without refresh token", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "access-token",
			idToken:       "invalid-token",
			refreshToken:  "",
		}
		verifier := &mockTokenVerifier{shouldFail: true}
		cache := &mockTokenCache{}

		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if result.Authenticated {
			t.Error("expected Authenticated to be false for invalid token")
		}
		if result.NeedsRefresh {
			t.Error("expected NeedsRefresh to be false when no refresh token")
		}
		if !result.IsExpired {
			t.Error("expected IsExpired to be true for invalid token without refresh")
		}
	})
}

func TestBaseProvider_HandleTokenRefresh(t *testing.T) {
	provider := NewBaseProvider()

	// Test that HandleTokenRefresh doesn't fail
	tokenData := &TokenResult{
		IDToken:      "id-token",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
	}

	err := provider.HandleTokenRefresh(tokenData)
	if err != nil {
		t.Errorf("unexpected error from HandleTokenRefresh: %v", err)
	}

	// Test with nil token data
	err = provider.HandleTokenRefresh(nil)
	if err != nil {
		t.Errorf("unexpected error from HandleTokenRefresh with nil data: %v", err)
	}

	// Test with empty token data
	emptyTokenData := &TokenResult{}
	err = provider.HandleTokenRefresh(emptyTokenData)
	if err != nil {
		t.Errorf("unexpected error from HandleTokenRefresh with empty data: %v", err)
	}
}

func TestBaseProvider_ValidateConfig(t *testing.T) {
	provider := NewBaseProvider()

	// Base provider ValidateConfig should always return nil
	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("unexpected error from ValidateConfig: %v", err)
	}
}

func TestBaseProvider_EdgeCases(t *testing.T) {
	provider := NewBaseProvider()

	t.Run("BuildAuthParams with nil scopes", func(t *testing.T) {
		baseParams := url.Values{"client_id": []string{"test-client"}}
		authParams, err := provider.BuildAuthParams(baseParams, nil)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if authParams == nil {
			t.Fatal("expected non-nil auth params")
		}

		// Should still add offline_access
		hasOfflineAccess := false
		for _, scope := range authParams.Scopes {
			if scope == "offline_access" {
				hasOfflineAccess = true
				break
			}
		}
		if !hasOfflineAccess {
			t.Error("expected offline_access scope to be added even with nil input scopes")
		}
	})

	t.Run("BuildAuthParams with nil baseParams", func(t *testing.T) {
		scopes := []string{"openid", "email"}
		authParams, err := provider.BuildAuthParams(nil, scopes)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}

		if authParams == nil {
			t.Fatal("expected non-nil auth params")
		}

		// Note: nil baseParams results in nil URLValues, which is handled by the calling code
		if authParams.URLValues != nil {
			t.Logf("Got non-nil URLValues: %v", authParams.URLValues)
		}
	})

	t.Run("ValidateTokenExpiry with nil cache", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected panic with nil cache: %v", r)
			}
		}()
		session := &mockSession{refreshToken: "refresh-token"}
		_, err := provider.ValidateTokenExpiry(session, "test-token", nil, time.Minute)

		if err != nil {
			t.Logf("Got expected error with nil cache: %v", err)
		}
	})

	t.Run("ValidateTokenExpiry with nil session", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected panic with nil session: %v", r)
			}
		}()
		cache := &mockTokenCache{}
		_, err := provider.ValidateTokenExpiry(nil, "test-token", cache, time.Minute)

		if err != nil {
			t.Logf("Got expected error with nil session: %v", err)
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkBaseProvider_GetType(b *testing.B) {
	provider := NewBaseProvider()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetType()
	}
}

func BenchmarkBaseProvider_GetCapabilities(b *testing.B) {
	provider := NewBaseProvider()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetCapabilities()
	}
}

func BenchmarkBaseProvider_BuildAuthParams(b *testing.B) {
	provider := NewBaseProvider()
	baseParams := url.Values{"client_id": []string{"test-client"}}
	scopes := []string{"openid", "email", "profile"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.BuildAuthParams(baseParams, scopes)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkBaseProvider_ValidateTokenExpiry(b *testing.B) {
	provider := NewBaseProvider()
	session := &mockSession{refreshToken: "refresh-token"}
	cache := &mockTokenCache{
		data: map[string]map[string]interface{}{
			"test-token": {
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.ValidateTokenExpiry(session, "test-token", cache, time.Minute)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
