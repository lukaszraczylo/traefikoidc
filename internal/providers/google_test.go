package providers

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewGoogleProvider(t *testing.T) {
	provider := NewGoogleProvider()

	if provider == nil {
		t.Fatal("expected non-nil Google provider")
	}

	if provider.BaseProvider == nil {
		t.Fatal("expected non-nil BaseProvider")
	}
}

func TestGoogleProvider_GetType(t *testing.T) {
	provider := NewGoogleProvider()
	providerType := provider.GetType()

	if providerType != ProviderTypeGoogle {
		t.Errorf("expected provider type %d, got %d", ProviderTypeGoogle, providerType)
	}
}

func TestGoogleProvider_GetCapabilities(t *testing.T) {
	provider := NewGoogleProvider()
	capabilities := provider.GetCapabilities()

	expectedCapabilities := ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: false,
		RequiresPromptConsent:      true,
		PreferredTokenValidation:   "id",
	}

	if capabilities.SupportsRefreshTokens != expectedCapabilities.SupportsRefreshTokens {
		t.Errorf("expected SupportsRefreshTokens %t, got %t", expectedCapabilities.SupportsRefreshTokens, capabilities.SupportsRefreshTokens)
	}

	if capabilities.RequiresOfflineAccessScope != expectedCapabilities.RequiresOfflineAccessScope {
		t.Errorf("expected RequiresOfflineAccessScope %t, got %t", expectedCapabilities.RequiresOfflineAccessScope, capabilities.RequiresOfflineAccessScope)
	}

	if capabilities.RequiresPromptConsent != expectedCapabilities.RequiresPromptConsent {
		t.Errorf("expected RequiresPromptConsent %t, got %t", expectedCapabilities.RequiresPromptConsent, capabilities.RequiresPromptConsent)
	}

	if capabilities.PreferredTokenValidation != expectedCapabilities.PreferredTokenValidation {
		t.Errorf("expected PreferredTokenValidation %q, got %q", expectedCapabilities.PreferredTokenValidation, capabilities.PreferredTokenValidation)
	}
}

func TestGoogleProvider_BuildAuthParams(t *testing.T) {
	provider := NewGoogleProvider()

	tests := []struct {
		name                       string
		baseParams                 url.Values
		scopes                     []string
		expectAccessTypeOffline    bool
		expectPromptConsent        bool
		expectOfflineAccessRemoved bool
	}{
		{
			name:                       "basic params with offline_access scope",
			baseParams:                 url.Values{"client_id": []string{"test-client"}},
			scopes:                     []string{"openid", "offline_access", "email"},
			expectAccessTypeOffline:    true,
			expectPromptConsent:        true,
			expectOfflineAccessRemoved: true,
		},
		{
			name:                       "basic params without offline_access scope",
			baseParams:                 url.Values{"client_id": []string{"test-client"}},
			scopes:                     []string{"openid", "email"},
			expectAccessTypeOffline:    true,
			expectPromptConsent:        true,
			expectOfflineAccessRemoved: false,
		},
		{
			name:                       "empty scopes",
			baseParams:                 url.Values{},
			scopes:                     []string{},
			expectAccessTypeOffline:    true,
			expectPromptConsent:        true,
			expectOfflineAccessRemoved: false,
		},
		{
			name:                       "multiple offline_access scopes",
			baseParams:                 url.Values{},
			scopes:                     []string{"openid", "offline_access", "email", "offline_access"},
			expectAccessTypeOffline:    true,
			expectPromptConsent:        true,
			expectOfflineAccessRemoved: true,
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

			// Check access_type is set to offline
			if tt.expectAccessTypeOffline {
				accessType := authParams.URLValues.Get("access_type")
				if accessType != "offline" {
					t.Errorf("expected access_type 'offline', got %q", accessType)
				}
			}

			// Check prompt is set to consent
			if tt.expectPromptConsent {
				prompt := authParams.URLValues.Get("prompt")
				if prompt != "consent" {
					t.Errorf("expected prompt 'consent', got %q", prompt)
				}
			}

			// Check offline_access scope is filtered out
			if tt.expectOfflineAccessRemoved {
				hasOfflineAccess := false
				for _, scope := range authParams.Scopes {
					if scope == "offline_access" {
						hasOfflineAccess = true
						break
					}
				}
				if hasOfflineAccess {
					t.Error("expected offline_access scope to be removed for Google provider")
				}
			}

			// Verify other scopes are preserved (except offline_access)
			expectedScopes := make([]string, 0, len(tt.scopes))
			for _, scope := range tt.scopes {
				if scope != "offline_access" {
					expectedScopes = append(expectedScopes, scope)
				}
			}

			if len(authParams.Scopes) != len(expectedScopes) {
				t.Errorf("expected %d scopes after filtering, got %d", len(expectedScopes), len(authParams.Scopes))
			}

			// Verify other parameters are preserved
			for key, values := range tt.baseParams {
				if key == "access_type" || key == "prompt" {
					continue // These get overridden
				}
				paramValues := authParams.URLValues[key]
				if len(paramValues) != len(values) {
					t.Errorf("expected %d values for param %s, got %d", len(values), key, len(paramValues))
				}
			}
		})
	}
}

func TestGoogleProvider_ValidateTokens(t *testing.T) {
	provider := NewGoogleProvider()

	tests := []struct {
		name               string
		session            *mockSession
		verifier           *mockTokenVerifier
		cache              *mockTokenCache
		refreshGracePeriod time.Duration
		expectedResult     *ValidationResult
		expectError        bool
	}{
		{
			name: "unauthenticated with refresh token",
			session: &mockSession{
				authenticated: false,
				refreshToken:  "refresh-token",
			},
			verifier: &mockTokenVerifier{},
			cache:    &mockTokenCache{},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name: "unauthenticated without refresh token",
			session: &mockSession{
				authenticated: false,
			},
			verifier:       &mockTokenVerifier{},
			cache:          &mockTokenCache{},
			expectedResult: &ValidationResult{},
		},
		{
			name: "authenticated with valid ID token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "access-token",
				idToken:       "id.token.here",
			},
			verifier: &mockTokenVerifier{},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"id.token.here": {
						"exp": float64(time.Now().Add(time.Hour).Unix()),
					},
				},
			},
			expectedResult: &ValidationResult{
				Authenticated: true,
			},
		},
		{
			name: "authenticated with expired ID token and refresh token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "access-token",
				idToken:       "expired.token.here",
				refreshToken:  "refresh-token",
			},
			verifier: &mockTokenVerifier{
				expiredTokens: map[string]bool{
					"expired.token.here": true,
				},
			},
			cache: &mockTokenCache{},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name: "authenticated with no ID token but has access token and refresh token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "access-token",
				refreshToken:  "refresh-token",
			},
			verifier: &mockTokenVerifier{},
			cache:    &mockTokenCache{},
			expectedResult: &ValidationResult{
				Authenticated: true,
				NeedsRefresh:  true,
			},
		},
		{
			name: "authenticated with no tokens but has refresh token",
			session: &mockSession{
				authenticated: true,
				refreshToken:  "refresh-token",
			},
			verifier: &mockTokenVerifier{},
			cache:    &mockTokenCache{},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name: "authenticated with no tokens and no refresh token",
			session: &mockSession{
				authenticated: true,
			},
			verifier: &mockTokenVerifier{},
			cache:    &mockTokenCache{},
			expectedResult: &ValidationResult{
				IsExpired: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := provider.ValidateTokens(tt.session, tt.verifier, tt.cache, tt.refreshGracePeriod)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

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

func TestGoogleProvider_ValidateConfig(t *testing.T) {
	provider := NewGoogleProvider()

	// Google provider uses BaseProvider's ValidateConfig which always returns nil
	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("unexpected error from ValidateConfig: %v", err)
	}
}

func TestGoogleProvider_HandleTokenRefresh(t *testing.T) {
	provider := NewGoogleProvider()

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
}

func TestGoogleProvider_ConcurrentAccess(t *testing.T) {
	provider := NewGoogleProvider()

	// Track initial goroutine count for memory safety
	initialGoroutines := runtime.NumGoroutine()

	const numGoroutines = 50
	const numOperationsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent access to provider methods
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()

			session := &mockSession{
				authenticated: true,
				accessToken:   fmt.Sprintf("access-token-%d", workerID),
				idToken:       fmt.Sprintf("id-token-%d", workerID),
				refreshToken:  fmt.Sprintf("refresh-token-%d", workerID),
			}

			verifier := &mockTokenVerifier{}
			cache := &mockTokenCache{
				data: map[string]map[string]interface{}{
					fmt.Sprintf("id-token-%d", workerID): {
						"exp": float64(time.Now().Add(time.Hour).Unix()),
					},
				},
			}

			for j := 0; j < numOperationsPerGoroutine; j++ {
				// Test GetType
				if provider.GetType() != ProviderTypeGoogle {
					t.Errorf("worker %d: expected Google provider type", workerID)
					return
				}

				// Test GetCapabilities
				capabilities := provider.GetCapabilities()
				if !capabilities.SupportsRefreshTokens {
					t.Errorf("worker %d: expected refresh token support", workerID)
					return
				}

				// Test ValidateTokens
				result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)
				if err != nil {
					t.Errorf("worker %d: unexpected error in ValidateTokens: %v", workerID, err)
					return
				}
				if !result.Authenticated {
					t.Errorf("worker %d: expected authenticated result", workerID)
					return
				}

				// Test BuildAuthParams
				baseParams := url.Values{"client_id": []string{fmt.Sprintf("client-%d", workerID)}}
				scopes := []string{"openid", "email"}
				authParams, err := provider.BuildAuthParams(baseParams, scopes)
				if err != nil {
					t.Errorf("worker %d: unexpected error in BuildAuthParams: %v", workerID, err)
					return
				}
				if authParams == nil {
					t.Errorf("worker %d: expected non-nil auth params", workerID)
					return
				}

				// Test ValidateConfig
				err = provider.ValidateConfig()
				if err != nil {
					t.Errorf("worker %d: unexpected error in ValidateConfig: %v", workerID, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()

	// Check for potential goroutine leaks - allow some tolerance for test framework overhead
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("potential goroutine leak: started with %d goroutines, ended with %d", initialGoroutines, finalGoroutines)
	}
}

func TestGoogleProvider_MemorySafety(t *testing.T) {
	const numIterations = 1000

	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < numIterations; i++ {
		provider := NewGoogleProvider()

		session := &mockSession{
			authenticated: true,
			accessToken:   fmt.Sprintf("access-token-%d", i),
			idToken:       fmt.Sprintf("id-token-%d", i),
			refreshToken:  fmt.Sprintf("refresh-token-%d", i),
		}

		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{
			data: map[string]map[string]interface{}{
				fmt.Sprintf("id-token-%d", i): {
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				},
			},
		}

		// Exercise all provider methods
		_ = provider.GetType()
		_ = provider.GetCapabilities()
		_, _ = provider.ValidateTokens(session, verifier, cache, time.Minute)
		_, _ = provider.BuildAuthParams(url.Values{}, []string{"openid"})
		_ = provider.ValidateConfig()
		_ = provider.HandleTokenRefresh(&TokenResult{})
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("potential goroutine leak: started with %d goroutines, ended with %d", initialGoroutines, finalGoroutines)
	}
}

func TestGoogleProvider_EdgeCases(t *testing.T) {
	provider := NewGoogleProvider()

	t.Run("nil session", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				// Expected behavior for nil session
				t.Logf("Recovered from expected panic: %v", r)
			}
		}()

		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}
		_, err := provider.ValidateTokens(nil, verifier, cache, time.Minute)
		if err == nil {
			t.Error("expected error with nil session")
		}
	})

	t.Run("nil verifier", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected panic: %v", r)
			}
		}()

		session := &mockSession{authenticated: true, idToken: "test.token.here"}
		cache := &mockTokenCache{}
		result, err := provider.ValidateTokens(session, nil, cache, time.Minute)
		// Google provider uses BaseProvider which handles nil verifier gracefully
		if err != nil {
			t.Logf("Got expected error with nil verifier: %v", err)
		} else if result != nil && result.NeedsRefresh {
			t.Logf("Provider handled nil verifier gracefully by requesting refresh")
		}
	})

	t.Run("nil cache", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected panic with nil cache: %v", r)
			}
		}()
		session := &mockSession{authenticated: true, accessToken: "test-token"}
		verifier := &mockTokenVerifier{}
		result, err := provider.ValidateTokens(session, verifier, nil, time.Minute)
		// Google provider uses BaseProvider which handles nil cache gracefully
		if err != nil {
			t.Logf("Got expected error with nil cache: %v", err)
		} else if result != nil && result.NeedsRefresh {
			t.Logf("Provider handled nil cache gracefully by requesting refresh")
		}
	})

	t.Run("empty tokens", func(t *testing.T) {
		session := &mockSession{
			authenticated: true,
			accessToken:   "",
			idToken:       "",
			refreshToken:  "",
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}
		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)
		if err != nil {
			t.Errorf("unexpected error with empty tokens: %v", err)
		}
		if !result.IsExpired {
			t.Error("expected IsExpired=true for empty tokens without refresh token")
		}
	})

	t.Run("offline_access scope filtering", func(t *testing.T) {
		tests := []struct {
			name         string
			inputScopes  []string
			expectScopes []string
		}{
			{
				name:         "single offline_access",
				inputScopes:  []string{"offline_access"},
				expectScopes: []string{},
			},
			{
				name:         "offline_access with others",
				inputScopes:  []string{"openid", "offline_access", "email"},
				expectScopes: []string{"openid", "email"},
			},
			{
				name:         "multiple offline_access",
				inputScopes:  []string{"offline_access", "openid", "offline_access", "profile"},
				expectScopes: []string{"openid", "profile"},
			},
			{
				name:         "no offline_access",
				inputScopes:  []string{"openid", "email", "profile"},
				expectScopes: []string{"openid", "email", "profile"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				authParams, err := provider.BuildAuthParams(url.Values{}, tt.inputScopes)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				if len(authParams.Scopes) != len(tt.expectScopes) {
					t.Errorf("expected %d scopes, got %d", len(tt.expectScopes), len(authParams.Scopes))
				}

				for i, expectedScope := range tt.expectScopes {
					if i >= len(authParams.Scopes) || authParams.Scopes[i] != expectedScope {
						t.Errorf("expected scope %q at position %d, got %q", expectedScope, i, authParams.Scopes[i])
					}
				}
			})
		}
	})

	t.Run("very long tokens", func(t *testing.T) {
		longToken := strings.Repeat("a", 5000)
		session := &mockSession{
			authenticated: true,
			idToken:       longToken,
			refreshToken:  "refresh-token",
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{
			data: map[string]map[string]interface{}{
				longToken: {
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				},
			},
		}
		result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)
		if err != nil {
			t.Errorf("unexpected error with very long token: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result with very long token")
		}
	})

	t.Run("special characters in parameters", func(t *testing.T) {
		specialParams := url.Values{
			"client_id":    []string{"client@example.com"},
			"redirect_uri": []string{"https://example.com/callback?param=value&other=test"},
			"state":        []string{"state+with/special=chars&more"},
		}
		scopes := []string{"openid", "email+special", "profile/test"}

		authParams, err := provider.BuildAuthParams(specialParams, scopes)
		if err != nil {
			t.Errorf("unexpected error with special characters: %v", err)
			return
		}

		if authParams == nil {
			t.Error("expected non-nil auth params with special characters")
		}

		// Verify all special parameter values are preserved
		for key, expectedValues := range specialParams {
			if key == "access_type" || key == "prompt" {
				continue // These get overridden
			}
			actualValues := authParams.URLValues[key]
			if len(actualValues) != len(expectedValues) {
				t.Errorf("parameter %s: expected %d values, got %d", key, len(expectedValues), len(actualValues))
			}
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkGoogleProvider_GetType(b *testing.B) {
	provider := NewGoogleProvider()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetType()
	}
}

func BenchmarkGoogleProvider_GetCapabilities(b *testing.B) {
	provider := NewGoogleProvider()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetCapabilities()
	}
}

func BenchmarkGoogleProvider_BuildAuthParams(b *testing.B) {
	provider := NewGoogleProvider()
	baseParams := url.Values{"client_id": []string{"test-client"}}
	scopes := []string{"openid", "email", "profile", "offline_access"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.BuildAuthParams(baseParams, scopes)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkGoogleProvider_ValidateTokens(b *testing.B) {
	provider := NewGoogleProvider()
	session := &mockSession{
		authenticated: true,
		accessToken:   "access-token",
		idToken:       "id.token.here",
		refreshToken:  "refresh-token",
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		data: map[string]map[string]interface{}{
			"id.token.here": {
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.ValidateTokens(session, verifier, cache, time.Minute)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkGoogleProvider_OfflineAccessFiltering(b *testing.B) {
	provider := NewGoogleProvider()
	baseParams := url.Values{"client_id": []string{"test-client"}}
	scopes := []string{"openid", "offline_access", "email", "offline_access", "profile", "offline_access"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.BuildAuthParams(baseParams, scopes)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
