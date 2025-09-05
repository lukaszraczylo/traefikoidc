package providers

import (
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockSession implements the Session interface for testing
type mockSession struct {
	idToken       string
	accessToken   string
	refreshToken  string
	authenticated bool
}

func (m *mockSession) GetIDToken() string {
	return m.idToken
}

func (m *mockSession) GetAccessToken() string {
	return m.accessToken
}

func (m *mockSession) GetRefreshToken() string {
	return m.refreshToken
}

func (m *mockSession) GetAuthenticated() bool {
	return m.authenticated
}

// mockTokenVerifier implements TokenVerifier for testing
type mockTokenVerifier struct {
	shouldFail    bool
	expiredTokens map[string]bool
}

func (m *mockTokenVerifier) VerifyToken(token string) error {
	if m.shouldFail {
		return errors.New("token verification failed")
	}
	if m.expiredTokens != nil && m.expiredTokens[token] {
		return errors.New("token has expired")
	}
	return nil
}

// mockTokenCache implements TokenCache for testing
type mockTokenCache struct {
	data map[string]map[string]interface{}
}

func (m *mockTokenCache) Get(key string) (map[string]interface{}, bool) {
	if m.data == nil {
		return nil, false
	}
	claims, exists := m.data[key]
	return claims, exists
}

func TestNewAzureProvider(t *testing.T) {
	provider := NewAzureProvider()

	if provider == nil {
		t.Fatal("expected non-nil Azure provider")
	}

	if provider.BaseProvider == nil {
		t.Fatal("expected non-nil BaseProvider")
	}
}

func TestAzureProvider_GetType(t *testing.T) {
	provider := NewAzureProvider()
	providerType := provider.GetType()

	if providerType != ProviderTypeAzure {
		t.Errorf("expected provider type %d, got %d", ProviderTypeAzure, providerType)
	}
}

func TestAzureProvider_GetCapabilities(t *testing.T) {
	provider := NewAzureProvider()
	capabilities := provider.GetCapabilities()

	expectedCapabilities := ProviderCapabilities{
		SupportsRefreshTokens:      true,
		RequiresOfflineAccessScope: true,
		PreferredTokenValidation:   "access",
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

func TestAzureProvider_BuildAuthParams(t *testing.T) {
	provider := NewAzureProvider()

	tests := []struct {
		name                string
		baseParams          url.Values
		scopes              []string
		expectOfflineAccess bool
		expectResponseMode  bool
	}{
		{
			name:                "basic params with offline_access scope",
			baseParams:          url.Values{"client_id": []string{"test-client"}},
			scopes:              []string{"openid", "offline_access", "email"},
			expectOfflineAccess: true,
			expectResponseMode:  true,
		},
		{
			name:                "basic params without offline_access scope",
			baseParams:          url.Values{"client_id": []string{"test-client"}},
			scopes:              []string{"openid", "email"},
			expectOfflineAccess: true, // Should be added automatically
			expectResponseMode:  true,
		},
		{
			name:                "empty scopes",
			baseParams:          url.Values{},
			scopes:              []string{},
			expectOfflineAccess: true, // Should be added automatically
			expectResponseMode:  true,
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

			// Check response_mode is set
			if tt.expectResponseMode {
				responseMode := authParams.URLValues.Get("response_mode")
				if responseMode != "query" {
					t.Errorf("expected response_mode 'query', got %q", responseMode)
				}
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
				if key == "response_mode" {
					continue // This gets overridden
				}
				paramValues := authParams.URLValues[key]
				if len(paramValues) != len(values) {
					t.Errorf("expected %d values for param %s, got %d", len(values), key, len(paramValues))
				}
			}
		})
	}
}

func TestAzureProvider_ValidateTokens(t *testing.T) {
	provider := NewAzureProvider()

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
			verifier: &mockTokenVerifier{},
			cache:    &mockTokenCache{},
			expectedResult: &ValidationResult{
				IsExpired: true,
			},
		},
		{
			name: "authenticated with valid JWT access token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "header.payload.signature",
			},
			verifier: &mockTokenVerifier{},
			cache: &mockTokenCache{
				data: map[string]map[string]interface{}{
					"header.payload.signature": {
						"exp": float64(time.Now().Add(time.Hour).Unix()),
					},
				},
			},
			expectedResult: &ValidationResult{
				Authenticated: true,
			},
		},
		{
			name: "authenticated with invalid access token but valid ID token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "header.payload.signature",
				idToken:       "id.token.here",
			},
			verifier: &mockTokenVerifier{shouldFail: true},
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
			name: "authenticated with opaque access token",
			session: &mockSession{
				authenticated: true,
				accessToken:   "opaque-token-no-dots",
			},
			verifier: &mockTokenVerifier{},
			cache:    &mockTokenCache{},
			expectedResult: &ValidationResult{
				Authenticated: true,
			},
		},
		{
			name: "authenticated with ID token only",
			session: &mockSession{
				authenticated: true,
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
			name: "expired ID token with refresh token",
			session: &mockSession{
				authenticated: true,
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
			name: "authenticated but no tokens",
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

func TestAzureProvider_ValidateConfig(t *testing.T) {
	provider := NewAzureProvider()

	// Azure provider uses BaseProvider's ValidateConfig which always returns nil
	err := provider.ValidateConfig()
	if err != nil {
		t.Errorf("unexpected error from ValidateConfig: %v", err)
	}
}

func TestAzureProvider_HandleTokenRefresh(t *testing.T) {
	provider := NewAzureProvider()

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

func TestAzureProvider_ConcurrentAccess(t *testing.T) {
	provider := NewAzureProvider()

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
					fmt.Sprintf("access-token-%d", workerID): {
						"exp": float64(time.Now().Add(time.Hour).Unix()),
					},
					fmt.Sprintf("id-token-%d", workerID): {
						"exp": float64(time.Now().Add(time.Hour).Unix()),
					},
				},
			}

			for j := 0; j < numOperationsPerGoroutine; j++ {
				// Test GetType
				if provider.GetType() != ProviderTypeAzure {
					t.Errorf("worker %d: expected Azure provider type", workerID)
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

func TestAzureProvider_MemorySafety(t *testing.T) {
	const numIterations = 1000

	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < numIterations; i++ {
		provider := NewAzureProvider()

		session := &mockSession{
			authenticated: true,
			accessToken:   fmt.Sprintf("access-token-%d.payload.signature", i),
			idToken:       fmt.Sprintf("id-token-%d.payload.signature", i),
			refreshToken:  fmt.Sprintf("refresh-token-%d", i),
		}

		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{
			data: map[string]map[string]interface{}{
				fmt.Sprintf("access-token-%d.payload.signature", i): {
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

func TestAzureProvider_EdgeCases(t *testing.T) {
	provider := NewAzureProvider()

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
		_, err := provider.ValidateTokens(session, nil, cache, time.Minute)
		if err == nil {
			t.Error("expected error with nil verifier")
		}
	})

	t.Run("nil cache", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected panic with nil cache: %v", r)
			}
		}()
		session := &mockSession{authenticated: true, accessToken: "test.token.here"}
		verifier := &mockTokenVerifier{}
		_, err := provider.ValidateTokens(session, verifier, nil, time.Minute)
		if err == nil {
			t.Error("expected error with nil cache")
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

	t.Run("malformed JWT tokens", func(t *testing.T) {
		malformedTokens := []string{
			"not.enough.parts",
			"too.many.parts.in.this.token",
			"",
			"single-part-token",
		}

		for _, token := range malformedTokens {
			session := &mockSession{
				authenticated: true,
				accessToken:   token,
				refreshToken:  "refresh-token",
			}
			verifier := &mockTokenVerifier{}
			cache := &mockTokenCache{}
			result, err := provider.ValidateTokens(session, verifier, cache, time.Minute)
			if err != nil {
				t.Errorf("unexpected error with malformed token %q: %v", token, err)
			}
			if result == nil {
				t.Errorf("expected non-nil result for malformed token %q", token)
			}
		}
	})

	t.Run("very long tokens", func(t *testing.T) {
		longToken := strings.Repeat("a", 10000) + "." + strings.Repeat("b", 10000) + "." + strings.Repeat("c", 10000)
		session := &mockSession{
			authenticated: true,
			accessToken:   longToken,
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
}

// Benchmark tests for performance validation
func BenchmarkAzureProvider_GetType(b *testing.B) {
	provider := NewAzureProvider()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetType()
	}
}

func BenchmarkAzureProvider_GetCapabilities(b *testing.B) {
	provider := NewAzureProvider()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider.GetCapabilities()
	}
}

func BenchmarkAzureProvider_BuildAuthParams(b *testing.B) {
	provider := NewAzureProvider()
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

func BenchmarkAzureProvider_ValidateTokens(b *testing.B) {
	provider := NewAzureProvider()
	session := &mockSession{
		authenticated: true,
		accessToken:   "header.payload.signature",
		idToken:       "id.token.here",
		refreshToken:  "refresh-token",
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		data: map[string]map[string]interface{}{
			"header.payload.signature": {
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
