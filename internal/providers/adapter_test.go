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

// mockLegacySettings implements LegacySettings for testing
type mockLegacySettings struct {
	issuerURL          string
	authURL            string
	scopes             []string
	pkceEnabled        bool
	clientID           string
	refreshGracePeriod time.Duration
	overrideScopes     bool
}

func (m *mockLegacySettings) GetIssuerURL() string {
	return m.issuerURL
}

func (m *mockLegacySettings) GetAuthURL() string {
	return m.authURL
}

func (m *mockLegacySettings) GetScopes() []string {
	return m.scopes
}

func (m *mockLegacySettings) IsPKCEEnabled() bool {
	return m.pkceEnabled
}

func (m *mockLegacySettings) GetClientID() string {
	return m.clientID
}

func (m *mockLegacySettings) GetRefreshGracePeriod() time.Duration {
	return m.refreshGracePeriod
}

func (m *mockLegacySettings) IsOverrideScopes() bool {
	return m.overrideScopes
}

func TestNewAdapter(t *testing.T) {
	provider := NewGoogleProvider()
	settings := &mockLegacySettings{
		clientID:    "test-client",
		issuerURL:   "https://accounts.google.com",
		authURL:     "https://accounts.google.com/o/oauth2/auth",
		scopes:      []string{"openid", "email"},
		pkceEnabled: true,
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}

	adapter := NewAdapter(provider, settings, verifier, cache)

	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}

	if adapter.provider != provider {
		t.Error("expected provider to be set correctly")
	}

	if adapter.legacySettings != settings {
		t.Error("expected legacy settings to be set correctly")
	}

	if adapter.tokenVerifier != verifier {
		t.Error("expected token verifier to be set correctly")
	}

	if adapter.tokenCache != cache {
		t.Error("expected token cache to be set correctly")
	}
}

func TestAdapter_GetType(t *testing.T) {
	tests := []struct {
		name         string
		provider     OIDCProvider
		expectedType ProviderType
	}{
		{
			name:         "Google provider",
			provider:     NewGoogleProvider(),
			expectedType: ProviderTypeGoogle,
		},
		{
			name:         "Azure provider",
			provider:     NewAzureProvider(),
			expectedType: ProviderTypeAzure,
		},
		{
			name:         "Generic provider",
			provider:     NewGenericProvider(),
			expectedType: ProviderTypeGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &mockLegacySettings{clientID: "test-client"}
			verifier := &mockTokenVerifier{}
			cache := &mockTokenCache{}

			adapter := NewAdapter(tt.provider, settings, verifier, cache)
			providerType := adapter.GetType()

			if providerType != tt.expectedType {
				t.Errorf("expected provider type %d, got %d", tt.expectedType, providerType)
			}
		})
	}
}

func TestAdapter_ValidateTokens(t *testing.T) {
	provider := NewGoogleProvider()
	settings := &mockLegacySettings{
		refreshGracePeriod: time.Minute * 5,
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		data: map[string]map[string]interface{}{
			"valid-token": {
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
		},
	}

	adapter := NewAdapter(provider, settings, verifier, cache)

	tests := []struct {
		name           string
		session        *mockSession
		expectedResult *ValidationResult
		expectError    bool
	}{
		{
			name: "valid authenticated session",
			session: &mockSession{
				authenticated: true,
				idToken:       "valid-token",
				accessToken:   "access-token",
				refreshToken:  "refresh-token",
			},
			expectedResult: &ValidationResult{
				Authenticated: true,
			},
		},
		{
			name: "unauthenticated with refresh token",
			session: &mockSession{
				authenticated: false,
				refreshToken:  "refresh-token",
			},
			expectedResult: &ValidationResult{
				NeedsRefresh: true,
			},
		},
		{
			name: "unauthenticated without refresh token",
			session: &mockSession{
				authenticated: false,
			},
			expectedResult: &ValidationResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := adapter.ValidateTokens(tt.session)

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

func TestAdapter_BuildAuthURL(t *testing.T) {
	tests := []struct {
		name              string
		provider          OIDCProvider
		settings          *mockLegacySettings
		redirectURL       string
		state             string
		nonce             string
		codeChallenge     string
		expectedSubstrs   []string
		unexpectedSubstrs []string
	}{
		{
			name:     "Google provider without override scopes",
			provider: NewGoogleProvider(),
			settings: &mockLegacySettings{
				clientID:       "google-client-id",
				issuerURL:      "https://accounts.google.com",
				authURL:        "https://accounts.google.com/o/oauth2/auth",
				scopes:         []string{"openid", "email", "profile"},
				pkceEnabled:    true,
				overrideScopes: false,
			},
			redirectURL:   "https://example.com/callback",
			state:         "random-state",
			nonce:         "random-nonce",
			codeChallenge: "code-challenge",
			expectedSubstrs: []string{
				"client_id=google-client-id",
				"response_type=code",
				"redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
				"state=random-state",
				"nonce=random-nonce",
				"code_challenge=code-challenge",
				"code_challenge_method=S256",
				"access_type=offline",
				"prompt=consent",
				"scope=openid+email+profile",
			},
		},
		{
			name:     "Azure provider with override scopes",
			provider: NewAzureProvider(),
			settings: &mockLegacySettings{
				clientID:       "azure-client-id",
				issuerURL:      "https://login.microsoftonline.com/tenant",
				authURL:        "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
				scopes:         []string{"openid", "offline_access"},
				pkceEnabled:    false,
				overrideScopes: true,
			},
			redirectURL:   "https://example.com/azure-callback",
			state:         "azure-state",
			nonce:         "azure-nonce",
			codeChallenge: "",
			expectedSubstrs: []string{
				"client_id=azure-client-id",
				"response_type=code",
				"redirect_uri=https%3A%2F%2Fexample.com%2Fazure-callback",
				"state=azure-state",
				"nonce=azure-nonce",
				"response_mode=query",
				"scope=openid+offline_access",
			},
			unexpectedSubstrs: []string{
				"code_challenge",
				"access_type",
				"prompt",
			},
		},
		{
			name:     "Generic provider with relative auth URL",
			provider: NewGenericProvider(),
			settings: &mockLegacySettings{
				clientID:       "generic-client-id",
				issuerURL:      "https://keycloak.example.com/auth/realms/master",
				authURL:        "/auth/realms/master/protocol/openid-connect/auth",
				scopes:         []string{"openid", "email"},
				pkceEnabled:    false,
				overrideScopes: false,
			},
			redirectURL:   "https://example.com/generic-callback",
			state:         "generic-state",
			nonce:         "generic-nonce",
			codeChallenge: "",
			expectedSubstrs: []string{
				"keycloak.example.com",
				"client_id=generic-client-id",
				"response_type=code",
				"scope=openid+email+offline_access", // Generic provider adds offline_access
			},
		},
		{
			name:     "PKCE disabled",
			provider: NewGoogleProvider(),
			settings: &mockLegacySettings{
				clientID:       "google-client-id-no-pkce",
				issuerURL:      "https://accounts.google.com",
				authURL:        "https://accounts.google.com/o/oauth2/auth",
				scopes:         []string{"openid", "email"},
				pkceEnabled:    false,
				overrideScopes: false,
			},
			redirectURL:   "https://example.com/callback",
			state:         "state-no-pkce",
			nonce:         "nonce-no-pkce",
			codeChallenge: "should-be-ignored",
			expectedSubstrs: []string{
				"client_id=google-client-id-no-pkce",
				"state=state-no-pkce",
				"nonce=nonce-no-pkce",
			},
			unexpectedSubstrs: []string{
				"code_challenge",
				"code_challenge_method",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &mockTokenVerifier{}
			cache := &mockTokenCache{}
			adapter := NewAdapter(tt.provider, tt.settings, verifier, cache)

			authURL := adapter.BuildAuthURL(tt.redirectURL, tt.state, tt.nonce, tt.codeChallenge)

			if authURL == "" {
				t.Fatal("expected non-empty auth URL")
			}

			for _, expectedSubstr := range tt.expectedSubstrs {
				if !strings.Contains(authURL, expectedSubstr) {
					t.Errorf("expected auth URL to contain %q, got %q", expectedSubstr, authURL)
				}
			}

			for _, unexpectedSubstr := range tt.unexpectedSubstrs {
				if strings.Contains(authURL, unexpectedSubstr) {
					t.Errorf("expected auth URL to NOT contain %q, got %q", unexpectedSubstr, authURL)
				}
			}
		})
	}
}

func TestAdapter_BuildAuthURL_ErrorCases(t *testing.T) {
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}

	t.Run("invalid issuer URL", func(t *testing.T) {
		provider := NewGenericProvider()
		settings := &mockLegacySettings{
			clientID:       "test-client",
			issuerURL:      "://invalid-url",
			authURL:        "/relative/path",
			scopes:         []string{"openid"},
			overrideScopes: false,
		}

		adapter := NewAdapter(provider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL("https://example.com/callback", "state", "nonce", "")

		if authURL != "" {
			t.Errorf("expected empty auth URL for invalid issuer URL, got %q", authURL)
		}
	})

	t.Run("invalid auth URL", func(t *testing.T) {
		provider := NewGenericProvider()
		settings := &mockLegacySettings{
			clientID:       "test-client",
			issuerURL:      "https://example.com",
			authURL:        "://invalid-auth-url",
			scopes:         []string{"openid"},
			overrideScopes: false,
		}

		adapter := NewAdapter(provider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL("https://example.com/callback", "state", "nonce", "")

		if authURL != "" {
			t.Errorf("expected empty auth URL for invalid auth URL, got %q", authURL)
		}
	})

	t.Run("invalid absolute auth URL", func(t *testing.T) {
		provider := NewGenericProvider()
		settings := &mockLegacySettings{
			clientID:       "test-client",
			issuerURL:      "https://example.com",
			authURL:        "://invalid-absolute-url",
			scopes:         []string{"openid"},
			overrideScopes: false,
		}

		adapter := NewAdapter(provider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL("https://example.com/callback", "state", "nonce", "")

		if authURL != "" {
			t.Errorf("expected empty auth URL for invalid absolute auth URL, got %q", authURL)
		}
	})

	t.Run("provider BuildAuthParams error", func(t *testing.T) {
		// Create a mock provider that returns an error
		mockProvider := &mockProviderWithError{}
		settings := &mockLegacySettings{
			clientID:       "test-client",
			issuerURL:      "https://example.com",
			authURL:        "https://example.com/auth",
			scopes:         []string{"openid"},
			overrideScopes: false,
		}

		adapter := NewAdapter(mockProvider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL("https://example.com/callback", "state", "nonce", "")

		if authURL != "" {
			t.Errorf("expected empty auth URL when provider returns error, got %q", authURL)
		}
	})
}

// mockProviderWithError is a test helper that returns errors from BuildAuthParams
type mockProviderWithError struct {
	*BaseProvider
}

func (m *mockProviderWithError) GetType() ProviderType {
	return ProviderTypeGeneric
}

func (m *mockProviderWithError) BuildAuthParams(baseParams url.Values, scopes []string) (*AuthParams, error) {
	return nil, fmt.Errorf("mock error from BuildAuthParams")
}

func TestAdapter_ConcurrentAccess(t *testing.T) {
	provider := NewGoogleProvider()
	settings := &mockLegacySettings{
		clientID:           "test-client",
		issuerURL:          "https://accounts.google.com",
		authURL:            "https://accounts.google.com/o/oauth2/auth",
		scopes:             []string{"openid", "email"},
		pkceEnabled:        true,
		refreshGracePeriod: time.Minute,
		overrideScopes:     false,
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		data: map[string]map[string]interface{}{
			"valid-token": {
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
		},
	}

	adapter := NewAdapter(provider, settings, verifier, cache)

	// Track initial goroutine count for memory safety
	initialGoroutines := runtime.NumGoroutine()

	const numGoroutines = 50
	const numOperationsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Test concurrent access to adapter methods
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine; j++ {
				// Test GetType
				providerType := adapter.GetType()
				if providerType != ProviderTypeGoogle {
					t.Errorf("worker %d: expected Google provider type", workerID)
					return
				}

				// Test BuildAuthURL
				authURL := adapter.BuildAuthURL(
					fmt.Sprintf("https://example.com/callback-%d", workerID),
					fmt.Sprintf("state-%d-%d", workerID, j),
					fmt.Sprintf("nonce-%d-%d", workerID, j),
					fmt.Sprintf("challenge-%d-%d", workerID, j),
				)
				if authURL == "" {
					t.Errorf("worker %d: expected non-empty auth URL", workerID)
					return
				}

				// Test ValidateTokens
				session := &mockSession{
					authenticated: true,
					idToken:       "valid-token",
					accessToken:   fmt.Sprintf("access-token-%d", workerID),
					refreshToken:  fmt.Sprintf("refresh-token-%d", workerID),
				}

				result, err := adapter.ValidateTokens(session)
				if err != nil {
					t.Errorf("worker %d: unexpected error in ValidateTokens: %v", workerID, err)
					return
				}
				if !result.Authenticated {
					t.Errorf("worker %d: expected authenticated result", workerID)
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

func TestAdapter_MemorySafety(t *testing.T) {
	const numIterations = 1000

	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < numIterations; i++ {
		provider := NewGenericProvider()
		settings := &mockLegacySettings{
			clientID:           fmt.Sprintf("client-%d", i),
			issuerURL:          fmt.Sprintf("https://example%d.com", i),
			authURL:            fmt.Sprintf("https://example%d.com/auth", i),
			scopes:             []string{"openid", "email"},
			pkceEnabled:        i%2 == 0, // Alternate PKCE setting
			refreshGracePeriod: time.Minute,
			overrideScopes:     i%3 == 0, // Alternate override setting
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{
			data: map[string]map[string]interface{}{
				fmt.Sprintf("token-%d", i): {
					"exp": float64(time.Now().Add(time.Hour).Unix()),
				},
			},
		}

		adapter := NewAdapter(provider, settings, verifier, cache)

		// Exercise all adapter methods
		_ = adapter.GetType()
		_ = adapter.BuildAuthURL("https://example.com/callback", "state", "nonce", "challenge")

		session := &mockSession{
			authenticated: true,
			idToken:       fmt.Sprintf("token-%d", i),
			accessToken:   fmt.Sprintf("access-%d", i),
			refreshToken:  fmt.Sprintf("refresh-%d", i),
		}
		_, _ = adapter.ValidateTokens(session)
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("potential goroutine leak: started with %d goroutines, ended with %d", initialGoroutines, finalGoroutines)
	}
}

func TestAdapter_EdgeCases(t *testing.T) {
	t.Run("empty parameters", func(t *testing.T) {
		provider := NewGenericProvider()
		settings := &mockLegacySettings{
			clientID:       "",
			issuerURL:      "",
			authURL:        "",
			scopes:         []string{},
			pkceEnabled:    false,
			overrideScopes: false,
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}

		adapter := NewAdapter(provider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL("", "", "", "")

		// Should not crash, but may return empty or invalid URL
		if authURL != "" {
			t.Logf("Got auth URL with empty parameters: %s", authURL)
		}
	})

	t.Run("very long parameters", func(t *testing.T) {
		provider := NewGenericProvider()
		longString := strings.Repeat("a", 5000)
		settings := &mockLegacySettings{
			clientID:       longString,
			issuerURL:      "https://example.com/" + longString,
			authURL:        "https://example.com/" + longString + "/auth",
			scopes:         []string{"openid", longString},
			pkceEnabled:    true,
			overrideScopes: false,
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}

		adapter := NewAdapter(provider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL(
			"https://example.com/callback",
			longString,
			longString,
			longString,
		)

		// Should not crash
		if authURL == "" {
			t.Log("Long parameters resulted in empty auth URL")
		}
	})

	t.Run("special characters in parameters", func(t *testing.T) {
		provider := NewGenericProvider()
		settings := &mockLegacySettings{
			clientID:       "client@example.com",
			issuerURL:      "https://example.com/auth?param=value&other=test",
			authURL:        "https://example.com/auth/endpoint?default=param",
			scopes:         []string{"openid", "email+special", "profile/test"},
			pkceEnabled:    true,
			overrideScopes: false,
		}
		verifier := &mockTokenVerifier{}
		cache := &mockTokenCache{}

		adapter := NewAdapter(provider, settings, verifier, cache)
		authURL := adapter.BuildAuthURL(
			"https://example.com/callback?return=url",
			"state+with/special=chars&more",
			"nonce_with_underscores",
			"challenge-with-dashes",
		)

		if authURL == "" {
			t.Error("expected non-empty auth URL with special characters")
		}

		// Verify URL is properly encoded
		if !strings.Contains(authURL, "%") {
			t.Error("expected auth URL to contain URL encoding")
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkAdapter_GetType(b *testing.B) {
	provider := NewGoogleProvider()
	settings := &mockLegacySettings{clientID: "test-client"}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}
	adapter := NewAdapter(provider, settings, verifier, cache)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.GetType()
	}
}

func BenchmarkAdapter_BuildAuthURL(b *testing.B) {
	provider := NewGoogleProvider()
	settings := &mockLegacySettings{
		clientID:       "test-client",
		issuerURL:      "https://accounts.google.com",
		authURL:        "https://accounts.google.com/o/oauth2/auth",
		scopes:         []string{"openid", "email", "profile"},
		pkceEnabled:    true,
		overrideScopes: false,
	}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{}
	adapter := NewAdapter(provider, settings, verifier, cache)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.BuildAuthURL(
			"https://example.com/callback",
			"test-state",
			"test-nonce",
			"test-challenge",
		)
	}
}

func BenchmarkAdapter_ValidateTokens(b *testing.B) {
	provider := NewGoogleProvider()
	settings := &mockLegacySettings{refreshGracePeriod: time.Minute}
	verifier := &mockTokenVerifier{}
	cache := &mockTokenCache{
		data: map[string]map[string]interface{}{
			"test-token": {
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
		},
	}
	adapter := NewAdapter(provider, settings, verifier, cache)

	session := &mockSession{
		authenticated: true,
		idToken:       "test-token",
		accessToken:   "access-token",
		refreshToken:  "refresh-token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := adapter.ValidateTokens(session)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
