package providers

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestNewConfigValidator(t *testing.T) {
	validator := NewConfigValidator()

	if validator == nil {
		t.Fatal("expected non-nil config validator")
	}
}

func TestConfigValidator_ValidateIssuerURL(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		issuerURL   string
		wantError   bool
		errorSubstr string
	}{
		{
			name:      "valid HTTPS URL",
			issuerURL: "https://accounts.google.com/.well-known/openid_configuration",
			wantError: false,
		},
		{
			name:      "valid HTTP URL",
			issuerURL: "http://localhost:8080/auth/realms/master",
			wantError: false,
		},
		{
			name:        "empty URL",
			issuerURL:   "",
			wantError:   true,
			errorSubstr: "issuer URL cannot be empty",
		},
		{
			name:        "invalid URL format",
			issuerURL:   "://invalid-url",
			wantError:   true,
			errorSubstr: "invalid issuer URL format",
		},
		{
			name:        "URL without scheme",
			issuerURL:   "example.com/auth",
			wantError:   true,
			errorSubstr: "issuer URL must include scheme",
		},
		{
			name:        "URL with invalid scheme",
			issuerURL:   "ftp://example.com/auth",
			wantError:   true,
			errorSubstr: "issuer URL scheme must be http or https",
		},
		{
			name:        "URL without host",
			issuerURL:   "https:///path/only",
			wantError:   true,
			errorSubstr: "issuer URL must include host",
		},
		{
			name:      "URL with port",
			issuerURL: "https://example.com:8443/auth",
			wantError: false,
		},
		{
			name:      "URL with path and query",
			issuerURL: "https://example.com/auth/realms/master?param=value",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIssuerURL(tt.issuerURL)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigValidator_ValidateClientID(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		clientID    string
		wantError   bool
		errorSubstr string
	}{
		{
			name:      "valid client ID",
			clientID:  "valid-client-id",
			wantError: false,
		},
		{
			name:      "long client ID",
			clientID:  "very-long-client-id-with-many-characters-12345678901234567890",
			wantError: false,
		},
		{
			name:        "empty client ID",
			clientID:    "",
			wantError:   true,
			errorSubstr: "client ID cannot be empty",
		},
		{
			name:        "very short client ID",
			clientID:    "ab",
			wantError:   true,
			errorSubstr: "client ID appears to be too short",
		},
		{
			name:      "minimum valid length",
			clientID:  "abc",
			wantError: false,
		},
		{
			name:      "client ID with special characters",
			clientID:  "client@example.com",
			wantError: false,
		},
		{
			name:      "client ID with numbers",
			clientID:  "client-123-456",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateClientID(tt.clientID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigValidator_ValidateScopes(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		scopes      []string
		wantError   bool
		errorSubstr string
	}{
		{
			name:      "valid scopes with openid",
			scopes:    []string{"openid", "email", "profile"},
			wantError: false,
		},
		{
			name:      "openid scope only",
			scopes:    []string{"openid"},
			wantError: false,
		},
		{
			name:        "empty scopes",
			scopes:      []string{},
			wantError:   true,
			errorSubstr: "at least one scope must be provided",
		},
		{
			name:        "nil scopes",
			scopes:      nil,
			wantError:   true,
			errorSubstr: "at least one scope must be provided",
		},
		{
			name:        "scopes without openid",
			scopes:      []string{"email", "profile"},
			wantError:   true,
			errorSubstr: "'openid' scope is required for OIDC authentication",
		},
		{
			name:      "scopes with openid and whitespace",
			scopes:    []string{" openid ", "email", "profile"},
			wantError: false,
		},
		{
			name:        "scopes with mixed case openid",
			scopes:      []string{"OpenID", "email"}, // This should fail as it's case sensitive
			wantError:   true,
			errorSubstr: "'openid' scope is required for OIDC authentication",
		},
		{
			name:      "scopes with offline_access",
			scopes:    []string{"openid", "offline_access", "email"},
			wantError: false,
		},
		{
			name:      "many scopes",
			scopes:    []string{"openid", "email", "profile", "address", "phone", "offline_access", "custom_scope"},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateScopes(tt.scopes)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigValidator_ValidateRedirectURL(t *testing.T) {
	validator := NewConfigValidator()

	tests := []struct {
		name        string
		redirectURL string
		wantError   bool
		errorSubstr string
	}{
		{
			name:        "valid HTTPS redirect URL",
			redirectURL: "https://example.com/callback",
			wantError:   false,
		},
		{
			name:        "valid HTTP redirect URL",
			redirectURL: "http://localhost:8080/callback",
			wantError:   false,
		},
		{
			name:        "empty redirect URL",
			redirectURL: "",
			wantError:   true,
			errorSubstr: "redirect URL cannot be empty",
		},
		{
			name:        "invalid redirect URL format",
			redirectURL: "://invalid-url",
			wantError:   true,
			errorSubstr: "invalid redirect URL format",
		},
		{
			name:        "redirect URL without scheme",
			redirectURL: "example.com/callback",
			wantError:   true,
			errorSubstr: "redirect URL must include scheme",
		},
		{
			name:        "redirect URL with custom scheme",
			redirectURL: "myapp://callback",
			wantError:   false, // Custom schemes are allowed for mobile apps
		},
		{
			name:        "redirect URL with query parameters",
			redirectURL: "https://example.com/callback?state=123&code=456",
			wantError:   false,
		},
		{
			name:        "redirect URL with fragment",
			redirectURL: "https://example.com/callback#section",
			wantError:   false,
		},
		{
			name:        "localhost redirect URL",
			redirectURL: "http://localhost/callback",
			wantError:   false,
		},
		{
			name:        "IP address redirect URL",
			redirectURL: "http://192.168.1.1:8080/callback",
			wantError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRedirectURL(tt.redirectURL)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigValidator_ValidateProviderSpecificConfig(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("Google provider config", func(t *testing.T) {
		provider := NewGoogleProvider()

		tests := []struct {
			name        string
			config      map[string]interface{}
			wantError   bool
			errorSubstr string
		}{
			{
				name: "valid Google issuer URL",
				config: map[string]interface{}{
					"issuer_url": "https://accounts.google.com/.well-known/openid_configuration",
				},
				wantError: false,
			},
			{
				name: "invalid Google issuer URL",
				config: map[string]interface{}{
					"issuer_url": "https://example.com/auth",
				},
				wantError:   true,
				errorSubstr: "google provider requires issuer URL to contain accounts.google.com",
			},
			{
				name:      "empty config",
				config:    map[string]interface{}{},
				wantError: false,
			},
			{
				name: "non-string issuer URL",
				config: map[string]interface{}{
					"issuer_url": 12345,
				},
				wantError: false, // Type assertion fails, but doesn't error
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.ValidateProviderSpecificConfig(provider, tt.config)

				if tt.wantError {
					if err == nil {
						t.Error("expected error but got none")
						return
					}
					if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			})
		}
	})

	t.Run("Azure provider config", func(t *testing.T) {
		provider := NewAzureProvider()

		tests := []struct {
			name        string
			config      map[string]interface{}
			wantError   bool
			errorSubstr string
		}{
			{
				name: "valid Azure issuer URL - login.microsoftonline.com",
				config: map[string]interface{}{
					"issuer_url": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
				},
				wantError: false,
			},
			{
				name: "valid Azure issuer URL - sts.windows.net",
				config: map[string]interface{}{
					"issuer_url": "https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
				},
				wantError: false,
			},
			{
				name: "valid Azure issuer URL with proper tenant ID",
				config: map[string]interface{}{
					"issuer_url": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
				},
				wantError: false,
			},
			{
				name: "invalid Azure issuer URL",
				config: map[string]interface{}{
					"issuer_url": "https://example.com/auth",
				},
				wantError:   true,
				errorSubstr: "azure provider requires issuer URL to contain login.microsoftonline.com or sts.windows.net",
			},
			{
				name: "Azure issuer URL without tenant ID",
				config: map[string]interface{}{
					"issuer_url": "https://login.microsoftonline.com/v2.0",
				},
				wantError:   true,
				errorSubstr: "azure issuer URL should include tenant ID",
			},
			{
				name:      "empty config",
				config:    map[string]interface{}{},
				wantError: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.ValidateProviderSpecificConfig(provider, tt.config)

				if tt.wantError {
					if err == nil {
						t.Error("expected error but got none")
						return
					}
					if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
						t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
				}
			})
		}
	})

	t.Run("Generic provider config", func(t *testing.T) {
		provider := NewGenericProvider()

		config := map[string]interface{}{
			"issuer_url": "https://example.com/auth",
			"any_key":    "any_value",
		}

		err := validator.ValidateProviderSpecificConfig(provider, config)
		if err != nil {
			t.Errorf("unexpected error for generic provider: %v", err)
		}
	})

	t.Run("unknown provider type", func(t *testing.T) {
		// Create a mock provider with invalid type
		mockProvider := &struct {
			OIDCProvider
		}{}
		mockProvider.OIDCProvider = NewGenericProvider()

		// Override GetType to return invalid type
		provider := &mockProviderWithInvalidType{mockProvider.OIDCProvider}

		err := validator.ValidateProviderSpecificConfig(provider, map[string]interface{}{})
		if err == nil {
			t.Error("expected error for unknown provider type")
		}
		if !strings.Contains(err.Error(), "unknown provider type") {
			t.Errorf("expected error about unknown provider type, got: %v", err)
		}
	})
}

// mockProviderWithInvalidType is a test helper that returns an invalid provider type
type mockProviderWithInvalidType struct {
	OIDCProvider
}

func (m *mockProviderWithInvalidType) GetType() ProviderType {
	return ProviderType(999) // Invalid provider type
}

func TestConfigValidator_ConcurrentAccess(t *testing.T) {
	validator := NewConfigValidator()

	// Track initial goroutine count for memory safety
	initialGoroutines := runtime.NumGoroutine()

	const numGoroutines = 50
	const numOperationsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	testData := []struct {
		issuerURL   string
		clientID    string
		scopes      []string
		redirectURL string
	}{
		{
			issuerURL:   "https://accounts.google.com/.well-known/openid_configuration",
			clientID:    "google-client-id",
			scopes:      []string{"openid", "email", "profile"},
			redirectURL: "https://example.com/callback",
		},
		{
			issuerURL:   "https://login.microsoftonline.com/tenant/v2.0",
			clientID:    "azure-client-id",
			scopes:      []string{"openid", "offline_access"},
			redirectURL: "https://example.com/azure-callback",
		},
		{
			issuerURL:   "https://keycloak.example.com/auth/realms/master",
			clientID:    "generic-client-id",
			scopes:      []string{"openid", "email"},
			redirectURL: "http://localhost:8080/callback",
		},
	}

	// Test concurrent validation operations
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()

			data := testData[workerID%len(testData)]

			for j := 0; j < numOperationsPerGoroutine; j++ {
				// Test ValidateIssuerURL
				err := validator.ValidateIssuerURL(data.issuerURL)
				if err != nil {
					t.Errorf("worker %d: unexpected error validating issuer URL: %v", workerID, err)
					return
				}

				// Test ValidateClientID
				err = validator.ValidateClientID(data.clientID)
				if err != nil {
					t.Errorf("worker %d: unexpected error validating client ID: %v", workerID, err)
					return
				}

				// Test ValidateScopes
				err = validator.ValidateScopes(data.scopes)
				if err != nil {
					t.Errorf("worker %d: unexpected error validating scopes: %v", workerID, err)
					return
				}

				// Test ValidateRedirectURL
				err = validator.ValidateRedirectURL(data.redirectURL)
				if err != nil {
					t.Errorf("worker %d: unexpected error validating redirect URL: %v", workerID, err)
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

func TestConfigValidator_MemorySafety(t *testing.T) {
	const numIterations = 1000

	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < numIterations; i++ {
		validator := NewConfigValidator()

		// Exercise all validation methods
		_ = validator.ValidateIssuerURL(fmt.Sprintf("https://example%d.com/auth", i))
		_ = validator.ValidateClientID(fmt.Sprintf("client-id-%d", i))
		_ = validator.ValidateScopes([]string{"openid", fmt.Sprintf("scope-%d", i)})
		_ = validator.ValidateRedirectURL(fmt.Sprintf("https://example%d.com/callback", i))

		// Test provider-specific validation
		provider := NewGoogleProvider()
		config := map[string]interface{}{
			"issuer_url": fmt.Sprintf("https://accounts.google.com/config-%d", i),
		}
		_ = validator.ValidateProviderSpecificConfig(provider, config)
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("potential goroutine leak: started with %d goroutines, ended with %d", initialGoroutines, finalGoroutines)
	}
}

func TestConfigValidator_EdgeCases(t *testing.T) {
	validator := NewConfigValidator()

	t.Run("very long URLs and strings", func(t *testing.T) {
		longString := strings.Repeat("a", 10000)
		longURL := "https://" + longString + ".com/auth"

		// These should not crash
		err := validator.ValidateIssuerURL(longURL)
		if err != nil {
			t.Logf("Long URL validation failed as expected: %v", err)
		}

		err = validator.ValidateClientID(longString)
		if err != nil {
			t.Logf("Long client ID validation failed as expected: %v", err)
		}

		err = validator.ValidateRedirectURL(longURL)
		if err != nil {
			t.Logf("Long redirect URL validation failed as expected: %v", err)
		}
	})

	t.Run("special characters and encoding", func(t *testing.T) {
		specialURLs := []string{
			"https://example.com/auth?param=value%20with%20spaces",
			"https://example.com/auth#fragment",
			"https://example.com/auth/path with spaces",
			"https://example.com/auth?param=特殊字符",
			"https://xn--e1afmkfd.xn--p1ai/auth", // Punycode domain
		}

		for _, url := range specialURLs {
			err := validator.ValidateIssuerURL(url)
			// Some may fail, but should not crash
			if err != nil {
				t.Logf("Special URL %q validation failed: %v", url, err)
			}
		}
	})

	t.Run("nil and empty inputs", func(t *testing.T) {
		// Test nil scopes
		err := validator.ValidateScopes(nil)
		if err == nil {
			t.Error("expected error for nil scopes")
		}

		// Test empty scopes
		err = validator.ValidateScopes([]string{})
		if err == nil {
			t.Error("expected error for empty scopes")
		}

		// Test nil provider
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected panic with nil provider: %v", r)
			}
		}()
		err = validator.ValidateProviderSpecificConfig(nil, map[string]interface{}{})
		if err == nil {
			t.Error("expected error with nil provider")
		}
	})

	t.Run("malformed tenant IDs", func(t *testing.T) {
		provider := NewAzureProvider()
		malformedTenantConfigs := []map[string]interface{}{
			{
				"issuer_url": "https://login.microsoftonline.com/not-a-guid/v2.0",
			},
			{
				"issuer_url": "https://login.microsoftonline.com/12345678-1234-1234-123456789012/v2.0", // Wrong length
			},
			{
				"issuer_url": "https://login.microsoftonline.com/12345678-1234-1234-1234-12345678901/v2.0", // Wrong format
			},
		}

		for i, config := range malformedTenantConfigs {
			err := validator.ValidateProviderSpecificConfig(provider, config)
			if err == nil {
				t.Errorf("expected error for malformed tenant ID in config %d", i)
			}
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkConfigValidator_ValidateIssuerURL(b *testing.B) {
	validator := NewConfigValidator()
	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://keycloak.example.com/auth/realms/master",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		validator.ValidateIssuerURL(url)
	}
}

func BenchmarkConfigValidator_ValidateScopes(b *testing.B) {
	validator := NewConfigValidator()
	scopes := []string{"openid", "email", "profile", "offline_access"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateScopes(scopes)
	}
}

func BenchmarkConfigValidator_ValidateProviderSpecificConfig(b *testing.B) {
	validator := NewConfigValidator()
	provider := NewGoogleProvider()
	config := map[string]interface{}{
		"issuer_url": "https://accounts.google.com/.well-known/openid_configuration",
		"client_id":  "test-client-id",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateProviderSpecificConfig(provider, config)
	}
}
