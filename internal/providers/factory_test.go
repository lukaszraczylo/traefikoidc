package providers

import (
	"runtime"
	"sync"
	"testing"
)

func TestNewProviderFactory(t *testing.T) {
	factory := NewProviderFactory()

	if factory == nil {
		t.Fatal("expected non-nil factory")
	}

	if factory.registry == nil {
		t.Fatal("expected non-nil registry in factory")
	}
}

func TestProviderFactory_CreateProvider(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name        string
		issuerURL   string
		wantType    ProviderType
		wantError   bool
		errorSubstr string
	}{
		{
			name:      "Google provider detection",
			issuerURL: "https://accounts.google.com/.well-known/openid_configuration",
			wantType:  ProviderTypeGoogle,
			wantError: false,
		},
		{
			name:      "Azure provider detection - login.microsoftonline.com",
			issuerURL: "https://login.microsoftonline.com/tenant-id/v2.0",
			wantType:  ProviderTypeAzure,
			wantError: false,
		},
		{
			name:      "Azure provider detection - sts.windows.net",
			issuerURL: "https://sts.windows.net/tenant-id/",
			wantType:  ProviderTypeAzure,
			wantError: false,
		},
		{
			name:      "Generic provider detection",
			issuerURL: "https://auth.example.com/realms/test",
			wantType:  ProviderTypeGeneric,
			wantError: false,
		},
		{
			name:        "Empty issuer URL",
			issuerURL:   "",
			wantError:   true,
			errorSubstr: "issuer URL cannot be empty",
		},
		{
			name:      "Invalid URL format",
			issuerURL: "not-a-valid-url",
			wantType:  ProviderTypeGeneric,
			wantError: false, // url.Parse accepts this as a valid URL
		},
		{
			name:      "URL with invalid scheme",
			issuerURL: "ftp://example.com/auth",
			wantType:  ProviderTypeGeneric,
			wantError: false, // Should create generic provider for non-standard schemes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.CreateProvider(tt.issuerURL)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorSubstr != "" && err.Error() != tt.errorSubstr {
					t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if provider == nil {
				t.Error("expected non-nil provider")
				return
			}

			if provider.GetType() != tt.wantType {
				t.Errorf("expected provider type %d, got %d", tt.wantType, provider.GetType())
			}
		})
	}
}

func TestProviderFactory_CreateProviderByType(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name         string
		providerType ProviderType
		wantError    bool
		errorSubstr  string
	}{
		{
			name:         "Generic provider",
			providerType: ProviderTypeGeneric,
			wantError:    false,
		},
		{
			name:         "Google provider",
			providerType: ProviderTypeGoogle,
			wantError:    false,
		},
		{
			name:         "Azure provider",
			providerType: ProviderTypeAzure,
			wantError:    false,
		},
		{
			name:         "Invalid provider type",
			providerType: ProviderType(999),
			wantError:    true,
			errorSubstr:  "unsupported provider type: 999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.CreateProviderByType(tt.providerType)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorSubstr != "" && err.Error() != tt.errorSubstr {
					t.Errorf("expected error to contain %q, got %q", tt.errorSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if provider == nil {
				t.Error("expected non-nil provider")
				return
			}

			if provider.GetType() != tt.providerType {
				t.Errorf("expected provider type %d, got %d", tt.providerType, provider.GetType())
			}
		})
	}
}

func TestProviderFactory_GetSupportedProviders(t *testing.T) {
	factory := NewProviderFactory()
	supported := factory.GetSupportedProviders()

	expectedProviders := map[ProviderType][]string{
		ProviderTypeGeneric: {"*"},
		ProviderTypeGoogle:  {"accounts.google.com"},
		ProviderTypeAzure:   {"login.microsoftonline.com", "sts.windows.net"},
	}

	if len(supported) != len(expectedProviders) {
		t.Errorf("expected %d supported providers, got %d", len(expectedProviders), len(supported))
	}

	for expectedType, expectedPatterns := range expectedProviders {
		patterns, exists := supported[expectedType]
		if !exists {
			t.Errorf("expected provider type %d to be supported", expectedType)
			continue
		}

		if len(patterns) != len(expectedPatterns) {
			t.Errorf("expected %d patterns for provider type %d, got %d", len(expectedPatterns), expectedType, len(patterns))
			continue
		}

		for i, expectedPattern := range expectedPatterns {
			if patterns[i] != expectedPattern {
				t.Errorf("expected pattern %q for provider type %d, got %q", expectedPattern, expectedType, patterns[i])
			}
		}
	}
}

func TestProviderFactory_DetectProviderType(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name      string
		issuerURL string
		wantType  ProviderType
		wantError bool
	}{
		{
			name:      "Google detection",
			issuerURL: "https://accounts.google.com/.well-known/openid_configuration",
			wantType:  ProviderTypeGoogle,
			wantError: false,
		},
		{
			name:      "Azure detection",
			issuerURL: "https://login.microsoftonline.com/tenant/v2.0",
			wantType:  ProviderTypeAzure,
			wantError: false,
		},
		{
			name:      "Generic detection",
			issuerURL: "https://keycloak.example.com/auth/realms/master",
			wantType:  ProviderTypeGeneric,
			wantError: false,
		},
		{
			name:      "Invalid URL",
			issuerURL: "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerType, err := factory.DetectProviderType(tt.issuerURL)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if providerType != tt.wantType {
				t.Errorf("expected provider type %d, got %d", tt.wantType, providerType)
			}
		})
	}
}

func TestProviderFactory_IsProviderSupported(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name        string
		issuerURL   string
		wantSupport bool
	}{
		{
			name:        "Google URL",
			issuerURL:   "https://accounts.google.com/o/oauth2/auth",
			wantSupport: true,
		},
		{
			name:        "Azure URL - login.microsoftonline.com",
			issuerURL:   "https://login.microsoftonline.com/tenant/v2.0",
			wantSupport: true,
		},
		{
			name:        "Azure URL - sts.windows.net",
			issuerURL:   "https://sts.windows.net/tenant/",
			wantSupport: true,
		},
		{
			name:        "Generic URL",
			issuerURL:   "https://auth.example.com/realms/master",
			wantSupport: true,
		},
		{
			name:        "Empty URL",
			issuerURL:   "",
			wantSupport: false,
		},
		{
			name:        "Invalid URL",
			issuerURL:   "not-a-valid-url",
			wantSupport: true, // Generic provider supports all URLs
		},
		{
			name:        "Valid but generic URL",
			issuerURL:   "https://keycloak.example.com/auth",
			wantSupport: true, // Should be supported as generic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supported := factory.IsProviderSupported(tt.issuerURL)
			if supported != tt.wantSupport {
				t.Errorf("expected support %v for URL %q, got %v", tt.wantSupport, tt.issuerURL, supported)
			}
		})
	}
}

func TestProviderFactory_ConcurrentAccess(t *testing.T) {
	factory := NewProviderFactory()

	// Track initial goroutine count for memory safety
	initialGoroutines := runtime.NumGoroutine()

	const numGoroutines = 100
	const numOperationsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://auth.example.com/realms/master",
	}

	// Test concurrent provider creation
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numOperationsPerGoroutine; j++ {
				url := urls[j%len(urls)]

				// Test CreateProvider
				provider, err := factory.CreateProvider(url)
				if err != nil {
					t.Errorf("worker %d: unexpected error creating provider: %v", workerID, err)
					return
				}
				if provider == nil {
					t.Errorf("worker %d: expected non-nil provider", workerID)
					return
				}

				// Test IsProviderSupported
				supported := factory.IsProviderSupported(url)
				if !supported {
					t.Errorf("worker %d: expected URL %s to be supported", workerID, url)
					return
				}

				// Test DetectProviderType
				_, err = factory.DetectProviderType(url)
				if err != nil {
					t.Errorf("worker %d: unexpected error detecting provider type: %v", workerID, err)
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

func TestProviderFactory_MemorySafety(t *testing.T) {
	// Test that creating many providers doesn't cause memory leaks
	const numCreations = 1000

	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < numCreations; i++ {
		factory := NewProviderFactory()
		_, err := factory.CreateProvider("https://accounts.google.com/.well-known/openid_configuration")
		if err != nil {
			t.Fatalf("unexpected error creating provider: %v", err)
		}
	}

	// Force garbage collection to cleanup any lingering resources
	runtime.GC()
	runtime.GC() // Call twice to ensure cleanup

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("potential goroutine leak: started with %d goroutines, ended with %d", initialGoroutines, finalGoroutines)
	}
}

func TestProviderFactory_EdgeCases(t *testing.T) {
	factory := NewProviderFactory()

	t.Run("nil factory registry handling", func(t *testing.T) {
		// This test ensures we handle edge cases properly
		defer func() {
			if r := recover(); r != nil {
				// Expected behavior - nil registry should cause panic or be handled
				t.Logf("Recovered from panic as expected: %v", r)
			}
		}()
		brokenFactory := &ProviderFactory{registry: nil}
		_, err := brokenFactory.CreateProvider("https://accounts.google.com")
		if err == nil {
			t.Error("expected error with nil registry")
		}
	})

	t.Run("malformed URLs", func(t *testing.T) {
		malformedURLs := []string{
			"://missing-scheme.com",
			"https://",
			"https:///missing-host",
			"https://example.com:port-not-number",
		}

		for _, url := range malformedURLs {
			_, err := factory.CreateProvider(url)
			// Some malformed URLs might still be accepted by url.Parse,
			// but we ensure the system doesn't crash
			if err == nil {
				// Still check that we get a valid provider
				provider, err := factory.CreateProvider(url)
				if err == nil && provider == nil {
					t.Errorf("got nil provider without error for URL: %s", url)
				}
			}
		}
	})

	t.Run("very long URLs", func(t *testing.T) {
		longURL := "https://accounts.google.com/" + string(make([]byte, 10000))
		for i := range longURL[len("https://accounts.google.com/"):] {
			longURL = longURL[:len("https://accounts.google.com/")+i] + "a" + longURL[len("https://accounts.google.com/")+i+1:]
		}

		provider, err := factory.CreateProvider(longURL)
		if err != nil {
			t.Logf("long URL rejected as expected: %v", err)
		} else if provider == nil {
			t.Error("got nil provider without error for very long URL")
		}
	})
}

// Benchmark tests for performance validation
func BenchmarkProviderFactory_CreateProvider(b *testing.B) {
	factory := NewProviderFactory()
	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://auth.example.com/realms/master",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		_, err := factory.CreateProvider(url)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkProviderFactory_DetectProviderType(b *testing.B) {
	factory := NewProviderFactory()
	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://auth.example.com/realms/master",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		_, err := factory.DetectProviderType(url)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

func BenchmarkProviderFactory_IsProviderSupported(b *testing.B) {
	factory := NewProviderFactory()
	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://auth.example.com/realms/master",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		factory.IsProviderSupported(url)
	}
}
