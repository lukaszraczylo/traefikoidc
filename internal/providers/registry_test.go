package providers

import (
	"sync"
	"testing"
)

// TestProviderRegistry_NewProviderRegistry tests registry constructor
func TestProviderRegistry_NewProviderRegistry(t *testing.T) {
	registry := NewProviderRegistry()

	if registry == nil {
		t.Fatal("Expected registry to be created, got nil")
	}

	if registry.providers == nil {
		t.Error("Providers slice should be initialized")
	}

	if registry.cache == nil {
		t.Error("Cache map should be initialized")
	}

	if registry.typeMap == nil {
		t.Error("TypeMap should be initialized")
	}

	if registry.maxCacheSize != 1000 {
		t.Errorf("Expected maxCacheSize 1000, got %d", registry.maxCacheSize)
	}

	if registry.cacheCount != 0 {
		t.Errorf("Expected initial cacheCount 0, got %d", registry.cacheCount)
	}
}

// TestProviderRegistry_RegisterProvider tests provider registration
func TestProviderRegistry_RegisterProvider(t *testing.T) {
	registry := NewProviderRegistry()

	genericProvider := NewGenericProvider()
	googleProvider := NewGoogleProvider()
	azureProvider := NewAzureProvider()

	// Register providers
	registry.RegisterProvider(genericProvider)
	registry.RegisterProvider(googleProvider)
	registry.RegisterProvider(azureProvider)

	// Verify providers are registered
	if len(registry.providers) != 3 {
		t.Errorf("Expected 3 providers, got %d", len(registry.providers))
	}

	if len(registry.typeMap) != 3 {
		t.Errorf("Expected 3 type mappings, got %d", len(registry.typeMap))
	}

	// Verify type mappings
	if registry.typeMap[ProviderTypeGeneric] != genericProvider {
		t.Error("Generic provider not mapped correctly")
	}

	if registry.typeMap[ProviderTypeGoogle] != googleProvider {
		t.Error("Google provider not mapped correctly")
	}

	if registry.typeMap[ProviderTypeAzure] != azureProvider {
		t.Error("Azure provider not mapped correctly")
	}
}

// TestProviderRegistry_GetProviderByType tests provider retrieval by type
func TestProviderRegistry_GetProviderByType(t *testing.T) {
	registry := NewProviderRegistry()

	genericProvider := NewGenericProvider()
	googleProvider := NewGoogleProvider()

	registry.RegisterProvider(genericProvider)
	registry.RegisterProvider(googleProvider)

	tests := []struct {
		name         string
		providerType ProviderType
		expected     OIDCProvider
	}{
		{
			name:         "Get Generic provider",
			providerType: ProviderTypeGeneric,
			expected:     genericProvider,
		},
		{
			name:         "Get Google provider",
			providerType: ProviderTypeGoogle,
			expected:     googleProvider,
		},
		{
			name:         "Get unregistered provider",
			providerType: ProviderTypeAzure,
			expected:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.GetProviderByType(tt.providerType)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestProviderRegistry_GetRegisteredProviders tests listing registered provider types
func TestProviderRegistry_GetRegisteredProviders(t *testing.T) {
	registry := NewProviderRegistry()

	// Initially empty
	types := registry.GetRegisteredProviders()
	if len(types) != 0 {
		t.Errorf("Expected 0 registered providers, got %d", len(types))
	}

	// Register some providers
	registry.RegisterProvider(NewGenericProvider())
	registry.RegisterProvider(NewGoogleProvider())

	types = registry.GetRegisteredProviders()
	if len(types) != 2 {
		t.Errorf("Expected 2 registered providers, got %d", len(types))
	}

	// Verify types are correct
	expectedTypes := map[ProviderType]bool{
		ProviderTypeGeneric: false,
		ProviderTypeGoogle:  false,
	}

	for _, providerType := range types {
		if _, exists := expectedTypes[providerType]; exists {
			expectedTypes[providerType] = true
		} else {
			t.Errorf("Unexpected provider type: %v", providerType)
		}
	}

	for providerType, found := range expectedTypes {
		if !found {
			t.Errorf("Provider type %v not found in results", providerType)
		}
	}
}

// TestProviderRegistry_DetectProvider tests provider detection
func TestProviderRegistry_DetectProvider(t *testing.T) {
	registry := NewProviderRegistry()

	// Register providers
	genericProvider := NewGenericProvider()
	googleProvider := NewGoogleProvider()
	azureProvider := NewAzureProvider()
	githubProvider := NewGitHubProvider()
	auth0Provider := NewAuth0Provider()
	oktaProvider := NewOktaProvider()
	keycloakProvider := NewKeycloakProvider()
	cognitoProvider := NewAWSCognitoProvider()
	gitlabProvider := NewGitLabProvider()

	registry.RegisterProvider(genericProvider)
	registry.RegisterProvider(googleProvider)
	registry.RegisterProvider(azureProvider)
	registry.RegisterProvider(githubProvider)
	registry.RegisterProvider(auth0Provider)
	registry.RegisterProvider(oktaProvider)
	registry.RegisterProvider(keycloakProvider)
	registry.RegisterProvider(cognitoProvider)
	registry.RegisterProvider(gitlabProvider)

	tests := []struct {
		name      string
		issuerURL string
		expected  OIDCProvider
	}{
		{
			name:      "Google provider detection",
			issuerURL: "https://accounts.google.com",
			expected:  googleProvider,
		},
		{
			name:      "Google provider with path",
			issuerURL: "https://accounts.google.com/oauth2",
			expected:  googleProvider,
		},
		{
			name:      "Azure provider detection - login.microsoftonline.com",
			issuerURL: "https://login.microsoftonline.com/tenant/v2.0",
			expected:  azureProvider,
		},
		{
			name:      "Azure provider detection - sts.windows.net",
			issuerURL: "https://sts.windows.net/tenant",
			expected:  azureProvider,
		},
		{
			name:      "GitHub provider detection",
			issuerURL: "https://github.com/login/oauth",
			expected:  githubProvider,
		},
		{
			name:      "Auth0 provider detection",
			issuerURL: "https://tenant.auth0.com",
			expected:  auth0Provider,
		},
		{
			name:      "Okta provider detection",
			issuerURL: "https://tenant.okta.com",
			expected:  oktaProvider,
		},
		{
			name:      "Okta preview provider detection",
			issuerURL: "https://tenant.oktapreview.com",
			expected:  oktaProvider,
		},
		{
			name:      "Keycloak provider detection",
			issuerURL: "https://auth.example.com/auth/realms/master",
			expected:  keycloakProvider,
		},
		{
			name:      "AWS Cognito provider detection",
			issuerURL: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
			expected:  cognitoProvider,
		},
		{
			name:      "GitLab provider detection",
			issuerURL: "https://gitlab.com/oauth",
			expected:  gitlabProvider,
		},
		{
			name:      "Generic provider fallback",
			issuerURL: "https://auth.example.com",
			expected:  genericProvider,
		},
		{
			name:      "Invalid URL",
			issuerURL: "not-a-url",
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.DetectProvider(tt.issuerURL)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestProviderRegistry_DetectProvider_Caching tests cache behavior
func TestProviderRegistry_DetectProvider_Caching(t *testing.T) {
	registry := NewProviderRegistry()

	genericProvider := NewGenericProvider()
	registry.RegisterProvider(genericProvider)

	issuerURL := "https://auth.example.com"

	// First call should detect and cache
	result1 := registry.DetectProvider(issuerURL)
	if result1 != genericProvider {
		t.Errorf("Expected generic provider, got %v", result1)
	}

	// Verify it's cached
	registry.mu.RLock()
	cachedResult, found := registry.cache[issuerURL]
	registry.mu.RUnlock()

	if !found {
		t.Error("Expected result to be cached")
	}

	if cachedResult != genericProvider {
		t.Errorf("Expected cached generic provider, got %v", cachedResult)
	}

	// Second call should return cached result
	result2 := registry.DetectProvider(issuerURL)
	if result2 != genericProvider {
		t.Errorf("Expected cached generic provider, got %v", result2)
	}

	// Should be same instance (from cache)
	if result1 != result2 {
		t.Error("Expected same instance from cache")
	}
}

// TestProviderRegistry_ClearCache tests cache clearing
func TestProviderRegistry_ClearCache(t *testing.T) {
	registry := NewProviderRegistry()

	genericProvider := NewGenericProvider()
	registry.RegisterProvider(genericProvider)

	// Populate cache
	registry.DetectProvider("https://auth1.example.com")
	registry.DetectProvider("https://auth2.example.com")

	// Verify cache has entries
	registry.mu.RLock()
	cacheSize := len(registry.cache)
	registry.mu.RUnlock()

	if cacheSize != 2 {
		t.Errorf("Expected 2 cache entries, got %d", cacheSize)
	}

	// Clear cache
	registry.ClearCache()

	// Verify cache is empty
	registry.mu.RLock()
	cacheSize = len(registry.cache)
	cacheCount := registry.cacheCount
	registry.mu.RUnlock()

	if cacheSize != 0 {
		t.Errorf("Expected 0 cache entries after clear, got %d", cacheSize)
	}

	if cacheCount != 0 {
		t.Errorf("Expected 0 cache count after clear, got %d", cacheCount)
	}
}

// TestProviderRegistry_CacheEviction tests cache size limits and eviction
func TestProviderRegistry_CacheEviction(t *testing.T) {
	registry := NewProviderRegistry()
	registry.maxCacheSize = 2 // Set small cache size for testing

	genericProvider := NewGenericProvider()
	registry.RegisterProvider(genericProvider)

	// Fill cache to capacity
	registry.DetectProvider("https://auth1.example.com")
	registry.DetectProvider("https://auth2.example.com")

	// Verify cache is at capacity
	registry.mu.RLock()
	cacheSize := len(registry.cache)
	registry.mu.RUnlock()

	if cacheSize != 2 {
		t.Errorf("Expected 2 cache entries, got %d", cacheSize)
	}

	// Add one more entry (should trigger eviction)
	registry.DetectProvider("https://auth3.example.com")

	// Cache size should still be at max
	registry.mu.RLock()
	cacheSize = len(registry.cache)
	registry.mu.RUnlock()

	if cacheSize != 2 {
		t.Errorf("Expected 2 cache entries after eviction, got %d", cacheSize)
	}

	// Verify the new entry is cached
	registry.mu.RLock()
	_, found := registry.cache["https://auth3.example.com"]
	registry.mu.RUnlock()

	if !found {
		t.Error("Expected new entry to be cached")
	}
}

// TestProviderRegistry_ConcurrentAccess tests thread safety
func TestProviderRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewProviderRegistry()

	genericProvider := NewGenericProvider()
	googleProvider := NewGoogleProvider()
	azureProvider := NewAzureProvider()

	registry.RegisterProvider(genericProvider)
	registry.RegisterProvider(googleProvider)
	registry.RegisterProvider(azureProvider)

	var wg sync.WaitGroup
	goroutines := 10
	iterations := 100

	// Test concurrent detection
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				issuerURL := "https://accounts.google.com"
				if id%2 == 0 {
					issuerURL = "https://login.microsoftonline.com/tenant"
				} else if id%3 == 0 {
					issuerURL = "https://auth.example.com"
				}

				result := registry.DetectProvider(issuerURL)
				if result == nil {
					t.Errorf("Expected provider for URL %s", issuerURL)
				}
			}
		}(i)
	}

	// Test concurrent registration
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			newProvider := NewGenericProvider()
			registry.RegisterProvider(newProvider)
		}
	}()

	// Test concurrent cache clearing
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			registry.ClearCache()
		}
	}()

	wg.Wait()

	// Verify final state is consistent
	types := registry.GetRegisteredProviders()
	if len(types) < 3 { // Should have at least the original 3
		t.Errorf("Expected at least 3 provider types, got %d", len(types))
	}
}

// TestProviderRegistry_DoubleCheckedLocking tests the double-checked locking pattern
func TestProviderRegistry_DoubleCheckedLocking(t *testing.T) {
	registry := NewProviderRegistry()

	genericProvider := NewGenericProvider()
	registry.RegisterProvider(genericProvider)

	var wg sync.WaitGroup
	goroutines := 100
	issuerURL := "https://auth.example.com"

	// Multiple goroutines trying to detect the same provider simultaneously
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := registry.DetectProvider(issuerURL)
			if result != genericProvider {
				t.Errorf("Expected generic provider, got %v", result)
			}
		}()
	}

	wg.Wait()

	// Verify only one cache entry was created
	registry.mu.RLock()
	cacheSize := len(registry.cache)
	registry.mu.RUnlock()

	if cacheSize != 1 {
		t.Errorf("Expected 1 cache entry, got %d", cacheSize)
	}
}

// Benchmark tests
func BenchmarkProviderRegistry_DetectProvider_Cached(b *testing.B) {
	registry := NewProviderRegistry()
	genericProvider := NewGenericProvider()
	registry.RegisterProvider(genericProvider)

	issuerURL := "https://auth.example.com"
	// Warm up cache
	registry.DetectProvider(issuerURL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.DetectProvider(issuerURL)
	}
}

func BenchmarkProviderRegistry_DetectProvider_Uncached(b *testing.B) {
	registry := NewProviderRegistry()
	genericProvider := NewGenericProvider()
	registry.RegisterProvider(genericProvider)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.ClearCache() // Clear cache for each iteration
		registry.DetectProvider("https://auth.example.com")
	}
}

func BenchmarkProviderRegistry_RegisterProvider(b *testing.B) {
	registry := NewProviderRegistry()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider := NewGenericProvider()
		registry.RegisterProvider(provider)
	}
}
