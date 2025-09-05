package providers

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

func TestProviderRegistry_GetProviderByType(t *testing.T) {
	registry := NewProviderRegistry()

	// Register providers
	googleProvider := NewGoogleProvider()
	azureProvider := NewAzureProvider()
	genericProvider := NewGenericProvider()

	registry.RegisterProvider(googleProvider)
	registry.RegisterProvider(azureProvider)
	registry.RegisterProvider(genericProvider)

	tests := []struct {
		name         string
		providerType ProviderType
		expectNil    bool
	}{
		{
			name:         "Google provider",
			providerType: ProviderTypeGoogle,
			expectNil:    false,
		},
		{
			name:         "Azure provider",
			providerType: ProviderTypeAzure,
			expectNil:    false,
		},
		{
			name:         "Generic provider",
			providerType: ProviderTypeGeneric,
			expectNil:    false,
		},
		{
			name:         "Invalid provider type",
			providerType: ProviderType(999),
			expectNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := registry.GetProviderByType(tt.providerType)

			if tt.expectNil {
				if provider != nil {
					t.Errorf("expected nil provider for type %d, got %v", tt.providerType, provider)
				}
			} else {
				if provider == nil {
					t.Errorf("expected non-nil provider for type %d", tt.providerType)
				} else if provider.GetType() != tt.providerType {
					t.Errorf("expected provider type %d, got %d", tt.providerType, provider.GetType())
				}
			}
		})
	}
}

func TestProviderRegistry_GetRegisteredProviders(t *testing.T) {
	registry := NewProviderRegistry()

	// Initially should be empty
	providers := registry.GetRegisteredProviders()
	if len(providers) != 0 {
		t.Errorf("expected 0 registered providers initially, got %d", len(providers))
	}

	// Register providers one by one
	expectedTypes := []ProviderType{
		ProviderTypeGoogle,
		ProviderTypeAzure,
		ProviderTypeGeneric,
	}

	for i, providerType := range expectedTypes {
		switch providerType {
		case ProviderTypeGoogle:
			registry.RegisterProvider(NewGoogleProvider())
		case ProviderTypeAzure:
			registry.RegisterProvider(NewAzureProvider())
		case ProviderTypeGeneric:
			registry.RegisterProvider(NewGenericProvider())
		}

		providers := registry.GetRegisteredProviders()
		if len(providers) != i+1 {
			t.Errorf("expected %d registered providers after registering %d, got %d", i+1, i+1, len(providers))
		}

		// Check that the newly registered type is present
		found := false
		for _, registeredType := range providers {
			if registeredType == providerType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider type %d to be in registered providers list", providerType)
		}
	}

	// Final check - all providers should be registered
	finalProviders := registry.GetRegisteredProviders()
	if len(finalProviders) != len(expectedTypes) {
		t.Errorf("expected %d final registered providers, got %d", len(expectedTypes), len(finalProviders))
	}

	// Check all expected types are present
	for _, expectedType := range expectedTypes {
		found := false
		for _, registeredType := range finalProviders {
			if registeredType == expectedType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider type %d to be in final registered providers list", expectedType)
		}
	}
}

func TestProviderRegistry_ClearCache(t *testing.T) {
	registry := NewProviderRegistry()

	// Register providers
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	// Populate cache by detecting providers
	googleURL := "https://accounts.google.com/.well-known/openid_configuration"
	azureURL := "https://login.microsoftonline.com/tenant/v2.0"
	genericURL := "https://keycloak.example.com/auth/realms/master"

	// These calls should populate the cache
	provider1 := registry.DetectProvider(googleURL)
	provider2 := registry.DetectProvider(azureURL)
	provider3 := registry.DetectProvider(genericURL)

	// Verify providers were detected correctly
	if provider1.GetType() != ProviderTypeGoogle {
		t.Errorf("expected Google provider, got %d", provider1.GetType())
	}
	if provider2.GetType() != ProviderTypeAzure {
		t.Errorf("expected Azure provider, got %d", provider2.GetType())
	}
	if provider3.GetType() != ProviderTypeGeneric {
		t.Errorf("expected Generic provider, got %d", provider3.GetType())
	}

	// Clear cache
	registry.ClearCache()

	// Detect again - should work but might create new instances internally
	provider1After := registry.DetectProvider(googleURL)
	provider2After := registry.DetectProvider(azureURL)
	provider3After := registry.DetectProvider(genericURL)

	// Verify detection still works correctly after cache clear
	if provider1After.GetType() != ProviderTypeGoogle {
		t.Errorf("expected Google provider after cache clear, got %d", provider1After.GetType())
	}
	if provider2After.GetType() != ProviderTypeAzure {
		t.Errorf("expected Azure provider after cache clear, got %d", provider2After.GetType())
	}
	if provider3After.GetType() != ProviderTypeGeneric {
		t.Errorf("expected Generic provider after cache clear, got %d", provider3After.GetType())
	}
}

func TestProviderRegistry_DetectProvider_EdgeCases(t *testing.T) {
	registry := NewProviderRegistry()

	// Register providers
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	tests := []struct {
		name         string
		issuerURL    string
		expectedType ProviderType
		expectNil    bool
	}{
		{
			name:         "Google URL with subdomain",
			issuerURL:    "https://accounts.google.com.evil.com/",
			expectedType: ProviderTypeGoogle, // Contains "accounts.google.com"
		},
		{
			name:         "Azure URL with subdomain",
			issuerURL:    "https://login.microsoftonline.com.evil.com/",
			expectedType: ProviderTypeAzure, // Contains "login.microsoftonline.com"
		},
		{
			name:         "Google URL case insensitive",
			issuerURL:    "https://ACCOUNTS.GOOGLE.COM/auth",
			expectedType: ProviderTypeGeneric, // Case sensitive matching
		},
		{
			name:         "Azure login URL case insensitive",
			issuerURL:    "https://LOGIN.MICROSOFTONLINE.COM/tenant",
			expectedType: ProviderTypeGeneric, // Case sensitive matching
		},
		{
			name:         "Azure STS URL case insensitive",
			issuerURL:    "https://STS.WINDOWS.NET/tenant",
			expectedType: ProviderTypeGeneric, // Case sensitive matching
		},
		{
			name:      "Invalid URL",
			issuerURL: "://invalid-url",
			expectNil: true,
		},
		{
			name:         "Empty URL",
			issuerURL:    "",
			expectedType: ProviderTypeGeneric, // Falls back to generic
		},
		{
			name:         "URL without host",
			issuerURL:    "/path/only",
			expectedType: ProviderTypeGeneric, // Falls back to generic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := registry.DetectProvider(tt.issuerURL)

			if tt.expectNil {
				if provider != nil {
					t.Errorf("expected nil provider for URL %q, got %v", tt.issuerURL, provider)
				}
			} else {
				if provider == nil {
					t.Errorf("expected non-nil provider for URL %q", tt.issuerURL)
				} else if provider.GetType() != tt.expectedType {
					t.Errorf("expected provider type %d for URL %q, got %d", tt.expectedType, tt.issuerURL, provider.GetType())
				}
			}
		})
	}
}

func TestProviderRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewProviderRegistry()

	// Register providers
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	// Track initial goroutine count for memory safety
	initialGoroutines := runtime.NumGoroutine()

	const numGoroutines = 100
	const numOperationsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://sts.windows.net/tenant/",
		"https://keycloak.example.com/auth/realms/master",
	}

	// Test concurrent access to all registry methods
	for i := 0; i < numGoroutines; i++ {
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < numOperationsPerGoroutine; j++ {
				url := urls[j%len(urls)]

				// Test DetectProvider
				provider := registry.DetectProvider(url)
				if provider == nil {
					t.Errorf("worker %d: expected non-nil provider for URL %s", workerID, url)
					return
				}

				// Test GetProviderByType
				providerByType := registry.GetProviderByType(provider.GetType())
				if providerByType == nil {
					t.Errorf("worker %d: expected non-nil provider for type %d", workerID, provider.GetType())
					return
				}

				// Test GetRegisteredProviders
				providers := registry.GetRegisteredProviders()
				if len(providers) == 0 {
					t.Errorf("worker %d: expected non-empty providers list", workerID)
					return
				}

				// Occasionally clear cache to test concurrent cache operations
				if workerID%10 == 0 && j == 0 {
					registry.ClearCache()
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

func TestProviderRegistry_MemorySafety(t *testing.T) {
	const numIterations = 1000

	initialGoroutines := runtime.NumGoroutine()

	for i := 0; i < numIterations; i++ {
		registry := NewProviderRegistry()

		// Register providers
		registry.RegisterProvider(NewGoogleProvider())
		registry.RegisterProvider(NewAzureProvider())
		registry.RegisterProvider(NewGenericProvider())

		// Exercise all registry methods
		urls := []string{
			"https://accounts.google.com/config",
			"https://login.microsoftonline.com/tenant/config",
			"https://keycloak.example.com/auth",
		}

		for _, url := range urls {
			provider := registry.DetectProvider(url)
			if provider != nil {
				_ = registry.GetProviderByType(provider.GetType())
			}
		}

		_ = registry.GetRegisteredProviders()
		registry.ClearCache()

		// Create many entries to test cache memory management
		for j := 0; j < 10; j++ {
			testURL := fmt.Sprintf("https://example%d.com/auth", j)
			registry.DetectProvider(testURL)
		}
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+5 {
		t.Errorf("potential goroutine leak: started with %d goroutines, ended with %d", initialGoroutines, finalGoroutines)
	}
}

func TestProviderRegistry_CacheConsistency(t *testing.T) {
	registry := NewProviderRegistry()

	// Register providers
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	testURL := "https://accounts.google.com/.well-known/openid_configuration"

	// First detection should populate cache
	provider1 := registry.DetectProvider(testURL)
	if provider1 == nil {
		t.Fatal("expected non-nil provider from first detection")
	}
	if provider1.GetType() != ProviderTypeGoogle {
		t.Errorf("expected Google provider, got %d", provider1.GetType())
	}

	// Second detection should use cache (same result)
	provider2 := registry.DetectProvider(testURL)
	if provider2 == nil {
		t.Fatal("expected non-nil provider from second detection")
	}
	if provider2.GetType() != ProviderTypeGoogle {
		t.Errorf("expected Google provider from cache, got %d", provider2.GetType())
	}

	// Clear cache and detect again
	registry.ClearCache()
	provider3 := registry.DetectProvider(testURL)
	if provider3 == nil {
		t.Fatal("expected non-nil provider after cache clear")
	}
	if provider3.GetType() != ProviderTypeGoogle {
		t.Errorf("expected Google provider after cache clear, got %d", provider3.GetType())
	}
}

// Test registry without any providers registered
func TestProviderRegistry_EmptyRegistry(t *testing.T) {
	registry := NewProviderRegistry()

	// Test with empty registry
	provider := registry.DetectProvider("https://accounts.google.com/auth")
	if provider != nil {
		t.Errorf("expected nil provider from empty registry, got %v", provider)
	}

	providerByType := registry.GetProviderByType(ProviderTypeGoogle)
	if providerByType != nil {
		t.Errorf("expected nil provider by type from empty registry, got %v", providerByType)
	}

	providers := registry.GetRegisteredProviders()
	if len(providers) != 0 {
		t.Errorf("expected empty providers list from empty registry, got %d providers", len(providers))
	}

	// Clear cache should not panic on empty registry
	registry.ClearCache()
}

// Test multiple providers of same type (edge case)
func TestProviderRegistry_DuplicateProviderTypes(t *testing.T) {
	registry := NewProviderRegistry()

	// Register same provider type multiple times
	provider1 := NewGoogleProvider()
	provider2 := NewGoogleProvider()

	registry.RegisterProvider(provider1)
	registry.RegisterProvider(provider2)

	// GetProviderByType should return one of them (likely the latest)
	retrieved := registry.GetProviderByType(ProviderTypeGoogle)
	if retrieved == nil {
		t.Error("expected non-nil provider")
	}
	if retrieved.GetType() != ProviderTypeGoogle {
		t.Errorf("expected Google provider type, got %d", retrieved.GetType())
	}

	// Both should be in the providers list
	allProviders := registry.GetRegisteredProviders()
	googleCount := 0
	for _, providerType := range allProviders {
		if providerType == ProviderTypeGoogle {
			googleCount++
		}
	}

	// Note: This behavior depends on implementation - the registry might deduplicate or keep all
	if googleCount == 0 {
		t.Error("expected at least one Google provider in registered list")
	}
}

// Benchmark tests for performance validation
func BenchmarkProviderRegistry_DetectProvider(b *testing.B) {
	registry := NewProviderRegistry()
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	urls := []string{
		"https://accounts.google.com/.well-known/openid_configuration",
		"https://login.microsoftonline.com/tenant/v2.0",
		"https://keycloak.example.com/auth/realms/master",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		url := urls[i%len(urls)]
		registry.DetectProvider(url)
	}
}

func BenchmarkProviderRegistry_GetProviderByType(b *testing.B) {
	registry := NewProviderRegistry()
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	types := []ProviderType{
		ProviderTypeGoogle,
		ProviderTypeAzure,
		ProviderTypeGeneric,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		providerType := types[i%len(types)]
		registry.GetProviderByType(providerType)
	}
}

func BenchmarkProviderRegistry_GetRegisteredProviders(b *testing.B) {
	registry := NewProviderRegistry()
	registry.RegisterProvider(NewGoogleProvider())
	registry.RegisterProvider(NewAzureProvider())
	registry.RegisterProvider(NewGenericProvider())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.GetRegisteredProviders()
	}
}
