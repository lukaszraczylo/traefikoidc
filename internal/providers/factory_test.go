package providers

import (
	"strings"
	"testing"
)

// TestProviderFactory_NewProviderFactory tests the factory constructor
func TestProviderFactory_NewProviderFactory(t *testing.T) {
	factory := NewProviderFactory()

	if factory == nil {
		t.Fatal("Expected factory to be created, got nil")
	}

	if factory.registry == nil {
		t.Error("Expected registry to be initialized")
	}
}

// TestProviderFactory_CreateProvider tests provider creation by issuer URL
func TestProviderFactory_CreateProvider(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name         string
		issuerURL    string
		expectedType ProviderType
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "Google provider",
			issuerURL:    "https://accounts.google.com",
			expectedType: ProviderTypeGoogle,
			wantErr:      false,
		},
		{
			name:         "Google provider with path",
			issuerURL:    "https://accounts.google.com/oauth2",
			expectedType: ProviderTypeGoogle,
			wantErr:      false,
		},
		{
			name:         "Azure provider - login.microsoftonline.com",
			issuerURL:    "https://login.microsoftonline.com/tenant-id/v2.0",
			expectedType: ProviderTypeAzure,
			wantErr:      false,
		},
		{
			name:         "Azure provider - sts.windows.net",
			issuerURL:    "https://sts.windows.net/tenant-id",
			expectedType: ProviderTypeAzure,
			wantErr:      false,
		},
		{
			name:         "Generic provider",
			issuerURL:    "https://auth.example.com",
			expectedType: ProviderTypeGeneric,
			wantErr:      false,
		},
		{
			name:      "Empty issuer URL",
			issuerURL: "",
			wantErr:   true,
			errMsg:    "issuer URL cannot be empty",
		},
		{
			name:      "Invalid URL format",
			issuerURL: "not-a-url",
			wantErr:   true,
			errMsg:    "invalid issuer URL format",
		},
		{
			name:      "URL without scheme",
			issuerURL: "example.com",
			wantErr:   true,
			errMsg:    "invalid issuer URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.CreateProvider(tt.issuerURL)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if provider == nil {
				t.Fatal("Expected provider to be created, got nil")
			}

			if provider.GetType() != tt.expectedType {
				t.Errorf("Expected provider type %v, got %v", tt.expectedType, provider.GetType())
			}
		})
	}
}

// TestProviderFactory_CreateProviderByType tests provider creation by type
func TestProviderFactory_CreateProviderByType(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name         string
		providerType ProviderType
		expectedType ProviderType
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "Generic provider",
			providerType: ProviderTypeGeneric,
			expectedType: ProviderTypeGeneric,
			wantErr:      false,
		},
		{
			name:         "Google provider",
			providerType: ProviderTypeGoogle,
			expectedType: ProviderTypeGoogle,
			wantErr:      false,
		},
		{
			name:         "Azure provider",
			providerType: ProviderTypeAzure,
			expectedType: ProviderTypeAzure,
			wantErr:      false,
		},
		{
			name:         "Invalid provider type",
			providerType: ProviderType(999),
			wantErr:      true,
			errMsg:       "unsupported provider type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.CreateProviderByType(tt.providerType)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if provider == nil {
				t.Fatal("Expected provider to be created, got nil")
			}

			if provider.GetType() != tt.expectedType {
				t.Errorf("Expected provider type %v, got %v", tt.expectedType, provider.GetType())
			}
		})
	}
}

// TestProviderFactory_GetSupportedProviders tests listing supported providers
func TestProviderFactory_GetSupportedProviders(t *testing.T) {
	factory := NewProviderFactory()
	supported := factory.GetSupportedProviders()

	// Verify expected provider types are present
	expectedTypes := []ProviderType{
		ProviderTypeGeneric,
		ProviderTypeGoogle,
		ProviderTypeAzure,
	}

	for _, expectedType := range expectedTypes {
		if _, exists := supported[expectedType]; !exists {
			t.Errorf("Expected provider type %v to be supported", expectedType)
		}
	}

	// Verify Google patterns
	googlePatterns := supported[ProviderTypeGoogle]
	if len(googlePatterns) != 1 || googlePatterns[0] != "accounts.google.com" {
		t.Errorf("Expected Google patterns ['accounts.google.com'], got %v", googlePatterns)
	}

	// Verify Azure patterns
	azurePatterns := supported[ProviderTypeAzure]
	expectedAzurePatterns := []string{"login.microsoftonline.com", "sts.windows.net"}
	if len(azurePatterns) != len(expectedAzurePatterns) {
		t.Errorf("Expected %d Azure patterns, got %d", len(expectedAzurePatterns), len(azurePatterns))
	}

	for _, expectedPattern := range expectedAzurePatterns {
		found := false
		for _, pattern := range azurePatterns {
			if pattern == expectedPattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Azure pattern '%s' not found", expectedPattern)
		}
	}

	// Verify Generic patterns
	genericPatterns := supported[ProviderTypeGeneric]
	if len(genericPatterns) != 1 || genericPatterns[0] != "*" {
		t.Errorf("Expected Generic patterns ['*'], got %v", genericPatterns)
	}
}

// TestProviderFactory_DetectProviderType tests provider type detection
func TestProviderFactory_DetectProviderType(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name         string
		issuerURL    string
		expectedType ProviderType
		wantErr      bool
	}{
		{
			name:         "Google provider detection",
			issuerURL:    "https://accounts.google.com",
			expectedType: ProviderTypeGoogle,
			wantErr:      false,
		},
		{
			name:         "Azure provider detection",
			issuerURL:    "https://login.microsoftonline.com/tenant/v2.0",
			expectedType: ProviderTypeAzure,
			wantErr:      false,
		},
		{
			name:         "Generic provider detection",
			issuerURL:    "https://auth.example.com",
			expectedType: ProviderTypeGeneric,
			wantErr:      false,
		},
		{
			name:      "Invalid URL",
			issuerURL: "not-a-url",
			wantErr:   true,
		},
		{
			name:      "Empty URL",
			issuerURL: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerType, err := factory.DetectProviderType(tt.issuerURL)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if providerType != tt.expectedType {
				t.Errorf("Expected provider type %v, got %v", tt.expectedType, providerType)
			}
		})
	}
}

// TestProviderFactory_IsProviderSupported tests provider support checking
func TestProviderFactory_IsProviderSupported(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name      string
		issuerURL string
		expected  bool
	}{
		{
			name:      "Google provider supported",
			issuerURL: "https://accounts.google.com",
			expected:  true,
		},
		{
			name:      "Google provider with subdomain supported",
			issuerURL: "https://accounts.google.com/oauth2",
			expected:  true,
		},
		{
			name:      "Azure login.microsoftonline.com supported",
			issuerURL: "https://login.microsoftonline.com/tenant/v2.0",
			expected:  true,
		},
		{
			name:      "Azure sts.windows.net supported",
			issuerURL: "https://sts.windows.net/tenant",
			expected:  true,
		},
		{
			name:      "Generic provider supported (wildcard)",
			issuerURL: "https://auth.example.com",
			expected:  true,
		},
		{
			name:      "Any valid URL supported (wildcard)",
			issuerURL: "https://custom-auth.company.org",
			expected:  true,
		},
		{
			name:      "Empty URL not supported",
			issuerURL: "",
			expected:  false,
		},
		{
			name:      "Invalid URL format not supported",
			issuerURL: "not-a-url",
			expected:  false,
		},
		{
			name:      "URL without scheme not supported",
			issuerURL: "example.com",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := factory.IsProviderSupported(tt.issuerURL)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestProviderFactory_IntegrationTest tests the full flow
func TestProviderFactory_IntegrationTest(t *testing.T) {
	factory := NewProviderFactory()

	// Test Google provider flow
	t.Run("Google Provider Flow", func(t *testing.T) {
		// Check if supported
		if !factory.IsProviderSupported("https://accounts.google.com") {
			t.Error("Google provider should be supported")
		}

		// Detect type
		providerType, err := factory.DetectProviderType("https://accounts.google.com")
		if err != nil {
			t.Errorf("Unexpected error detecting Google provider: %v", err)
		}
		if providerType != ProviderTypeGoogle {
			t.Errorf("Expected ProviderTypeGoogle, got %v", providerType)
		}

		// Create provider by URL
		provider, err := factory.CreateProvider("https://accounts.google.com")
		if err != nil {
			t.Errorf("Unexpected error creating Google provider: %v", err)
		}
		if provider.GetType() != ProviderTypeGoogle {
			t.Errorf("Expected ProviderTypeGoogle, got %v", provider.GetType())
		}

		// Create provider by type
		provider2, err := factory.CreateProviderByType(ProviderTypeGoogle)
		if err != nil {
			t.Errorf("Unexpected error creating Google provider by type: %v", err)
		}
		if provider2.GetType() != ProviderTypeGoogle {
			t.Errorf("Expected ProviderTypeGoogle, got %v", provider2.GetType())
		}
	})

	// Test Azure provider flow
	t.Run("Azure Provider Flow", func(t *testing.T) {
		azureURL := "https://login.microsoftonline.com/tenant/v2.0"

		// Check if supported
		if !factory.IsProviderSupported(azureURL) {
			t.Error("Azure provider should be supported")
		}

		// Detect type
		providerType, err := factory.DetectProviderType(azureURL)
		if err != nil {
			t.Errorf("Unexpected error detecting Azure provider: %v", err)
		}
		if providerType != ProviderTypeAzure {
			t.Errorf("Expected ProviderTypeAzure, got %v", providerType)
		}

		// Create provider
		provider, err := factory.CreateProvider(azureURL)
		if err != nil {
			t.Errorf("Unexpected error creating Azure provider: %v", err)
		}
		if provider.GetType() != ProviderTypeAzure {
			t.Errorf("Expected ProviderTypeAzure, got %v", provider.GetType())
		}
	})

	// Test Generic provider flow
	t.Run("Generic Provider Flow", func(t *testing.T) {
		genericURL := "https://auth.custom-provider.com"

		// Check if supported
		if !factory.IsProviderSupported(genericURL) {
			t.Error("Generic provider should be supported")
		}

		// Detect type
		providerType, err := factory.DetectProviderType(genericURL)
		if err != nil {
			t.Errorf("Unexpected error detecting generic provider: %v", err)
		}
		if providerType != ProviderTypeGeneric {
			t.Errorf("Expected ProviderTypeGeneric, got %v", providerType)
		}

		// Create provider
		provider, err := factory.CreateProvider(genericURL)
		if err != nil {
			t.Errorf("Unexpected error creating generic provider: %v", err)
		}
		if provider.GetType() != ProviderTypeGeneric {
			t.Errorf("Expected ProviderTypeGeneric, got %v", provider.GetType())
		}
	})
}

// TestProviderFactory_CaseInsensitiveHostMatching tests case insensitive host matching
func TestProviderFactory_CaseInsensitiveHostMatching(t *testing.T) {
	factory := NewProviderFactory()

	tests := []struct {
		name         string
		issuerURL    string
		expectedType ProviderType
	}{
		{
			name:         "Google with uppercase",
			issuerURL:    "https://ACCOUNTS.GOOGLE.COM",
			expectedType: ProviderTypeGoogle,
		},
		{
			name:         "Google with mixed case",
			issuerURL:    "https://Accounts.Google.Com",
			expectedType: ProviderTypeGoogle,
		},
		{
			name:         "Azure with uppercase",
			issuerURL:    "https://LOGIN.MICROSOFTONLINE.COM/tenant",
			expectedType: ProviderTypeAzure,
		},
		{
			name:         "Azure STS with mixed case",
			issuerURL:    "https://Sts.Windows.Net/tenant",
			expectedType: ProviderTypeAzure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should be supported
			if !factory.IsProviderSupported(tt.issuerURL) {
				t.Errorf("URL %s should be supported", tt.issuerURL)
			}

			// Should detect correct type
			providerType, err := factory.DetectProviderType(tt.issuerURL)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if providerType != tt.expectedType {
				t.Errorf("Expected %v, got %v", tt.expectedType, providerType)
			}

			// Should create correct provider
			provider, err := factory.CreateProvider(tt.issuerURL)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if provider.GetType() != tt.expectedType {
				t.Errorf("Expected %v, got %v", tt.expectedType, provider.GetType())
			}
		})
	}
}

// Benchmark tests
func BenchmarkProviderFactory_CreateProvider(b *testing.B) {
	factory := NewProviderFactory()
	issuerURL := "https://accounts.google.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		factory.CreateProvider(issuerURL)
	}
}

func BenchmarkProviderFactory_IsProviderSupported(b *testing.B) {
	factory := NewProviderFactory()
	issuerURL := "https://auth.example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		factory.IsProviderSupported(issuerURL)
	}
}

func BenchmarkProviderFactory_DetectProviderType(b *testing.B) {
	factory := NewProviderFactory()
	issuerURL := "https://login.microsoftonline.com/tenant"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		factory.DetectProviderType(issuerURL)
	}
}
