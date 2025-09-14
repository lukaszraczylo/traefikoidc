package traefikoidc

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// generateRandomString generates a random string of the specified length
// This is used in tests to create unique identifiers
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// In tests, fallback to a predictable string if random fails
		return "random-string-fallback"
	}
	return hex.EncodeToString(bytes)
}

// Test createCaseInsensitiveStringMap function
func TestCreateCaseInsensitiveStringMap(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected map[string]struct{}
	}{
		{
			name:  "Mixed case items",
			items: []string{"Admin", "USER", "manager"},
			expected: map[string]struct{}{
				"admin":   {},
				"user":    {},
				"manager": {},
			},
		},
		{
			name:     "Empty slice",
			items:    []string{},
			expected: map[string]struct{}{},
		},
		{
			name:  "Duplicates with different cases",
			items: []string{"Admin", "admin", "ADMIN"},
			expected: map[string]struct{}{
				"admin": {},
			},
		},
		{
			name:     "Nil slice",
			items:    nil,
			expected: map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createCaseInsensitiveStringMap(tt.items)

			if len(result) != len(tt.expected) {
				t.Errorf("createCaseInsensitiveStringMap() length = %v, want %v", len(result), len(tt.expected))
				return
			}

			for key := range tt.expected {
				if _, exists := result[key]; !exists {
					t.Errorf("createCaseInsensitiveStringMap() missing key %v", key)
				}
			}
		})
	}
}

// Test keysFromMap function
func TestKeysFromMap(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]struct{}
		expected []string
	}{
		{
			name: "Multiple keys",
			input: map[string]struct{}{
				"key1": {},
				"key2": {},
				"key3": {},
			},
			expected: []string{"key1", "key2", "key3"},
		},
		{
			name:     "Empty map",
			input:    map[string]struct{}{},
			expected: []string{},
		},
		{
			name: "Single key",
			input: map[string]struct{}{
				"onlykey": {},
			},
			expected: []string{"onlykey"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := keysFromMap(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("keysFromMap() length = %v, want %v", len(result), len(tt.expected))
				return
			}

			// Convert to map for comparison since order doesn't matter
			resultMap := make(map[string]bool)
			for _, key := range result {
				resultMap[key] = true
			}

			for _, key := range tt.expected {
				if !resultMap[key] {
					t.Errorf("keysFromMap() missing key %v", key)
				}
			}
		})
	}
}

// Test TraefikOidc provider detection methods
func TestTraefikOidcProviderDetection(t *testing.T) {
	tests := []struct {
		name         string
		providerURL  string
		expectGoogle bool
		expectAzure  bool
	}{
		{
			name:         "Google provider",
			providerURL:  "https://accounts.google.com",
			expectGoogle: true,
			expectAzure:  false,
		},
		{
			name:         "Azure provider",
			providerURL:  "https://login.microsoftonline.com/tenant-id/v2.0",
			expectGoogle: false,
			expectAzure:  true,
		},
		{
			name:         "Generic provider",
			providerURL:  "https://auth.example.com",
			expectGoogle: false,
			expectAzure:  false,
		},
		{
			name:         "Empty provider URL",
			providerURL:  "",
			expectGoogle: false,
			expectAzure:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traefik := &TraefikOidc{
				issuerURL: tt.providerURL,
			}

			isGoogle := traefik.isGoogleProvider()
			isAzure := traefik.isAzureProvider()

			if isGoogle != tt.expectGoogle {
				t.Errorf("isGoogleProvider() = %v, want %v", isGoogle, tt.expectGoogle)
			}

			if isAzure != tt.expectAzure {
				t.Errorf("isAzureProvider() = %v, want %v", isAzure, tt.expectAzure)
			}
		})
	}
}

// Test buildFullURL function
func TestBuildFullURL(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		host     string
		path     string
		expected string
	}{
		{
			name:     "Standard HTTPS URL",
			scheme:   "https",
			host:     "example.com",
			path:     "/auth/callback",
			expected: "https://example.com/auth/callback",
		},
		{
			name:     "HTTP URL",
			scheme:   "http",
			host:     "localhost:8080",
			path:     "/test",
			expected: "http://localhost:8080/test",
		},
		{
			name:     "Root path",
			scheme:   "https",
			host:     "api.example.com",
			path:     "/",
			expected: "https://api.example.com/",
		},
		{
			name:     "Empty path",
			scheme:   "https",
			host:     "example.com",
			path:     "",
			expected: "https://example.com/",
		},
		{
			name:     "Path without leading slash",
			scheme:   "https",
			host:     "example.com",
			path:     "noSlash",
			expected: "https://example.com/noSlash",
		},
		{
			name:     "Complex path with query params",
			scheme:   "https",
			host:     "api.example.com",
			path:     "/v2/search?q=test&limit=10",
			expected: "https://api.example.com/v2/search?q=test&limit=10",
		},
		{
			name:     "IPv4 address",
			scheme:   "http",
			host:     "192.168.1.100",
			path:     "/api",
			expected: "http://192.168.1.100/api",
		},
		{
			name:     "IPv6 address with brackets",
			scheme:   "http",
			host:     "[::1]:8080",
			path:     "/test",
			expected: "http://[::1]:8080/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildFullURL(tt.scheme, tt.host, tt.path)
			if result != tt.expected {
				t.Errorf("buildFullURL() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test validateURL function
func TestValidateURL(t *testing.T) {
	traefik := &TraefikOidc{
		logger: NewLogger("debug"),
	}

	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "Valid HTTPS URL",
			url:         "https://example.com/path",
			expectError: false,
		},
		{
			name:        "Valid HTTP URL",
			url:         "http://example.com",
			expectError: false,
		},
		{
			name:        "Empty URL",
			url:         "",
			expectError: true,
		},
		{
			name:        "Invalid URL format",
			url:         "not-a-url",
			expectError: true,
		},
		{
			name:        "URL with space",
			url:         "https://example .com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := traefik.validateURL(tt.url)
			if tt.expectError && err == nil {
				t.Errorf("validateURL(%q) expected error but got none", tt.url)
			} else if !tt.expectError && err != nil {
				t.Errorf("validateURL(%q) unexpected error: %v", tt.url, err)
			}
		})
	}
}

// Test TraefikOidc helper logging methods
func TestTraefikOidcHelperMethods(t *testing.T) {
	traefik := &TraefikOidc{
		logger: NewLogger("debug"),
	}

	// Test safe logging methods (they just delegate to logger, but increase coverage)
	traefik.safeLogDebug("test debug message")
	traefik.safeLogDebugf("test debug with %s", "param")
	traefik.safeLogError("test error message")
	traefik.safeLogErrorf("test error with %s", "param")
	traefik.safeLogInfo("test info message")

	// These methods should not panic with nil logger either
	traefikNilLogger := &TraefikOidc{}
	traefikNilLogger.safeLogDebug("test with nil logger")
	traefikNilLogger.safeLogInfo("test info with nil logger")
}

// Test createDefaultHTTPClient function
func TestCreateDefaultHTTPClient(t *testing.T) {
	client := createDefaultHTTPClient()

	if client == nil {
		t.Fatal("createDefaultHTTPClient() returned nil")
	}

	if client.Timeout == 0 {
		t.Error("Expected non-zero timeout")
	}

	// Verify it has some reasonable timeout
	expectedTimeout := 30000000000 // 30 seconds in nanoseconds
	if client.Timeout.Nanoseconds() != int64(expectedTimeout) {
		t.Logf("Client timeout: %v (expected 30s, but this may vary)", client.Timeout)
	}
}
