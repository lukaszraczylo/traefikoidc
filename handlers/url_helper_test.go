package handlers

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestURLHelper_NewURLHelper tests the URLHelper constructor
func TestURLHelper_NewURLHelper(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	if helper == nil {
		t.Fatal("Expected URLHelper to be created, got nil")
	}

	if helper.logger != logger {
		t.Error("Logger not set correctly")
	}
}

// TestURLHelper_DetermineExcludedURL tests URL exclusion checking
func TestURLHelper_DetermineExcludedURL(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name         string
		currentURL   string
		excludedURLs map[string]struct{}
		expected     bool
	}{
		{
			name:       "Exact match",
			currentURL: "/health",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: true,
		},
		{
			name:       "Prefix match",
			currentURL: "/health/status",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: true,
		},
		{
			name:       "No match",
			currentURL: "/api/users",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: false,
		},
		{
			name:       "Multiple exclusions - first match",
			currentURL: "/api/health",
			excludedURLs: map[string]struct{}{
				"/api":    {},
				"/health": {},
			},
			expected: true,
		},
		{
			name:       "Multiple exclusions - second match",
			currentURL: "/health/check",
			excludedURLs: map[string]struct{}{
				"/api":    {},
				"/health": {},
			},
			expected: true,
		},
		{
			name:         "Empty excluded URLs",
			currentURL:   "/api/users",
			excludedURLs: map[string]struct{}{},
			expected:     false,
		},
		{
			name:       "Root path exclusion",
			currentURL: "/anything",
			excludedURLs: map[string]struct{}{
				"/": {},
			},
			expected: true,
		},
		{
			name:       "Case sensitive matching",
			currentURL: "/API/users",
			excludedURLs: map[string]struct{}{
				"/api": {},
			},
			expected: false,
		},
		{
			name:       "Partial substring but not prefix",
			currentURL: "/user/api/test",
			excludedURLs: map[string]struct{}{
				"/api": {},
			},
			expected: false,
		},
		{
			name:       "Empty current URL",
			currentURL: "",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: false,
		},
		{
			name:       "URL with query parameters",
			currentURL: "/health?status=ok",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := helper.DetermineExcludedURL(tt.currentURL, tt.excludedURLs)
			if result != tt.expected {
				t.Errorf("DetermineExcludedURL() = %v, expected %v", result, tt.expected)
			}

			// Verify debug logging for excluded URLs
			if result && len(logger.debugMessages) > 0 {
				// Should have logged a debug message for excluded URL
				found := false
				for _, msg := range logger.debugMessages {
					if msg == "URL is excluded - got %s / excluded hit: %s" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected debug message for excluded URL")
				}
			}

			// Reset logger messages for next test
			logger.debugMessages = nil
		})
	}
}

// TestURLHelper_DetermineScheme tests scheme determination
func TestURLHelper_DetermineScheme(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedScheme string
	}{
		{
			name: "X-Forwarded-Proto header present - https",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			},
			expectedScheme: "https",
		},
		{
			name: "X-Forwarded-Proto header present - http",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Header.Set("X-Forwarded-Proto", "http")
				return req
			},
			expectedScheme: "http",
		},
		{
			name: "TLS connection without X-Forwarded-Proto",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com", nil)
				req.TLS = &tls.ConnectionState{} // Simulate TLS connection
				return req
			},
			expectedScheme: "https",
		},
		{
			name: "No TLS and no X-Forwarded-Proto",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				return req
			},
			expectedScheme: "http",
		},
		{
			name: "X-Forwarded-Proto takes precedence over TLS",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com", nil)
				req.TLS = &tls.ConnectionState{} // Simulate TLS connection
				req.Header.Set("X-Forwarded-Proto", "http")
				return req
			},
			expectedScheme: "http",
		},
		{
			name: "Empty X-Forwarded-Proto falls back to TLS",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com", nil)
				req.TLS = &tls.ConnectionState{} // Simulate TLS connection
				req.Header.Set("X-Forwarded-Proto", "")
				return req
			},
			expectedScheme: "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			result := helper.DetermineScheme(req)
			if result != tt.expectedScheme {
				t.Errorf("DetermineScheme() = %v, expected %v", result, tt.expectedScheme)
			}
		})
	}
}

// TestURLHelper_DetermineHost tests host determination
func TestURLHelper_DetermineHost(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name         string
		setupRequest func() *http.Request
		expectedHost string
	}{
		{
			name: "X-Forwarded-Host header present",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Host = "internal.example.com"
				req.Header.Set("X-Forwarded-Host", "public.example.com")
				return req
			},
			expectedHost: "public.example.com",
		},
		{
			name: "No X-Forwarded-Host, use req.Host",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Host = "direct.example.com"
				return req
			},
			expectedHost: "direct.example.com",
		},
		{
			name: "Empty X-Forwarded-Host falls back to req.Host",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Host = "fallback.example.com"
				req.Header.Set("X-Forwarded-Host", "")
				return req
			},
			expectedHost: "fallback.example.com",
		},
		{
			name: "X-Forwarded-Host with port",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Host = "internal.example.com:8080"
				req.Header.Set("X-Forwarded-Host", "public.example.com:443")
				return req
			},
			expectedHost: "public.example.com:443",
		},
		{
			name: "req.Host with port",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com:8080", nil)
				req.Host = "example.com:8080"
				return req
			},
			expectedHost: "example.com:8080",
		},
		{
			name: "Multiple X-Forwarded-Host values (first one used)",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com", nil)
				req.Host = "internal.example.com"
				req.Header.Set("X-Forwarded-Host", "first.example.com, second.example.com")
				return req
			},
			expectedHost: "first.example.com, second.example.com", // Header value as-is
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			result := helper.DetermineHost(req)
			if result != tt.expectedHost {
				t.Errorf("DetermineHost() = %v, expected %v", result, tt.expectedHost)
			}
		})
	}
}

// TestURLHelper_DetermineSchemeAndHost_Integration tests scheme and host working together
func TestURLHelper_DetermineSchemeAndHost_Integration(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedScheme string
		expectedHost   string
	}{
		{
			name: "Both headers present",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://internal.example.com", nil)
				req.Host = "internal.example.com"
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "public.example.com")
				return req
			},
			expectedScheme: "https",
			expectedHost:   "public.example.com",
		},
		{
			name: "Neither header present, TLS connection",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://secure.example.com", nil)
				req.Host = "secure.example.com"
				req.TLS = &tls.ConnectionState{} // Simulate TLS connection
				return req
			},
			expectedScheme: "https",
			expectedHost:   "secure.example.com",
		},
		{
			name: "Neither header present, no TLS",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://plain.example.com", nil)
				req.Host = "plain.example.com"
				return req
			},
			expectedScheme: "http",
			expectedHost:   "plain.example.com",
		},
		{
			name: "Mixed - only scheme header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://mixed.example.com", nil)
				req.Host = "mixed.example.com"
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			},
			expectedScheme: "https",
			expectedHost:   "mixed.example.com",
		},
		{
			name: "Mixed - only host header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://mixed.example.com", nil)
				req.Host = "internal.example.com"
				req.Header.Set("X-Forwarded-Host", "external.example.com")
				return req
			},
			expectedScheme: "http",
			expectedHost:   "external.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()

			scheme := helper.DetermineScheme(req)
			host := helper.DetermineHost(req)

			if scheme != tt.expectedScheme {
				t.Errorf("DetermineScheme() = %v, expected %v", scheme, tt.expectedScheme)
			}

			if host != tt.expectedHost {
				t.Errorf("DetermineHost() = %v, expected %v", host, tt.expectedHost)
			}

			// Test that we can build a complete URL
			fullURL := scheme + "://" + host + "/callback"
			expectedURL := tt.expectedScheme + "://" + tt.expectedHost + "/callback"
			if fullURL != expectedURL {
				t.Errorf("Combined URL = %v, expected %v", fullURL, expectedURL)
			}
		})
	}
}

// Benchmark tests to ensure the helper methods are performant
func BenchmarkURLHelper_DetermineExcludedURL(b *testing.B) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)
	excludedURLs := map[string]struct{}{
		"/health":  {},
		"/metrics": {},
		"/status":  {},
		"/api/v1":  {},
		"/api/v2":  {},
		"/static":  {},
		"/assets":  {},
		"/favicon": {},
		"/robots":  {},
		"/sitemap": {},
	}

	testURL := "/api/users"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.DetermineExcludedURL(testURL, excludedURLs)
	}
}

func BenchmarkURLHelper_DetermineScheme(b *testing.B) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.DetermineScheme(req)
	}
}

func BenchmarkURLHelper_DetermineHost(b *testing.B) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Host = "internal.example.com"
	req.Header.Set("X-Forwarded-Host", "external.example.com")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.DetermineHost(req)
	}
}
