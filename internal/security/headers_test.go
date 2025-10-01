package security

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()

	if config.ContentSecurityPolicy == "" {
		t.Error("Expected default CSP to be set")
	}

	if config.FrameOptions != "DENY" {
		t.Errorf("Expected frame options to be DENY, got %s", config.FrameOptions)
	}

	if !config.DisableServerHeader {
		t.Error("Expected server header to be disabled by default")
	}
}

func TestSecurityHeadersMiddleware_Apply(t *testing.T) {
	config := DefaultSecurityConfig()
	middleware := NewSecurityHeadersMiddleware(config)

	// Create a mock request (HTTPS)
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{} // Mock TLS

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Apply security headers
	middleware.Apply(rr, req)

	headers := rr.Header()

	// Check that security headers are set
	if headers.Get("Content-Security-Policy") == "" {
		t.Error("Expected CSP header to be set")
	}

	if headers.Get("X-Frame-Options") != "DENY" {
		t.Errorf("Expected X-Frame-Options to be DENY, got %s", headers.Get("X-Frame-Options"))
	}

	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options to be nosniff, got %s", headers.Get("X-Content-Type-Options"))
	}

	if headers.Get("X-XSS-Protection") != "1; mode=block" {
		t.Errorf("Expected X-XSS-Protection to be '1; mode=block', got %s", headers.Get("X-XSS-Protection"))
	}

	// Check HSTS for HTTPS requests
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("Expected HSTS header for HTTPS request")
	}

	if !strings.Contains(hsts, "max-age=") {
		t.Error("Expected HSTS header to contain max-age")
	}
}

func TestSecurityHeadersMiddleware_HTTPSOnly(t *testing.T) {
	config := DefaultSecurityConfig()
	middleware := NewSecurityHeadersMiddleware(config)

	// Test HTTP request (no HSTS)
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	rr := httptest.NewRecorder()

	middleware.Apply(rr, req)

	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("Expected no HSTS header for HTTP request")
	}

	// Test HTTPS request (with HSTS)
	req = httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{}
	rr = httptest.NewRecorder()

	middleware.Apply(rr, req)

	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Error("Expected HSTS header for HTTPS request")
	}
}

func TestCORSHeaders(t *testing.T) {
	config := DefaultSecurityConfig()
	config.CORSEnabled = true
	config.CORSAllowedOrigins = []string{"https://example.com", "https://*.test.com"}
	config.CORSAllowCredentials = true

	middleware := NewSecurityHeadersMiddleware(config)

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{
			name:           "exact match",
			origin:         "https://example.com",
			expectedOrigin: "https://example.com",
		},
		{
			name:           "wildcard subdomain match",
			origin:         "https://api.test.com",
			expectedOrigin: "https://api.test.com",
		},
		{
			name:           "no match",
			origin:         "https://malicious.com",
			expectedOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://example.com/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			rr := httptest.NewRecorder()
			middleware.Apply(rr, req)

			actualOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			if actualOrigin != tt.expectedOrigin {
				t.Errorf("Expected origin %s, got %s", tt.expectedOrigin, actualOrigin)
			}

			if tt.expectedOrigin != "" {
				// Should have credentials header
				if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Error("Expected credentials header for allowed origin")
				}
			}
		})
	}
}

func TestCORSPreflight(t *testing.T) {
	config := DefaultSecurityConfig()
	config.CORSEnabled = true
	config.CORSAllowedOrigins = []string{"*"}
	config.CORSAllowedMethods = []string{"GET", "POST", "OPTIONS"}

	middleware := NewSecurityHeadersMiddleware(config)

	req := httptest.NewRequest("OPTIONS", "https://example.com/test", nil)
	req.Header.Set("Origin", "https://other.com")

	rr := httptest.NewRecorder()
	middleware.Apply(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Expected wildcard origin for preflight request")
	}

	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Expected methods header for preflight request")
	}

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for preflight, got %d", rr.Code)
	}
}

func TestOriginMatching(t *testing.T) {
	config := &SecurityHeadersConfig{
		CORSEnabled: true,
		CORSAllowedOrigins: []string{
			"https://example.com",
			"https://*.example.com",
			"http://localhost:*",
		},
	}

	middleware := NewSecurityHeadersMiddleware(config)

	tests := []struct {
		origin   string
		expected bool
	}{
		{"https://example.com", true},
		{"https://api.example.com", true},
		{"https://sub.api.example.com", true},
		{"http://localhost:3000", true},
		{"http://localhost:8080", true},
		{"https://malicious.com", false},
		{"http://example.com", false},           // Different scheme
		{"https://example.com.evil.com", false}, // Domain suffix attack
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			result := middleware.isOriginAllowed(tt.origin)
			if result != tt.expected {
				t.Errorf("Origin %s: expected %v, got %v", tt.origin, tt.expected, result)
			}
		})
	}
}

func TestDevelopmentMode(t *testing.T) {
	config := DevelopmentSecurityConfig()

	if !config.DevelopmentMode {
		t.Error("Expected development mode to be enabled")
	}

	if !config.CORSEnabled {
		t.Error("Expected CORS to be enabled in development mode")
	}

	if config.FrameOptions != "SAMEORIGIN" {
		t.Errorf("Expected frame options to be SAMEORIGIN in dev mode, got %s", config.FrameOptions)
	}

	// Should be less strict CSP
	if strings.Contains(config.ContentSecurityPolicy, "'none'") {
		t.Error("Expected less strict CSP in development mode")
	}
}

func TestStrictSecurityConfig(t *testing.T) {
	config := StrictSecurityConfig()

	if !strings.Contains(config.ContentSecurityPolicy, "'none'") {
		t.Error("Expected very strict CSP with 'none' defaults")
	}

	if config.CORSEnabled {
		t.Error("Expected CORS to be disabled in strict mode")
	}

	if config.FrameOptions != "DENY" {
		t.Error("Expected frame options to be DENY in strict mode")
	}
}

func TestAPISecurityConfig(t *testing.T) {
	config := APISecurityConfig()

	if !config.CORSEnabled {
		t.Error("Expected CORS to be enabled for API config")
	}

	methods := config.CORSAllowedMethods
	expectedMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}

	for _, method := range expectedMethods {
		found := false
		for _, allowed := range methods {
			if allowed == method {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected method %s to be allowed in API config", method)
		}
	}
}

func TestMiddlewareWrap(t *testing.T) {
	config := DefaultSecurityConfig()
	middleware := NewSecurityHeadersMiddleware(config)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with security middleware
	wrappedHandler := middleware.Wrap(handler)

	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rr, req)

	// Check response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if rr.Body.String() != "OK" {
		t.Errorf("Expected body 'OK', got %s", rr.Body.String())
	}

	// Check security headers were applied
	if rr.Header().Get("X-Frame-Options") == "" {
		t.Error("Expected security headers to be applied by wrapper")
	}
}

func TestConfigValidation(t *testing.T) {
	config := &SecurityHeadersConfig{
		StrictTransportSecurityMaxAge: -1,
		CORSMaxAge:                    -1,
		FrameOptions:                  "INVALID",
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Unexpected validation error: %v", err)
	}

	// Should fix invalid values
	if config.StrictTransportSecurityMaxAge != 0 {
		t.Error("Expected negative HSTS max age to be reset to 0")
	}

	if config.CORSMaxAge != 0 {
		t.Error("Expected negative CORS max age to be reset to 0")
	}

	if config.FrameOptions != "DENY" {
		t.Error("Expected invalid frame options to be reset to DENY")
	}
}

func BenchmarkSecurityHeadersApply(b *testing.B) {
	config := DefaultSecurityConfig()
	middleware := NewSecurityHeadersMiddleware(config)

	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rr := httptest.NewRecorder()
			middleware.Apply(rr, req)
		}
	})
}
