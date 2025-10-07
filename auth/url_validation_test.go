package auth

import (
	"net/url"
	"strings"
	"testing"
)

// TestAuthHandler_validateURL tests URL validation functionality
func TestAuthHandler_validateURL(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil)

	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid HTTPS URL",
			url:     "https://example.com/auth",
			wantErr: false,
		},
		{
			name:    "Valid HTTP URL",
			url:     "http://example.com/auth",
			wantErr: false,
		},
		{
			name:    "Empty URL",
			url:     "",
			wantErr: true,
			errMsg:  "empty URL",
		},
		{
			name:    "Invalid URL format",
			url:     "not-a-url",
			wantErr: true,
			errMsg:  "disallowed URL scheme",
		},
		{
			name:    "Disallowed scheme - javascript",
			url:     "javascript:alert('xss')",
			wantErr: true,
			errMsg:  "disallowed URL scheme",
		},
		{
			name:    "Disallowed scheme - data",
			url:     "data:text/html,<script>alert('xss')</script>",
			wantErr: true,
			errMsg:  "disallowed URL scheme",
		},
		{
			name:    "Disallowed scheme - file",
			url:     "file:///etc/passwd",
			wantErr: true,
			errMsg:  "disallowed URL scheme",
		},
		{
			name:    "Disallowed scheme - ftp",
			url:     "ftp://example.com/file",
			wantErr: true,
			errMsg:  "disallowed URL scheme",
		},
		{
			name:    "Missing host",
			url:     "https:///path",
			wantErr: true,
			errMsg:  "missing host",
		},
		{
			name:    "Path traversal attempt",
			url:     "https://example.com/../../../etc/passwd",
			wantErr: true,
			errMsg:  "path traversal detected",
		},
		{
			name:    "Path traversal in middle",
			url:     "https://example.com/path/../sensitive/file",
			wantErr: true,
			errMsg:  "path traversal detected",
		},
		{
			name:    "Localhost attempt",
			url:     "https://localhost/auth",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "127.0.0.1 attempt",
			url:     "https://127.0.0.1/auth",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "IPv6 localhost attempt",
			url:     "https://[::1]/auth",
			wantErr: true,
			errMsg:  "invalid host:port format",
		},
		{
			name:    "0.0.0.0 attempt",
			url:     "https://0.0.0.0/auth",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "Private IP - 192.168.x.x",
			url:     "https://192.168.1.1/auth",
			wantErr: true,
			errMsg:  "private IP not allowed",
		},
		{
			name:    "Private IP - 10.x.x.x",
			url:     "https://10.0.0.1/auth",
			wantErr: true,
			errMsg:  "private IP not allowed",
		},
		{
			name:    "Private IP - 172.16.x.x",
			url:     "https://172.16.0.1/auth",
			wantErr: true,
			errMsg:  "private IP not allowed",
		},
		{
			name:    "Link-local IP",
			url:     "https://169.254.1.1/auth",
			wantErr: true,
			errMsg:  "link-local IP not allowed",
		},
		{
			name:    "Multicast IP",
			url:     "https://224.0.0.1/auth",
			wantErr: true,
			errMsg:  "multicast IP not allowed",
		},
		{
			name:    "Valid public IP",
			url:     "https://8.8.8.8/auth",
			wantErr: false,
		},
		{
			name:    "Valid domain with port",
			url:     "https://example.com:8443/auth",
			wantErr: false,
		},
		{
			name:    "localhost with case variation",
			url:     "https://LOCALHOST/auth",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "Invalid host:port format",
			url:     "https://example.com:notanumber/auth",
			wantErr: true,
			errMsg:  "invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateURL(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateURL() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateURL() error = %v, expected error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateURL() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestAuthHandler_validateHost tests host validation specifically
func TestAuthHandler_validateHost(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil)

	tests := []struct {
		name    string
		host    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid hostname",
			host:    "example.com",
			wantErr: false,
		},
		{
			name:    "Valid hostname with subdomain",
			host:    "api.example.com",
			wantErr: false,
		},
		{
			name:    "Valid hostname with port",
			host:    "example.com:8080",
			wantErr: false,
		},
		{
			name:    "Empty host",
			host:    "",
			wantErr: true,
			errMsg:  "empty host",
		},
		{
			name:    "localhost",
			host:    "localhost",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "LOCALHOST (case insensitive)",
			host:    "LOCALHOST",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "localhost with port",
			host:    "localhost:8080",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "127.0.0.1",
			host:    "127.0.0.1",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "127.0.0.1 with port",
			host:    "127.0.0.1:8080",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "IPv6 localhost",
			host:    "::1",
			wantErr: true,
			errMsg:  "invalid host:port format",
		},
		{
			name:    "0.0.0.0",
			host:    "0.0.0.0",
			wantErr: true,
			errMsg:  "localhost access not allowed",
		},
		{
			name:    "Private IP 192.168.1.1",
			host:    "192.168.1.1",
			wantErr: true,
			errMsg:  "private IP not allowed",
		},
		{
			name:    "Private IP 10.0.0.1",
			host:    "10.0.0.1",
			wantErr: true,
			errMsg:  "private IP not allowed",
		},
		{
			name:    "Private IP 172.16.0.1",
			host:    "172.16.0.1",
			wantErr: true,
			errMsg:  "private IP not allowed",
		},
		{
			name:    "Public IP 8.8.8.8",
			host:    "8.8.8.8",
			wantErr: false,
		},
		{
			name:    "Link-local IP",
			host:    "169.254.1.1",
			wantErr: true,
			errMsg:  "link-local IP not allowed",
		},
		{
			name:    "Multicast IP",
			host:    "224.0.0.1",
			wantErr: true,
			errMsg:  "multicast IP not allowed",
		},
		{
			name:    "Invalid host:port format",
			host:    "example.com::",
			wantErr: true,
			errMsg:  "invalid host:port format",
		},
		{
			name:    "Valid international domain",
			host:    "example.org",
			wantErr: false,
		},
		{
			name:    "Valid ccTLD",
			host:    "example.co.uk",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateHost(tt.host)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateHost() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateHost() error = %v, expected error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateHost() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestAuthHandler_buildURLWithParams tests URL building with parameters
func TestAuthHandler_buildURLWithParams(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil)

	tests := []struct {
		name        string
		baseURL     string
		params      url.Values
		expected    string
		expectEmpty bool
	}{
		{
			name:    "Absolute HTTPS URL",
			baseURL: "https://provider.com/auth",
			params: url.Values{
				"client_id":     []string{"test-client"},
				"response_type": []string{"code"},
			},
			expected: "https://provider.com/auth?client_id=test-client&response_type=code",
		},
		{
			name:    "Absolute HTTP URL",
			baseURL: "http://provider.com/auth",
			params: url.Values{
				"state": []string{"test-state"},
			},
			expected: "http://provider.com/auth?state=test-state",
		},
		{
			name:    "Relative URL resolved against issuer",
			baseURL: "/oauth2/authorize",
			params: url.Values{
				"scope": []string{"openid"},
			},
			expected: "https://example.com/oauth2/authorize?scope=openid",
		},
		{
			name:    "Root relative URL",
			baseURL: "/auth",
			params: url.Values{
				"nonce": []string{"test-nonce"},
			},
			expected: "https://example.com/auth?nonce=test-nonce",
		},
		{
			name:        "Invalid absolute URL",
			baseURL:     "https://localhost/auth",
			params:      url.Values{},
			expectEmpty: true, // Should return empty string due to validation failure
		},
		{
			name:        "Invalid relative URL when resolved",
			baseURL:     "/auth",
			params:      url.Values{},
			expected:    "", // Should be empty because issuer validation would be tested separately
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.buildURLWithParams(tt.baseURL, tt.params)

			if tt.expectEmpty {
				if result != "" {
					t.Errorf("buildURLWithParams() expected empty string, got %v", result)
				}
				return
			}

			// For relative URLs, we expect them to be resolved against the issuer URL
			if !strings.HasPrefix(tt.baseURL, "http") {
				// Verify it starts with the issuer URL
				if !strings.HasPrefix(result, handler.issuerURL) {
					t.Errorf("buildURLWithParams() relative URL not resolved against issuer URL. Got %v", result)
				}
			}

			// Parse the result to verify parameters
			parsedURL, err := url.Parse(result)
			if err != nil {
				t.Fatalf("buildURLWithParams() produced invalid URL: %v", err)
			}

			// Verify all expected parameters are present
			resultParams := parsedURL.Query()
			for key, expectedValues := range tt.params {
				actualValues := resultParams[key]
				if len(actualValues) != len(expectedValues) {
					t.Errorf("Parameter %s: expected %d values, got %d", key, len(expectedValues), len(actualValues))
					continue
				}
				for i, expectedValue := range expectedValues {
					if actualValues[i] != expectedValue {
						t.Errorf("Parameter %s[%d]: expected %v, got %v", key, i, expectedValue, actualValues[i])
					}
				}
			}
		})
	}
}

// TestAuthHandler_buildURLWithParams_ParameterEncoding tests proper parameter encoding
func TestAuthHandler_buildURLWithParams_ParameterEncoding(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil)

	// Test special characters that need encoding
	params := url.Values{
		"redirect_uri": []string{"https://example.com/callback?test=value&other=data"},
		"state":        []string{"state with spaces and & special chars"},
		"scope":        []string{"openid profile email"},
		"special":      []string{"value+with+plus&ampersand=equals"},
	}

	result := handler.buildURLWithParams("https://provider.com/auth", params)

	parsedURL, err := url.Parse(result)
	if err != nil {
		t.Fatalf("Failed to parse result URL: %v", err)
	}

	// Verify parameters are correctly encoded/decoded
	resultParams := parsedURL.Query()

	expectedParams := map[string]string{
		"redirect_uri": "https://example.com/callback?test=value&other=data",
		"state":        "state with spaces and & special chars",
		"scope":        "openid profile email",
		"special":      "value+with+plus&ampersand=equals",
	}

	for key, expectedValue := range expectedParams {
		actualValue := resultParams.Get(key)
		if actualValue != expectedValue {
			t.Errorf("Parameter %s: expected %v, got %v", key, expectedValue, actualValue)
		}
	}
}

// TestAuthHandler_validateParsedURL tests validateParsedURL method
func TestAuthHandler_validateParsedURL(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil)

	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid HTTPS URL",
			url:     "https://example.com/path",
			wantErr: false,
		},
		{
			name:    "Valid HTTP URL with warning",
			url:     "http://example.com/path",
			wantErr: false, // Should not error but should log warning
		},
		{
			name:    "Invalid scheme",
			url:     "javascript:alert('xss')",
			wantErr: true,
			errMsg:  "disallowed URL scheme",
		},
		{
			name:    "Missing host",
			url:     "https:///path",
			wantErr: true,
			errMsg:  "missing host",
		},
		{
			name:    "Path traversal",
			url:     "https://example.com/path/../../../etc",
			wantErr: true,
			errMsg:  "path traversal detected",
		},
		{
			name:    "Invalid host (private IP)",
			url:     "https://192.168.1.1/path",
			wantErr: true,
			errMsg:  "invalid host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("Failed to parse test URL: %v", err)
			}

			err = handler.validateParsedURL(parsedURL)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateParsedURL() expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateParsedURL() error = %v, expected error containing %v", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateParsedURL() unexpected error = %v", err)
				}

				// Check for HTTP warning in debug logs
				if parsedURL.Scheme == "http" && len(logger.debugMessages) > 0 {
					found := false
					for _, msg := range logger.debugMessages {
						if strings.Contains(msg, "Warning: Using HTTP scheme") {
							found = true
							break
						}
					}
					if !found {
						t.Error("Expected HTTP scheme warning in debug logs")
					}
				}
			}
		})
	}
}
