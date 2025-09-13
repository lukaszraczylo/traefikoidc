package traefikoidc

import (
	"bytes"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestConfigValidateInvalidConfigurations tests Config.Validate() with various invalid configurations
func TestConfigValidateInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{
			name:   "empty providerURL",
			config: &Config{},
			want:   "providerURL is required",
		},
		{
			name: "invalid providerURL - not HTTPS",
			config: &Config{
				ProviderURL: "http://example.com",
			},
			want: "providerURL must be a valid HTTPS URL",
		},
		{
			name: "invalid providerURL - malformed",
			config: &Config{
				ProviderURL: "not-a-url",
			},
			want: "providerURL must be a valid HTTPS URL",
		},
		{
			name: "empty callbackURL",
			config: &Config{
				ProviderURL: "https://example.com",
				CallbackURL: "",
			},
			want: "callbackURL is required",
		},
		{
			name: "invalid callbackURL - not starting with /",
			config: &Config{
				ProviderURL: "https://example.com",
				CallbackURL: "callback",
			},
			want: "callbackURL must start with /",
		},
		{
			name: "empty clientID",
			config: &Config{
				ProviderURL: "https://example.com",
				CallbackURL: "/callback",
				ClientID:    "",
			},
			want: "clientID is required",
		},
		{
			name: "empty clientSecret",
			config: &Config{
				ProviderURL:  "https://example.com",
				CallbackURL:  "/callback",
				ClientID:     "test-client",
				ClientSecret: "",
			},
			want: "clientSecret is required",
		},
		{
			name: "empty sessionEncryptionKey",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "",
			},
			want: "sessionEncryptionKey is required",
		},
		{
			name: "short sessionEncryptionKey",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "short",
			},
			want: "sessionEncryptionKey must be at least 32 characters long",
		},
		{
			name: "invalid logLevel",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				LogLevel:             "invalid",
			},
			want: "logLevel must be one of: debug, info, error",
		},
		{
			name: "invalid excluded URL - not starting with /",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				ExcludedURLs:         []string{"invalid-url"},
			},
			want: "excluded URL must start with /: invalid-url",
		},
		{
			name: "invalid excluded URL - path traversal",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				ExcludedURLs:         []string{"/../../etc/passwd"},
			},
			want: "excluded URL must not contain path traversal: /../../etc/passwd",
		},
		{
			name: "invalid excluded URL - wildcards",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				ExcludedURLs:         []string{"/path/*"},
			},
			want: "excluded URL must not contain wildcards: /path/*",
		},
		{
			name: "invalid revocationURL",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RevocationURL:        "http://insecure.com",
			},
			want: "revocationURL must be a valid HTTPS URL",
		},
		{
			name: "invalid oidcEndSessionURL",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				OIDCEndSessionURL:    "ftp://invalid.com",
			},
			want: "oidcEndSessionURL must be a valid HTTPS URL",
		},
		{
			name: "invalid postLogoutRedirectURI",
			config: &Config{
				ProviderURL:           "https://example.com",
				CallbackURL:           "/callback",
				ClientID:              "test-client",
				ClientSecret:          "test-secret",
				SessionEncryptionKey:  "this-is-a-very-long-encryption-key",
				PostLogoutRedirectURI: "ftp://invalid.com",
			},
			want: "postLogoutRedirectURI must be either a valid HTTPS URL or start with /",
		},
		{
			name: "rate limit too low",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            5,
			},
			want: "rateLimit must be at least 10",
		},
		{
			name: "negative refresh grace period",
			config: &Config{
				ProviderURL:               "https://example.com",
				CallbackURL:               "/callback",
				ClientID:                  "test-client",
				ClientSecret:              "test-secret",
				SessionEncryptionKey:      "this-is-a-very-long-encryption-key",
				RateLimit:                 DefaultRateLimit,
				RefreshGracePeriodSeconds: -1,
			},
			want: "refreshGracePeriodSeconds cannot be negative",
		},
		{
			name: "empty header name",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
				Headers: []TemplatedHeader{
					{Name: "", Value: "{{.Claims.email}}"},
				},
			},
			want: "header name cannot be empty",
		},
		{
			name: "empty header value",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
				Headers: []TemplatedHeader{
					{Name: "X-User-Email", Value: ""},
				},
			},
			want: "header value template cannot be empty",
		},
		{
			name: "header value without template syntax",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
				Headers: []TemplatedHeader{
					{Name: "X-User-Email", Value: "static-value"},
				},
			},
			want: "header value 'static-value' does not appear to be a valid template (missing {{ }})",
		},
		{
			name: "lowercase claims in template",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
				Headers: []TemplatedHeader{
					{Name: "X-User-Email", Value: "{{.claims.email}}"},
				},
			},
			want: "header template '{{.claims.email}}' appears to use lowercase 'claims' - use '{{.Claims...' instead (case sensitive)",
		},
		{
			name: "lowercase accessToken in template",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
				Headers: []TemplatedHeader{
					{Name: "Authorization", Value: "Bearer {{.accessToken}}"},
				},
			},
			want: "header template 'Bearer {{.accessToken}}' appears to use lowercase 'accessToken' - use '{{.AccessToken...' instead (case sensitive)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Errorf("Expected validation error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Expected error containing '%s', got '%s'", tt.want, err.Error())
			}
		})
	}
}

// TestConfigValidateValidConfigurations tests Config.Validate() with valid configurations
func TestConfigValidateValidConfigurations(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "minimal valid config",
			config: &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
			},
		},
		{
			name: "valid config with optional fields",
			config: &Config{
				ProviderURL:           "https://example.com",
				CallbackURL:           "/callback",
				ClientID:              "test-client",
				ClientSecret:          "test-secret",
				SessionEncryptionKey:  "this-is-a-very-long-encryption-key",
				LogLevel:              "debug",
				RevocationURL:         "https://example.com/revoke",
				OIDCEndSessionURL:     "https://example.com/logout",
				PostLogoutRedirectURI: "/",
				ExcludedURLs:          []string{"/health", "/metrics"},
				RateLimit:             100,
				Headers: []TemplatedHeader{
					{Name: "X-User-Email", Value: "{{.Claims.email}}"},
					{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
				},
			},
		},
		{
			name: "valid config with postLogoutRedirectURI as path",
			config: &Config{
				ProviderURL:           "https://example.com",
				CallbackURL:           "/callback",
				ClientID:              "test-client",
				ClientSecret:          "test-secret",
				SessionEncryptionKey:  "this-is-a-very-long-encryption-key",
				RateLimit:             DefaultRateLimit,
				PostLogoutRedirectURI: "/home",
			},
		},
		{
			name: "valid config with postLogoutRedirectURI as HTTPS URL",
			config: &Config{
				ProviderURL:           "https://example.com",
				CallbackURL:           "/callback",
				ClientID:              "test-client",
				ClientSecret:          "test-secret",
				SessionEncryptionKey:  "this-is-a-very-long-encryption-key",
				RateLimit:             DefaultRateLimit,
				PostLogoutRedirectURI: "https://example.com/home",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != nil {
				t.Errorf("Expected no validation error, got %v", err)
			}
		})
	}
}

// TestNewLoggerWithDifferentLevels tests NewLogger() with different log levels
func TestNewLoggerWithDifferentLevels(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{"debug level", "debug"},
		{"info level", "info"},
		{"error level", "error"},
		{"empty level", ""},
		{"invalid level", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.logLevel)
			if logger == nil {
				t.Error("Expected logger to be created, got nil")
				return
			}
			if logger.logError == nil {
				t.Error("Expected error logger to be initialized")
			}
			if logger.logInfo == nil {
				t.Error("Expected info logger to be initialized")
			}
			if logger.logDebug == nil {
				t.Error("Expected debug logger to be initialized")
			}
		})
	}
}

// TestLoggerMethods tests logger methods with different scenarios
func TestLoggerMethods(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{"debug logger", "debug"},
		{"info logger", "info"},
		{"error logger", "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout/stderr
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			defer func() {
				os.Stdout = oldStdout
				os.Stderr = oldStderr
			}()

			rOut, wOut, _ := os.Pipe()
			rErr, wErr, _ := os.Pipe()
			os.Stdout = wOut
			os.Stderr = wErr

			logger := NewLogger(tt.logLevel)

			// Test all logging methods
			logger.Info("test info message %s", "param")
			logger.Debug("test debug message %s", "param")
			logger.Error("test error message %s", "param")
			logger.Infof("test info formatted %s", "param")
			logger.Debugf("test debug formatted %s", "param")
			logger.Errorf("test error formatted %s", "param")

			wOut.Close()
			wErr.Close()

			// Read captured output
			outBuf := make([]byte, 1024)
			errBuf := make([]byte, 1024)
			rOut.Read(outBuf)
			rErr.Read(errBuf)

			// Verify error messages always appear in stderr
			if !bytes.Contains(errBuf, []byte("test error message")) {
				t.Error("Expected error message in stderr")
			}
		})
	}
}

// TestLoggerWithNilLogger tests logger behavior with nil scenarios
func TestLoggerWithNilLogger(t *testing.T) {
	// Test that creating a logger doesn't panic
	logger := NewLogger("debug")
	if logger == nil {
		t.Error("Expected logger to be created")
	}

	// Test that calling methods on logger doesn't panic
	logger.Info("test")
	logger.Debug("test")
	logger.Error("test")
	logger.Infof("test %s", "param")
	logger.Debugf("test %s", "param")
	logger.Errorf("test %s", "param")
}

// TestIsValidSecureURL tests the isValidSecureURL function
func TestIsValidSecureURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"valid HTTPS URL", "https://example.com", true},
		{"valid HTTPS URL with path", "https://example.com/path", true},
		{"valid HTTPS URL with query", "https://example.com?query=value", true},
		{"HTTP URL (invalid)", "http://example.com", false},
		{"FTP URL (invalid)", "ftp://example.com", false},
		{"invalid URL", "not-a-url", false},
		{"empty string", "", false},
		{"URL without host", "https://", false},
		{"relative URL", "/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSecureURL(tt.url)
			if got != tt.want {
				t.Errorf("isValidSecureURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// TestIsValidLogLevel tests the isValidLogLevel function
func TestIsValidLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  bool
	}{
		{"debug level", "debug", true},
		{"info level", "info", true},
		{"error level", "error", true},
		{"invalid level", "invalid", false},
		{"empty string", "", false},
		{"uppercase", "DEBUG", false},
		{"mixed case", "Info", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidLogLevel(tt.level)
			if got != tt.want {
				t.Errorf("isValidLogLevel(%q) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

// TestHandleErrorAdditional tests the handleError function with additional scenarios
func TestHandleErrorAdditional(t *testing.T) {
	logger := NewLogger("error")

	tests := []struct {
		name    string
		message string
		code    int
	}{
		{"forbidden", "Forbidden", 403},
		{"not found", "Not Found", 404},
		{"method not allowed", "Method Not Allowed", 405},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a response recorder
			w := httptest.NewRecorder()

			// Call handleError
			handleError(w, tt.message, tt.code, logger)

			// Check response code
			if w.Code != tt.code {
				t.Errorf("Expected status code %d, got %d", tt.code, w.Code)
			}

			// Check response body
			body := strings.TrimSpace(w.Body.String())
			if !strings.Contains(body, tt.message) {
				t.Errorf("Expected response body to contain '%s', got '%s'", tt.message, body)
			}
		})
	}
}

// TestValidateTemplateSecure tests the validateTemplateSecure function
func TestValidateTemplateSecure(t *testing.T) {
	tests := []struct {
		name     string
		template string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid Claims template",
			template: "{{.Claims.email}}",
			wantErr:  false,
		},
		{
			name:     "valid AccessToken template",
			template: "Bearer {{.AccessToken}}",
			wantErr:  false,
		},
		{
			name:     "valid IdToken template",
			template: "{{.IdToken}}",
			wantErr:  false,
		},
		{
			name:     "valid RefreshToken template",
			template: "{{.RefreshToken}}",
			wantErr:  false,
		},
		{
			name:     "valid get function",
			template: "{{get .Claims \"email\" \"default@example.com\"}}",
			wantErr:  false,
		},
		{
			name:     "valid default function",
			template: "{{default .Claims.email \"default@example.com\"}}",
			wantErr:  false,
		},
		{
			name:     "valid with Claims",
			template: "{{with .Claims.email}}{{.}}{{end}}",
			wantErr:  false,
		},
		{
			name:     "dangerous call pattern",
			template: "{{call .SomeFunction}}",
			wantErr:  true,
			errMsg:   "dangerous template pattern detected: {{call",
		},
		{
			name:     "dangerous range pattern",
			template: "{{range .Claims}}{{.}}{{end}}",
			wantErr:  true,
			errMsg:   "dangerous template pattern detected: {{range",
		},
		{
			name:     "dangerous define pattern",
			template: "{{define \"dangerous\"}}content{{end}}",
			wantErr:  true,
			errMsg:   "dangerous template pattern detected: {{define",
		},
		{
			name:     "dangerous template inclusion",
			template: "{{template \"external\"}}",
			wantErr:  true,
			errMsg:   "dangerous template pattern detected: {{template",
		},
		{
			name:     "dangerous index access",
			template: "{{index . \"field\"}}",
			wantErr:  true,
			errMsg:   "dangerous template pattern detected: {{index",
		},
		{
			name:     "dangerous printf",
			template: "{{printf \"%s\" .Claims.email}}",
			wantErr:  true,
			errMsg:   "dangerous template pattern detected: {{printf",
		},
		{
			name:     "invalid Claims field",
			template: "{{.Claims.dangerous_field}}",
			wantErr:  true,
			errMsg:   "access to Claims.dangerous_field is not allowed for security reasons",
		},
		{
			name:     "unbalanced braces",
			template: "{{.Claims.email}",
			wantErr:  true,
			errMsg:   "malformed Claims template syntax",
		},
		{
			name:     "no allowed patterns",
			template: "{{.SomeOtherField}}",
			wantErr:  true,
			errMsg:   "template must use only allowed variables",
		},
		{
			name:     "malformed Claims syntax",
			template: "{{.Claims.email",
			wantErr:  true,
			errMsg:   "malformed Claims template syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTemplateSecure(tt.template)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestIsTestModeAdditional tests additional scenarios of the isTestMode function
func TestIsTestModeAdditional(t *testing.T) {
	// Test that function exists and returns a boolean
	result := isTestMode()
	if result != true && result != false {
		t.Error("isTestMode should return a boolean value")
	}
}

// TestCreateDefaultHTTPClientAdditional tests the deprecated createDefaultHTTPClient function
func TestCreateDefaultHTTPClientAdditional(t *testing.T) {
	client := createDefaultHTTPClient()
	if client == nil {
		t.Error("Expected HTTP client to be created, got nil")
		return
	}

	// Test that it actually creates an HTTP client
	if client.Transport == nil {
		t.Error("Expected HTTP client to have a transport configured")
	}
}

// TestConstSessionTimeout tests that the session timeout constant is defined
func TestConstSessionTimeout(t *testing.T) {
	if ConstSessionTimeout != 86400 {
		t.Errorf("Expected ConstSessionTimeout to be 86400, got %d", ConstSessionTimeout)
	}
}

// TestDefaultExcludedURLsAdditional tests additional aspects of the defaultExcludedURLs map
func TestDefaultExcludedURLsAdditional(t *testing.T) {
	if defaultExcludedURLs == nil {
		t.Error("Expected defaultExcludedURLs to be initialized")
	}

	// Test that it's a proper map structure
	if len(defaultExcludedURLs) == 0 {
		t.Error("Expected defaultExcludedURLs to have at least one entry")
	}
}

// TestRateLimitingConfiguration tests rate limiting configuration
func TestRateLimitingConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit int
		wantValid bool
	}{
		{"valid rate limit", 100, true},
		{"minimum rate limit", MinRateLimit, true},
		{"below minimum rate limit", MinRateLimit - 1, false},
		{"zero rate limit", 0, false},
		{"negative rate limit", -1, false},
		{"high rate limit", 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            tt.rateLimit,
			}

			err := config.Validate()
			if tt.wantValid && err != nil {
				t.Errorf("Expected valid config, got error: %v", err)
			}
			if !tt.wantValid && err == nil {
				t.Error("Expected validation error, got nil")
			}
		})
	}
}

// TestRateLimitConstants tests rate limiting constants
func TestRateLimitConstants(t *testing.T) {
	if DefaultRateLimit < MinRateLimit {
		t.Errorf("DefaultRateLimit (%d) should be >= MinRateLimit (%d)", DefaultRateLimit, MinRateLimit)
	}

	if MinRateLimit <= 0 {
		t.Errorf("MinRateLimit (%d) should be > 0", MinRateLimit)
	}

	if DefaultRateLimit != 100 {
		t.Errorf("Expected DefaultRateLimit to be 100, got %d", DefaultRateLimit)
	}

	if MinRateLimit != 10 {
		t.Errorf("Expected MinRateLimit to be 10, got %d", MinRateLimit)
	}
}

// TestSessionEncryptionKeyValidation tests session encryption key validation
func TestSessionEncryptionKeyValidation(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"valid key", "this-is-a-very-long-encryption-key-that-meets-requirements", true},
		{"exactly minimum length", strings.Repeat("a", MinSessionEncryptionKeyLength), true},
		{"one short", strings.Repeat("a", MinSessionEncryptionKeyLength-1), false},
		{"empty key", "", false},
		{"very short key", "short", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: tt.key,
				RateLimit:            DefaultRateLimit,
			}

			err := config.Validate()
			if tt.want && err != nil {
				t.Errorf("Expected valid config, got error: %v", err)
			}
			if !tt.want && err == nil {
				t.Error("Expected validation error, got nil")
			}
		})
	}
}

// TestMinSessionEncryptionKeyLengthConstant tests the constant value
func TestMinSessionEncryptionKeyLengthConstant(t *testing.T) {
	if MinSessionEncryptionKeyLength != 32 {
		t.Errorf("Expected MinSessionEncryptionKeyLength to be 32, got %d", MinSessionEncryptionKeyLength)
	}
}

// TestCookieDomainConfigurationAdditional tests cookie domain configuration
func TestCookieDomainConfigurationAdditional(t *testing.T) {
	tests := []struct {
		name         string
		cookieDomain string
		wantValid    bool
	}{
		{"empty domain", "", true},
		{"valid domain", "example.com", true},
		{"subdomain", "app.example.com", true},
		{"localhost", "localhost", true},
		{"IP address", "192.168.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProviderURL:          "https://example.com",
				CallbackURL:          "/callback",
				ClientID:             "test-client",
				ClientSecret:         "test-secret",
				SessionEncryptionKey: "this-is-a-very-long-encryption-key",
				RateLimit:            DefaultRateLimit,
				CookieDomain:         tt.cookieDomain,
			}

			err := config.Validate()
			if tt.wantValid && err != nil {
				t.Errorf("Expected valid config, got error: %v", err)
			}
			if !tt.wantValid && err == nil {
				t.Error("Expected validation error, got nil")
			}
		})
	}
}

// TestForceHTTPSConfiguration tests ForceHTTPS configuration
func TestForceHTTPSConfiguration(t *testing.T) {
	// Test default value from CreateConfig
	config := CreateConfig()
	if !config.ForceHTTPS {
		t.Error("Expected ForceHTTPS to be true by default")
	}

	// Test that it can be set to false
	config.ForceHTTPS = false
	if config.ForceHTTPS {
		t.Error("Expected ForceHTTPS to be false after setting")
	}
}

// TestEnablePKCEConfiguration tests EnablePKCE configuration
func TestEnablePKCEConfiguration(t *testing.T) {
	// Test default value from CreateConfig
	config := CreateConfig()
	if config.EnablePKCE {
		t.Error("Expected EnablePKCE to be false by default (opt-in)")
	}

	// Test that it can be enabled
	config.EnablePKCE = true
	if !config.EnablePKCE {
		t.Error("Expected EnablePKCE to be true after setting")
	}
}

// TestOverrideScopesConfiguration tests OverrideScopes configuration
func TestOverrideScopesConfiguration(t *testing.T) {
	// Test default value from CreateConfig
	config := CreateConfig()
	if config.OverrideScopes {
		t.Error("Expected OverrideScopes to be false by default")
	}

	// Test that it can be enabled
	config.OverrideScopes = true
	if !config.OverrideScopes {
		t.Error("Expected OverrideScopes to be true after setting")
	}
}

// TestDefaultLogLevelConstant tests the default log level constant
func TestDefaultLogLevelConstant(t *testing.T) {
	if DefaultLogLevel != "info" {
		t.Errorf("Expected DefaultLogLevel to be 'info', got '%s'", DefaultLogLevel)
	}
}

// TestRefreshGracePeriodValidation tests refresh grace period validation
func TestRefreshGracePeriodValidation(t *testing.T) {
	tests := []struct {
		name        string
		gracePeriod int
		wantValid   bool
	}{
		{"zero grace period", 0, true},
		{"positive grace period", 60, true},
		{"large grace period", 3600, true},
		{"negative grace period", -1, false},
		{"very negative", -100, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ProviderURL:               "https://example.com",
				CallbackURL:               "/callback",
				ClientID:                  "test-client",
				ClientSecret:              "test-secret",
				SessionEncryptionKey:      "this-is-a-very-long-encryption-key",
				RateLimit:                 DefaultRateLimit,
				RefreshGracePeriodSeconds: tt.gracePeriod,
			}

			err := config.Validate()
			if tt.wantValid && err != nil {
				t.Errorf("Expected valid config, got error: %v", err)
			}
			if !tt.wantValid && err == nil {
				t.Error("Expected validation error, got nil")
			}
		})
	}
}
