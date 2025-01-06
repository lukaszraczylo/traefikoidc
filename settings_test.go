package traefikoidc

import (
	"bytes"
	"log"
	"net/http"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	t.Run("Default Values", func(t *testing.T) {
		config := CreateConfig()

		// Check default scopes
		expectedScopes := []string{"openid", "profile", "email"}
		if len(config.Scopes) != len(expectedScopes) {
			t.Errorf("Expected %d default scopes, got %d", len(expectedScopes), len(config.Scopes))
		}
		for i, scope := range expectedScopes {
			if config.Scopes[i] != scope {
				t.Errorf("Expected scope %s at position %d, got %s", scope, i, config.Scopes[i])
			}
		}

		// Check default log level
		if config.LogLevel != "info" {
			t.Errorf("Expected default log level 'info', got '%s'", config.LogLevel)
		}

		// Check default rate limit
		if config.RateLimit != 100 {
			t.Errorf("Expected default rate limit 100, got %d", config.RateLimit)
		}
	})

	t.Run("Custom Values Preserved", func(t *testing.T) {
		config := CreateConfig()
		config.Scopes = []string{"custom_scope"}
		config.LogLevel = "debug"
		config.RateLimit = 50

		// Verify custom values are not overwritten
		if len(config.Scopes) != 1 || config.Scopes[0] != "custom_scope" {
			t.Error("Custom scopes were overwritten")
		}
		if config.LogLevel != "debug" {
			t.Error("Custom log level was overwritten")
		}
		if config.RateLimit != 50 {
			t.Error("Custom rate limit was overwritten")
		}
	})
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectedError string
	}{
		{
			name:          "Empty Config",
			config:        &Config{},
			expectedError: "providerURL is required",
		},
		{
			name: "Missing CallbackURL",
			config: &Config{
				ProviderURL: "https://provider.com",
			},
			expectedError: "callbackURL is required",
		},
		{
			name: "Missing ClientID",
			config: &Config{
				ProviderURL: "https://provider.com",
				CallbackURL: "/callback",
			},
			expectedError: "clientID is required",
		},
		{
			name: "Missing ClientSecret",
			config: &Config{
				ProviderURL: "https://provider.com",
				CallbackURL: "/callback",
				ClientID:    "client-id",
			},
			expectedError: "clientSecret is required",
		},
		{
			name: "Missing SessionEncryptionKey",
			config: &Config{
				ProviderURL:  "https://provider.com",
				CallbackURL:  "/callback",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectedError: "sessionEncryptionKey is required",
		},
		{
			name: "Invalid ProviderURL",
			config: &Config{
				ProviderURL:          "not-a-url",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "encryption-key",
			},
			expectedError: "providerURL must be a valid URL",
		},
		{
			name: "Invalid CallbackURL",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "callback", // Missing leading slash
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "encryption-key",
			},
			expectedError: "callbackURL must start with /",
		},
		{
			name: "Short SessionEncryptionKey",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "short",
			},
			expectedError: "sessionEncryptionKey must be at least 32 characters long",
		},
		{
			name: "Negative RateLimit",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				RateLimit:            -1,
			},
			expectedError: "rateLimit must be non-negative",
		},
		{
			name: "Invalid LogLevel",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				LogLevel:             "invalid",
			},
			expectedError: "logLevel must be one of: debug, info, error",
		},
		{
			name: "Valid Config",
			config: &Config{
				ProviderURL:          "https://provider.com",
				CallbackURL:          "/callback",
				ClientID:             "client-id",
				ClientSecret:         "client-secret",
				SessionEncryptionKey: "this-is-a-long-enough-encryption-key",
				LogLevel:             "debug",
				RateLimit:            100,
			},
			expectedError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tc.expectedError)
				} else if err.Error() != tc.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tc.expectedError, err.Error())
				}
			}
		})
	}
}

func TestLogger(t *testing.T) {
	// Capture log output
	var debugBuf, infoBuf, errorBuf bytes.Buffer

	tests := []struct {
		name     string
		logLevel string
		testFunc func(*Logger)
		checkFunc func(t *testing.T, debugOut, infoOut, errorOut string)
	}{
		{
			name:     "Debug Level",
			logLevel: "debug",
			testFunc: func(l *Logger) {
				l.Debug("debug message")
				l.Info("info message")
				l.Error("error message")
			},
			checkFunc: func(t *testing.T, debugOut, infoOut, errorOut string) {
				if debugOut == "" {
					t.Error("Expected debug message in output")
				}
				if infoOut == "" {
					t.Error("Expected info message in output")
				}
				if errorOut == "" {
					t.Error("Expected error message in output")
				}
			},
		},
		{
			name:     "Info Level",
			logLevel: "info",
			testFunc: func(l *Logger) {
				l.Debug("debug message")
				l.Info("info message")
				l.Error("error message")
			},
			checkFunc: func(t *testing.T, debugOut, infoOut, errorOut string) {
				if debugOut != "" {
					t.Error("Did not expect debug message in output")
				}
				if infoOut == "" {
					t.Error("Expected info message in output")
				}
				if errorOut == "" {
					t.Error("Expected error message in output")
				}
			},
		},
		{
			name:     "Error Level",
			logLevel: "error",
			testFunc: func(l *Logger) {
				l.Debug("debug message")
				l.Info("info message")
				l.Error("error message")
			},
			checkFunc: func(t *testing.T, debugOut, infoOut, errorOut string) {
				if debugOut != "" {
					t.Error("Did not expect debug message in output")
				}
				if infoOut != "" {
					t.Error("Did not expect info message in output")
				}
				if errorOut == "" {
					t.Error("Expected error message in output")
				}
			},
		},
		{
			name:     "Printf Methods",
			logLevel: "debug",
			testFunc: func(l *Logger) {
				l.Debugf("debug %s", "formatted")
				l.Infof("info %s", "formatted")
				l.Errorf("error %s", "formatted")
			},
			checkFunc: func(t *testing.T, debugOut, infoOut, errorOut string) {
				if !bytes.Contains([]byte(debugOut), []byte("debug formatted")) {
					t.Error("Expected formatted debug message")
				}
				if !bytes.Contains([]byte(infoOut), []byte("info formatted")) {
					t.Error("Expected formatted info message")
				}
				if !bytes.Contains([]byte(errorOut), []byte("error formatted")) {
					t.Error("Expected formatted error message")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset buffers
			debugBuf.Reset()
			infoBuf.Reset()
			errorBuf.Reset()

			// Create logger with test buffers
			logger := NewLogger(tc.logLevel)
			logger.logError.SetOutput(&errorBuf)
			
			if tc.logLevel == "debug" || tc.logLevel == "info" {
				logger.logInfo.SetOutput(&infoBuf)
			}
			if tc.logLevel == "debug" {
				logger.logDebug.SetOutput(&debugBuf)
			}

			// Run test
			tc.testFunc(logger)

			// Check results
			tc.checkFunc(t, debugBuf.String(), infoBuf.String(), errorBuf.String())
		})
	}
}

func TestHandleError(t *testing.T) {
	// Create a test logger with captured output
	var errorBuf bytes.Buffer
	logger := &Logger{
		logError: log.New(&errorBuf, "ERROR: ", log.Ldate|log.Ltime),
	}
	logger.logError.SetOutput(&errorBuf)

	// Create a test response recorder
	rr := &testResponseRecorder{
		headers: make(map[string][]string),
	}

	// Test error handling
	message := "test error message"
	code := 400
	handleError(rr, message, code, logger)

	// Check response code
	if rr.statusCode != code {
		t.Errorf("Expected status code %d, got %d", code, rr.statusCode)
	}

	// Check response body
	expectedBody := message + "\n"
	if rr.body != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, rr.body)
	}

	// Check error was logged
	if !bytes.Contains(errorBuf.Bytes(), []byte(message)) {
		t.Error("Error message was not logged")
	}
}

// Test helper types
type testResponseRecorder struct {
	statusCode int
	body       string
	headers    map[string][]string
}

func (r *testResponseRecorder) Header() http.Header {
	return r.headers
}

func (r *testResponseRecorder) Write(b []byte) (int, error) {
	r.body = string(b)
	return len(b), nil
}

func (r *testResponseRecorder) WriteHeader(code int) {
	r.statusCode = code
}
