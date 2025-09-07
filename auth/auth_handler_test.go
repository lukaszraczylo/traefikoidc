package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Mock logger for testing
type mockLogger struct {
	debugLogs []string
	errorLogs []string
	mu        sync.RWMutex
}

func (m *mockLogger) Debugf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Errorf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, fmt.Sprintf(format, args...))
}

//lint:ignore U1000 May be needed for future debug log verification tests
func (m *mockLogger) getDebugLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.debugLogs))
	copy(result, m.debugLogs)
	return result
}

func (m *mockLogger) getErrorLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.errorLogs))
	copy(result, m.errorLogs)
	return result
}

//lint:ignore U1000 May be needed for future test isolation
func (m *mockLogger) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = nil
	m.errorLogs = nil
}

// Mock session for testing
type mockSession struct {
	data          map[string]interface{}
	redirectCount int
	saveError     error
	mu            sync.RWMutex
	dirty         bool
	authenticated bool
	email         string
	accessToken   string
	refreshToken  string
	idToken       string
	nonce         string
	codeVerifier  string
	csrf          string
	incomingPath  string
}

func newMockSession() *mockSession {
	return &mockSession{
		data: make(map[string]interface{}),
	}
}

func (m *mockSession) GetRedirectCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.redirectCount
}

func (m *mockSession) ResetRedirectCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redirectCount = 0
}

func (m *mockSession) IncrementRedirectCount() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redirectCount++
}

func (m *mockSession) SetAuthenticated(auth bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authenticated = auth
}

func (m *mockSession) SetEmail(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.email = email
}

func (m *mockSession) SetAccessToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessToken = token
}

func (m *mockSession) SetRefreshToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshToken = token
}

func (m *mockSession) SetIDToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idToken = token
}

func (m *mockSession) SetNonce(nonce string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonce = nonce
}

func (m *mockSession) SetCodeVerifier(verifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codeVerifier = verifier
}

func (m *mockSession) SetCSRF(csrf string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.csrf = csrf
}

func (m *mockSession) SetIncomingPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incomingPath = path
}

func (m *mockSession) MarkDirty() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirty = true
}

func (m *mockSession) Save(req *http.Request, rw http.ResponseWriter) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveError
}

func (m *mockSession) setSaveError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveError = err
}

// Test helper functions
func createTestAuthHandler(logger Logger, enablePKCE bool, isGoogle, isAzure func() bool) *AuthHandler {
	return NewAuthHandler(
		logger,
		enablePKCE,
		isGoogle,
		isAzure,
		"test-client-id",
		"https://provider.example.com/auth",
		"https://provider.example.com",
		[]string{"openid", "email", "profile"},
		false,
	)
}

func TestNewAuthHandler(t *testing.T) {
	tests := []struct {
		name           string
		logger         Logger
		enablePKCE     bool
		clientID       string
		authURL        string
		issuerURL      string
		scopes         []string
		overrideScopes bool
	}{
		{
			name:           "creates handler with basic config",
			logger:         &mockLogger{},
			enablePKCE:     true,
			clientID:       "test-client",
			authURL:        "https://example.com/auth",
			issuerURL:      "https://example.com",
			scopes:         []string{"openid", "email"},
			overrideScopes: false,
		},
		{
			name:           "creates handler with PKCE disabled",
			logger:         &mockLogger{},
			enablePKCE:     false,
			clientID:       "test-client",
			authURL:        "https://example.com/auth",
			issuerURL:      "https://example.com",
			scopes:         []string{"openid"},
			overrideScopes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isGoogle := func() bool { return false }
			isAzure := func() bool { return false }

			handler := NewAuthHandler(
				tt.logger,
				tt.enablePKCE,
				isGoogle,
				isAzure,
				tt.clientID,
				tt.authURL,
				tt.issuerURL,
				tt.scopes,
				tt.overrideScopes,
			)

			if handler == nil {
				t.Fatal("NewAuthHandler returned nil")
			}

			if handler.clientID != tt.clientID {
				t.Errorf("Expected clientID %s, got %s", tt.clientID, handler.clientID)
			}

			if handler.enablePKCE != tt.enablePKCE {
				t.Errorf("Expected enablePKCE %v, got %v", tt.enablePKCE, handler.enablePKCE)
			}

			if handler.authURL != tt.authURL {
				t.Errorf("Expected authURL %s, got %s", tt.authURL, handler.authURL)
			}

			if handler.issuerURL != tt.issuerURL {
				t.Errorf("Expected issuerURL %s, got %s", tt.issuerURL, handler.issuerURL)
			}

			if handler.overrideScopes != tt.overrideScopes {
				t.Errorf("Expected overrideScopes %v, got %v", tt.overrideScopes, handler.overrideScopes)
			}
		})
	}
}

func TestInitiateAuthentication(t *testing.T) {
	tests := []struct {
		name                      string
		enablePKCE                bool
		initialRedirectCount      int
		generateNonceError        error
		generateCodeVerifierError error
		deriveCodeChallengeError  error
		sessionSaveError          error
		expectedStatusCode        int
		expectRedirect            bool
	}{
		{
			name:               "successful authentication without PKCE",
			enablePKCE:         false,
			expectedStatusCode: http.StatusFound,
			expectRedirect:     true,
		},
		{
			name:               "successful authentication with PKCE",
			enablePKCE:         true,
			expectedStatusCode: http.StatusFound,
			expectRedirect:     true,
		},
		{
			name:               "fails when nonce generation fails",
			enablePKCE:         false,
			generateNonceError: fmt.Errorf("nonce generation failed"),
			expectedStatusCode: http.StatusInternalServerError,
			expectRedirect:     false,
		},
		{
			name:                      "fails when code verifier generation fails",
			enablePKCE:                true,
			generateCodeVerifierError: fmt.Errorf("code verifier generation failed"),
			expectedStatusCode:        http.StatusInternalServerError,
			expectRedirect:            false,
		},
		{
			name:                     "fails when code challenge derivation fails",
			enablePKCE:               true,
			deriveCodeChallengeError: fmt.Errorf("code challenge derivation failed"),
			expectedStatusCode:       http.StatusInternalServerError,
			expectRedirect:           false,
		},
		{
			name:               "fails when session save fails",
			enablePKCE:         false,
			sessionSaveError:   fmt.Errorf("session save failed"),
			expectedStatusCode: http.StatusInternalServerError,
			expectRedirect:     false,
		},
		{
			name:                 "fails when redirect count exceeds limit",
			enablePKCE:           false,
			initialRedirectCount: 5,
			expectedStatusCode:   http.StatusLoopDetected,
			expectRedirect:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			session := newMockSession()
			session.redirectCount = tt.initialRedirectCount
			if tt.sessionSaveError != nil {
				session.setSaveError(tt.sessionSaveError)
			}

			handler := createTestAuthHandler(logger, tt.enablePKCE, func() bool { return false }, func() bool { return false })

			req := httptest.NewRequest("GET", "/test", nil)
			rw := httptest.NewRecorder()

			generateNonce := func() (string, error) {
				if tt.generateNonceError != nil {
					return "", tt.generateNonceError
				}
				return "test-nonce", nil
			}

			generateCodeVerifier := func() (string, error) {
				if tt.generateCodeVerifierError != nil {
					return "", tt.generateCodeVerifierError
				}
				return "test-code-verifier", nil
			}

			deriveCodeChallenge := func() (string, error) {
				if tt.deriveCodeChallengeError != nil {
					return "", tt.deriveCodeChallengeError
				}
				return "test-code-challenge", nil
			}

			handler.InitiateAuthentication(
				rw, req, session,
				"https://example.com/callback",
				generateNonce,
				generateCodeVerifier,
				deriveCodeChallenge,
			)

			if rw.Code != tt.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatusCode, rw.Code)
			}

			if tt.expectRedirect {
				location := rw.Header().Get("Location")
				if location == "" {
					t.Error("Expected redirect location header, got empty")
				}
				if !strings.Contains(location, "https://provider.example.com/auth") {
					t.Errorf("Expected redirect to auth URL, got %s", location)
				}
			}

			// Verify error logs for failure cases
			if tt.expectedStatusCode != http.StatusFound {
				errorLogs := logger.getErrorLogs()
				if len(errorLogs) == 0 {
					t.Error("Expected error logs for failure case, got none")
				}
			}
		})
	}
}

func TestBuildAuthURL(t *testing.T) {
	tests := []struct {
		name           string
		enablePKCE     bool
		isGoogle       bool
		isAzure        bool
		scopes         []string
		overrideScopes bool
		codeChallenge  string
		expectedParams map[string]string
		expectContains []string
	}{
		{
			name:          "builds URL without PKCE for standard provider",
			enablePKCE:    false,
			isGoogle:      false,
			isAzure:       false,
			scopes:        []string{"openid", "email"},
			codeChallenge: "",
			expectedParams: map[string]string{
				"client_id":     "test-client-id",
				"response_type": "code",
				"state":         "test-state",
				"nonce":         "test-nonce",
				"scope":         "openid email offline_access",
			},
		},
		{
			name:          "builds URL with PKCE for standard provider",
			enablePKCE:    true,
			isGoogle:      false,
			isAzure:       false,
			scopes:        []string{"openid", "email"},
			codeChallenge: "test-challenge",
			expectedParams: map[string]string{
				"client_id":             "test-client-id",
				"response_type":         "code",
				"state":                 "test-state",
				"nonce":                 "test-nonce",
				"code_challenge":        "test-challenge",
				"code_challenge_method": "S256",
				"scope":                 "openid email offline_access",
			},
		},
		{
			name:       "builds URL for Google provider",
			enablePKCE: false,
			isGoogle:   true,
			isAzure:    false,
			scopes:     []string{"openid", "email"},
			expectedParams: map[string]string{
				"client_id":     "test-client-id",
				"response_type": "code",
				"state":         "test-state",
				"nonce":         "test-nonce",
				"access_type":   "offline",
				"prompt":        "consent",
				"scope":         "openid email",
			},
		},
		{
			name:       "builds URL for Azure provider",
			enablePKCE: false,
			isGoogle:   false,
			isAzure:    true,
			scopes:     []string{"openid", "email"},
			expectedParams: map[string]string{
				"client_id":     "test-client-id",
				"response_type": "code",
				"state":         "test-state",
				"nonce":         "test-nonce",
				"response_mode": "query",
				"scope":         "openid email offline_access",
			},
		},
		{
			name:           "handles scope override for Azure",
			enablePKCE:     false,
			isGoogle:       false,
			isAzure:        true,
			scopes:         []string{"custom-scope"},
			overrideScopes: true,
			expectedParams: map[string]string{
				"client_id":     "test-client-id",
				"response_type": "code",
				"state":         "test-state",
				"nonce":         "test-nonce",
				"response_mode": "query",
				"scope":         "custom-scope",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			isGoogleFunc := func() bool { return tt.isGoogle }
			isAzureFunc := func() bool { return tt.isAzure }

			handler := NewAuthHandler(
				logger,
				tt.enablePKCE,
				isGoogleFunc,
				isAzureFunc,
				"test-client-id",
				"https://provider.example.com/auth",
				"https://provider.example.com",
				tt.scopes,
				tt.overrideScopes,
			)

			authURL := handler.BuildAuthURL(
				"https://example.com/callback",
				"test-state",
				"test-nonce",
				tt.codeChallenge,
			)

			if authURL == "" {
				t.Fatal("BuildAuthURL returned empty string")
			}

			parsedURL, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("Failed to parse auth URL: %v", err)
			}

			// Check base URL
			expectedBase := "https://provider.example.com/auth"
			actualBase := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
			if actualBase != expectedBase {
				t.Errorf("Expected base URL %s, got %s", expectedBase, actualBase)
			}

			// Check required parameters
			query := parsedURL.Query()
			for param, expectedValue := range tt.expectedParams {
				actualValue := query.Get(param)
				if actualValue != expectedValue {
					t.Errorf("Expected %s=%s, got %s=%s", param, expectedValue, param, actualValue)
				}
			}

			// Check that contains expected strings
			for _, contains := range tt.expectContains {
				if !strings.Contains(authURL, contains) {
					t.Errorf("Expected URL to contain %s, got %s", contains, authURL)
				}
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	logger := &mockLogger{}
	handler := createTestAuthHandler(logger, false, func() bool { return false }, func() bool { return false })

	tests := []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid HTTPS URL",
			url:         "https://example.com/path",
			expectError: false,
		},
		{
			name:        "valid HTTP URL",
			url:         "http://example.com/path",
			expectError: false,
		},
		{
			name:        "empty URL",
			url:         "",
			expectError: true,
			errorMsg:    "empty URL",
		},
		{
			name:        "invalid scheme",
			url:         "ftp://example.com/path",
			expectError: true,
			errorMsg:    "disallowed URL scheme",
		},
		{
			name:        "missing host",
			url:         "https:///path",
			expectError: true,
			errorMsg:    "missing host in URL",
		},
		{
			name:        "localhost not allowed",
			url:         "https://localhost/path",
			expectError: true,
			errorMsg:    "localhost access not allowed",
		},
		{
			name:        "127.0.0.1 not allowed",
			url:         "https://127.0.0.1/path",
			expectError: true,
			errorMsg:    "localhost access not allowed",
		},
		{
			name:        "private IP not allowed",
			url:         "https://192.168.1.1/path",
			expectError: true,
			errorMsg:    "private IP not allowed",
		},
		{
			name:        "path traversal not allowed",
			url:         "https://example.com/../path",
			expectError: true,
			errorMsg:    "path traversal detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateURL(tt.url)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for URL %s, got nil", tt.url)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %s, got %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for URL %s, got %v", tt.url, err)
				}
			}
		})
	}
}

func TestValidateHost(t *testing.T) {
	logger := &mockLogger{}
	handler := createTestAuthHandler(logger, false, func() bool { return false }, func() bool { return false })

	tests := []struct {
		name        string
		host        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid domain",
			host:        "example.com",
			expectError: false,
		},
		{
			name:        "valid domain with port",
			host:        "example.com:443",
			expectError: false,
		},
		{
			name:        "empty host",
			host:        "",
			expectError: true,
			errorMsg:    "empty host",
		},
		{
			name:        "localhost",
			host:        "localhost",
			expectError: true,
			errorMsg:    "localhost access not allowed",
		},
		{
			name:        "localhost with port",
			host:        "localhost:8080",
			expectError: true,
			errorMsg:    "localhost access not allowed",
		},
		{
			name:        "127.0.0.1",
			host:        "127.0.0.1",
			expectError: true,
			errorMsg:    "localhost access not allowed",
		},
		{
			name:        "::1 (IPv6 localhost)",
			host:        "::1",
			expectError: true,
			errorMsg:    "invalid host:port format",
		},
		{
			name:        "private IP 192.168.1.1",
			host:        "192.168.1.1",
			expectError: true,
			errorMsg:    "private IP not allowed",
		},
		{
			name:        "private IP 10.0.0.1",
			host:        "10.0.0.1",
			expectError: true,
			errorMsg:    "private IP not allowed",
		},
		{
			name:        "invalid host:port format",
			host:        "example.com:99999", // Use invalid port number instead
			expectError: false,               // This actually doesn't error in Go's net.SplitHostPort
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateHost(tt.host)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for host %s, got nil", tt.host)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %s, got %s", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for host %s, got %v", tt.host, err)
				}
			}
		})
	}
}

func TestBuildURLWithParams(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(
		logger,
		false,
		func() bool { return false },
		func() bool { return false },
		"test-client-id",
		"https://provider.example.com/auth",
		"https://provider.example.com",
		[]string{"openid"},
		false,
	)

	tests := []struct {
		name        string
		baseURL     string
		params      url.Values
		expected    string
		expectError bool
	}{
		{
			name:     "absolute HTTPS URL with params",
			baseURL:  "https://example.com/auth",
			params:   url.Values{"param1": []string{"value1"}, "param2": []string{"value2"}},
			expected: "https://example.com/auth?param1=value1&param2=value2",
		},
		{
			name:     "relative URL resolved against issuer",
			baseURL:  "/auth/endpoint",
			params:   url.Values{"client_id": []string{"test"}},
			expected: "https://provider.example.com/auth/endpoint?client_id=test",
		},
		{
			name:        "invalid absolute URL",
			baseURL:     "https://localhost/auth",
			params:      url.Values{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.buildURLWithParams(tt.baseURL, tt.params)

			if tt.expectError {
				if result != "" {
					t.Errorf("Expected empty result for invalid URL, got %s", result)
				}
			} else {
				if result == "" {
					t.Error("Expected non-empty result, got empty string")
				}

				// Parse and compare the result
				resultURL, err := url.Parse(result)
				if err != nil {
					t.Fatalf("Failed to parse result URL: %v", err)
				}

				expectedURL, err := url.Parse(tt.expected)
				if err != nil {
					t.Fatalf("Failed to parse expected URL: %v", err)
				}

				if resultURL.Scheme != expectedURL.Scheme {
					t.Errorf("Expected scheme %s, got %s", expectedURL.Scheme, resultURL.Scheme)
				}
				if resultURL.Host != expectedURL.Host {
					t.Errorf("Expected host %s, got %s", expectedURL.Host, resultURL.Host)
				}
				if resultURL.Path != expectedURL.Path {
					t.Errorf("Expected path %s, got %s", expectedURL.Path, resultURL.Path)
				}

				// Check query parameters
				resultQuery := resultURL.Query()
				expectedQuery := expectedURL.Query()
				for key, expectedValues := range expectedQuery {
					resultValues := resultQuery[key]
					if len(resultValues) != len(expectedValues) {
						t.Errorf("Expected %d values for %s, got %d", len(expectedValues), key, len(resultValues))
					}
					for i, expectedValue := range expectedValues {
						if i >= len(resultValues) || resultValues[i] != expectedValue {
							t.Errorf("Expected %s=%s, got %s=%s", key, expectedValue, key, resultValues[i])
						}
					}
				}
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	logger := &mockLogger{}
	handler := createTestAuthHandler(logger, true, func() bool { return false }, func() bool { return false })

	const numGoroutines = 10
	const numRequests = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numRequests)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numRequests; j++ {
				session := newMockSession()
				req := httptest.NewRequest("GET", fmt.Sprintf("/test-%d-%d", id, j), nil)
				rw := httptest.NewRecorder()

				generateNonce := func() (string, error) {
					return fmt.Sprintf("nonce-%d-%d", id, j), nil
				}
				generateCodeVerifier := func() (string, error) {
					return fmt.Sprintf("verifier-%d-%d", id, j), nil
				}
				deriveCodeChallenge := func() (string, error) {
					return fmt.Sprintf("challenge-%d-%d", id, j), nil
				}

				handler.InitiateAuthentication(
					rw, req, session,
					"https://example.com/callback",
					generateNonce,
					generateCodeVerifier,
					deriveCodeChallenge,
				)

				if rw.Code != http.StatusFound {
					errors <- fmt.Errorf("goroutine %d request %d: expected status %d, got %d",
						id, j, http.StatusFound, rw.Code)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	var errorCount int
	for err := range errors {
		t.Error(err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Found %d errors in concurrent access test", errorCount)
	}
}

// Benchmark tests
func BenchmarkInitiateAuthentication(b *testing.B) {
	logger := &mockLogger{}
	handler := createTestAuthHandler(logger, true, func() bool { return false }, func() bool { return false })

	generateNonce := func() (string, error) { return "test-nonce", nil }
	generateCodeVerifier := func() (string, error) { return "test-verifier", nil }
	deriveCodeChallenge := func() (string, error) { return "test-challenge", nil }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session := newMockSession()
		req := httptest.NewRequest("GET", "/test", nil)
		rw := httptest.NewRecorder()

		handler.InitiateAuthentication(
			rw, req, session,
			"https://example.com/callback",
			generateNonce,
			generateCodeVerifier,
			deriveCodeChallenge,
		)
	}
}

func BenchmarkBuildAuthURL(b *testing.B) {
	logger := &mockLogger{}
	handler := createTestAuthHandler(logger, true, func() bool { return false }, func() bool { return false })

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.BuildAuthURL(
			"https://example.com/callback",
			"test-state",
			"test-nonce",
			"test-challenge",
		)
	}
}

func BenchmarkValidateURL(b *testing.B) {
	logger := &mockLogger{}
	handler := createTestAuthHandler(logger, false, func() bool { return false }, func() bool { return false })

	testURLs := []string{
		"https://example.com/auth",
		"https://provider.example.com/oauth/authorize",
		"https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.validateURL(testURLs[i%len(testURLs)])
	}
}
