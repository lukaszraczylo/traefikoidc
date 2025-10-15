package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Mock implementations that embed SessionHandler
type MockSessionHandlerWrapper struct {
	*SessionHandler
}

func NewMockSessionHandlerWrapper() *MockSessionHandlerWrapper {
	sessionManager := &MockSessionManager{}
	logger := &MockLogger{}

	sessionHandler := NewSessionHandler(
		sessionManager,
		logger,
		"/logout",
		"https://example.com/post-logout",
		"https://provider.example.com/logout",
		"test-client-id",
	)

	return &MockSessionHandlerWrapper{
		SessionHandler: sessionHandler,
	}
}

type MockSessionManager struct {
	session Session
	err     error
}

func (m *MockSessionManager) GetSession(req *http.Request) (Session, error) {
	return m.session, m.err
}

func (m *MockSessionManager) CleanupOldCookies(rw http.ResponseWriter, req *http.Request) {
	// Mock implementation
}

type MockSession struct {
	authenticated bool
	email         string
	idToken       string
	accessToken   string
	refreshToken  string
	saveError     error
	clearError    error
}

func (m *MockSession) GetAuthenticated() bool                                { return m.authenticated }
func (m *MockSession) SetAuthenticated(auth bool) error                      { m.authenticated = auth; return nil }
func (m *MockSession) GetEmail() string                                      { return m.email }
func (m *MockSession) SetEmail(email string)                                 { m.email = email }
func (m *MockSession) GetIDToken() string                                    { return m.idToken }
func (m *MockSession) GetAccessToken() string                                { return m.accessToken }
func (m *MockSession) GetRefreshToken() string                               { return m.refreshToken }
func (m *MockSession) SetRefreshToken(token string)                          { m.refreshToken = token }
func (m *MockSession) Clear(req *http.Request, rw http.ResponseWriter) error { return m.clearError }
func (m *MockSession) Save(req *http.Request, rw http.ResponseWriter) error  { return m.saveError }
func (m *MockSession) ReturnToPoolSafely()                                   {}

type MockTokenHandler struct {
	verifyError   error
	refreshError  error
	tokenResponse *TokenResponse
}

func (m *MockTokenHandler) VerifyToken(token string) error {
	return m.verifyError
}

func (m *MockTokenHandler) RefreshToken(refreshToken string) (*TokenResponse, error) {
	return m.tokenResponse, m.refreshError
}

type MockLogger struct {
	debugMessages []string
	errorMessages []string
}

func (m *MockLogger) Debug(msg string) {
	m.debugMessages = append(m.debugMessages, msg)
}

func (m *MockLogger) Debugf(format string, args ...interface{}) {
	m.debugMessages = append(m.debugMessages, format)
}

func (m *MockLogger) Info(msg string) {}

func (m *MockLogger) Infof(format string, args ...interface{}) {}

func (m *MockLogger) Error(msg string) {
	m.errorMessages = append(m.errorMessages, msg)
}

func (m *MockLogger) Errorf(format string, args ...interface{}) {
	m.errorMessages = append(m.errorMessages, format)
}

func TestNewAuthFlowHandler(t *testing.T) {
	sessionHandler := NewMockSessionHandlerWrapper()
	tokenHandler := &MockTokenHandler{}
	logger := &MockLogger{}
	excludedURLs := map[string]struct{}{"/health": {}}
	initComplete := make(chan struct{})
	issuerURL := "https://issuer.example.com"

	handler := NewAuthFlowHandler(sessionHandler.SessionHandler, tokenHandler, logger, excludedURLs, initComplete, issuerURL)

	if handler == nil {
		t.Fatal("NewAuthFlowHandler returned nil")
	}

	if handler.sessionHandler == nil {
		t.Error("SessionHandler not set correctly")
	}

	if handler.tokenHandler != tokenHandler {
		t.Error("TokenHandler not set correctly")
	}

	if handler.logger != logger {
		t.Error("Logger not set correctly")
	}

	if handler.issuerURL != issuerURL {
		t.Error("IssuerURL not set correctly")
	}
}

func TestAuthFlowHandler_shouldExcludeURL(t *testing.T) {
	excludedURLs := map[string]struct{}{
		"/health":     {},
		"/metrics":    {},
		"/api/public": {},
	}

	handler := &AuthFlowHandler{excludedURLs: excludedURLs}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/health/check", true},
		{"/metrics", true},
		{"/metrics/prometheus", true},
		{"/api/public", true},
		{"/api/public/endpoint", true},
		{"/api/private", false},
		{"/login", false},
		{"/dashboard", false},
	}

	for _, test := range tests {
		result := handler.shouldExcludeURL(test.path)
		if result != test.expected {
			t.Errorf("For path '%s': expected %v, got %v", test.path, test.expected, result)
		}
	}
}

func TestAuthFlowHandler_isStreamingRequest(t *testing.T) {
	handler := &AuthFlowHandler{}

	tests := []struct {
		name     string
		accept   string
		expected bool
	}{
		{
			name:     "SSE request",
			accept:   "text/event-stream",
			expected: true,
		},
		{
			name:     "Regular HTML request",
			accept:   "text/html,application/xhtml+xml",
			expected: false,
		},
		{
			name:     "JSON request",
			accept:   "application/json",
			expected: false,
		},
		{
			name:     "Empty accept header",
			accept:   "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Accept", test.accept)

			result := handler.isStreamingRequest(req)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestAuthFlowHandler_waitForInitialization(t *testing.T) {
	tests := []struct {
		name           string
		setupHandler   func() (*AuthFlowHandler, context.CancelFunc)
		expectedResult bool
	}{
		{
			name: "Initialization complete successfully",
			setupHandler: func() (*AuthFlowHandler, context.CancelFunc) {
				initComplete := make(chan struct{})
				close(initComplete) // Already complete
				handler := &AuthFlowHandler{
					initComplete: initComplete,
					issuerURL:    "https://issuer.example.com",
				}
				return handler, nil
			},
			expectedResult: true,
		},
		{
			name: "Initialization complete but no issuer URL",
			setupHandler: func() (*AuthFlowHandler, context.CancelFunc) {
				initComplete := make(chan struct{})
				close(initComplete)
				handler := &AuthFlowHandler{
					initComplete: initComplete,
					issuerURL:    "",
					logger:       &MockLogger{},
				}
				return handler, nil
			},
			expectedResult: false,
		},
		{
			name: "Request canceled",
			setupHandler: func() (*AuthFlowHandler, context.CancelFunc) {
				initComplete := make(chan struct{})
				handler := &AuthFlowHandler{
					initComplete: initComplete,
					logger:       &MockLogger{},
				}
				_, cancel := context.WithCancel(context.Background())
				return handler, cancel
			},
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, cancelFunc := test.setupHandler()

			req := httptest.NewRequest("GET", "/", nil)
			if cancelFunc != nil {
				ctx, cancel := context.WithCancel(context.Background())
				req = req.WithContext(ctx)
				cancel() // Cancel immediately
			}

			result := handler.waitForInitialization(req)
			if result != test.expectedResult {
				t.Errorf("Expected %v, got %v", test.expectedResult, result)
			}
		})
	}
}

func TestAuthFlowHandler_ProcessRequest(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		setupHandler   func() *AuthFlowHandler
		expectedResult AuthFlowResult
	}{
		{
			name: "Excluded URL bypasses authentication",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/health", nil)
			},
			setupHandler: func() *AuthFlowHandler {
				return &AuthFlowHandler{
					excludedURLs: map[string]struct{}{"/health": {}},
					logger:       &MockLogger{},
				}
			},
			expectedResult: AuthFlowResult{Authenticated: true},
		},
		{
			name: "Streaming request bypasses authentication",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/events", nil)
				req.Header.Set("Accept", "text/event-stream")
				return req
			},
			setupHandler: func() *AuthFlowHandler {
				return &AuthFlowHandler{
					excludedURLs: map[string]struct{}{},
					logger:       &MockLogger{},
				}
			},
			expectedResult: AuthFlowResult{Authenticated: true},
		},
		{
			name: "Initialization timeout",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/dashboard", nil)
			},
			setupHandler: func() *AuthFlowHandler {
				return &AuthFlowHandler{
					excludedURLs: map[string]struct{}{},
					initComplete: make(chan struct{}), // Never closes
					logger:       &MockLogger{},
				}
			},
			expectedResult: AuthFlowResult{
				Error:      ErrInitializationTimeout,
				StatusCode: http.StatusServiceUnavailable,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := test.setupRequest()
			handler := test.setupHandler()
			rw := httptest.NewRecorder()

			// For timeout test, use context with timeout
			if test.name == "Initialization timeout" {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()
				req = req.WithContext(ctx)
			}

			result := handler.ProcessRequest(rw, req)

			if result.Authenticated != test.expectedResult.Authenticated {
				t.Errorf("Expected Authenticated %v, got %v", test.expectedResult.Authenticated, result.Authenticated)
			}

			if result.StatusCode != test.expectedResult.StatusCode {
				t.Errorf("Expected StatusCode %d, got %d", test.expectedResult.StatusCode, result.StatusCode)
			}

			if test.expectedResult.Error != nil && result.Error == nil {
				t.Error("Expected error but got nil")
			}
		})
	}
}

func TestAuthFlowHandler_validateAndRefreshTokens(t *testing.T) {
	tests := []struct {
		name           string
		session        *MockSession
		tokenHandler   *MockTokenHandler
		expectedResult AuthFlowResult
	}{
		{
			name: "Valid access token",
			session: &MockSession{
				authenticated: true,
				accessToken:   "valid-access-token",
			},
			tokenHandler: &MockTokenHandler{
				verifyError: nil,
			},
			expectedResult: AuthFlowResult{Authenticated: true},
		},
		{
			name: "Invalid access token, successful refresh",
			session: &MockSession{
				authenticated: true,
				accessToken:   "invalid-access-token",
				refreshToken:  "valid-refresh-token",
			},
			tokenHandler: &MockTokenHandler{
				verifyError:  errors.New("token expired"),
				refreshError: nil,
				tokenResponse: &TokenResponse{
					IDToken:     "new-id-token",
					AccessToken: "new-access-token",
				},
			},
			expectedResult: AuthFlowResult{Authenticated: true},
		},
		{
			name: "Invalid access token, no refresh token",
			session: &MockSession{
				authenticated: true,
				accessToken:   "invalid-access-token",
				refreshToken:  "",
			},
			tokenHandler: &MockTokenHandler{
				verifyError: errors.New("token expired"),
			},
			expectedResult: AuthFlowResult{RequiresAuth: true},
		},
		{
			name: "Valid ID token only",
			session: &MockSession{
				authenticated: true,
				idToken:       "valid-id-token",
			},
			tokenHandler: &MockTokenHandler{
				verifyError: nil,
			},
			expectedResult: AuthFlowResult{Authenticated: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &AuthFlowHandler{
				tokenHandler: test.tokenHandler,
				logger:       &MockLogger{},
			}

			req := httptest.NewRequest("GET", "/", nil)
			rw := httptest.NewRecorder()

			result := handler.validateAndRefreshTokens(test.session, req, rw)

			if result.Authenticated != test.expectedResult.Authenticated {
				t.Errorf("Expected Authenticated %v, got %v", test.expectedResult.Authenticated, result.Authenticated)
			}

			if result.RequiresAuth != test.expectedResult.RequiresAuth {
				t.Errorf("Expected RequiresAuth %v, got %v", test.expectedResult.RequiresAuth, result.RequiresAuth)
			}
		})
	}
}

func TestAuthFlowHandler_attemptTokenRefresh(t *testing.T) {
	tests := []struct {
		name           string
		session        *MockSession
		tokenHandler   *MockTokenHandler
		isAjax         bool
		expectedResult AuthFlowResult
	}{
		{
			name: "No refresh token",
			session: &MockSession{
				refreshToken: "",
			},
			tokenHandler:   &MockTokenHandler{},
			expectedResult: AuthFlowResult{RequiresAuth: true},
		},
		{
			name: "AJAX request with expired session",
			session: &MockSession{
				refreshToken: "refresh-token",
			},
			tokenHandler: &MockTokenHandler{},
			isAjax:       true,
			expectedResult: AuthFlowResult{
				Error:      ErrSessionExpiredAjax,
				StatusCode: http.StatusUnauthorized,
			},
		},
		{
			name: "Successful token refresh",
			session: &MockSession{
				refreshToken: "valid-refresh-token",
			},
			tokenHandler: &MockTokenHandler{
				refreshError: nil,
				tokenResponse: &TokenResponse{
					IDToken:     "new-id-token",
					AccessToken: "new-access-token",
				},
			},
			expectedResult: AuthFlowResult{Authenticated: true},
		},
		{
			name: "Failed token refresh",
			session: &MockSession{
				refreshToken: "invalid-refresh-token",
			},
			tokenHandler: &MockTokenHandler{
				refreshError: errors.New("refresh failed"),
			},
			expectedResult: AuthFlowResult{RequiresAuth: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessionHandlerWrapper := NewMockSessionHandlerWrapper()
			handler := &AuthFlowHandler{
				sessionHandler: sessionHandlerWrapper.SessionHandler,
				tokenHandler:   test.tokenHandler,
				logger:         &MockLogger{},
			}

			req := httptest.NewRequest("GET", "/", nil)
			if test.isAjax {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			rw := httptest.NewRecorder()

			result := handler.attemptTokenRefresh(test.session, req, rw)

			if result.Authenticated != test.expectedResult.Authenticated {
				t.Errorf("Expected Authenticated %v, got %v", test.expectedResult.Authenticated, result.Authenticated)
			}

			if result.RequiresAuth != test.expectedResult.RequiresAuth {
				t.Errorf("Expected RequiresAuth %v, got %v", test.expectedResult.RequiresAuth, result.RequiresAuth)
			}

			if result.StatusCode != test.expectedResult.StatusCode {
				t.Errorf("Expected StatusCode %d, got %d", test.expectedResult.StatusCode, result.StatusCode)
			}
		})
	}
}

func TestAuthFlowError_Error(t *testing.T) {
	err := &AuthFlowError{
		Code:    "TEST_ERROR",
		Message: "This is a test error",
	}

	expected := "This is a test error"
	result := err.Error()

	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestAuthFlowResult(t *testing.T) {
	// Test AuthFlowResult struct
	result := AuthFlowResult{
		Authenticated:   true,
		RequiresAuth:    false,
		RequiresRefresh: false,
		Error:           nil,
		RedirectURL:     "https://example.com",
		StatusCode:      200,
	}

	if !result.Authenticated {
		t.Error("Expected Authenticated to be true")
	}

	if result.RequiresAuth {
		t.Error("Expected RequiresAuth to be false")
	}

	if result.StatusCode != 200 {
		t.Errorf("Expected StatusCode 200, got %d", result.StatusCode)
	}
}

func TestTokenResponse(t *testing.T) {
	response := &TokenResponse{
		IDToken:      "id-token-value",
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		ExpiresIn:    3600,
	}

	if response.IDToken != "id-token-value" {
		t.Errorf("Expected IDToken 'id-token-value', got '%s'", response.IDToken)
	}

	if response.ExpiresIn != 3600 {
		t.Errorf("Expected ExpiresIn 3600, got %d", response.ExpiresIn)
	}
}
