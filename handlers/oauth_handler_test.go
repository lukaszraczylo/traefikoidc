package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Mock implementations for testing
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

func (m *mockLogger) Error(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, msg)
}

//lint:ignore U1000 May be needed for future debug log verification tests
func (m *mockLogger) getDebugLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.debugLogs))
	copy(result, m.debugLogs)
	return result
}

//lint:ignore U1000 May be needed for future error log verification tests
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

type mockSessionManager struct {
	sessionData  *mockSessionData
	sessionError error
	mu           sync.RWMutex
}

func (m *mockSessionManager) GetSession(req *http.Request) (SessionData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.sessionError != nil {
		return nil, m.sessionError
	}
	return m.sessionData, nil
}

func (m *mockSessionManager) setSessionError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionError = err
}

type mockSessionData struct {
	csrf          string
	nonce         string
	codeVerifier  string
	incomingPath  string
	authenticated bool
	email         string
	idToken       string
	accessToken   string
	refreshToken  string
	saveError     error
	setAuthError  error
	mu            sync.RWMutex
	returned      bool
}

func newMockSessionData() *mockSessionData {
	return &mockSessionData{
		csrf:          "test-csrf-token",
		nonce:         "test-nonce",
		codeVerifier:  "test-code-verifier",
		incomingPath:  "/original/path",
		authenticated: false,
	}
}

func (m *mockSessionData) GetCSRF() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.csrf
}

func (m *mockSessionData) GetNonce() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nonce
}

func (m *mockSessionData) GetCodeVerifier() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.codeVerifier
}

func (m *mockSessionData) GetIncomingPath() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.incomingPath
}

func (m *mockSessionData) GetAuthenticated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.authenticated
}

func (m *mockSessionData) SetAuthenticated(auth bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setAuthError != nil {
		return m.setAuthError
	}
	m.authenticated = auth
	return nil
}

func (m *mockSessionData) SetEmail(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.email = email
}

func (m *mockSessionData) SetIDToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idToken = token
}

func (m *mockSessionData) SetAccessToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessToken = token
}

func (m *mockSessionData) SetRefreshToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshToken = token
}

func (m *mockSessionData) SetCSRF(csrf string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.csrf = csrf
}

func (m *mockSessionData) SetNonce(nonce string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonce = nonce
}

func (m *mockSessionData) SetCodeVerifier(verifier string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codeVerifier = verifier
}

func (m *mockSessionData) SetIncomingPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incomingPath = path
}

func (m *mockSessionData) ResetRedirectCount() {
	// Mock implementation
}

func (m *mockSessionData) Save(req *http.Request, rw http.ResponseWriter) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveError
}

func (m *mockSessionData) returnToPoolSafely() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.returned = true
}

func (m *mockSessionData) setSaveError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveError = err
}

func (m *mockSessionData) setSetAuthError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setAuthError = err
}

type mockTokenExchanger struct {
	tokenResponse *TokenResponse
	exchangeError error
	mu            sync.RWMutex
}

func (m *mockTokenExchanger) ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.exchangeError != nil {
		return nil, m.exchangeError
	}
	return m.tokenResponse, nil
}

//lint:ignore U1000 May be needed for future token exchange tests
func (m *mockTokenExchanger) setTokenResponse(response *TokenResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenResponse = response
}

func (m *mockTokenExchanger) setExchangeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exchangeError = err
}

type mockTokenVerifier struct {
	verifyError error
}

func (m *mockTokenVerifier) VerifyToken(token string) error {
	return m.verifyError
}

// Test helper functions
func createTestOAuthHandler() *OAuthHandler {
	logger := &mockLogger{}
	sessionManager := &mockSessionManager{sessionData: newMockSessionData()}
	tokenExchanger := &mockTokenExchanger{
		tokenResponse: &TokenResponse{
			IDToken:      "test.id.token",
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
		},
	}
	tokenVerifier := &mockTokenVerifier{}

	extractClaimsFunc := func(tokenString string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"nonce": "test-nonce",
			"email": "test@example.com",
			"sub":   "test-user-id",
		}, nil
	}

	isAllowedDomainFunc := func(email string) bool {
		return strings.HasSuffix(email, "@example.com")
	}

	sendErrorResponseFunc := func(rw http.ResponseWriter, req *http.Request, message string, code int) {
		http.Error(rw, message, code)
	}

	return NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaimsFunc, isAllowedDomainFunc, "/auth/callback", sendErrorResponseFunc)
}

func TestNewOAuthHandler(t *testing.T) {
	handler := createTestOAuthHandler()

	if handler == nil {
		t.Fatal("NewOAuthHandler returned nil")
	}

	if handler.logger == nil {
		t.Error("Expected logger to be set")
	}

	if handler.sessionManager == nil {
		t.Error("Expected sessionManager to be set")
	}

	if handler.tokenExchanger == nil {
		t.Error("Expected tokenExchanger to be set")
	}

	if handler.redirURLPath != "/auth/callback" {
		t.Errorf("Expected redirURLPath to be '/auth/callback', got %s", handler.redirURLPath)
	}
}

func TestHandleCallback_Success(t *testing.T) {
	handler := createTestOAuthHandler()

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rw.Code)
	}

	location := rw.Header().Get("Location")
	if location != "/original/path" {
		t.Errorf("Expected redirect to '/original/path', got %s", location)
	}

	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	if sessionData.email != "test@example.com" {
		t.Errorf("Expected email to be set to 'test@example.com', got %s", sessionData.email)
	}

	if !sessionData.authenticated {
		t.Error("Expected session to be authenticated")
	}
}

func TestHandleCallback_SessionError(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionManager := handler.sessionManager.(*mockSessionManager)
	sessionManager.setSessionError(fmt.Errorf("session error"))

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Session error during callback") {
		t.Errorf("Expected session error message, got %s", responseBody)
	}
}

func TestHandleCallback_AuthError(t *testing.T) {
	handler := createTestOAuthHandler()

	req := httptest.NewRequest("GET", "/auth/callback?error=access_denied&error_description=User+denied+access", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "User denied access") {
		t.Errorf("Expected error description in response, got %s", responseBody)
	}
}

func TestHandleCallback_MissingState(t *testing.T) {
	handler := createTestOAuthHandler()

	req := httptest.NewRequest("GET", "/auth/callback?code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "State parameter missing") {
		t.Errorf("Expected state missing message, got %s", responseBody)
	}
}

func TestHandleCallback_MissingCSRFToken(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	sessionData.csrf = "" // Clear CSRF token

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "CSRF token missing in session") {
		t.Errorf("Expected CSRF missing message, got %s", responseBody)
	}
}

func TestHandleCallback_CSRFMismatch(t *testing.T) {
	handler := createTestOAuthHandler()

	req := httptest.NewRequest("GET", "/auth/callback?state=wrong-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "CSRF mismatch") {
		t.Errorf("Expected CSRF mismatch message, got %s", responseBody)
	}
}

func TestHandleCallback_MissingCode(t *testing.T) {
	handler := createTestOAuthHandler()

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "No authorization code received") {
		t.Errorf("Expected missing code message, got %s", responseBody)
	}
}

func TestHandleCallback_TokenExchangeError(t *testing.T) {
	handler := createTestOAuthHandler()
	tokenExchanger := handler.tokenExchanger.(*mockTokenExchanger)
	tokenExchanger.setExchangeError(fmt.Errorf("token exchange failed"))

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Could not exchange code for token") {
		t.Errorf("Expected token exchange error message, got %s", responseBody)
	}
}

func TestHandleCallback_TokenVerificationError(t *testing.T) {
	handler := createTestOAuthHandler()
	tokenVerifier := handler.tokenVerifier.(*mockTokenVerifier)
	tokenVerifier.verifyError = fmt.Errorf("token verification failed")

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Could not verify ID token") {
		t.Errorf("Expected token verification error message, got %s", responseBody)
	}
}

func TestHandleCallback_ClaimsExtractionError(t *testing.T) {
	handler := createTestOAuthHandler()
	handler.extractClaimsFunc = func(tokenString string) (map[string]interface{}, error) {
		return nil, fmt.Errorf("claims extraction failed")
	}

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Could not extract claims from token") {
		t.Errorf("Expected claims extraction error message, got %s", responseBody)
	}
}

func TestHandleCallback_MissingNonceClaim(t *testing.T) {
	handler := createTestOAuthHandler()
	handler.extractClaimsFunc = func(tokenString string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"email": "test@example.com",
			"sub":   "test-user-id",
		}, nil
	}

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Nonce missing in token") {
		t.Errorf("Expected nonce missing message, got %s", responseBody)
	}
}

func TestHandleCallback_MissingSessionNonce(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	sessionData.nonce = "" // Clear session nonce

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Nonce missing in session") {
		t.Errorf("Expected nonce missing in session message, got %s", responseBody)
	}
}

func TestHandleCallback_NonceMismatch(t *testing.T) {
	handler := createTestOAuthHandler()
	handler.extractClaimsFunc = func(tokenString string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"nonce": "wrong-nonce",
			"email": "test@example.com",
			"sub":   "test-user-id",
		}, nil
	}

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Nonce mismatch") {
		t.Errorf("Expected nonce mismatch message, got %s", responseBody)
	}
}

func TestHandleCallback_MissingEmail(t *testing.T) {
	handler := createTestOAuthHandler()
	handler.extractClaimsFunc = func(tokenString string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"nonce": "test-nonce",
			"sub":   "test-user-id",
		}, nil
	}

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Email missing in token") {
		t.Errorf("Expected email missing message, got %s", responseBody)
	}
}

func TestHandleCallback_DisallowedEmailDomain(t *testing.T) {
	handler := createTestOAuthHandler()
	handler.extractClaimsFunc = func(tokenString string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"nonce": "test-nonce",
			"email": "test@disallowed.com",
			"sub":   "test-user-id",
		}, nil
	}

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Email domain not allowed") {
		t.Errorf("Expected domain not allowed message, got %s", responseBody)
	}
}

func TestHandleCallback_SetAuthenticatedError(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	sessionData.setSetAuthError(fmt.Errorf("failed to set authenticated"))

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Failed to update session") {
		t.Errorf("Expected session update error message, got %s", responseBody)
	}
}

func TestHandleCallback_SessionSaveError(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	sessionData.setSaveError(fmt.Errorf("failed to save session"))

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Failed to save session after callback") {
		t.Errorf("Expected session save error message, got %s", responseBody)
	}
}

func TestHandleCallback_DefaultRedirect(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	sessionData.incomingPath = "" // No incoming path

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rw.Code)
	}

	location := rw.Header().Get("Location")
	if location != "/" {
		t.Errorf("Expected redirect to '/', got %s", location)
	}
}

func TestHandleCallback_CallbackPathNotRedirected(t *testing.T) {
	handler := createTestOAuthHandler()
	sessionData := handler.sessionManager.(*mockSessionManager).sessionData
	sessionData.incomingPath = "/auth/callback" // Incoming path is callback path

	req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "https://example.com/callback")

	if rw.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rw.Code)
	}

	location := rw.Header().Get("Location")
	if location != "/" {
		t.Errorf("Expected redirect to '/' when incoming path is callback path, got %s", location)
	}
}

func TestURLHelper_NewURLHelper(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	if helper == nil {
		t.Fatal("NewURLHelper returned nil")
	}

	if helper.logger != logger {
		t.Error("Expected logger to be set correctly")
	}
}

func TestURLHelper_DetermineExcludedURL(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name         string
		currentReq   string
		excludedURLs map[string]struct{}
		expected     bool
	}{
		{
			name:       "matches excluded URL",
			currentReq: "/health/check",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: true,
		},
		{
			name:       "does not match excluded URL",
			currentReq: "/protected/resource",
			excludedURLs: map[string]struct{}{
				"/health": {},
				"/api":    {},
			},
			expected: false,
		},
		{
			name:         "empty excluded URLs",
			currentReq:   "/any/path",
			excludedURLs: map[string]struct{}{},
			expected:     false,
		},
		{
			name:       "exact match",
			currentReq: "/health",
			excludedURLs: map[string]struct{}{
				"/health": {},
			},
			expected: true,
		},
		{
			name:       "prefix match",
			currentReq: "/api/v1/users",
			excludedURLs: map[string]struct{}{
				"/api": {},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := helper.DetermineExcludedURL(tt.currentReq, tt.excludedURLs)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestURLHelper_DetermineScheme(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name     string
		req      *http.Request
		expected string
	}{
		{
			name: "X-Forwarded-Proto header present",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Forwarded-Proto", "https")
				return req
			}(),
			expected: "https",
		},
		{
			name: "TLS present",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.TLS = &tls.ConnectionState{}
				return req
			}(),
			expected: "https",
		},
		{
			name:     "no TLS or header",
			req:      httptest.NewRequest("GET", "/test", nil),
			expected: "http",
		},
		{
			name: "X-Forwarded-Proto takes precedence over TLS",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Forwarded-Proto", "http")
				req.TLS = &tls.ConnectionState{}
				return req
			}(),
			expected: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := helper.DetermineScheme(tt.req)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestURLHelper_DetermineHost(t *testing.T) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)

	tests := []struct {
		name     string
		req      *http.Request
		expected string
	}{
		{
			name: "X-Forwarded-Host header present",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com/test", nil)
				req.Header.Set("X-Forwarded-Host", "proxy.example.com")
				return req
			}(),
			expected: "proxy.example.com",
		},
		{
			name:     "no X-Forwarded-Host header",
			req:      httptest.NewRequest("GET", "http://example.com/test", nil),
			expected: "example.com",
		},
		{
			name: "X-Forwarded-Host with port",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "http://example.com:8080/test", nil)
				req.Header.Set("X-Forwarded-Host", "proxy.example.com:443")
				return req
			}(),
			expected: "proxy.example.com:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := helper.DetermineHost(tt.req)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestConcurrentCallbacks(t *testing.T) {
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Create unique session data for each goroutine
			sessionData := newMockSessionData()
			sessionData.csrf = fmt.Sprintf("csrf-token-%d", id)
			sessionData.nonce = fmt.Sprintf("nonce-%d", id)

			sessionManager := &mockSessionManager{sessionData: sessionData}
			localHandler := createTestOAuthHandler()
			localHandler.sessionManager = sessionManager

			// Update extract claims function to match the session nonce
			localHandler.extractClaimsFunc = func(tokenString string) (map[string]interface{}, error) {
				return map[string]interface{}{
					"nonce": fmt.Sprintf("nonce-%d", id),
					"email": fmt.Sprintf("test%d@example.com", id),
					"sub":   fmt.Sprintf("test-user-%d", id),
				}, nil
			}

			req := httptest.NewRequest("GET",
				fmt.Sprintf("/auth/callback?state=csrf-token-%d&code=auth-code-%d", id, id), nil)
			rw := httptest.NewRecorder()

			localHandler.HandleCallback(rw, req, "https://example.com/callback")

			if rw.Code != http.StatusFound {
				errors <- fmt.Errorf("goroutine %d: expected status %d, got %d",
					id, http.StatusFound, rw.Code)
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
		t.Errorf("Found %d errors in concurrent callback test", errorCount)
	}
}

// Benchmark tests
func BenchmarkHandleCallback_Success(b *testing.B) {
	handler := createTestOAuthHandler()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/auth/callback?state=test-csrf-token&code=test-auth-code", nil)
		rw := httptest.NewRecorder()
		handler.HandleCallback(rw, req, "https://example.com/callback")
	}
}

func BenchmarkURLHelper_DetermineExcludedURL(b *testing.B) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)
	excludedURLs := map[string]struct{}{
		"/health": {},
		"/api":    {},
		"/status": {},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.DetermineExcludedURL("/protected/resource", excludedURLs)
	}
}

func BenchmarkURLHelper_DetermineScheme(b *testing.B) {
	logger := &mockLogger{}
	helper := NewURLHelper(logger)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		helper.DetermineScheme(req)
	}
}
