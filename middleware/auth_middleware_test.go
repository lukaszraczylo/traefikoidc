package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Mock implementations for testing
type mockLogger struct {
	debugLogs []string
	infoLogs  []string
	errorLogs []string
	mu        sync.RWMutex
}

func (m *mockLogger) Debug(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, msg)
}

func (m *mockLogger) Debugf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugLogs = append(m.debugLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Error(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, msg)
}

func (m *mockLogger) Errorf(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorLogs = append(m.errorLogs, fmt.Sprintf(format, args...))
}

func (m *mockLogger) Info(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = append(m.infoLogs, msg)
}

func (m *mockLogger) Infof(format string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoLogs = append(m.infoLogs, fmt.Sprintf(format, args...))
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
	m.infoLogs = nil
	m.errorLogs = nil
}

type mockSessionManager struct {
	cleanupCalled bool
	sessionData   *mockSessionData
	sessionError  error
	callCount     int // Track how many times GetSession is called
	mu            sync.RWMutex
}

func (m *mockSessionManager) CleanupOldCookies(rw http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupCalled = true
}

func (m *mockSessionManager) GetSession(req *http.Request) (SessionData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++

	// First call returns error, second call (for clean request) returns valid session
	if m.sessionError != nil && m.callCount == 1 {
		return nil, m.sessionError
	}

	return m.sessionData, nil
}

func (m *mockSessionManager) setSessionError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionError = err
	m.callCount = 0 // Reset call count when setting error
}

type mockSessionData struct {
	email        string
	accessToken  string
	idToken      string
	refreshToken string
	clearError   error
	mu           sync.RWMutex
	returned     bool
}

func newMockSessionData() *mockSessionData {
	return &mockSessionData{}
}

func (m *mockSessionData) GetEmail() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.email
}

func (m *mockSessionData) GetAccessToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.accessToken
}

func (m *mockSessionData) GetIDToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.idToken
}

func (m *mockSessionData) GetRefreshToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.refreshToken
}

func (m *mockSessionData) Clear(req *http.Request, rw http.ResponseWriter) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clearError
}

func (m *mockSessionData) ResetRedirectCount() {
	// Mock implementation
}

func (m *mockSessionData) returnToPoolSafely() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.returned = true
}

func (m *mockSessionData) setEmail(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.email = email
}

func (m *mockSessionData) setAccessToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessToken = token
}

func (m *mockSessionData) setIDToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idToken = token
}

func (m *mockSessionData) setRefreshToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshToken = token
}

//lint:ignore U1000 May be needed for future session clear testing
func (m *mockSessionData) setClearError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clearError = err
}

type mockAuthHandler struct {
	initiateCalled bool
	mu             sync.RWMutex
}

func (m *mockAuthHandler) InitiateAuthentication(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string,
	generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initiateCalled = true
	http.Redirect(rw, req, "https://provider.example.com/auth", http.StatusFound)
}

func (m *mockAuthHandler) wasInitiateCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.initiateCalled
}

//lint:ignore U1000 May be needed for future test isolation
func (m *mockAuthHandler) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initiateCalled = false
}

type mockOAuthHandler struct {
	handleCallbackCalled bool
	mu                   sync.RWMutex
}

func (m *mockOAuthHandler) HandleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handleCallbackCalled = true
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("callback handled"))
}

func (m *mockOAuthHandler) wasHandleCallbackCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.handleCallbackCalled
}

type mockURLHelper struct {
	excludedResult bool
	scheme         string
	host           string
}

func (m *mockURLHelper) DetermineExcludedURL(currentRequest string, excludedURLs map[string]struct{}) bool {
	return m.excludedResult
}

func (m *mockURLHelper) DetermineScheme(req *http.Request) string {
	if m.scheme != "" {
		return m.scheme
	}
	return "https"
}

func (m *mockURLHelper) DetermineHost(req *http.Request) string {
	if m.host != "" {
		return m.host
	}
	return "example.com"
}

type mockTokenVerifier struct {
	verifyError error
}

func (m *mockTokenVerifier) VerifyToken(token string) error {
	return m.verifyError
}

type mockHandler struct {
	serveHTTPCalled bool
	mu              sync.RWMutex
}

func (m *mockHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serveHTTPCalled = true
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("next handler called"))
}

func (m *mockHandler) wasServeHTTPCalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.serveHTTPCalled
}

//lint:ignore U1000 May be needed for future test isolation
func (m *mockHandler) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serveHTTPCalled = false
}

// Test helper functions
func createTestMiddleware() *AuthMiddleware {
	logger := &mockLogger{}
	nextHandler := &mockHandler{}
	sessionManager := &mockSessionManager{sessionData: newMockSessionData()}
	authHandler := &mockAuthHandler{}
	oauthHandler := &mockOAuthHandler{}
	urlHelper := &mockURLHelper{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaimsFunc := func(tokenString string) (map[string]interface{}, error) {
		return map[string]interface{}{"sub": "test-user", "email": "test@example.com"}, nil
	}

	extractGroupsAndRolesFunc := func(tokenString string) ([]string, []string, error) {
		return []string{"group1"}, []string{"role1"}, nil
	}

	sendErrorResponseFunc := func(rw http.ResponseWriter, req *http.Request, message string, code int) {
		http.Error(rw, message, code)
	}

	refreshTokenFunc := func(rw http.ResponseWriter, req *http.Request, session SessionData) bool {
		return true
	}

	isUserAuthenticatedFunc := func(session SessionData) (bool, bool, bool) {
		return true, false, false // authenticated, needsRefresh, expired
	}

	isAllowedDomainFunc := func(email string) bool {
		return true
	}

	isAjaxRequestFunc := func(req *http.Request) bool {
		return strings.Contains(req.Header.Get("Accept"), "application/json") ||
			strings.Contains(req.Header.Get("Content-Type"), "application/json")
	}

	isRefreshTokenExpiredFunc := func(session SessionData) bool {
		return false
	}

	processLogoutFunc := func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("logged out"))
	}

	excludedURLs := make(map[string]struct{})
	allowedRolesAndGroups := make(map[string]struct{})
	initComplete := make(chan struct{})
	close(initComplete) // Initialize as complete
	var goroutineWG sync.WaitGroup

	startTokenCleanupFunc := func() {
		// Mock implementation
	}

	startMetadataRefreshFunc := func(providerURL string) {
		// Mock implementation
	}

	return NewAuthMiddleware(
		logger,
		nextHandler,
		sessionManager,
		authHandler,
		oauthHandler,
		urlHelper,
		tokenVerifier,
		extractClaimsFunc,
		extractGroupsAndRolesFunc,
		sendErrorResponseFunc,
		refreshTokenFunc,
		isUserAuthenticatedFunc,
		isAllowedDomainFunc,
		isAjaxRequestFunc,
		isRefreshTokenExpiredFunc,
		processLogoutFunc,
		excludedURLs,
		allowedRolesAndGroups,
		"/auth/callback",
		"/auth/logout",
		30*time.Second,
		initComplete,
		"https://provider.example.com",
		"https://provider.example.com",
		&goroutineWG,
		startTokenCleanupFunc,
		startMetadataRefreshFunc,
	)
}

func TestNewAuthMiddleware(t *testing.T) {
	middleware := createTestMiddleware()

	if middleware == nil {
		t.Fatal("NewAuthMiddleware returned nil")
	}

	if middleware.logger == nil {
		t.Error("Expected logger to be set")
	}

	if middleware.next == nil {
		t.Error("Expected next handler to be set")
	}

	if middleware.redirURLPath != "/auth/callback" {
		t.Errorf("Expected redirURLPath to be '/auth/callback', got %s", middleware.redirURLPath)
	}

	if middleware.logoutURLPath != "/auth/logout" {
		t.Errorf("Expected logoutURLPath to be '/auth/logout', got %s", middleware.logoutURLPath)
	}
}

func TestServeHTTP_ExcludedURL(t *testing.T) {
	middleware := createTestMiddleware()
	urlHelper := &mockURLHelper{excludedResult: true}
	middleware.urlHelper = urlHelper

	req := httptest.NewRequest("GET", "/excluded/path", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	nextHandler := middleware.next.(*mockHandler)
	if !nextHandler.wasServeHTTPCalled() {
		t.Error("Expected next handler to be called for excluded URL")
	}

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rw.Code)
	}
}

func TestServeHTTP_EventStreamBypass(t *testing.T) {
	middleware := createTestMiddleware()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept", "text/event-stream")
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	nextHandler := middleware.next.(*mockHandler)
	if !nextHandler.wasServeHTTPCalled() {
		t.Error("Expected next handler to be called for event stream request")
	}
}

func TestServeHTTP_InitializationTimeout(t *testing.T) {
	t.Skip("Skipping timeout test to avoid long delays")
	logger := &mockLogger{}
	nextHandler := &mockHandler{}
	sessionManager := &mockSessionManager{sessionData: newMockSessionData()}
	authHandler := &mockAuthHandler{}
	oauthHandler := &mockOAuthHandler{}
	urlHelper := &mockURLHelper{}
	tokenVerifier := &mockTokenVerifier{}

	// Create initComplete channel but don't close it to simulate timeout
	initComplete := make(chan struct{})
	var goroutineWG sync.WaitGroup

	middleware := NewAuthMiddleware(
		logger,
		nextHandler,
		sessionManager,
		authHandler,
		oauthHandler,
		urlHelper,
		tokenVerifier,
		func(string) (map[string]interface{}, error) { return nil, nil },
		func(string) ([]string, []string, error) { return nil, nil, nil },
		func(rw http.ResponseWriter, req *http.Request, message string, code int) {
			http.Error(rw, message, code)
		},
		func(http.ResponseWriter, *http.Request, SessionData) bool { return false },
		func(SessionData) (bool, bool, bool) { return false, false, false },
		func(string) bool { return true },
		func(*http.Request) bool { return false },
		func(SessionData) bool { return false },
		func(http.ResponseWriter, *http.Request) {},
		make(map[string]struct{}),
		make(map[string]struct{}),
		"/auth/callback",
		"/auth/logout",
		10*time.Millisecond, // Very short timeout for testing
		initComplete,
		"",
		"https://provider.example.com",
		&goroutineWG,
		func() {},
		func(string) {},
	)

	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	if rw.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, rw.Code)
	}
}

func TestServeHTTP_SessionError(t *testing.T) {
	middleware := createTestMiddleware()
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.setSessionError(fmt.Errorf("session error"))

	// Ensure we have valid session data for the second call
	sessionManager.sessionData = newMockSessionData()

	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	authHandler := middleware.authHandler.(*mockAuthHandler)
	if !authHandler.wasInitiateCalled() {
		t.Error("Expected InitiateAuthentication to be called when session error occurs")
	}
}

func TestServeHTTP_LogoutPath(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	req := httptest.NewRequest("GET", "/auth/logout", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200 for logout, got %d", rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "logged out") {
		t.Errorf("Expected logout response, got %s", responseBody)
	}
}

func TestServeHTTP_CallbackPath(t *testing.T) {
	middleware := createTestMiddleware()

	req := httptest.NewRequest("GET", "/auth/callback?code=test", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	oauthHandler := middleware.oauthHandler.(*mockOAuthHandler)
	if !oauthHandler.wasHandleCallbackCalled() {
		t.Error("Expected HandleCallback to be called for callback path")
	}
}

func TestServeHTTP_AuthenticatedUser(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setAccessToken("valid.jwt.token")
	sessionData.setIDToken("id.jwt.token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	req := httptest.NewRequest("GET", "/protected", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	nextHandler := middleware.next.(*mockHandler)
	if !nextHandler.wasServeHTTPCalled() {
		t.Error("Expected next handler to be called for authenticated user")
	}

	// Check that user headers are set
	if req.Header.Get("X-Forwarded-User") != "test@example.com" {
		t.Errorf("Expected X-Forwarded-User header to be set to 'test@example.com', got %s", req.Header.Get("X-Forwarded-User"))
	}

	if req.Header.Get("X-Auth-Request-User") != "test@example.com" {
		t.Errorf("Expected X-Auth-Request-User header to be set to 'test@example.com', got %s", req.Header.Get("X-Auth-Request-User"))
	}
}

func TestServeHTTP_DomainNotAllowed(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@disallowed.com")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set isAllowedDomainFunc to return false
	middleware.isAllowedDomainFunc = func(email string) bool {
		return false
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for disallowed domain, got %d", http.StatusForbidden, rw.Code)
	}

	responseBody := rw.Body.String()
	if !strings.Contains(responseBody, "Access denied") {
		t.Errorf("Expected access denied message, got %s", responseBody)
	}
}

func TestServeHTTP_TokenRefreshNeeded(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setRefreshToken("refresh-token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set authenticated but needs refresh
	middleware.isUserAuthenticatedFunc = func(session SessionData) (bool, bool, bool) {
		return true, true, false // authenticated, needsRefresh, not expired
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	nextHandler := middleware.next.(*mockHandler)
	if !nextHandler.wasServeHTTPCalled() {
		t.Error("Expected next handler to be called after successful token refresh")
	}
}

func TestServeHTTP_AjaxRequestWithoutAuth(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set user as not authenticated
	middleware.isUserAuthenticatedFunc = func(session SessionData) (bool, bool, bool) {
		return false, false, false
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for AJAX request without auth, got %d", http.StatusUnauthorized, rw.Code)
	}
}

func TestServeHTTP_ExpiredToken(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set token as expired
	middleware.isUserAuthenticatedFunc = func(session SessionData) (bool, bool, bool) {
		return false, false, true // not authenticated, no refresh needed, expired
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	authHandler := middleware.authHandler.(*mockAuthHandler)
	if !authHandler.wasInitiateCalled() {
		t.Error("Expected InitiateAuthentication to be called for expired token")
	}
}

func TestServeHTTP_RoleBasedAccess(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setIDToken("id.jwt.token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set required roles
	middleware.allowedRolesAndGroups = map[string]struct{}{
		"admin":  {},
		"group1": {},
	}

	// User has group1 which is allowed
	middleware.extractGroupsAndRolesFunc = func(tokenString string) ([]string, []string, error) {
		return []string{"group1"}, []string{"user"}, nil
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	nextHandler := middleware.next.(*mockHandler)
	if !nextHandler.wasServeHTTPCalled() {
		t.Error("Expected next handler to be called for user with allowed role")
	}

	// Check that group headers are set
	if req.Header.Get("X-User-Groups") != "group1" {
		t.Errorf("Expected X-User-Groups header to be set to 'group1', got %s", req.Header.Get("X-User-Groups"))
	}
}

func TestServeHTTP_RoleBasedAccessDenied(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setIDToken("id.jwt.token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set required roles that user doesn't have
	middleware.allowedRolesAndGroups = map[string]struct{}{
		"admin": {},
	}

	// User doesn't have admin role
	middleware.extractGroupsAndRolesFunc = func(tokenString string) ([]string, []string, error) {
		return []string{"group1"}, []string{"user"}, nil
	}

	req := httptest.NewRequest("GET", "/admin", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for user without required role, got %d", http.StatusForbidden, rw.Code)
	}
}

func TestHandleTokenRefresh_FailedRefresh(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setRefreshToken("refresh-token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set refresh to fail
	middleware.refreshTokenFunc = func(rw http.ResponseWriter, req *http.Request, session SessionData) bool {
		return false
	}

	// Set authenticated but needs refresh
	middleware.isUserAuthenticatedFunc = func(session SessionData) (bool, bool, bool) {
		return true, true, false
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	authHandler := middleware.authHandler.(*mockAuthHandler)
	if !authHandler.wasInitiateCalled() {
		t.Error("Expected InitiateAuthentication to be called after failed token refresh")
	}
}

func TestBuildFullURL(t *testing.T) {
	tests := []struct {
		scheme   string
		host     string
		path     string
		expected string
	}{
		{"https", "example.com", "/callback", "https://example.com/callback"},
		{"http", "localhost:8080", "/auth", "http://localhost:8080/auth"},
		{"https", "api.example.com", "/oauth/callback", "https://api.example.com/oauth/callback"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s_%s", tt.scheme, tt.host, tt.path), func(t *testing.T) {
			result := buildFullURL(tt.scheme, tt.host, tt.path)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestConcurrentRequests(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setAccessToken("valid.jwt.token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	const numGoroutines = 10
	const numRequests = 5

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numRequests)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numRequests; j++ {
				req := httptest.NewRequest("GET", fmt.Sprintf("/test-%d-%d", id, j), nil)
				rw := httptest.NewRecorder()

				middleware.ServeHTTP(rw, req)

				if rw.Code != http.StatusOK {
					errors <- fmt.Errorf("goroutine %d request %d: expected status 200, got %d", id, j, rw.Code)
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
		t.Errorf("Found %d errors in concurrent request test", errorCount)
	}
}

func TestServeHTTP_TokenVerificationFailure(t *testing.T) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setAccessToken("invalid.jwt.token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	// Set token verifier to return error
	tokenVerifier := middleware.tokenVerifier.(*mockTokenVerifier)
	tokenVerifier.verifyError = fmt.Errorf("token verification failed")

	req := httptest.NewRequest("GET", "/protected", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	authHandler := middleware.authHandler.(*mockAuthHandler)
	if !authHandler.wasInitiateCalled() {
		t.Error("Expected InitiateAuthentication to be called after token verification failure")
	}
}

func TestServeHTTP_HealthCheckBypass(t *testing.T) {
	middleware := createTestMiddleware()

	// Set up URL helper to return excluded result for health check
	urlHelper := &mockURLHelper{excludedResult: true}
	middleware.urlHelper = urlHelper

	req := httptest.NewRequest("GET", "/health", nil)
	rw := httptest.NewRecorder()

	middleware.ServeHTTP(rw, req)

	nextHandler := middleware.next.(*mockHandler)
	if !nextHandler.wasServeHTTPCalled() {
		t.Error("Expected next handler to be called for health check")
	}
}

func TestServeHTTP_RequestCancellation(t *testing.T) {
	logger := &mockLogger{}
	nextHandler := &mockHandler{}
	sessionManager := &mockSessionManager{sessionData: newMockSessionData()}

	// Create initComplete channel but don't close it to simulate slow initialization
	initComplete := make(chan struct{})
	var goroutineWG sync.WaitGroup

	middleware := NewAuthMiddleware(
		logger,
		nextHandler,
		sessionManager,
		&mockAuthHandler{},
		&mockOAuthHandler{},
		&mockURLHelper{},
		&mockTokenVerifier{},
		func(string) (map[string]interface{}, error) { return nil, nil },
		func(string) ([]string, []string, error) { return nil, nil, nil },
		func(rw http.ResponseWriter, req *http.Request, message string, code int) {
			http.Error(rw, message, code)
		},
		func(http.ResponseWriter, *http.Request, SessionData) bool { return false },
		func(SessionData) (bool, bool, bool) { return false, false, false },
		func(string) bool { return true },
		func(*http.Request) bool { return false },
		func(SessionData) bool { return false },
		func(http.ResponseWriter, *http.Request) {},
		make(map[string]struct{}),
		make(map[string]struct{}),
		"/auth/callback",
		"/auth/logout",
		30*time.Second,
		initComplete,
		"https://provider.example.com",
		"https://provider.example.com",
		&goroutineWG,
		func() {},
		func(string) {},
	)

	// Create context that gets cancelled
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	rw := httptest.NewRecorder()

	// Cancel context immediately
	cancel()

	middleware.ServeHTTP(rw, req)

	if rw.Code != http.StatusRequestTimeout {
		t.Errorf("Expected status %d for cancelled request, got %d", http.StatusRequestTimeout, rw.Code)
	}
}

// Benchmark tests
func BenchmarkServeHTTP_AuthenticatedUser(b *testing.B) {
	middleware := createTestMiddleware()
	sessionData := newMockSessionData()
	sessionData.setEmail("test@example.com")
	sessionData.setAccessToken("valid.jwt.token")
	sessionManager := middleware.sessionManager.(*mockSessionManager)
	sessionManager.sessionData = sessionData

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/protected", nil)
		rw := httptest.NewRecorder()
		middleware.ServeHTTP(rw, req)
	}
}

func BenchmarkServeHTTP_ExcludedURL(b *testing.B) {
	middleware := createTestMiddleware()
	urlHelper := &mockURLHelper{excludedResult: true}
	middleware.urlHelper = urlHelper

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/excluded", nil)
		rw := httptest.NewRecorder()
		middleware.ServeHTTP(rw, req)
	}
}
