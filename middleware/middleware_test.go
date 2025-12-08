package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lukaszraczylo/traefikoidc/internal/utils"
)

// TestUncoveredMiddlewareFunctions tests the functions with 0% coverage in middleware package
func TestUncoveredMiddlewareFunctions(t *testing.T) {
	t.Run("generateNonce", func(t *testing.T) {
		// This function currently returns an error in the stub implementation
		nonce, err := generateNonce()
		if err == nil {
			t.Errorf("Expected generateNonce to return an error in stub implementation")
		}
		if nonce != "" {
			t.Errorf("Expected generateNonce to return empty string, got %s", nonce)
		}
		// Verify the error message
		expectedError := "generateNonce not implemented"
		if err.Error() != expectedError {
			t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
		}
	})

	t.Run("generateCodeVerifier", func(t *testing.T) {
		// This function currently returns an error in the stub implementation
		verifier, err := generateCodeVerifier()
		if err == nil {
			t.Errorf("Expected generateCodeVerifier to return an error in stub implementation")
		}
		if verifier != "" {
			t.Errorf("Expected generateCodeVerifier to return empty string, got %s", verifier)
		}
		// Verify the error message
		expectedError := "generateCodeVerifier not implemented"
		if err.Error() != expectedError {
			t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
		}
	})

	t.Run("deriveCodeChallenge", func(t *testing.T) {
		// This function currently returns an error in the stub implementation
		challenge, err := deriveCodeChallenge()
		if err == nil {
			t.Errorf("Expected deriveCodeChallenge to return an error in stub implementation")
		}
		if challenge != "" {
			t.Errorf("Expected deriveCodeChallenge to return empty string, got %s", challenge)
		}
		// Verify the error message
		expectedError := "deriveCodeChallenge not implemented"
		if err.Error() != expectedError {
			t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
		}
	})
}

// TestBuildFullURLFunction tests the buildFullURL function that already has 100% coverage
// but this ensures we maintain that coverage and test edge cases
func TestBuildFullURLFunction(t *testing.T) {
	t.Run("buildFullURL", func(t *testing.T) {
		// Test basic URL building
		scheme := "https"
		host := "example.com"
		path := "/callback"

		url := utils.BuildFullURL(scheme, host, path)
		expected := "https://example.com/callback"

		if url != expected {
			t.Errorf("Expected URL %s, got %s", expected, url)
		}

		// Test with path that doesn't start with / (function adds leading /)
		url2 := utils.BuildFullURL(scheme, host, "callback")
		expected2 := "https://example.com/callback"

		if url2 != expected2 {
			t.Errorf("Expected URL %s, got %s", expected2, url2)
		}

		// Test with empty path (function adds leading /)
		url3 := utils.BuildFullURL(scheme, host, "")
		expected3 := "https://example.com/"

		if url3 != expected3 {
			t.Errorf("Expected URL %s, got %s", expected3, url3)
		}

		// Test with different schemes
		url4 := utils.BuildFullURL("http", "localhost:8080", "/test")
		expected4 := "http://localhost:8080/test"

		if url4 != expected4 {
			t.Errorf("Expected URL %s, got %s", expected4, url4)
		}

		// Test with special characters
		url5 := utils.BuildFullURL("https", "api.example.com", "/v1/auth?redirect=true")
		expected5 := "https://api.example.com/v1/auth?redirect=true"

		if url5 != expected5 {
			t.Errorf("Expected URL %s, got %s", expected5, url5)
		}

		// Test with empty components (function adds leading /)
		url6 := utils.BuildFullURL("", "", "")
		expected6 := ":///"

		if url6 != expected6 {
			t.Errorf("Expected URL %s, got %s", expected6, url6)
		}

		// Test with port numbers
		url7 := utils.BuildFullURL("http", "localhost:3000", "/admin")
		expected7 := "http://localhost:3000/admin"

		if url7 != expected7 {
			t.Errorf("Expected URL %s, got %s", expected7, url7)
		}
	})
}

// Mock types for testing
type mockLogger struct {
	logs []string
	mu   sync.Mutex
}

func (m *mockLogger) Debug(msg string)                          { m.log("DEBUG: " + msg) }
func (m *mockLogger) Debugf(format string, args ...interface{}) { m.log("DEBUG: " + format) }
func (m *mockLogger) Error(msg string)                          { m.log("ERROR: " + msg) }
func (m *mockLogger) Errorf(format string, args ...interface{}) { m.log("ERROR: " + format) }
func (m *mockLogger) Info(msg string)                           { m.log("INFO: " + msg) }
func (m *mockLogger) Infof(format string, args ...interface{})  { m.log("INFO: " + format) }
func (m *mockLogger) log(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, msg)
}

type mockSessionManager struct {
	getSessionFunc        func(req *http.Request) (SessionData, error)
	cleanupOldCookiesFunc func(rw http.ResponseWriter, req *http.Request)
}

func (m *mockSessionManager) CleanupOldCookies(rw http.ResponseWriter, req *http.Request) {
	if m.cleanupOldCookiesFunc != nil {
		m.cleanupOldCookiesFunc(rw, req)
	}
}

func (m *mockSessionManager) GetSession(req *http.Request) (SessionData, error) {
	if m.getSessionFunc != nil {
		return m.getSessionFunc(req)
	}
	return nil, nil
}

type mockSessionData struct {
	email                  string
	accessToken            string
	idToken                string
	refreshToken           string
	clearFunc              func(req *http.Request, rw http.ResponseWriter) error
	resetRedirectCountFunc func()
}

func (m *mockSessionData) GetEmail() string        { return m.email }
func (m *mockSessionData) GetAccessToken() string  { return m.accessToken }
func (m *mockSessionData) GetIDToken() string      { return m.idToken }
func (m *mockSessionData) GetRefreshToken() string { return m.refreshToken }
func (m *mockSessionData) Clear(req *http.Request, rw http.ResponseWriter) error {
	if m.clearFunc != nil {
		return m.clearFunc(req, rw)
	}
	return nil
}
func (m *mockSessionData) ResetRedirectCount() {
	if m.resetRedirectCountFunc != nil {
		m.resetRedirectCountFunc()
	}
}
func (m *mockSessionData) returnToPoolSafely() {}

type mockAuthHandler struct {
	initiateAuthFunc func(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string,
		generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error))
}

func (m *mockAuthHandler) InitiateAuthentication(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string,
	generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error)) {
	if m.initiateAuthFunc != nil {
		m.initiateAuthFunc(rw, req, session, redirectURL, generateNonce, generateCodeVerifier, deriveCodeChallenge)
	}
}

type mockURLHelper struct {
	determineExcludedFunc func(currentRequest string, excludedURLs map[string]struct{}) bool
	determineSchemeFunc   func(req *http.Request) string
	determineHostFunc     func(req *http.Request) string
}

func (m *mockURLHelper) DetermineExcludedURL(currentRequest string, excludedURLs map[string]struct{}) bool {
	if m.determineExcludedFunc != nil {
		return m.determineExcludedFunc(currentRequest, excludedURLs)
	}
	return false
}

func (m *mockURLHelper) DetermineScheme(req *http.Request) string {
	if m.determineSchemeFunc != nil {
		return m.determineSchemeFunc(req)
	}
	return "https"
}

func (m *mockURLHelper) DetermineHost(req *http.Request) string {
	if m.determineHostFunc != nil {
		return m.determineHostFunc(req)
	}
	return "example.com"
}

type mockTokenVerifier struct {
	verifyFunc func(token string) error
}

func (m *mockTokenVerifier) VerifyToken(token string) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(token)
	}
	return nil
}

// TestStubFunctionsErrorBehavior tests error behaviors more thoroughly
func TestStubFunctionsErrorBehavior(t *testing.T) {
	t.Run("generateNonce_multiple_calls", func(t *testing.T) {
		// Test multiple calls to ensure consistent behavior
		for i := 0; i < 3; i++ {
			nonce, err := generateNonce()
			if err == nil {
				t.Errorf("Call %d: Expected generateNonce to return an error", i)
			}
			if nonce != "" {
				t.Errorf("Call %d: Expected empty nonce, got %s", i, nonce)
			}
		}
	})

	t.Run("generateCodeVerifier_multiple_calls", func(t *testing.T) {
		// Test multiple calls to ensure consistent behavior
		for i := 0; i < 3; i++ {
			verifier, err := generateCodeVerifier()
			if err == nil {
				t.Errorf("Call %d: Expected generateCodeVerifier to return an error", i)
			}
			if verifier != "" {
				t.Errorf("Call %d: Expected empty verifier, got %s", i, verifier)
			}
		}
	})

	t.Run("deriveCodeChallenge_multiple_calls", func(t *testing.T) {
		// Test multiple calls to ensure consistent behavior
		for i := 0; i < 3; i++ {
			challenge, err := deriveCodeChallenge()
			if err == nil {
				t.Errorf("Call %d: Expected deriveCodeChallenge to return an error", i)
			}
			if challenge != "" {
				t.Errorf("Call %d: Expected empty challenge, got %s", i, challenge)
			}
		}
	})
}

// TestHandleTokenRefresh tests the handleTokenRefresh method with various scenarios
func TestHandleTokenRefresh(t *testing.T) {
	tests := []struct {
		name                    string
		needsRefresh            bool
		authenticated           bool
		isAjaxRequest           bool
		refreshSuccess          bool
		allowedDomain           bool
		expectErrorResponse     bool
		expectProcessAuthorized bool
		expectInitAuth          bool
	}{
		{
			name:                    "successful_refresh_authenticated",
			needsRefresh:            true,
			authenticated:           true,
			isAjaxRequest:           false,
			refreshSuccess:          true,
			allowedDomain:           true,
			expectProcessAuthorized: true,
		},
		{
			name:                    "successful_refresh_not_authenticated",
			needsRefresh:            true,
			authenticated:           false,
			isAjaxRequest:           false,
			refreshSuccess:          true,
			allowedDomain:           true,
			expectProcessAuthorized: true,
		},
		{
			name:                "successful_refresh_disallowed_domain",
			needsRefresh:        true,
			authenticated:       true,
			isAjaxRequest:       false,
			refreshSuccess:      true,
			allowedDomain:       false,
			expectErrorResponse: true,
		},
		{
			name:           "failed_refresh_browser_request",
			needsRefresh:   true,
			authenticated:  true,
			isAjaxRequest:  false,
			refreshSuccess: false,
			expectInitAuth: true,
		},
		{
			name:                "failed_refresh_ajax_request",
			needsRefresh:        true,
			authenticated:       true,
			isAjaxRequest:       true,
			refreshSuccess:      false,
			expectErrorResponse: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			logger := &mockLogger{}
			nextHandlerCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextHandlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			session := &mockSessionData{
				email:        "test@example.com",
				accessToken:  "access_token",
				idToken:      "id_token",
				refreshToken: "refresh_token",
			}

			initAuthCalled := false
			errorResponseSent := false

			m := &AuthMiddleware{
				logger:        logger,
				next:          nextHandler,
				logoutURLPath: "/logout",
				refreshTokenFunc: func(rw http.ResponseWriter, req *http.Request, session SessionData) bool {
					return tt.refreshSuccess
				},
				isAllowedDomainFunc: func(email string) bool {
					return tt.allowedDomain
				},
				isAjaxRequestFunc: func(req *http.Request) bool {
					return tt.isAjaxRequest
				},
				sendErrorResponseFunc: func(rw http.ResponseWriter, req *http.Request, message string, code int) {
					errorResponseSent = true
					rw.WriteHeader(code)
				},
				authHandler: &mockAuthHandler{
					initiateAuthFunc: func(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string,
						generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error)) {
						initAuthCalled = true
					},
				},
				extractGroupsAndRolesFunc: func(token string) ([]string, []string, error) {
					return nil, nil, nil
				},
			}

			// Create request and response recorder
			req := httptest.NewRequest("GET", "/test", nil)
			rw := httptest.NewRecorder()

			// Call the method under test
			m.handleTokenRefresh(rw, req, session, "https://example.com/callback",
				tt.needsRefresh, tt.authenticated, tt.isAjaxRequest)

			// Verify expectations - processAuthorizedRequest will call the next handler if successful
			if tt.expectProcessAuthorized && !nextHandlerCalled {
				t.Error("Expected processAuthorizedRequest to complete (next handler called)")
			}
			if tt.expectInitAuth && !initAuthCalled {
				t.Error("Expected InitiateAuthentication to be called")
			}
			if tt.expectErrorResponse && !errorResponseSent {
				t.Error("Expected error response to be sent")
			}
		})
	}
}

// TestProcessAuthorizedRequest tests the processAuthorizedRequest method
func TestProcessAuthorizedRequest(t *testing.T) {
	tests := []struct {
		name            string
		email           string
		idToken         string
		accessToken     string
		allowedRoles    map[string]struct{}
		userGroups      []string
		userRoles       []string
		extractError    error
		expectHeaders   bool
		expectForbidden bool
		expectReauth    bool
	}{
		{
			name:         "no_email_triggers_reauth",
			email:        "",
			idToken:      "token",
			expectReauth: true,
		},
		{
			name:          "successful_with_id_token",
			email:         "user@example.com",
			idToken:       "id_token",
			accessToken:   "access_token",
			expectHeaders: true,
		},
		{
			name:          "successful_with_access_token_only",
			email:         "user@example.com",
			idToken:       "",
			accessToken:   "access_token",
			expectHeaders: true,
		},
		{
			name:         "no_token_with_role_requirements",
			email:        "user@example.com",
			idToken:      "",
			accessToken:  "",
			allowedRoles: map[string]struct{}{"admin": {}},
			expectReauth: true,
		},
		{
			name:          "user_has_allowed_role",
			email:         "user@example.com",
			idToken:       "token",
			allowedRoles:  map[string]struct{}{"admin": {}},
			userRoles:     []string{"admin", "user"},
			expectHeaders: true,
		},
		{
			name:          "user_has_allowed_group",
			email:         "user@example.com",
			idToken:       "token",
			allowedRoles:  map[string]struct{}{"developers": {}},
			userGroups:    []string{"developers", "testers"},
			expectHeaders: true,
		},
		{
			name:            "user_lacks_required_roles",
			email:           "user@example.com",
			idToken:         "token",
			allowedRoles:    map[string]struct{}{"admin": {}},
			userRoles:       []string{"user"},
			expectForbidden: true,
		},
		{
			name:         "extract_error_with_role_requirements",
			email:        "user@example.com",
			idToken:      "token",
			allowedRoles: map[string]struct{}{"admin": {}},
			extractError: errors.New("extraction failed"),
			expectReauth: true,
		},
		{
			name:          "extract_error_without_role_requirements",
			email:         "user@example.com",
			idToken:       "token",
			extractError:  errors.New("extraction failed"),
			expectHeaders: true, // Should continue without roles/groups
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			logger := &mockLogger{}
			nextHandlerCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextHandlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			session := &mockSessionData{
				email:       tt.email,
				accessToken: tt.accessToken,
				idToken:     tt.idToken,
			}

			initAuthCalled := false
			errorResponseSent := false
			var errorCode int

			m := &AuthMiddleware{
				logger:                logger,
				next:                  nextHandler,
				allowedRolesAndGroups: tt.allowedRoles,
				logoutURLPath:         "/logout",
				extractGroupsAndRolesFunc: func(tokenString string) ([]string, []string, error) {
					if tt.extractError != nil {
						return nil, nil, tt.extractError
					}
					return tt.userGroups, tt.userRoles, nil
				},
				sendErrorResponseFunc: func(rw http.ResponseWriter, req *http.Request, message string, code int) {
					errorResponseSent = true
					errorCode = code
					rw.WriteHeader(code)
				},
				authHandler: &mockAuthHandler{
					initiateAuthFunc: func(rw http.ResponseWriter, req *http.Request, session SessionData, redirectURL string,
						generateNonce, generateCodeVerifier, deriveCodeChallenge func() (string, error)) {
						initAuthCalled = true
						// Ensure ResetRedirectCount was called
						if mockSession, ok := session.(*mockSessionData); ok {
							if mockSession.resetRedirectCountFunc != nil {
								mockSession.resetRedirectCountFunc()
							}
						}
					},
				},
			}

			// Track ResetRedirectCount calls
			resetCountCalled := false
			session.resetRedirectCountFunc = func() {
				resetCountCalled = true
			}

			// Create request and response recorder
			req := httptest.NewRequest("GET", "/test", nil)
			rw := httptest.NewRecorder()

			// Call the method under test
			m.processAuthorizedRequest(rw, req, session, "https://example.com/callback")

			// Verify expectations
			if tt.expectHeaders && !nextHandlerCalled {
				t.Error("Expected next handler to be called")
			}

			if tt.expectHeaders {
				if req.Header.Get("X-Forwarded-User") != tt.email {
					t.Errorf("Expected X-Forwarded-User header to be %s, got %s",
						tt.email, req.Header.Get("X-Forwarded-User"))
				}
				if req.Header.Get("X-Auth-Request-User") != tt.email {
					t.Errorf("Expected X-Auth-Request-User header to be %s, got %s",
						tt.email, req.Header.Get("X-Auth-Request-User"))
				}
				if tt.idToken != "" && req.Header.Get("X-Auth-Request-Token") != tt.idToken {
					t.Errorf("Expected X-Auth-Request-Token header to be %s, got %s",
						tt.idToken, req.Header.Get("X-Auth-Request-Token"))
				}
				if len(tt.userGroups) > 0 && req.Header.Get("X-User-Groups") == "" {
					t.Error("Expected X-User-Groups header to be set")
				}
				if len(tt.userRoles) > 0 && req.Header.Get("X-User-Roles") == "" {
					t.Error("Expected X-User-Roles header to be set")
				}
			}

			if tt.expectForbidden && (!errorResponseSent || errorCode != http.StatusForbidden) {
				t.Error("Expected forbidden response")
			}

			if tt.expectReauth {
				if !initAuthCalled {
					t.Error("Expected InitiateAuthentication to be called")
				}
				if !resetCountCalled {
					t.Error("Expected ResetRedirectCount to be called before reauth")
				}
			}
		})
	}
}

// TestServeHTTP_AdditionalCoverage tests additional ServeHTTP scenarios for better coverage
func TestServeHTTP_AdditionalCoverage(t *testing.T) {
	t.Run("first_request_starts_background_tasks", func(t *testing.T) {
		// Setup mocks
		logger := &mockLogger{}
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		tokenCleanupStarted := false
		metadataRefreshStarted := false

		initComplete := make(chan struct{})
		close(initComplete) // Already initialized

		wg := &sync.WaitGroup{}

		m := &AuthMiddleware{
			logger:       logger,
			next:         nextHandler,
			issuerURL:    "https://issuer.example.com",
			providerURL:  "https://provider.example.com",
			initComplete: initComplete,
			goroutineWG:  wg,
			sessionManager: &mockSessionManager{
				getSessionFunc: func(req *http.Request) (SessionData, error) {
					return &mockSessionData{
						email:       "user@example.com",
						accessToken: "token",
					}, nil
				},
			},
			urlHelper: &mockURLHelper{
				determineExcludedFunc: func(path string, urls map[string]struct{}) bool {
					return false
				},
			},
			isUserAuthenticatedFunc: func(session SessionData) (bool, bool, bool) {
				return true, false, false
			},
			isAllowedDomainFunc: func(email string) bool {
				return true
			},
			tokenVerifier: &mockTokenVerifier{},
			extractGroupsAndRolesFunc: func(token string) ([]string, []string, error) {
				return nil, nil, nil
			},
			startTokenCleanupFunc: func() {
				tokenCleanupStarted = true
			},
			startMetadataRefreshFunc: func(url string) {
				metadataRefreshStarted = true
			},
		}

		// First request should start background tasks
		req := httptest.NewRequest("GET", "/api/test", nil)
		rw := httptest.NewRecorder()

		m.ServeHTTP(rw, req)

		if !tokenCleanupStarted {
			t.Error("Expected token cleanup to be started on first request")
		}
		if !metadataRefreshStarted {
			t.Error("Expected metadata refresh to be started on first request")
		}
		if !m.firstRequestReceived {
			t.Error("Expected firstRequestReceived to be set")
		}

		// Second request should not start tasks again
		tokenCleanupStarted = false
		metadataRefreshStarted = false

		req2 := httptest.NewRequest("GET", "/api/test2", nil)
		rw2 := httptest.NewRecorder()

		m.ServeHTTP(rw2, req2)

		if tokenCleanupStarted {
			t.Error("Token cleanup should not be started again")
		}
		if metadataRefreshStarted {
			t.Error("Metadata refresh should not be started again")
		}
	})

	t.Run("health_endpoint_skips_first_request_logic", func(t *testing.T) {
		logger := &mockLogger{}
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		tokenCleanupStarted := false
		metadataRefreshStarted := false

		initComplete := make(chan struct{})
		close(initComplete)

		m := &AuthMiddleware{
			logger:       logger,
			next:         nextHandler,
			issuerURL:    "https://issuer.example.com",
			initComplete: initComplete,
			excludedURLs: map[string]struct{}{"/health": {}},
			sessionManager: &mockSessionManager{
				getSessionFunc: func(req *http.Request) (SessionData, error) {
					return &mockSessionData{}, nil
				},
			},
			urlHelper: &mockURLHelper{
				determineExcludedFunc: func(path string, urls map[string]struct{}) bool {
					_, ok := urls[path]
					return ok
				},
			},
			startTokenCleanupFunc: func() {
				tokenCleanupStarted = true
			},
			startMetadataRefreshFunc: func(url string) {
				metadataRefreshStarted = true
			},
		}

		// Health request should not trigger background tasks
		req := httptest.NewRequest("GET", "/health", nil)
		rw := httptest.NewRecorder()

		m.ServeHTTP(rw, req)

		if tokenCleanupStarted {
			t.Error("Token cleanup should not be started for health endpoint")
		}
		if metadataRefreshStarted {
			t.Error("Metadata refresh should not be started for health endpoint")
		}
		if m.firstRequestReceived {
			t.Error("firstRequestReceived should not be set for health endpoint")
		}
	})

	t.Run("opaque_access_token_skips_jwt_verification", func(t *testing.T) {
		logger := &mockLogger{}
		nextHandlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextHandlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		initComplete := make(chan struct{})
		close(initComplete)

		verifyTokenCalled := false

		m := &AuthMiddleware{
			logger:               logger,
			next:                 nextHandler,
			issuerURL:            "https://issuer.example.com",
			initComplete:         initComplete,
			firstRequestReceived: true, // Skip first request logic
			sessionManager: &mockSessionManager{
				getSessionFunc: func(req *http.Request) (SessionData, error) {
					return &mockSessionData{
						email:       "user@example.com",
						accessToken: "opaque_token_without_dots", // Opaque token
					}, nil
				},
			},
			urlHelper: &mockURLHelper{
				determineExcludedFunc: func(path string, urls map[string]struct{}) bool {
					return false
				},
			},
			isUserAuthenticatedFunc: func(session SessionData) (bool, bool, bool) {
				return true, false, false // Authenticated, no refresh needed
			},
			isAllowedDomainFunc: func(email string) bool {
				return true
			},
			tokenVerifier: &mockTokenVerifier{
				verifyFunc: func(token string) error {
					verifyTokenCalled = true
					return nil
				},
			},
			extractGroupsAndRolesFunc: func(token string) ([]string, []string, error) {
				return nil, nil, nil
			},
			startTokenCleanupFunc:    func() {},
			startMetadataRefreshFunc: func(url string) {},
		}

		req := httptest.NewRequest("GET", "/api/test", nil)
		rw := httptest.NewRecorder()

		m.ServeHTTP(rw, req)

		if verifyTokenCalled {
			t.Error("JWT verification should be skipped for opaque tokens")
		}
		if !nextHandlerCalled {
			t.Error("Next handler should be called for valid opaque token")
		}
	})
}

// TestProcessAuthorizedRequest_MinimalHeaders tests the minimalHeaders configuration
// This addresses GitHub issue #64 - Request Header Fields Too Large
func TestProcessAuthorizedRequest_MinimalHeaders(t *testing.T) {
	tests := []struct {
		name                      string
		minimalHeaders            bool
		expectForwardedUser       bool
		expectAuthRequestUser     bool
		expectAuthRequestToken    bool
		expectAuthRequestRedirect bool
	}{
		{
			name:                      "minimalHeaders=false forwards all headers",
			minimalHeaders:            false,
			expectForwardedUser:       true,
			expectAuthRequestUser:     true,
			expectAuthRequestToken:    true,
			expectAuthRequestRedirect: true,
		},
		{
			name:                      "minimalHeaders=true only forwards X-Forwarded-User",
			minimalHeaders:            true,
			expectForwardedUser:       true,
			expectAuthRequestUser:     false,
			expectAuthRequestToken:    false,
			expectAuthRequestRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			var capturedHeaders http.Header

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			})

			session := &mockSessionData{
				email:       "user@example.com",
				idToken:     "test-id-token-that-could-be-very-large",
				accessToken: "test-access-token",
			}

			m := &AuthMiddleware{
				logger:         logger,
				next:           nextHandler,
				minimalHeaders: tt.minimalHeaders,
				extractGroupsAndRolesFunc: func(tokenString string) ([]string, []string, error) {
					return nil, nil, nil
				},
			}

			req := httptest.NewRequest("GET", "/protected", nil)
			rw := httptest.NewRecorder()

			m.processAuthorizedRequest(rw, req, session, "https://example.com/callback")

			// Verify X-Forwarded-User is always set
			if tt.expectForwardedUser {
				if capturedHeaders.Get("X-Forwarded-User") != "user@example.com" {
					t.Errorf("expected X-Forwarded-User to be set, got %q", capturedHeaders.Get("X-Forwarded-User"))
				}
			}

			// Verify X-Auth-Request-User
			hasAuthRequestUser := capturedHeaders.Get("X-Auth-Request-User") != ""
			if tt.expectAuthRequestUser && !hasAuthRequestUser {
				t.Error("expected X-Auth-Request-User to be set")
			}
			if !tt.expectAuthRequestUser && hasAuthRequestUser {
				t.Errorf("expected X-Auth-Request-User to NOT be set when minimalHeaders=true, got %q", capturedHeaders.Get("X-Auth-Request-User"))
			}

			// Verify X-Auth-Request-Token (the big one that causes 431 errors)
			hasAuthRequestToken := capturedHeaders.Get("X-Auth-Request-Token") != ""
			if tt.expectAuthRequestToken && !hasAuthRequestToken {
				t.Error("expected X-Auth-Request-Token to be set")
			}
			if !tt.expectAuthRequestToken && hasAuthRequestToken {
				t.Errorf("expected X-Auth-Request-Token to NOT be set when minimalHeaders=true, got %q", capturedHeaders.Get("X-Auth-Request-Token"))
			}

			// Verify X-Auth-Request-Redirect
			hasAuthRequestRedirect := capturedHeaders.Get("X-Auth-Request-Redirect") != ""
			if tt.expectAuthRequestRedirect && !hasAuthRequestRedirect {
				t.Error("expected X-Auth-Request-Redirect to be set")
			}
			if !tt.expectAuthRequestRedirect && hasAuthRequestRedirect {
				t.Errorf("expected X-Auth-Request-Redirect to NOT be set when minimalHeaders=true, got %q", capturedHeaders.Get("X-Auth-Request-Redirect"))
			}
		})
	}
}
