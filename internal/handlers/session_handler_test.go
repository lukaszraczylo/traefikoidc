package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSessionHandler(t *testing.T) {
	sessionManager := &MockSessionManager{}
	logger := &MockLogger{}
	logoutURLPath := "/logout"
	postLogoutRedirectURI := "https://example.com/post-logout"
	endSessionURL := "https://provider.example.com/logout"
	clientID := "test-client-id"

	handler := NewSessionHandler(
		sessionManager,
		logger,
		logoutURLPath,
		postLogoutRedirectURI,
		endSessionURL,
		clientID,
	)

	if handler == nil {
		t.Fatal("NewSessionHandler returned nil")
	}

	if handler.sessionManager != sessionManager {
		t.Error("SessionManager not set correctly")
	}

	if handler.logger != logger {
		t.Error("Logger not set correctly")
	}

	if handler.logoutURLPath != logoutURLPath {
		t.Error("LogoutURLPath not set correctly")
	}

	if handler.postLogoutRedirectURI != postLogoutRedirectURI {
		t.Error("PostLogoutRedirectURI not set correctly")
	}

	if handler.endSessionURL != endSessionURL {
		t.Error("EndSessionURL not set correctly")
	}

	if handler.clientID != clientID {
		t.Error("ClientID not set correctly")
	}
}

func TestSessionHandler_HandleLogout(t *testing.T) {
	tests := []struct {
		name         string
		setupSession func() *MockSession
		setupManager func() *MockSessionManager
		expectedCode int
		expectedURL  string
	}{
		{
			name: "Successful logout with ID token",
			setupSession: func() *MockSession {
				return &MockSession{
					authenticated: true,
					idToken:       "test-id-token",
				}
			},
			setupManager: func() *MockSessionManager {
				return &MockSessionManager{
					session: &MockSession{
						authenticated: true,
						idToken:       "test-id-token",
					},
				}
			},
			expectedCode: http.StatusFound,
			expectedURL:  "https://provider.example.com/logout?id_token_hint=test-id-token&post_logout_redirect_uri=https://example.com/post-logout&client_id=test-client-id",
		},
		{
			name: "Logout without ID token",
			setupSession: func() *MockSession {
				return &MockSession{
					authenticated: true,
					idToken:       "",
				}
			},
			setupManager: func() *MockSessionManager {
				return &MockSessionManager{
					session: &MockSession{
						authenticated: true,
						idToken:       "",
					},
				}
			},
			expectedCode: http.StatusFound,
			expectedURL:  "https://provider.example.com/logout?post_logout_redirect_uri=https://example.com/post-logout&client_id=test-client-id",
		},
		{
			name:         "Session retrieval error",
			setupSession: func() *MockSession { return nil },
			setupManager: func() *MockSessionManager {
				return &MockSessionManager{
					err: fmt.Errorf("session error"),
				}
			},
			expectedCode: http.StatusFound,
			expectedURL:  "https://provider.example.com/logout?post_logout_redirect_uri=https://example.com/post-logout&client_id=test-client-id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &SessionHandler{
				sessionManager:        test.setupManager(),
				logger:                &MockLogger{},
				logoutURLPath:         "/logout",
				postLogoutRedirectURI: "https://example.com/post-logout",
				endSessionURL:         "https://provider.example.com/logout",
				clientID:              "test-client-id",
			}

			req := httptest.NewRequest("POST", "/logout", nil)
			rw := httptest.NewRecorder()

			handler.HandleLogout(rw, req)

			if rw.Code != test.expectedCode {
				t.Errorf("Expected status code %d, got %d", test.expectedCode, rw.Code)
			}

			location := rw.Header().Get("Location")
			if location != test.expectedURL {
				t.Errorf("Expected location '%s', got '%s'", test.expectedURL, location)
			}
		})
	}
}

func TestSessionHandler_buildLogoutURL(t *testing.T) {
	tests := []struct {
		name                  string
		endSessionURL         string
		postLogoutRedirectURI string
		clientID              string
		idToken               string
		expected              string
	}{
		{
			name:                  "Complete logout URL with all parameters",
			endSessionURL:         "https://provider.example.com/logout",
			postLogoutRedirectURI: "https://example.com/post-logout",
			clientID:              "test-client-id",
			idToken:               "test-id-token",
			expected:              "https://provider.example.com/logout?id_token_hint=test-id-token&post_logout_redirect_uri=https://example.com/post-logout&client_id=test-client-id",
		},
		{
			name:                  "Logout URL without ID token",
			endSessionURL:         "https://provider.example.com/logout",
			postLogoutRedirectURI: "https://example.com/post-logout",
			clientID:              "test-client-id",
			idToken:               "",
			expected:              "https://provider.example.com/logout?post_logout_redirect_uri=https://example.com/post-logout&client_id=test-client-id",
		},
		{
			name:                  "No end session URL",
			endSessionURL:         "",
			postLogoutRedirectURI: "https://example.com/post-logout",
			clientID:              "test-client-id",
			idToken:               "test-id-token",
			expected:              "https://example.com/post-logout",
		},
		{
			name:                  "End session URL with existing query parameters",
			endSessionURL:         "https://provider.example.com/logout?foo=bar",
			postLogoutRedirectURI: "https://example.com/post-logout",
			clientID:              "test-client-id",
			idToken:               "",
			expected:              "https://provider.example.com/logout?foo=bar&post_logout_redirect_uri=https://example.com/post-logout&client_id=test-client-id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &SessionHandler{
				endSessionURL:         test.endSessionURL,
				postLogoutRedirectURI: test.postLogoutRedirectURI,
				clientID:              test.clientID,
			}

			result := handler.buildLogoutURL(test.idToken)
			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestSessionHandler_ValidateSession(t *testing.T) {
	handler := &SessionHandler{}

	tests := []struct {
		name            string
		session         Session
		expectedValid   bool
		expectedAuth    bool
		expectedMessage string
	}{
		{
			name:            "Nil session",
			session:         nil,
			expectedValid:   false,
			expectedAuth:    true,
			expectedMessage: "session is nil",
		},
		{
			name: "Not authenticated session",
			session: &MockSession{
				authenticated: false,
			},
			expectedValid:   false,
			expectedAuth:    true,
			expectedMessage: "session not authenticated",
		},
		{
			name: "Authenticated session without email",
			session: &MockSession{
				authenticated: true,
				email:         "",
			},
			expectedValid:   false,
			expectedAuth:    true,
			expectedMessage: "no email in session",
		},
		{
			name: "Valid authenticated session with email",
			session: &MockSession{
				authenticated: true,
				email:         "user@example.com",
			},
			expectedValid:   true,
			expectedAuth:    false,
			expectedMessage: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := handler.ValidateSession(test.session)

			if result.Valid != test.expectedValid {
				t.Errorf("Expected Valid %v, got %v", test.expectedValid, result.Valid)
			}

			if result.NeedsAuth != test.expectedAuth {
				t.Errorf("Expected NeedsAuth %v, got %v", test.expectedAuth, result.NeedsAuth)
			}

			if result.ErrorMessage != test.expectedMessage {
				t.Errorf("Expected ErrorMessage '%s', got '%s'", test.expectedMessage, result.ErrorMessage)
			}
		})
	}
}

func TestSessionHandler_CleanupExpiredSession(t *testing.T) {
	tests := []struct {
		name        string
		session     *MockSession
		expectError bool
	}{
		{
			name: "Successful cleanup",
			session: &MockSession{
				authenticated: true,
				email:         "user@example.com",
				refreshToken:  "refresh-token",
			},
			expectError: false,
		},
		{
			name: "Save error during cleanup",
			session: &MockSession{
				authenticated: true,
				email:         "user@example.com",
				refreshToken:  "refresh-token",
				saveError:     fmt.Errorf("save failed"),
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &SessionHandler{
				logger: &MockLogger{},
			}

			req := httptest.NewRequest("GET", "/", nil)
			rw := httptest.NewRecorder()

			err := handler.CleanupExpiredSession(rw, req, test.session)

			if test.expectError && err == nil {
				t.Error("Expected error but got nil")
			}

			if !test.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if test.session != nil && !test.expectError {
				if test.session.authenticated {
					t.Error("Expected session authenticated to be false after cleanup")
				}

				if test.session.email != "" {
					t.Error("Expected session email to be empty after cleanup")
				}

				if test.session.refreshToken != "" {
					t.Error("Expected session refresh token to be empty after cleanup")
				}
			}
		})
	}

	// Test nil session separately
	t.Run("Nil session", func(t *testing.T) {
		handler := &SessionHandler{
			logger: &MockLogger{},
		}

		req := httptest.NewRequest("GET", "/", nil)
		rw := httptest.NewRecorder()

		var nilSession Session = nil
		err := handler.CleanupExpiredSession(rw, req, nilSession)

		if err != nil {
			t.Errorf("Expected no error for nil session, got: %v", err)
		}
	})
}

func TestSessionHandler_IsAjaxRequest(t *testing.T) {
	handler := &SessionHandler{}

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "XMLHttpRequest header",
			headers: map[string]string{
				"X-Requested-With": "XMLHttpRequest",
			},
			expected: true,
		},
		{
			name: "JSON Accept header without HTML",
			headers: map[string]string{
				"Accept": "application/json",
			},
			expected: true,
		},
		{
			name: "JSON Accept header with HTML",
			headers: map[string]string{
				"Accept": "application/json, text/html",
			},
			expected: false,
		},
		{
			name: "Fetch API CORS mode",
			headers: map[string]string{
				"Sec-Fetch-Mode": "cors",
			},
			expected: true,
		},
		{
			name: "Regular browser request",
			headers: map[string]string{
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			},
			expected: false,
		},
		{
			name:     "No special headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for key, value := range test.headers {
				req.Header.Set(key, value)
			}

			result := handler.IsAjaxRequest(req)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestSessionHandler_SendErrorResponse(t *testing.T) {
	tests := []struct {
		name                 string
		isAjax               bool
		message              string
		statusCode           int
		expectedContentType  string
		expectedBodyContains string
	}{
		{
			name:                 "AJAX error response",
			isAjax:               true,
			message:              "Authentication failed",
			statusCode:           http.StatusUnauthorized,
			expectedContentType:  "application/json",
			expectedBodyContains: `{"error": "Authentication failed"}`,
		},
		{
			name:                 "Browser error response",
			isAjax:               false,
			message:              "Session expired",
			statusCode:           http.StatusForbidden,
			expectedContentType:  "text/html",
			expectedBodyContains: "<h1>Error 403</h1>",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &SessionHandler{}

			req := httptest.NewRequest("GET", "/", nil)
			if test.isAjax {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}

			rw := httptest.NewRecorder()

			handler.SendErrorResponse(rw, req, test.message, test.statusCode)

			if rw.Code != test.statusCode {
				t.Errorf("Expected status code %d, got %d", test.statusCode, rw.Code)
			}

			contentType := rw.Header().Get("Content-Type")
			if contentType != test.expectedContentType {
				t.Errorf("Expected Content-Type '%s', got '%s'", test.expectedContentType, contentType)
			}

			body := rw.Body.String()
			if !strings.Contains(body, test.expectedBodyContains) {
				t.Errorf("Expected body to contain '%s', got '%s'", test.expectedBodyContains, body)
			}
		})
	}
}

func TestSessionHandler_SetSecurityHeaders(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		origin         string
		expectedCORS   bool
		expectedStatus int
	}{
		{
			name:           "Regular request without CORS",
			method:         "GET",
			origin:         "",
			expectedCORS:   false,
			expectedStatus: 0, // No status written
		},
		{
			name:           "CORS request with origin",
			method:         "GET",
			origin:         "https://example.com",
			expectedCORS:   true,
			expectedStatus: 0,
		},
		{
			name:           "OPTIONS preflight request",
			method:         "OPTIONS",
			origin:         "https://example.com",
			expectedCORS:   true,
			expectedStatus: http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &SessionHandler{}

			req := httptest.NewRequest(test.method, "/", nil)
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}

			rw := httptest.NewRecorder()

			handler.SetSecurityHeaders(rw, req)

			// Check standard security headers
			expectedSecurityHeaders := map[string]string{
				"X-Frame-Options":        "DENY",
				"X-Content-Type-Options": "nosniff",
				"X-XSS-Protection":       "1; mode=block",
				"Referrer-Policy":        "strict-origin-when-cross-origin",
			}

			for header, expectedValue := range expectedSecurityHeaders {
				actualValue := rw.Header().Get(header)
				if actualValue != expectedValue {
					t.Errorf("Expected %s header '%s', got '%s'", header, expectedValue, actualValue)
				}
			}

			// Check CORS headers
			if test.expectedCORS {
				corsOrigin := rw.Header().Get("Access-Control-Allow-Origin")
				if corsOrigin != test.origin {
					t.Errorf("Expected CORS origin '%s', got '%s'", test.origin, corsOrigin)
				}

				corsCredentials := rw.Header().Get("Access-Control-Allow-Credentials")
				if corsCredentials != "true" {
					t.Errorf("Expected CORS credentials 'true', got '%s'", corsCredentials)
				}

				corsMethods := rw.Header().Get("Access-Control-Allow-Methods")
				if corsMethods != "GET, POST, OPTIONS" {
					t.Errorf("Expected CORS methods 'GET, POST, OPTIONS', got '%s'", corsMethods)
				}

				corsHeaders := rw.Header().Get("Access-Control-Allow-Headers")
				if corsHeaders != "Authorization, Content-Type" {
					t.Errorf("Expected CORS headers 'Authorization, Content-Type', got '%s'", corsHeaders)
				}
			} else {
				corsOrigin := rw.Header().Get("Access-Control-Allow-Origin")
				if corsOrigin != "" {
					t.Errorf("Expected no CORS origin header, got '%s'", corsOrigin)
				}
			}

			// Check status code for OPTIONS requests
			if test.expectedStatus > 0 {
				if rw.Code != test.expectedStatus {
					t.Errorf("Expected status code %d, got %d", test.expectedStatus, rw.Code)
				}
			}
		})
	}
}

func TestSessionValidationResult(t *testing.T) {
	result := SessionValidationResult{
		Valid:        true,
		NeedsAuth:    false,
		ErrorMessage: "test message",
	}

	if !result.Valid {
		t.Error("Expected Valid to be true")
	}

	if result.NeedsAuth {
		t.Error("Expected NeedsAuth to be false")
	}

	if result.ErrorMessage != "test message" {
		t.Errorf("Expected ErrorMessage 'test message', got '%s'", result.ErrorMessage)
	}
}
