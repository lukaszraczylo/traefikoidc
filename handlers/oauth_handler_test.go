package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test mocks - implementing interfaces defined in oauth_handler.go
type mockLogger struct {
	debugMessages []string
	errorMessages []string
}

func (l *mockLogger) Debugf(format string, args ...interface{}) {
	l.debugMessages = append(l.debugMessages, format)
}

func (l *mockLogger) Errorf(format string, args ...interface{}) {
	l.errorMessages = append(l.errorMessages, format)
}

func (l *mockLogger) Error(msg string) {
	l.errorMessages = append(l.errorMessages, msg)
}

type mockSessionManager struct {
	sessionToReturn SessionData
	errorToReturn   error
}

func (m *mockSessionManager) GetSession(req *http.Request) (SessionData, error) {
	return m.sessionToReturn, m.errorToReturn
}

type mockSessionData struct {
	authenticated bool
	email         string
	csrf          string
	nonce         string
	codeVerifier  string
	incomingPath  string
	accessToken   string
	refreshToken  string
	idToken       string
	saveError     error
	setAuthError  error
}

func (s *mockSessionData) GetCSRF() string         { return s.csrf }
func (s *mockSessionData) GetNonce() string        { return s.nonce }
func (s *mockSessionData) GetCodeVerifier() string { return s.codeVerifier }
func (s *mockSessionData) GetIncomingPath() string { return s.incomingPath }
func (s *mockSessionData) GetAuthenticated() bool  { return s.authenticated }
func (s *mockSessionData) GetAccessToken() string  { return s.accessToken }
func (s *mockSessionData) GetRefreshToken() string { return s.refreshToken }
func (s *mockSessionData) GetIDToken() string      { return s.idToken }
func (s *mockSessionData) GetEmail() string        { return s.email }

func (s *mockSessionData) SetAuthenticated(auth bool) error {
	s.authenticated = auth
	return s.setAuthError
}

func (s *mockSessionData) SetEmail(email string)        { s.email = email }
func (s *mockSessionData) SetIDToken(token string)      { s.idToken = token }
func (s *mockSessionData) SetAccessToken(token string)  { s.accessToken = token }
func (s *mockSessionData) SetRefreshToken(token string) { s.refreshToken = token }
func (s *mockSessionData) SetCSRF(csrf string)          { s.csrf = csrf }
func (s *mockSessionData) SetNonce(nonce string)        { s.nonce = nonce }
func (s *mockSessionData) SetCodeVerifier(verif string) { s.codeVerifier = verif }
func (s *mockSessionData) SetIncomingPath(path string)  { s.incomingPath = path }
func (s *mockSessionData) ResetRedirectCount()          {}
func (s *mockSessionData) returnToPoolSafely()          {}

func (s *mockSessionData) Save(req *http.Request, rw http.ResponseWriter) error {
	return s.saveError
}

type mockTokenExchanger struct {
	response *TokenResponse
	err      error
}

func (e *mockTokenExchanger) ExchangeCodeForToken(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	return e.response, e.err
}

type mockTokenVerifier struct {
	err error
}

func (v *mockTokenVerifier) VerifyToken(token string) error {
	return v.err
}

// TestOAuthHandler_NewOAuthHandler tests the constructor
func TestOAuthHandler_NewOAuthHandler(t *testing.T) {
	logger := &mockLogger{}
	sessionManager := &mockSessionManager{}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}

	isAllowed := func(email string) bool { return true }
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	if handler == nil {
		t.Fatal("Expected handler to be created, got nil")
	}

	if handler.logger != logger {
		t.Error("Logger not set correctly")
	}

	if handler.redirURLPath != "/callback" {
		t.Errorf("Expected redirURLPath '/callback', got '%s'", handler.redirURLPath)
	}
}

// TestOAuthHandler_HandleCallback_SessionError tests session retrieval errors
func TestOAuthHandler_HandleCallback_SessionError(t *testing.T) {
	logger := &mockLogger{}
	sessionManager := &mockSessionManager{errorToReturn: errors.New("session error")}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return nil, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Session error") {
			t.Errorf("Expected error message to contain 'Session error', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test&state=test", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}
}

// TestOAuthHandler_HandleCallback_ProviderError tests OAuth provider errors
func TestOAuthHandler_HandleCallback_ProviderError(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, code)
		}
		if !strings.Contains(msg, "Authentication error from provider") {
			t.Errorf("Expected error message to contain 'Authentication error from provider', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	// Test with error parameter
	req := httptest.NewRequest("GET", "/callback?error=access_denied&error_description=User%20denied%20access", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}
}

// TestOAuthHandler_HandleCallback_MissingState tests missing state parameter
func TestOAuthHandler_HandleCallback_MissingState(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, code)
		}
		if !strings.Contains(msg, "State parameter missing") {
			t.Errorf("Expected error message to contain 'State parameter missing', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_MissingCSRF tests missing CSRF token in session
func TestOAuthHandler_HandleCallback_MissingCSRF(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: ""} // Empty CSRF
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, code)
		}
		if !strings.Contains(msg, "CSRF token missing") {
			t.Errorf("Expected error message to contain 'CSRF token missing', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_CSRFMismatch tests CSRF token mismatch
func TestOAuthHandler_HandleCallback_CSRFMismatch(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "different-token"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, code)
		}
		if !strings.Contains(msg, "CSRF mismatch") {
			t.Errorf("Expected error message to contain 'CSRF mismatch', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_MissingCode tests missing authorization code
func TestOAuthHandler_HandleCallback_MissingCode(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenExchanger := &mockTokenExchanger{}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, code)
		}
		if !strings.Contains(msg, "No authorization code received") {
			t.Errorf("Expected error message to contain 'No authorization code received', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_TokenExchangeError tests token exchange failure
func TestOAuthHandler_HandleCallback_TokenExchangeError(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce", codeVerifier: "test-verifier"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenExchanger := &mockTokenExchanger{err: errors.New("token exchange failed")}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Could not exchange code for token") {
			t.Errorf("Expected error message to contain 'Could not exchange code for token', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_TokenVerificationError tests token verification failure
func TestOAuthHandler_HandleCallback_TokenVerificationError(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "invalid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{err: errors.New("token verification failed")}

	extractClaims := func(token string) (map[string]interface{}, error) { return nil, nil }
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Could not verify ID token") {
			t.Errorf("Expected error message to contain 'Could not verify ID token', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_ClaimsExtractionError tests claims extraction failure
func TestOAuthHandler_HandleCallback_ClaimsExtractionError(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return nil, errors.New("claims extraction failed")
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Could not extract claims") {
			t.Errorf("Expected error message to contain 'Could not extract claims', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_MissingNonceInToken tests missing nonce in token
func TestOAuthHandler_HandleCallback_MissingNonceInToken(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	// Claims without nonce
	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com"}, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Nonce missing in token") {
			t.Errorf("Expected error message to contain 'Nonce missing in token', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_MissingNonceInSession tests missing nonce in session
func TestOAuthHandler_HandleCallback_MissingNonceInSession(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: ""} // Empty nonce
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Nonce missing in session") {
			t.Errorf("Expected error message to contain 'Nonce missing in session', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_NonceMismatch tests nonce mismatch
func TestOAuthHandler_HandleCallback_NonceMismatch(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "session-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "token-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Nonce mismatch") {
			t.Errorf("Expected error message to contain 'Nonce mismatch', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_MissingEmail tests missing email in claims
func TestOAuthHandler_HandleCallback_MissingEmail(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"nonce": "test-nonce"}, nil // No email
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Email missing in token") {
			t.Errorf("Expected error message to contain 'Email missing in token', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_DisallowedDomain tests disallowed email domain
func TestOAuthHandler_HandleCallback_DisallowedDomain(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{csrf: "test-state", nonce: "test-nonce"}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@disallowed.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return false } // Disallow all domains

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, code)
		}
		if !strings.Contains(msg, "Email domain not allowed") {
			t.Errorf("Expected error message to contain 'Email domain not allowed', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_SessionSaveError tests session save failure
func TestOAuthHandler_HandleCallback_SessionSaveError(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{
		csrf:      "test-state",
		nonce:     "test-nonce",
		saveError: errors.New("save failed"),
	}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token", RefreshToken: "refresh-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Failed to save session") {
			t.Errorf("Expected error message to contain 'Failed to save session', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_SetAuthenticatedError tests SetAuthenticated failure
func TestOAuthHandler_HandleCallback_SetAuthenticatedError(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{
		csrf:         "test-state",
		nonce:        "test-nonce",
		setAuthError: errors.New("set auth failed"),
	}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		if code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, code)
		}
		if !strings.Contains(msg, "Failed to update session") {
			t.Errorf("Expected error message to contain 'Failed to update session', got '%s'", msg)
		}
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if !errorSent {
		t.Error("Expected error response to be sent")
	}
}

// TestOAuthHandler_HandleCallback_Success tests successful callback handling
func TestOAuthHandler_HandleCallback_Success(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{
		csrf:         "test-state",
		nonce:        "test-nonce",
		incomingPath: "/dashboard",
	}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{
		IDToken:      "valid-id-token",
		AccessToken:  "valid-access-token",
		RefreshToken: "valid-refresh-token",
	}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	errorSent := false
	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		errorSent = true
		t.Errorf("Unexpected error sent: %s (code: %d)", msg, code)
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	if errorSent {
		t.Error("Unexpected error response sent")
	}

	// Check redirect
	if rw.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rw.Code)
	}

	location := rw.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected redirect to '/dashboard', got '%s'", location)
	}

	// Verify session data was set correctly
	if session.email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", session.email)
	}

	if session.idToken != "valid-id-token" {
		t.Errorf("Expected ID token 'valid-id-token', got '%s'", session.idToken)
	}

	if session.accessToken != "valid-access-token" {
		t.Errorf("Expected access token 'valid-access-token', got '%s'", session.accessToken)
	}

	if session.refreshToken != "valid-refresh-token" {
		t.Errorf("Expected refresh token 'valid-refresh-token', got '%s'", session.refreshToken)
	}

	if !session.authenticated {
		t.Error("Expected session to be authenticated")
	}

	// Check that temporary fields are cleared
	if session.csrf != "" {
		t.Errorf("Expected CSRF to be cleared, got '%s'", session.csrf)
	}

	if session.nonce != "" {
		t.Errorf("Expected nonce to be cleared, got '%s'", session.nonce)
	}

	if session.codeVerifier != "" {
		t.Errorf("Expected code verifier to be cleared, got '%s'", session.codeVerifier)
	}

	if session.incomingPath != "" {
		t.Errorf("Expected incoming path to be cleared, got '%s'", session.incomingPath)
	}
}

// TestOAuthHandler_HandleCallback_SuccessDefaultRedirect tests successful callback with default redirect
func TestOAuthHandler_HandleCallback_SuccessDefaultRedirect(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{
		csrf:         "test-state",
		nonce:        "test-nonce",
		incomingPath: "", // No incoming path, should default to "/"
	}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		t.Errorf("Unexpected error sent: %s (code: %d)", msg, code)
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	// Check redirect to default path
	if rw.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rw.Code)
	}

	location := rw.Header().Get("Location")
	if location != "/" {
		t.Errorf("Expected redirect to '/', got '%s'", location)
	}
}

// TestOAuthHandler_HandleCallback_RedirectURLPathExcluded tests incoming path same as redirect URL
func TestOAuthHandler_HandleCallback_RedirectURLPathExcluded(t *testing.T) {
	logger := &mockLogger{}
	session := &mockSessionData{
		csrf:         "test-state",
		nonce:        "test-nonce",
		incomingPath: "/callback", // Same as redirect URL path
	}
	sessionManager := &mockSessionManager{sessionToReturn: session}
	tokenResponse := &TokenResponse{IDToken: "valid-token", AccessToken: "access-token"}
	tokenExchanger := &mockTokenExchanger{response: tokenResponse}
	tokenVerifier := &mockTokenVerifier{}

	extractClaims := func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{"email": "test@example.com", "nonce": "test-nonce"}, nil
	}
	isAllowed := func(email string) bool { return true }

	sendError := func(rw http.ResponseWriter, req *http.Request, msg string, code int) {
		t.Errorf("Unexpected error sent: %s (code: %d)", msg, code)
	}

	handler := NewOAuthHandler(logger, sessionManager, tokenExchanger, tokenVerifier,
		extractClaims, isAllowed, "/callback", sendError)

	req := httptest.NewRequest("GET", "/callback?code=test-code&state=test-state", nil)
	rw := httptest.NewRecorder()

	handler.HandleCallback(rw, req, "http://example.com/callback")

	// Should redirect to default path when incoming path is same as callback path
	location := rw.Header().Get("Location")
	if location != "/" {
		t.Errorf("Expected redirect to '/', got '%s'", location)
	}
}
