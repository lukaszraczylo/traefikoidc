package traefikoidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/suite"
)

// AuthFlowBehaviourSuite tests authentication flow behavior using enhanced mocks
type AuthFlowBehaviourSuite struct {
	suite.Suite
	tOidc   *TraefikOidc
	logger  *Logger
	session *SessionData
}

func (s *AuthFlowBehaviourSuite) SetupTest() {
	s.logger = NewLogger("error")

	// Create a minimal TraefikOidc instance for testing
	s.tOidc = &TraefikOidc{
		logger:              s.logger,
		enablePKCE:          false,
		userIdentifierClaim: "email",
		authURL:             "https://auth.example.com/authorize",
	}
}

func (s *AuthFlowBehaviourSuite) TearDownTest() {
	s.tOidc = nil
	s.session = nil
}

// TestValidateRedirectCount_UnderLimit tests redirect validation when under limit
func (s *AuthFlowBehaviourSuite) TestValidateRedirectCount_UnderLimit() {
	// Create a session manager for testing
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create request/response
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	// Create a real session data for testing
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set redirect count to 2 (under limit of 5)
	session.mainSession.Values["redirect_count"] = 2

	// Call validateRedirectCount
	err = s.tOidc.validateRedirectCount(session, rw, req)

	// Should pass (no error) since count is under limit
	s.NoError(err)

	// Redirect count should be incremented
	s.Equal(3, session.GetRedirectCount())
}

// TestValidateRedirectCount_AtLimit tests redirect validation when at limit
func (s *AuthFlowBehaviourSuite) TestValidateRedirectCount_AtLimit() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	// Create request/response
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	// Create a real session data for testing
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set redirect count to 5 (at limit)
	session.mainSession.Values["redirect_count"] = 5

	// Call validateRedirectCount
	err = s.tOidc.validateRedirectCount(session, rw, req)

	// Should fail with error
	s.Error(err)
	s.Contains(err.Error(), "redirect limit exceeded")

	// Redirect count should be reset
	s.Equal(0, session.GetRedirectCount())
}

// TestValidateRedirectCount_OverLimit tests redirect validation when over limit
func (s *AuthFlowBehaviourSuite) TestValidateRedirectCount_OverLimit() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	// Create request/response
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	// Create a real session data for testing
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set redirect count to 10 (over limit)
	session.mainSession.Values["redirect_count"] = 10

	// Call validateRedirectCount
	err = s.tOidc.validateRedirectCount(session, rw, req)

	// Should fail with error
	s.Error(err)
	s.Contains(err.Error(), "redirect limit exceeded")

	// Response should have error status
	s.Equal(http.StatusLoopDetected, rw.Code)
}

// TestGeneratePKCEParameters_Disabled tests PKCE generation when disabled
func (s *AuthFlowBehaviourSuite) TestGeneratePKCEParameters_Disabled() {
	s.tOidc.enablePKCE = false

	verifier, challenge, err := s.tOidc.generatePKCEParameters()

	s.NoError(err)
	s.Empty(verifier)
	s.Empty(challenge)
}

// TestGeneratePKCEParameters_Enabled tests PKCE generation when enabled
func (s *AuthFlowBehaviourSuite) TestGeneratePKCEParameters_Enabled() {
	s.tOidc.enablePKCE = true

	verifier, challenge, err := s.tOidc.generatePKCEParameters()

	s.NoError(err)
	s.NotEmpty(verifier)
	s.NotEmpty(challenge)
	// Verifier should be at least 43 characters (PKCE spec)
	s.GreaterOrEqual(len(verifier), 43)
}

// TestPrepareSessionForAuthentication tests session preparation
func (s *AuthFlowBehaviourSuite) TestPrepareSessionForAuthentication() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	// Create a real session data for testing
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Pre-populate session with old data
	_ = session.SetAuthenticated(true)
	session.SetEmail("old@example.com")
	session.SetAccessToken("old-access-token-with-many-characters")
	session.SetRefreshToken("old-refresh-token-with-many-characters")
	session.SetIDToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature")

	// Prepare session for new authentication
	csrfToken := "new-csrf-token"
	nonce := "new-nonce"
	codeVerifier := "new-code-verifier"
	incomingPath := "/original/path"

	s.tOidc.prepareSessionForAuthentication(session, csrfToken, nonce, codeVerifier, incomingPath)

	// Verify old data is cleared
	s.False(session.GetAuthenticated())
	s.Empty(session.GetEmail())

	// Verify new data is set
	s.Equal(csrfToken, session.GetCSRF())
	s.Equal(nonce, session.GetNonce())
	s.Equal(incomingPath, session.GetIncomingPath())
}

// TestPrepareSessionForAuthentication_WithPKCE tests session preparation with PKCE enabled
func (s *AuthFlowBehaviourSuite) TestPrepareSessionForAuthentication_WithPKCE() {
	s.tOidc.enablePKCE = true

	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	// Create a real session data for testing
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Prepare session with PKCE
	csrfToken := "csrf-token"
	nonce := "nonce-value"
	codeVerifier := "pkce-code-verifier-value"
	incomingPath := "/protected/resource"

	s.tOidc.prepareSessionForAuthentication(session, csrfToken, nonce, codeVerifier, incomingPath)

	// Verify PKCE code verifier is set
	s.Equal(codeVerifier, session.GetCodeVerifier())
}

// TestIsAjaxRequest tests AJAX request detection
func (s *AuthFlowBehaviourSuite) TestIsAjaxRequest() {
	testCases := []struct {
		name       string
		headers    map[string]string
		expectAjax bool
	}{
		{
			name:       "XMLHttpRequest header",
			headers:    map[string]string{"X-Requested-With": "XMLHttpRequest"},
			expectAjax: true,
		},
		{
			name:       "JSON content type",
			headers:    map[string]string{"Content-Type": "application/json"},
			expectAjax: true,
		},
		{
			name:       "JSON accept header",
			headers:    map[string]string{"Accept": "application/json"},
			expectAjax: true,
		},
		{
			name:       "HTML accept header",
			headers:    map[string]string{"Accept": "text/html"},
			expectAjax: false,
		},
		{
			name:       "No special headers",
			headers:    map[string]string{},
			expectAjax: false,
		},
		{
			name: "Mixed headers with JSON",
			headers: map[string]string{
				"Accept":       "application/json, text/plain",
				"Content-Type": "text/html",
			},
			expectAjax: true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			result := s.tOidc.isAjaxRequest(req)
			s.Equal(tc.expectAjax, result)
		})
	}
}

// TestHandleCallback_MissingState tests callback with missing state parameter
func (s *AuthFlowBehaviourSuite) TestHandleCallback_MissingState() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create callback request without state parameter
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code", nil)
	rw := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw, req, "https://example.com/callback")

	// Should return bad request due to missing state
	s.Equal(http.StatusBadRequest, rw.Code)
}

// TestHandleCallback_ProviderError tests callback with provider error
func (s *AuthFlowBehaviourSuite) TestHandleCallback_ProviderError() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create callback request with provider error
	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=User+denied+access", nil)
	rw := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw, req, "https://example.com/callback")

	// Should return bad request with error from provider
	s.Equal(http.StatusBadRequest, rw.Code)
}

// TestHandleCallback_MissingCSRF tests callback with missing CSRF in session
func (s *AuthFlowBehaviourSuite) TestHandleCallback_MissingCSRF() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create callback request with state but session has no CSRF
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=some-state", nil)
	rw := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw, req, "https://example.com/callback")

	// Should return bad request due to missing CSRF in session
	s.Equal(http.StatusBadRequest, rw.Code)
}

// TestHandleCallback_CSRFMismatch tests callback with CSRF mismatch
func (s *AuthFlowBehaviourSuite) TestHandleCallback_CSRFMismatch() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create request first to get session
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=wrong-state", nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF("correct-csrf-token")
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state=wrong-state", nil)
	// Copy cookies from response to new request
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should return bad request due to CSRF mismatch
	s.Equal(http.StatusBadRequest, rw2.Code)
}

// TestHandleCallback_MissingCode tests callback with missing authorization code
func (s *AuthFlowBehaviourSuite) TestHandleCallback_MissingCode() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+csrfToken, nil) // No code parameter
	rw := httptest.NewRecorder()

	// Get session and set CSRF
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should return bad request due to missing code
	s.Equal(http.StatusBadRequest, rw2.Code)
}

// TestHandleCallback_TokenExchangeFailure tests callback when token exchange fails
func (s *AuthFlowBehaviourSuite) TestHandleCallback_TokenExchangeFailure() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Set up mock token exchanger that fails
	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeErr: errors.New("token exchange failed"),
	}
	s.tOidc.tokenExchanger = mockExchanger

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF and nonce
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce("test-nonce")
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should return internal server error due to token exchange failure
	s.Equal(http.StatusInternalServerError, rw2.Code)

	// Verify token exchange was called
	mockExchanger.AssertExchangeCalled(s.T())
}

// TestHandleCallback_SuccessfulAuthentication tests complete successful callback flow
func (s *AuthFlowBehaviourSuite) TestHandleCallback_SuccessfulAuthentication() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager
	// Allow all users by not setting any specific users
	s.tOidc.allowedUsers = nil

	// Create a valid ID token (JWT format)
	nonce := "test-nonce-12345"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibm9uY2UiOiJ0ZXN0LW5vbmNlLTEyMzQ1IiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"

	// Set up mock token exchanger
	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token-value",
			RefreshToken: "refresh-token-value",
			IDToken:      idToken,
			ExpiresIn:    3600,
		},
	}
	s.tOidc.tokenExchanger = mockExchanger

	// Set up mock token verifier
	mockVerifier := &EnhancedMockTokenVerifier{
		Err: nil, // Token is valid
	}
	s.tOidc.tokenVerifier = mockVerifier

	// Set up claims extraction function
	s.tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"sub":   "1234567890",
			"email": "test@example.com",
			"nonce": nonce,
		}, nil
	}

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF and nonce
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	session.SetIncomingPath("/original/protected/path")
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should redirect to original path
	s.Equal(http.StatusFound, rw2.Code)
	location := rw2.Header().Get("Location")
	s.Equal("/original/protected/path", location)

	// Verify mocks were called
	mockExchanger.AssertExchangeCalled(s.T())
	mockVerifier.AssertVerifyTokenCalled(s.T())
}

// TestHandleExpiredToken tests expired token handling
func (s *AuthFlowBehaviourSuite) TestHandleExpiredToken() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager
	s.tOidc.issuerURL = "https://auth.example.com"
	s.tOidc.clientID = "test-client-id"
	s.tOidc.scopes = []string{"openid", "email"}

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	// Get session and set some existing data
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	_ = session.SetAuthenticated(true)
	session.SetEmail("test@example.com")
	session.SetIDToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature")
	session.mainSession.Values["redirect_count"] = 3

	// Call handleExpiredToken
	s.tOidc.handleExpiredToken(rw, req, session, "https://example.com/callback")

	// Session should be cleared
	s.False(session.GetAuthenticated())
	s.Empty(session.GetEmail())
	s.Empty(session.GetIDToken())

	// Redirect count should be reset to 0 and then incremented by defaultInitiateAuthentication
	// So it should be 1 (0 reset + 1 increment)
	s.Equal(1, session.GetRedirectCount())

	// Should redirect to auth provider
	s.Equal(http.StatusFound, rw.Code)

	session.returnToPoolSafely()
}

// TestIsRefreshTokenExpired tests refresh token expiration check
func (s *AuthFlowBehaviourSuite) TestIsRefreshTokenExpired() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Test isRefreshTokenExpired (currently returns false as placeholder)
	result := s.tOidc.isRefreshTokenExpired(session)
	s.False(result) // Placeholder implementation always returns false
}

// TestBuildAuthURL tests building authorization URL
func (s *AuthFlowBehaviourSuite) TestBuildAuthURL() {
	s.tOidc.issuerURL = "https://auth.example.com"
	s.tOidc.clientID = "test-client-id"
	s.tOidc.scopes = []string{"openid", "email", "profile"}
	redirectURL := "https://myapp.com/callback"
	csrfToken := "csrf-token-value"
	nonce := "nonce-value"
	codeChallenge := ""

	authURL := s.tOidc.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)

	// Parse the URL
	parsedURL, err := url.Parse(authURL)
	s.Require().NoError(err)

	// Verify base URL
	s.Equal("https", parsedURL.Scheme)
	s.Equal("auth.example.com", parsedURL.Host)
	s.Equal("/authorize", parsedURL.Path)

	// Verify query parameters
	queryParams := parsedURL.Query()
	s.Equal("test-client-id", queryParams.Get("client_id"))
	s.Equal("code", queryParams.Get("response_type"))
	s.Equal(redirectURL, queryParams.Get("redirect_uri"))
	// The actual scopes may include additional ones like offline_access
	scopeValue := queryParams.Get("scope")
	s.Contains(scopeValue, "openid")
	s.Contains(scopeValue, "email")
	s.Contains(scopeValue, "profile")
	s.Equal(csrfToken, queryParams.Get("state"))
	s.Equal(nonce, queryParams.Get("nonce"))
}

// TestBuildAuthURL_WithPKCE tests building authorization URL with PKCE
func (s *AuthFlowBehaviourSuite) TestBuildAuthURL_WithPKCE() {
	s.tOidc.issuerURL = "https://auth.example.com"
	s.tOidc.clientID = "test-client-id"
	s.tOidc.scopes = []string{"openid", "email"}
	s.tOidc.enablePKCE = true

	redirectURL := "https://myapp.com/callback"
	csrfToken := "csrf-token-value"
	nonce := "nonce-value"
	codeChallenge := "generated-code-challenge"

	authURL := s.tOidc.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)

	// Parse the URL
	parsedURL, err := url.Parse(authURL)
	s.Require().NoError(err)

	// Verify PKCE parameters
	queryParams := parsedURL.Query()
	s.Equal(codeChallenge, queryParams.Get("code_challenge"))
	s.Equal("S256", queryParams.Get("code_challenge_method"))
}

// TestDefaultInitiateAuthentication_Success tests successful auth initiation
func (s *AuthFlowBehaviourSuite) TestDefaultInitiateAuthentication_Success() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager
	s.tOidc.issuerURL = "https://auth.example.com"
	s.tOidc.clientID = "test-client-id"
	s.tOidc.scopes = []string{"openid", "email"}

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/protected/resource?query=value", nil)
	rw := httptest.NewRecorder()

	// Get session
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)

	// Call defaultInitiateAuthentication
	s.tOidc.defaultInitiateAuthentication(rw, req, session, "https://myapp.com/callback")

	// Should redirect to auth provider
	s.Equal(http.StatusFound, rw.Code)

	// Location header should contain auth URL
	location := rw.Header().Get("Location")
	s.Contains(location, "https://auth.example.com/authorize")
	s.Contains(location, "client_id=test-client-id")

	session.returnToPoolSafely()
}

// TestDefaultInitiateAuthentication_RedirectLimitExceeded tests auth initiation when redirect limit exceeded
func (s *AuthFlowBehaviourSuite) TestDefaultInitiateAuthentication_RedirectLimitExceeded() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rw := httptest.NewRecorder()

	// Get session and set redirect count over limit
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.mainSession.Values["redirect_count"] = 10

	// Call defaultInitiateAuthentication
	s.tOidc.defaultInitiateAuthentication(rw, req, session, "https://myapp.com/callback")

	// Should return error status due to redirect loop detection
	s.Equal(http.StatusLoopDetected, rw.Code)

	session.returnToPoolSafely()
}

// TestHandleCallback_NonceMismatch tests callback with nonce mismatch
func (s *AuthFlowBehaviourSuite) TestHandleCallback_NonceMismatch() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Create a valid ID token with a different nonce
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibm9uY2UiOiJ3cm9uZy1ub25jZSIsImlhdCI6MTUxNjIzOTAyMn0.signature"

	// Set up mock token exchanger
	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token-value",
			RefreshToken: "refresh-token-value",
			IDToken:      idToken,
			ExpiresIn:    3600,
		},
	}
	s.tOidc.tokenExchanger = mockExchanger

	// Set up mock token verifier
	mockVerifier := &EnhancedMockTokenVerifier{
		Err: nil, // Token is valid
	}
	s.tOidc.tokenVerifier = mockVerifier

	// Set up claims extraction function that returns a different nonce
	s.tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"sub":   "1234567890",
			"email": "test@example.com",
			"nonce": "wrong-nonce", // Different from session nonce
		}, nil
	}

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF and nonce
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce("correct-nonce") // Different from token nonce
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should return internal server error due to nonce mismatch
	s.Equal(http.StatusInternalServerError, rw2.Code)
}

// TestHandleCallback_UserNotAuthorized tests callback when user is not authorized
func (s *AuthFlowBehaviourSuite) TestHandleCallback_UserNotAuthorized() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager
	// Set allowed users to only allow a specific user
	s.tOidc.allowedUsers = map[string]struct{}{"allowed@example.com": {}}

	nonce := "test-nonce-12345"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ1bmF1dGhvcml6ZWRAZXhhbXBsZS5jb20iLCJub25jZSI6InRlc3Qtbm9uY2UtMTIzNDUiLCJpYXQiOjE1MTYyMzkwMjJ9.signature"

	// Set up mock token exchanger
	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token-value",
			RefreshToken: "refresh-token-value",
			IDToken:      idToken,
			ExpiresIn:    3600,
		},
	}
	s.tOidc.tokenExchanger = mockExchanger

	// Set up mock token verifier
	mockVerifier := &EnhancedMockTokenVerifier{
		Err: nil,
	}
	s.tOidc.tokenVerifier = mockVerifier

	// Set up claims extraction
	s.tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
		return map[string]interface{}{
			"sub":   "1234567890",
			"email": "unauthorized@example.com", // Not in allowed list
			"nonce": nonce,
		}, nil
	}

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF and nonce
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should return forbidden due to user not being authorized
	s.Equal(http.StatusForbidden, rw2.Code)
}

// TestHandleCallback_TokenVerificationFailure tests callback when token verification fails
func (s *AuthFlowBehaviourSuite) TestHandleCallback_TokenVerificationFailure() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibm9uY2UiOiJ0ZXN0LW5vbmNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"

	// Set up mock token exchanger
	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeResponse: &TokenResponse{
			AccessToken:  "access-token-value",
			RefreshToken: "refresh-token-value",
			IDToken:      idToken,
			ExpiresIn:    3600,
		},
	}
	s.tOidc.tokenExchanger = mockExchanger

	// Set up mock token verifier that fails
	mockVerifier := &EnhancedMockTokenVerifier{
		Err: errors.New("token signature verification failed"),
	}
	s.tOidc.tokenVerifier = mockVerifier

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	req := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF and nonce
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce("test-nonce")
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code=auth-code&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, "https://example.com/callback")

	// Should return internal server error due to token verification failure
	s.Equal(http.StatusInternalServerError, rw2.Code)
}

// TestHandleCallback_WithExchangerCallTracking tests that we can verify exchanger behavior
func (s *AuthFlowBehaviourSuite) TestHandleCallback_WithExchangerCallTracking() {
	sessionManager, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer sessionManager.Shutdown()

	s.tOidc.sessionManager = sessionManager

	// Set up mock token exchanger with call tracking
	mockExchanger := &EnhancedMockTokenExchanger{
		ExchangeErr: errors.New("token exchange failed"),
	}
	s.tOidc.tokenExchanger = mockExchanger

	// Create request first to get session
	csrfToken := "valid-csrf-token"
	authCode := "test-auth-code"
	redirectURL := "https://example.com/callback"

	req := httptest.NewRequest(http.MethodGet, "/callback?code="+authCode+"&state="+csrfToken, nil)
	rw := httptest.NewRecorder()

	// Get session and set CSRF and nonce
	session, err := sessionManager.GetSession(req)
	s.Require().NoError(err)
	session.SetCSRF(csrfToken)
	session.SetNonce("test-nonce")
	session.SetCodeVerifier("test-code-verifier")
	err = session.Save(req, rw)
	s.Require().NoError(err)
	session.returnToPoolSafely()

	// Now make the callback request with cookies from the response
	req2 := httptest.NewRequest(http.MethodGet, "/callback?code="+authCode+"&state="+csrfToken, nil)
	for _, cookie := range rw.Result().Cookies() {
		req2.AddCookie(cookie)
	}
	rw2 := httptest.NewRecorder()

	// Call handleCallback
	s.tOidc.handleCallback(rw2, req2, redirectURL)

	// Verify exchanger was called with correct parameters
	mockExchanger.AssertExchangeCalled(s.T())
	mockExchanger.AssertExchangeCalledWith(s.T(), "authorization_code")
	s.Equal(1, mockExchanger.GetExchangeCallCount())

	// Check last call details
	lastCall := mockExchanger.LastExchangeCall()
	s.NotNil(lastCall)
	s.Equal("authorization_code", lastCall.GrantType)
	s.Equal(authCode, lastCall.CodeOrToken)
	s.Equal(redirectURL, lastCall.RedirectURL)
	s.Equal("test-code-verifier", lastCall.CodeVerifier)
}

func TestAuthFlowBehaviourSuite(t *testing.T) {
	suite.Run(t, new(AuthFlowBehaviourSuite))
}
