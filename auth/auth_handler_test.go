package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Test mocks
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

type mockSessionData struct {
	authenticated bool
	email         string
	accessToken   string
	refreshToken  string
	idToken       string
	csrf          string
	nonce         string
	codeVerifier  string
	incomingPath  string
	redirectCount int
	saveError     error
	dirty         bool
}

func (s *mockSessionData) GetRedirectCount() int           { return s.redirectCount }
func (s *mockSessionData) ResetRedirectCount()             { s.redirectCount = 0 }
func (s *mockSessionData) IncrementRedirectCount()         { s.redirectCount++ }
func (s *mockSessionData) SetAuthenticated(auth bool)      { s.authenticated = auth }
func (s *mockSessionData) SetEmail(email string)           { s.email = email }
func (s *mockSessionData) SetAccessToken(token string)     { s.accessToken = token }
func (s *mockSessionData) SetRefreshToken(token string)    { s.refreshToken = token }
func (s *mockSessionData) SetIDToken(token string)         { s.idToken = token }
func (s *mockSessionData) SetNonce(nonce string)           { s.nonce = nonce }
func (s *mockSessionData) SetCodeVerifier(verifier string) { s.codeVerifier = verifier }
func (s *mockSessionData) SetCSRF(csrf string)             { s.csrf = csrf }
func (s *mockSessionData) SetIncomingPath(path string)     { s.incomingPath = path }
func (s *mockSessionData) MarkDirty()                      { s.dirty = true }

func (s *mockSessionData) Save(req *http.Request, rw http.ResponseWriter) error {
	return s.saveError
}

// TestAuthHandler_NewAuthHandler tests the constructor
func TestAuthHandler_NewAuthHandler(t *testing.T) {
	logger := &mockLogger{}
	isGoogleProv := func() bool { return false }
	isAzureProv := func() bool { return true }
	scopes := []string{"openid", "profile", "email"}

	handler := NewAuthHandler(logger, true, isGoogleProv, isAzureProv,
		"test-client-id", "https://example.com/auth", "https://example.com",
		scopes, false)

	if handler == nil {
		t.Fatal("Expected handler to be created, got nil")
	}

	if handler.logger != logger {
		t.Error("Logger not set correctly")
	}

	if !handler.enablePKCE {
		t.Error("PKCE should be enabled")
	}

	if handler.clientID != "test-client-id" {
		t.Errorf("Expected clientID 'test-client-id', got '%s'", handler.clientID)
	}

	if handler.authURL != "https://example.com/auth" {
		t.Errorf("Expected authURL 'https://example.com/auth', got '%s'", handler.authURL)
	}

	if handler.issuerURL != "https://example.com" {
		t.Errorf("Expected issuerURL 'https://example.com', got '%s'", handler.issuerURL)
	}

	if len(handler.scopes) != 3 {
		t.Errorf("Expected 3 scopes, got %d", len(handler.scopes))
	}

	if handler.overrideScopes {
		t.Error("overrideScopes should be false")
	}
}

// TestAuthHandler_InitiateAuthentication_MaxRedirects tests redirect limit enforcement
func TestAuthHandler_InitiateAuthentication_MaxRedirects(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false)

	session := &mockSessionData{redirectCount: 5} // At the limit
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	generateNonce := func() (string, error) { return "test-nonce", nil }
	generateCodeVerifier := func() (string, error) { return "", nil }
	deriveCodeChallenge := func() (string, error) { return "", nil }

	handler.InitiateAuthentication(rw, req, session, "https://example.com/callback",
		generateNonce, generateCodeVerifier, deriveCodeChallenge)

	if rw.Code != http.StatusLoopDetected {
		t.Errorf("Expected status %d, got %d", http.StatusLoopDetected, rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "Too many redirects") {
		t.Errorf("Expected 'Too many redirects' in response body, got '%s'", body)
	}

	if session.redirectCount != 0 {
		t.Errorf("Expected redirect count to be reset, got %d", session.redirectCount)
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}
}

// TestAuthHandler_InitiateAuthentication_NonceGenerationError tests nonce generation failure
func TestAuthHandler_InitiateAuthentication_NonceGenerationError(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false)

	session := &mockSessionData{}
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	generateNonce := func() (string, error) { return "", &testError{"nonce generation failed"} }
	generateCodeVerifier := func() (string, error) { return "", nil }
	deriveCodeChallenge := func() (string, error) { return "", nil }

	handler.InitiateAuthentication(rw, req, session, "https://example.com/callback",
		generateNonce, generateCodeVerifier, deriveCodeChallenge)

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "Failed to generate nonce") {
		t.Errorf("Expected 'Failed to generate nonce' in response body, got '%s'", body)
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}
}

// TestAuthHandler_InitiateAuthentication_PKCECodeVerifierError tests PKCE code verifier generation failure
func TestAuthHandler_InitiateAuthentication_PKCECodeVerifierError(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, true, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false)

	session := &mockSessionData{}
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	generateNonce := func() (string, error) { return "test-nonce", nil }
	generateCodeVerifier := func() (string, error) { return "", &testError{"code verifier generation failed"} }
	deriveCodeChallenge := func() (string, error) { return "", nil }

	handler.InitiateAuthentication(rw, req, session, "https://example.com/callback",
		generateNonce, generateCodeVerifier, deriveCodeChallenge)

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "Failed to generate code verifier") {
		t.Errorf("Expected 'Failed to generate code verifier' in response body, got '%s'", body)
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}
}

// TestAuthHandler_InitiateAuthentication_PKCECodeChallengeError tests PKCE code challenge derivation failure
func TestAuthHandler_InitiateAuthentication_PKCECodeChallengeError(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, true, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false)

	session := &mockSessionData{}
	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()

	generateNonce := func() (string, error) { return "test-nonce", nil }
	generateCodeVerifier := func() (string, error) { return "test-verifier", nil }
	deriveCodeChallenge := func() (string, error) { return "", &testError{"code challenge derivation failed"} }

	handler.InitiateAuthentication(rw, req, session, "https://example.com/callback",
		generateNonce, generateCodeVerifier, deriveCodeChallenge)

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "Failed to generate code challenge") {
		t.Errorf("Expected 'Failed to generate code challenge' in response body, got '%s'", body)
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}
}

// TestAuthHandler_InitiateAuthentication_SessionSaveError tests session save failure
func TestAuthHandler_InitiateAuthentication_SessionSaveError(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false)

	session := &mockSessionData{saveError: &testError{"save failed"}}
	req := httptest.NewRequest("GET", "/test?param=value", nil)
	rw := httptest.NewRecorder()

	generateNonce := func() (string, error) { return "test-nonce", nil }
	generateCodeVerifier := func() (string, error) { return "", nil }
	deriveCodeChallenge := func() (string, error) { return "", nil }

	handler.InitiateAuthentication(rw, req, session, "https://example.com/callback",
		generateNonce, generateCodeVerifier, deriveCodeChallenge)

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "Failed to save session") {
		t.Errorf("Expected 'Failed to save session' in response body, got '%s'", body)
	}

	if len(logger.errorMessages) == 0 {
		t.Error("Expected error to be logged")
	}

	// Verify session was prepared correctly before the save failure
	if session.incomingPath != "/test?param=value" {
		t.Errorf("Expected incoming path '/test?param=value', got '%s'", session.incomingPath)
	}

	if session.nonce != "test-nonce" {
		t.Errorf("Expected nonce 'test-nonce', got '%s'", session.nonce)
	}

	if session.redirectCount != 1 {
		t.Errorf("Expected redirect count 1, got %d", session.redirectCount)
	}
}

// TestAuthHandler_InitiateAuthentication_Success tests successful authentication initiation
func TestAuthHandler_InitiateAuthentication_Success(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, true, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com", []string{"openid", "email"}, false)

	session := &mockSessionData{}
	req := httptest.NewRequest("GET", "/protected/resource", nil)
	rw := httptest.NewRecorder()

	generateNonce := func() (string, error) { return "generated-nonce", nil }
	generateCodeVerifier := func() (string, error) { return "generated-verifier", nil }
	deriveCodeChallenge := func() (string, error) { return "generated-challenge", nil }

	handler.InitiateAuthentication(rw, req, session, "https://example.com/callback",
		generateNonce, generateCodeVerifier, deriveCodeChallenge)

	// Should redirect
	if rw.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, rw.Code)
	}

	location := rw.Header().Get("Location")
	if location == "" {
		t.Error("Expected Location header to be set")
	}

	// Parse the redirect URL to verify parameters
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL: %v", err)
	}

	query := parsedURL.Query()

	// Verify required parameters
	if query.Get("client_id") != "test-client" {
		t.Errorf("Expected client_id 'test-client', got '%s'", query.Get("client_id"))
	}

	if query.Get("response_type") != "code" {
		t.Errorf("Expected response_type 'code', got '%s'", query.Get("response_type"))
	}

	if query.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("Expected redirect_uri 'https://example.com/callback', got '%s'", query.Get("redirect_uri"))
	}

	if query.Get("nonce") != "generated-nonce" {
		t.Errorf("Expected nonce 'generated-nonce', got '%s'", query.Get("nonce"))
	}

	// Verify PKCE parameters
	if query.Get("code_challenge") != "generated-challenge" {
		t.Errorf("Expected code_challenge 'generated-challenge', got '%s'", query.Get("code_challenge"))
	}

	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("Expected code_challenge_method 'S256', got '%s'", query.Get("code_challenge_method"))
	}

	// Verify scope
	scope := query.Get("scope")
	if !strings.Contains(scope, "openid") || !strings.Contains(scope, "email") {
		t.Errorf("Expected scope to contain 'openid' and 'email', got '%s'", scope)
	}

	// Verify session was updated correctly
	if !session.dirty {
		t.Error("Expected session to be marked dirty")
	}

	if session.incomingPath != "/protected/resource" {
		t.Errorf("Expected incoming path '/protected/resource', got '%s'", session.incomingPath)
	}

	if session.nonce != "generated-nonce" {
		t.Errorf("Expected session nonce 'generated-nonce', got '%s'", session.nonce)
	}

	if session.codeVerifier != "generated-verifier" {
		t.Errorf("Expected session code verifier 'generated-verifier', got '%s'", session.codeVerifier)
	}

	// Verify session data was cleared
	if session.authenticated {
		t.Error("Expected session to not be authenticated")
	}

	if session.email != "" {
		t.Errorf("Expected email to be cleared, got '%s'", session.email)
	}

	if session.accessToken != "" {
		t.Errorf("Expected access token to be cleared, got '%s'", session.accessToken)
	}

	if session.idToken != "" {
		t.Errorf("Expected ID token to be cleared, got '%s'", session.idToken)
	}
}

// TestAuthHandler_BuildAuthURL_GoogleProvider tests Google-specific URL building
func TestAuthHandler_BuildAuthURL_GoogleProvider(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return true }, func() bool { return false },
		"google-client", "https://accounts.google.com/oauth2/auth", "https://accounts.google.com",
		[]string{"openid", "profile", "email"}, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()

	// Google-specific parameters
	if query.Get("access_type") != "offline" {
		t.Errorf("Expected access_type 'offline' for Google, got '%s'", query.Get("access_type"))
	}

	if query.Get("prompt") != "consent" {
		t.Errorf("Expected prompt 'consent' for Google, got '%s'", query.Get("prompt"))
	}

	// Standard parameters should still be present
	if query.Get("client_id") != "google-client" {
		t.Errorf("Expected client_id 'google-client', got '%s'", query.Get("client_id"))
	}

	if query.Get("state") != "test-state" {
		t.Errorf("Expected state 'test-state', got '%s'", query.Get("state"))
	}

	if query.Get("nonce") != "test-nonce" {
		t.Errorf("Expected nonce 'test-nonce', got '%s'", query.Get("nonce"))
	}
}

// TestAuthHandler_BuildAuthURL_AzureProvider tests Azure-specific URL building
func TestAuthHandler_BuildAuthURL_AzureProvider(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return true },
		"azure-client", "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
		"https://login.microsoftonline.com/tenant/v2.0",
		[]string{"openid", "profile", "email"}, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()

	// Azure-specific parameters
	if query.Get("response_mode") != "query" {
		t.Errorf("Expected response_mode 'query' for Azure, got '%s'", query.Get("response_mode"))
	}

	// Azure should add offline_access scope automatically
	scope := query.Get("scope")
	if !strings.Contains(scope, "offline_access") {
		t.Errorf("Expected scope to contain 'offline_access' for Azure, got '%s'", scope)
	}
}

// TestAuthHandler_BuildAuthURL_PKCEEnabled tests PKCE parameter inclusion
func TestAuthHandler_BuildAuthURL_PKCEEnabled(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, true, func() bool { return false }, func() bool { return false },
		"pkce-client", "https://example.com/auth", "https://example.com",
		[]string{"openid"}, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "test-challenge")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()

	if query.Get("code_challenge") != "test-challenge" {
		t.Errorf("Expected code_challenge 'test-challenge', got '%s'", query.Get("code_challenge"))
	}

	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("Expected code_challenge_method 'S256', got '%s'", query.Get("code_challenge_method"))
	}
}

// TestAuthHandler_BuildAuthURL_PKCEDisabled tests when PKCE is disabled
func TestAuthHandler_BuildAuthURL_PKCEDisabled(t *testing.T) {
	logger := &mockLogger{}
	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"no-pkce-client", "https://example.com/auth", "https://example.com",
		[]string{"openid"}, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "test-challenge")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()

	// PKCE parameters should not be included
	if query.Get("code_challenge") != "" {
		t.Errorf("Expected no code_challenge when PKCE disabled, got '%s'", query.Get("code_challenge"))
	}

	if query.Get("code_challenge_method") != "" {
		t.Errorf("Expected no code_challenge_method when PKCE disabled, got '%s'", query.Get("code_challenge_method"))
	}
}

// TestAuthHandler_BuildAuthURL_ScopeHandling tests various scope configurations
func TestAuthHandler_BuildAuthURL_ScopeHandling(t *testing.T) {
	tests := []struct {
		name           string
		scopes         []string
		overrideScopes bool
		isAzure        bool
		expectedScopes []string
	}{
		{
			name:           "Basic scopes",
			scopes:         []string{"openid", "profile", "email"},
			overrideScopes: false,
			isAzure:        false,
			expectedScopes: []string{"openid", "profile", "email", "offline_access"},
		},
		{
			name:           "Azure with offline_access already present",
			scopes:         []string{"openid", "profile", "offline_access"},
			overrideScopes: false,
			isAzure:        true,
			expectedScopes: []string{"openid", "profile", "offline_access"},
		},
		{
			name:           "Azure auto-add offline_access",
			scopes:         []string{"openid", "profile"},
			overrideScopes: false,
			isAzure:        true,
			expectedScopes: []string{"openid", "profile", "offline_access"},
		},
		{
			name:           "Override scopes with empty array",
			scopes:         []string{},
			overrideScopes: true,
			isAzure:        true,
			expectedScopes: []string{"offline_access"},
		},
		{
			name:           "Override scopes prevents auto-add",
			scopes:         []string{"openid", "custom_scope"},
			overrideScopes: true,
			isAzure:        true,
			expectedScopes: []string{"openid", "custom_scope"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{}
			handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return tt.isAzure },
				"test-client", "https://example.com/auth", "https://example.com",
				tt.scopes, tt.overrideScopes)

			authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

			parsedURL, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("Failed to parse auth URL: %v", err)
			}

			actualScope := parsedURL.Query().Get("scope")
			actualScopes := strings.Split(actualScope, " ")

			// Check each expected scope is present
			for _, expectedScope := range tt.expectedScopes {
				found := false
				for _, actualScope := range actualScopes {
					if actualScope == expectedScope {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected scope '%s' not found in '%s'", expectedScope, actualScope)
				}
			}

			// Check no unexpected scopes are present
			for _, actualScope := range actualScopes {
				if actualScope == "" {
					continue // Skip empty strings from split
				}
				found := false
				for _, expectedScope := range tt.expectedScopes {
					if actualScope == expectedScope {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected scope '%s' found in '%s'", actualScope, parsedURL.Query().Get("scope"))
				}
			}
		})
	}
}

// Test helper type for errors
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
