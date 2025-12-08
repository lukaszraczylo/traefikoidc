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

// mockScopeFilter is a mock implementation of the ScopeFilter interface for testing
type mockScopeFilter struct{}

func (m *mockScopeFilter) FilterSupportedScopes(requestedScopes, supportedScopes []string, providerURL string) []string {
	// For testing, just return requested scopes if no supported scopes provided
	if len(supportedScopes) == 0 {
		return requestedScopes
	}
	// Simple filter logic for tests
	filtered := make([]string, 0, len(requestedScopes))
	supportedMap := make(map[string]bool)
	for _, s := range supportedScopes {
		supportedMap[s] = true
	}
	for _, s := range requestedScopes {
		if supportedMap[s] {
			filtered = append(filtered, s)
		}
	}
	return filtered
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
		scopes, false, nil, nil, false)

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
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil, false)

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
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil, false)

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
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil, false)

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
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil, false)

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
		"test-client", "https://example.com/auth", "https://example.com", []string{}, false, nil, nil, false)

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
		"test-client", "https://example.com/auth", "https://example.com", []string{"openid", "email"}, false, nil, nil, false)

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
		[]string{"openid", "profile", "email"}, false, nil, nil, false)

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
		[]string{"openid", "profile", "email"}, false, nil, nil, false)

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
		[]string{"openid"}, false, nil, nil, false)

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
		[]string{"openid"}, false, nil, nil, false)

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
				tt.scopes, tt.overrideScopes, nil, nil, false)

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

// SCOPE FILTERING INTEGRATION TESTS

// TestAuthHandler_BuildAuthURL_WithScopeFiltering tests scope filtering when enabled
func TestAuthHandler_BuildAuthURL_WithScopeFiltering(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	// Requested scopes include offline_access
	scopes := []string{"openid", "profile", "email", "offline_access"}
	// Provider only supports these
	scopesSupported := []string{"openid", "profile", "email"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")
	actualScopes := strings.Split(actualScope, " ")

	// offline_access should have been filtered out in the first pass
	// The standard provider logic then tries to add it back
	// But the final filtering pass removes it again
	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("offline_access should have been filtered out when not in scopesSupported")
		}
	}

	// Should contain the supported scopes
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in final scope string")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in final scope string")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in final scope string")
	}
}

// TestAuthHandler_BuildAuthURL_WithoutScopeFiltering tests backward compatibility
func TestAuthHandler_BuildAuthURL_WithoutScopeFiltering(t *testing.T) {
	logger := &mockLogger{}

	scopes := []string{"openid", "profile", "email"}
	// No scopeFilter or scopesSupported (backward compatibility)

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, nil, nil, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")

	// All scopes should be present, plus offline_access added by standard provider logic
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope string")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in scope string")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in scope string")
	}
	if !strings.Contains(actualScope, "offline_access") {
		t.Error("Expected offline_access added by standard provider logic")
	}
}

// TestAuthHandler_BuildAuthURL_GitLabFiltersOfflineAccess tests GitLab scenario
func TestAuthHandler_BuildAuthURL_GitLabFiltersOfflineAccess(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "email", "offline_access"}
	// GitLab discovery doc doesn't include offline_access
	scopesSupported := []string{"openid", "profile", "email", "read_user", "read_api"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"gitlab-client", "https://gitlab.example.com/oauth/authorize",
		"https://gitlab.example.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")
	actualScopes := strings.Split(actualScope, " ")

	// offline_access should be filtered out
	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("GitLab scenario: offline_access should have been filtered out")
		}
	}

	// Should contain standard scopes
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in final scope string")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in final scope string")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in final scope string")
	}
}

// TestAuthHandler_BuildAuthURL_GoogleRemovesOfflineAccess tests Google provider
func TestAuthHandler_BuildAuthURL_GoogleRemovesOfflineAccess(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "email", "offline_access"}
	scopesSupported := []string{"openid", "profile", "email"}

	handler := NewAuthHandler(logger, false, func() bool { return true }, func() bool { return false },
		"google-client", "https://accounts.google.com/o/oauth2/v2/auth",
		"https://accounts.google.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()
	actualScope := query.Get("scope")
	actualScopes := strings.Split(actualScope, " ")

	// Google removes offline_access and uses access_type=offline instead
	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("Google scenario: offline_access should have been removed by Google-specific logic")
		}
	}

	// Google-specific parameters should be present
	if query.Get("access_type") != "offline" {
		t.Error("Expected access_type=offline for Google")
	}
	if query.Get("prompt") != "consent" {
		t.Error("Expected prompt=consent for Google")
	}
}

// TestAuthHandler_BuildAuthURL_AzureAddsOfflineAccess tests Azure provider
func TestAuthHandler_BuildAuthURL_AzureAddsOfflineAccess(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "email"}
	// Azure supports offline_access
	scopesSupported := []string{"openid", "profile", "email", "offline_access"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return true },
		"azure-client", "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
		"https://login.microsoftonline.com/tenant/v2.0",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()
	actualScope := query.Get("scope")

	// Azure should add offline_access automatically and it should pass filtering
	if !strings.Contains(actualScope, "offline_access") {
		t.Error("Azure scenario: offline_access should be present")
	}

	// Azure-specific parameter
	if query.Get("response_mode") != "query" {
		t.Error("Expected response_mode=query for Azure")
	}
}

// TestAuthHandler_BuildAuthURL_GenericWithFiltering tests generic provider with discovery filtering
func TestAuthHandler_BuildAuthURL_GenericWithFiltering(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "email", "custom_scope", "offline_access"}
	scopesSupported := []string{"openid", "profile", "email", "custom_scope"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"generic-client", "https://auth.provider.com/authorize",
		"https://auth.provider.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")

	// Should contain supported scopes including custom_scope
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope string")
	}
	if !strings.Contains(actualScope, "custom_scope") {
		t.Error("Expected custom_scope in scope string")
	}

	// offline_access should be filtered out (not in scopesSupported)
	actualScopes := strings.Split(actualScope, " ")
	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("offline_access should have been filtered out when not supported")
		}
	}
}

// TestAuthHandler_BuildAuthURL_OverrideScopesWithFiltering tests override scopes + filtering
func TestAuthHandler_BuildAuthURL_OverrideScopesWithFiltering(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	// User explicitly overrides scopes
	scopes := []string{"openid", "custom:read", "custom:write"}
	scopesSupported := []string{"openid", "custom:read"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, true, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")
	actualScopes := strings.Split(actualScope, " ")

	// Should contain only supported scopes from override
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope string")
	}
	if !strings.Contains(actualScope, "custom:read") {
		t.Error("Expected custom:read in scope string")
	}

	// custom:write should be filtered out
	for _, scope := range actualScopes {
		if scope == "custom:write" {
			t.Error("custom:write should have been filtered out (not supported)")
		}
	}

	// offline_access should NOT be auto-added when overrideScopes=true
	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("offline_access should not be auto-added when user overrides scopes")
		}
	}
}

// TestAuthHandler_BuildAuthURL_DoubleFiltering tests initial + final filtering passes
func TestAuthHandler_BuildAuthURL_DoubleFiltering(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "email"}
	// Provider supports offline_access
	scopesSupported := []string{"openid", "profile", "email", "offline_access"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")

	// Initial filtering: All requested scopes pass (all in scopesSupported)
	// Provider-specific logic: Adds offline_access (standard provider)
	// Final filtering: offline_access should still be present (it's in scopesSupported)
	if !strings.Contains(actualScope, "offline_access") {
		t.Error("offline_access should be present (supported by provider and added by logic)")
	}

	// Original scopes should be present
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope string")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in scope string")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in scope string")
	}
}

// TestAuthHandler_BuildAuthURL_NoScopeFilterProvided tests when scopeFilter is nil
func TestAuthHandler_BuildAuthURL_NoScopeFilterProvided(t *testing.T) {
	logger := &mockLogger{}

	scopes := []string{"openid", "profile", "email"}
	scopesSupported := []string{"openid", "profile"} // Even with scopesSupported, no filter

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, nil, scopesSupported, false) // scopeFilter is nil

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")

	// Without scopeFilter, all scopes should be present (no filtering)
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope string")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in scope string")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in scope string (no filtering without scopeFilter)")
	}
}

// TestAuthHandler_BuildAuthURL_EmptyScopesSupported tests empty scopesSupported list
func TestAuthHandler_BuildAuthURL_EmptyScopesSupported(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "email"}
	scopesSupported := []string{} // Empty - backward compatibility mode

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	actualScope := parsedURL.Query().Get("scope")

	// With empty scopesSupported, mockScopeFilter returns requested scopes unchanged
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope string")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in scope string")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in scope string")
	}
}

// TestAuthHandler_BuildAuthURL_FilteringWithPKCE tests scope filtering with PKCE enabled
func TestAuthHandler_BuildAuthURL_FilteringWithPKCE(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "offline_access"}
	scopesSupported := []string{"openid", "profile"}

	handler := NewAuthHandler(logger, true, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "test-challenge")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()

	// PKCE parameters should be present
	if query.Get("code_challenge") != "test-challenge" {
		t.Error("Expected code_challenge parameter with PKCE enabled")
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Error("Expected code_challenge_method=S256 with PKCE enabled")
	}

	// Scope filtering should still work
	actualScope := query.Get("scope")
	actualScopes := strings.Split(actualScope, " ")

	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("offline_access should have been filtered out even with PKCE")
		}
	}
}

// TestAuthHandler_BuildAuthURL_ComplexScenario tests realistic complex scenario
func TestAuthHandler_BuildAuthURL_ComplexScenario(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	// User configures: openid, profile, email, custom:read, offline_access
	scopes := []string{"openid", "profile", "email", "custom:read", "offline_access"}

	// Provider discovery returns: openid, profile, email, custom:read, custom:write, admin:all
	scopesSupported := []string{"openid", "profile", "email", "custom:read", "custom:write", "admin:all"}

	handler := NewAuthHandler(logger, true, func() bool { return false }, func() bool { return false },
		"complex-client", "https://auth.complex.com/authorize", "https://auth.complex.com",
		scopes, false, scopeFilter, scopesSupported, false)

	authURL := handler.BuildAuthURL("https://example.com/callback", "state-123", "nonce-456", "challenge-789")

	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	query := parsedURL.Query()

	// Verify basic OAuth parameters
	if query.Get("client_id") != "complex-client" {
		t.Error("Expected correct client_id")
	}
	if query.Get("response_type") != "code" {
		t.Error("Expected response_type=code")
	}
	if query.Get("state") != "state-123" {
		t.Error("Expected correct state")
	}
	if query.Get("nonce") != "nonce-456" {
		t.Error("Expected correct nonce")
	}

	// Verify PKCE parameters
	if query.Get("code_challenge") != "challenge-789" {
		t.Error("Expected correct code_challenge")
	}

	// Verify scope filtering
	actualScope := query.Get("scope")

	// Should contain: openid, profile, email, custom:read
	if !strings.Contains(actualScope, "openid") {
		t.Error("Expected openid in scope")
	}
	if !strings.Contains(actualScope, "profile") {
		t.Error("Expected profile in scope")
	}
	if !strings.Contains(actualScope, "email") {
		t.Error("Expected email in scope")
	}
	if !strings.Contains(actualScope, "custom:read") {
		t.Error("Expected custom:read in scope")
	}

	// offline_access should be filtered (not in scopesSupported)
	actualScopes := strings.Split(actualScope, " ")
	for _, scope := range actualScopes {
		if scope == "offline_access" {
			t.Error("offline_access should have been filtered (not in scopesSupported)")
		}
	}
}

// TestAuthHandler_BuildAuthURL_LoggingVerification tests that logging occurs correctly
func TestAuthHandler_BuildAuthURL_LoggingVerification(t *testing.T) {
	logger := &mockLogger{}
	scopeFilter := &mockScopeFilter{}

	scopes := []string{"openid", "profile", "offline_access"}
	scopesSupported := []string{"openid", "profile"}

	handler := NewAuthHandler(logger, false, func() bool { return false }, func() bool { return false },
		"test-client", "https://example.com/auth", "https://example.com",
		scopes, false, scopeFilter, scopesSupported, false)

	handler.BuildAuthURL("https://example.com/callback", "test-state", "test-nonce", "")

	// Should have logged debug messages about filtering
	if len(logger.debugMessages) == 0 {
		t.Error("Expected debug messages to be logged during scope filtering")
	}

	// Verify specific log messages were generated
	hasDiscoveryFilterLog := false
	hasFinalFilterLog := false
	hasFinalScopeLog := false

	for _, msg := range logger.debugMessages {
		if strings.Contains(msg, "After discovery filtering") {
			hasDiscoveryFilterLog = true
		}
		if strings.Contains(msg, "After final filtering") {
			hasFinalFilterLog = true
		}
		if strings.Contains(msg, "Final scope string being sent") {
			hasFinalScopeLog = true
		}
	}

	if !hasDiscoveryFilterLog {
		t.Error("Expected log message about discovery filtering")
	}
	if !hasFinalFilterLog {
		t.Error("Expected log message about final filtering")
	}
	if !hasFinalScopeLog {
		t.Error("Expected log message about final scope string")
	}
}
