package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// MockJWTVerifier implements the JWTVerifier interface for testing
type MockJWTVerifier struct {
	VerifyJWTFunc func(jwt *JWT, token string) error
}

func (m *MockJWTVerifier) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	if m.VerifyJWTFunc != nil {
		return m.VerifyJWTFunc(jwt, token)
	}
	return nil
}

func TestGoogleOIDCRefreshTokenHandling(t *testing.T) {
	// Create a mocked TraefikOidc instance that simulates Google provider behavior
	mockLogger := NewLogger("debug")

	// Create a test instance with a Google-like issuer URL
	tOidc := &TraefikOidc{
		issuerURL:          "https://accounts.google.com",
		clientID:           "test-client-id",
		clientSecret:       "test-client-secret",
		logger:             mockLogger,
		scopes:             []string{"openid", "profile", "email"},
		refreshGracePeriod: 60,
	}

	// Create a session manager
	sessionManager, _ := NewSessionManager("0123456789abcdef0123456789abcdef", true, "", mockLogger)
	tOidc.sessionManager = sessionManager

	t.Run("Google provider detection adds required parameters", func(t *testing.T) {
		// Test buildAuthURL to ensure it adds access_type=offline and prompt=consent for Google
		authURL := tOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Check that access_type=offline was added (not offline_access scope for Google)
		if !strings.Contains(authURL, "access_type=offline") {
			t.Errorf("access_type=offline not added to Google auth URL: %s", authURL)
		}

		// Verify offline_access scope is NOT included for Google providers
		if strings.Contains(authURL, "offline_access") {
			t.Errorf("offline_access scope incorrectly added to Google auth URL: %s", authURL)
		}

		// Check that prompt=consent was added
		if !strings.Contains(authURL, "prompt=consent") {
			t.Errorf("prompt=consent not added to Google auth URL: %s", authURL)
		}
	})

	t.Run("Non-Google provider doesn't add Google-specific params", func(t *testing.T) {
		// Create a test instance with a non-Google issuer URL
		nonGoogleOidc := &TraefikOidc{
			issuerURL:    "https://auth.example.com",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			logger:       mockLogger,
			scopes:       []string{"openid", "profile", "email"},
		}

		// Test buildAuthURL without Google-specific parameters
		authURL := nonGoogleOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Check that prompt=consent is not automatically added
		if strings.Contains(authURL, "prompt=consent") {
			t.Errorf("prompt=consent added to non-Google auth URL: %s", authURL)
		}
	})

	t.Run("Session refresh with Google provider", func(t *testing.T) {
		// Create a request and response recorder
		req := httptest.NewRequest("GET", "/test", nil)
		rw := httptest.NewRecorder()

		// Create a session and set a refresh token
		session, _ := sessionManager.GetSession(req)
		session.SetAuthenticated(true)
		session.SetEmail("test@example.com")
		session.SetAccessToken(ValidAccessToken)
		session.SetRefreshToken("valid-refresh-token")

		// Create a mock token exchanger that simulates Google's behavior
		mockTokenExchanger := &MockTokenExchanger{
			RefreshTokenFunc: func(refreshToken string) (*TokenResponse, error) {
				// Check that the refresh token is passed correctly
				if refreshToken != "valid-refresh-token" {
					t.Errorf("Incorrect refresh token passed: %s", refreshToken)
					return nil, fmt.Errorf("invalid token")
				}

				// Use standardized test tokens instead of ad-hoc strings
				testTokens := NewTestTokens()
				googleTokens := testTokens.GetGoogleTokenSet()

				// Return a simulated Google token response with a new access token
				// but without a new refresh token (Google doesn't always return a new refresh token)
				return &TokenResponse{
					IDToken:      googleTokens.IDToken,
					AccessToken:  googleTokens.AccessToken,
					RefreshToken: "", // Google often doesn't return a new refresh token
					ExpiresIn:    3600,
				}, nil
			},
		}

		// Set the mock token exchanger
		tOidc.tokenExchanger = mockTokenExchanger

		// Create a struct that implements the TokenVerifier interface
		tOidc.tokenVerifier = &MockTokenVerifier{
			VerifyFunc: func(token string) error {
				return nil
			},
		}

		tOidc.extractClaimsFunc = func(token string) (map[string]interface{}, error) {
			// Return mock claims
			return map[string]interface{}{
				"email": "test@example.com",
				"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
			}, nil
		}

		// Attempt to refresh the token
		refreshed := tOidc.refreshToken(rw, req, session)

		// Verify the refresh was successful
		if !refreshed {
			t.Error("Token refresh failed for Google provider")
		}

		// Check that we kept the original refresh token since Google didn't provide a new one
		if session.GetRefreshToken() != "valid-refresh-token" {
			t.Errorf("Original refresh token not preserved: got %s, expected 'valid-refresh-token'",
				session.GetRefreshToken())
		}

		// Use the same test tokens for validation
		testTokens := NewTestTokens()
		expectedTokens := testTokens.GetGoogleTokenSet()

		// Check that the tokens were updated correctly
		if session.GetIDToken() != expectedTokens.IDToken {
			t.Errorf("ID token not updated: got %s, expected %s",
				session.GetIDToken(), expectedTokens.IDToken)
		}

		if session.GetAccessToken() != expectedTokens.AccessToken {
			t.Errorf("Access token not updated: got %s, expected %s",
				session.GetAccessToken(), expectedTokens.AccessToken)
		}
	})
	// Test that our fix specifically addresses the reported Google error
	t.Run("Google provider handles offline access correctly", func(t *testing.T) {
		// Build the auth URL with Google provider detection
		authURL := tOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Parse the URL to examine its parameters
		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("Failed to parse auth URL: %v", err)
		}

		params := parsedURL.Query()

		// Verify that access_type=offline is set (Google's way of requesting refresh tokens)
		if params.Get("access_type") != "offline" {
			t.Errorf("access_type=offline not set in Google auth URL")
		}

		// Verify that the scope parameter doesn't contain offline_access
		// (which Google reports as invalid: {invalid=[offline_access]})
		scope := params.Get("scope")
		if strings.Contains(scope, "offline_access") {
			t.Errorf("offline_access incorrectly included in scope for Google provider: %s", scope)
		}

		// Verify that the necessary scopes are still included
		for _, requiredScope := range []string{"openid", "profile", "email"} {
			if !strings.Contains(scope, requiredScope) {
				t.Errorf("Required scope '%s' missing from auth URL", requiredScope)
			}
		}
	})

	// Enhanced test for verifying non-Google provider includes offline_access scope
	t.Run("Non-Google provider includes offline_access scope", func(t *testing.T) {
		// Create a test instance with a non-Google issuer URL
		nonGoogleOidc := &TraefikOidc{
			issuerURL:    "https://auth.example.com",
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			logger:       mockLogger,
			scopes:       []string{"openid", "profile", "email"},
		}

		// Test buildAuthURL for a non-Google provider
		authURL := nonGoogleOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Parse the URL to examine its parameters
		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("Failed to parse auth URL: %v", err)
		}

		params := parsedURL.Query()

		// Verify that access_type=offline is NOT set for non-Google providers
		if params.Get("access_type") == "offline" {
			t.Errorf("access_type=offline incorrectly added to non-Google auth URL")
		}

		// Verify that offline_access scope IS included for non-Google providers
		scope := params.Get("scope")
		if !strings.Contains(scope, "offline_access") {
			t.Errorf("offline_access scope missing from non-Google auth URL scope: %s", scope)
		}

		// Verify that the necessary scopes are still included
		for _, requiredScope := range []string{"openid", "profile", "email"} {
			if !strings.Contains(scope, requiredScope) {
				t.Errorf("Required scope '%s' missing from non-Google auth URL", requiredScope)
			}
		}
	})

	// Additional test for complete URL construction for Google provider
	t.Run("Complete Google auth URL construction", func(t *testing.T) {
		// Build the auth URL with additional parameters
		redirectURL := "https://example.com/callback"
		state := "state123"
		nonce := "nonce123"
		codeChallenge := "code_challenge_value" // For PKCE

		// Enable PKCE for this test
		tOidc.enablePKCE = true

		// Build auth URL
		authURL := tOidc.buildAuthURL(redirectURL, state, nonce, codeChallenge)

		// Parse the URL to examine its structure and parameters
		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("Failed to parse auth URL: %v", err)
		}

		// Verify the base URL
		expectedBaseURL := "https://accounts.google.com/o/oauth2/v2/auth"
		if !strings.HasPrefix(authURL, expectedBaseURL) && !strings.Contains(authURL, "accounts.google.com") {
			t.Errorf("Auth URL doesn't start with expected Google OAuth endpoint: %s", authURL)
		}

		// Check all required parameters
		params := parsedURL.Query()
		expectedParams := map[string]string{
			"client_id":     "test-client-id",
			"response_type": "code",
			"redirect_uri":  redirectURL,
			"state":         state,
			"nonce":         nonce,
			"access_type":   "offline",
			"prompt":        "consent",
		}

		// Also check PKCE parameters if enabled
		if tOidc.enablePKCE {
			expectedParams["code_challenge"] = codeChallenge
			expectedParams["code_challenge_method"] = "S256"
		}

		for key, expectedValue := range expectedParams {
			if value := params.Get(key); value != expectedValue {
				t.Errorf("Parameter %s has incorrect value. Expected: %s, Got: %s",
					key, expectedValue, value)
			}
		}

		// Verify scope parameter separately due to it being space-separated values
		scope := params.Get("scope")
		if scope == "" {
			t.Error("Scope parameter missing from Google auth URL")
		}

		// Check that all required scopes are present
		scopeList := strings.Split(scope, " ")
		expectedScopes := []string{"openid", "profile", "email"}
		for _, expectedScope := range expectedScopes {
			found := false
			for _, s := range scopeList {
				if s == expectedScope {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected scope '%s' not found in scope parameter: %s", expectedScope, scope)
			}
		}

		// Verify offline_access is NOT in the scope list
		for _, actualScope := range scopeList {
			if actualScope == "offline_access" {
				t.Errorf("offline_access scope incorrectly included in Google auth URL: %s", scope)
			}
		}
	})

	// Integration test with mocked Google provider
	t.Run("Integration test with mocked Google provider", func(t *testing.T) {
		// Generate an RSA key for signing the test JWTs
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// Create JWK for the RSA public key
		jwk := JWK{
			Kty: "RSA",
			Kid: "test-key-id",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(rsaPrivateKey.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(rsaPrivateKey.PublicKey.E)))),
		}
		jwks := &JWKSet{
			Keys: []JWK{jwk},
		}

		// Create a mock JWK cache
		mockJWKCache := &MockJWKCache{
			JWKS: jwks,
			Err:  nil,
		}

		// Create test cleanup helper
		tc := newTestCleanup(t)

		// Create a complete test instance with all required fields
		mockLogger := NewLogger("debug")
		googleTOidc := &TraefikOidc{
			issuerURL:          "https://accounts.google.com",
			clientID:           "test-client-id",
			clientSecret:       "test-client-secret",
			logger:             mockLogger,
			scopes:             []string{"openid", "profile", "email"},
			refreshGracePeriod: 60,
			tokenCache:         tc.addTokenCache(NewTokenCache()), // Initialize tokenCache with cleanup
			tokenBlacklist:     tc.addCache(NewCache()),           // Initialize tokenBlacklist with cleanup
			enablePKCE:         false,
			limiter:            rate.NewLimiter(rate.Inf, 0), // No rate limiting for tests
			jwkCache:           mockJWKCache,
			jwksURL:            "https://accounts.google.com/jwks",
		}

		// Create a session manager
		sessionManager, _ := NewSessionManager("0123456789abcdef0123456789abcdef", true, "", mockLogger)
		googleTOidc.sessionManager = sessionManager

		// Create a mock token verifier
		mockTokenVerifier := &MockTokenVerifier{
			VerifyFunc: func(token string) error {
				return nil // Always verify successfully for this test
			},
		}
		googleTOidc.tokenVerifier = mockTokenVerifier

		// Create JWT tokens for the test
		now := time.Now()
		exp := now.Add(1 * time.Hour).Unix()
		iat := now.Unix()
		nbf := now.Unix()

		// Create initial ID token
		initialIDToken, err := createTestJWT(rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://accounts.google.com",
			"aud":   "test-client-id",
			"exp":   exp,
			"iat":   iat,
			"nbf":   nbf,
			"sub":   "test-subject",
			"email": "user@example.com",
			"nonce": "nonce123", // For initial authentication verification
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create test ID token: %v", err)
		}

		// Create refresh ID token
		refreshedIDToken, err := createTestJWT(rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":   "https://accounts.google.com",
			"aud":   "test-client-id",
			"exp":   exp,
			"iat":   iat,
			"nbf":   nbf,
			"sub":   "test-subject",
			"email": "user@example.com",
			"jti":   generateRandomString(16),
		})
		if err != nil {
			t.Fatalf("Failed to create refreshed test ID token: %v", err)
		}

		// Set up token verifier with mock
		googleTOidc.tokenVerifier = &MockTokenVerifier{
			VerifyFunc: func(token string) error {
				return nil // Always verify successfully for this test
			},
		}

		// Set up JWT verifier with mock
		googleTOidc.jwtVerifier = &MockJWTVerifier{
			VerifyJWTFunc: func(jwt *JWT, token string) error {
				return nil // Always verify successfully for this test
			},
		}

		// Create a mock token exchanger that simulates Google's OAuth behavior
		mockTokenExchanger := &MockTokenExchanger{
			ExchangeCodeFunc: func(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
				// Verify the correct parameters are passed
				if grantType != "authorization_code" {
					t.Errorf("Expected grant_type=authorization_code, got %s", grantType)
				}
				if codeOrToken != "test_auth_code" {
					t.Errorf("Expected code=test_auth_code, got %s", codeOrToken)
				}
				if redirectURL != "https://example.com/callback" {
					t.Errorf("Expected redirect_uri=https://example.com/callback, got %s", redirectURL)
				}

				// Return a successful token response with a proper JWT
				return &TokenResponse{
					IDToken:      initialIDToken,
					AccessToken:  initialIDToken, // Use a valid JWT as the access token too
					RefreshToken: "google_refresh_token",
					ExpiresIn:    3600,
				}, nil
			},
			RefreshTokenFunc: func(refreshToken string) (*TokenResponse, error) {
				// Verify the correct refresh token is passed
				if refreshToken != "google_refresh_token" {
					t.Errorf("Expected refresh_token=google_refresh_token, got %s", refreshToken)
				}

				// Return a successful refresh response with a proper JWT
				return &TokenResponse{
					IDToken:      refreshedIDToken,
					AccessToken:  refreshedIDToken, // Use a valid JWT as the access token
					RefreshToken: "",               // Google doesn't always return a new refresh token
					ExpiresIn:    3600,
				}, nil
			},
		}

		googleTOidc.tokenExchanger = mockTokenExchanger

		// Use the real extractClaimsFunc to parse the proper JWT tokens
		googleTOidc.extractClaimsFunc = extractClaims

		// 1. Test building the authorization URL
		authURL := googleTOidc.buildAuthURL("https://example.com/callback", "state123", "nonce123", "")

		// Verify Google-specific parameters
		if !strings.Contains(authURL, "access_type=offline") {
			t.Errorf("Google auth URL missing access_type=offline: %s", authURL)
		}
		if !strings.Contains(authURL, "prompt=consent") {
			t.Errorf("Google auth URL missing prompt=consent: %s", authURL)
		}
		if strings.Contains(authURL, "offline_access") {
			t.Errorf("Google auth URL incorrectly includes offline_access scope: %s", authURL)
		}

		// 2. Test handling the callback and token exchange
		// Create a request and response recorder for the callback
		req := httptest.NewRequest("GET", "/callback?code=test_auth_code&state=state123", nil)
		rw := httptest.NewRecorder()

		// Create a session and set the necessary values
		session, _ := googleTOidc.sessionManager.GetSession(req)
		session.SetCSRF("state123") // Must match the state parameter
		session.SetNonce("nonce123")

		// Save the session to the request
		if err := session.Save(req, rw); err != nil {
			t.Fatalf("Failed to save session: %v", err)
		}

		// Get cookies from the response and add them to a new request
		cookies := rw.Result().Cookies()
		callbackReq := httptest.NewRequest("GET", "/callback?code=test_auth_code&state=state123", nil)
		for _, cookie := range cookies {
			callbackReq.AddCookie(cookie)
		}
		callbackRw := httptest.NewRecorder()

		// Handle the callback
		googleTOidc.handleCallback(callbackRw, callbackReq, "https://example.com/callback")

		// Verify the response is a redirect (302 Found)
		if callbackRw.Code != 302 {
			t.Errorf("Expected 302 redirect, got %d", callbackRw.Code)
		}

		// Create a new request to get the updated session
		newReq := httptest.NewRequest("GET", "/", nil)
		for _, cookie := range callbackRw.Result().Cookies() {
			newReq.AddCookie(cookie)
		}

		// Get the updated session
		newSession, err := googleTOidc.sessionManager.GetSession(newReq)
		if err != nil {
			t.Fatalf("Failed to get session after callback: %v", err)
		}

		// Verify the session contains the expected values
		if !newSession.GetAuthenticated() {
			t.Error("Session not marked as authenticated after callback")
		}
		if newSession.GetEmail() != "user@example.com" {
			t.Errorf("Session email incorrect: got %s, expected user@example.com",
				newSession.GetEmail())
		}

		// Check for non-empty access token that can be parsed as JWT
		accessToken := newSession.GetAccessToken()
		if accessToken == "" {
			t.Error("Session access token is empty")
		} else {
			claims, err := extractClaims(accessToken)
			if err != nil {
				t.Errorf("Failed to parse access token as JWT: %v", err)
			} else if email, ok := claims["email"].(string); !ok || email != "user@example.com" {
				t.Errorf("Access token JWT doesn't contain expected email claim")
			}
		}

		// Check refresh token
		if newSession.GetRefreshToken() != "google_refresh_token" {
			t.Errorf("Session refresh token incorrect: got %s, expected google_refresh_token",
				newSession.GetRefreshToken())
		}

		// 3. Test token refresh
		refreshReq := httptest.NewRequest("GET", "/", nil)
		for _, cookie := range callbackRw.Result().Cookies() {
			refreshReq.AddCookie(cookie)
		}
		refreshRw := httptest.NewRecorder()

		// Get the session for refresh
		refreshSession, _ := googleTOidc.sessionManager.GetSession(refreshReq)

		// Refresh the token
		refreshed := googleTOidc.refreshToken(refreshRw, refreshReq, refreshSession)

		// Verify refresh was successful
		if !refreshed {
			t.Error("Token refresh failed")
		}

		// Verify the session data after refresh
		// Check for non-empty refreshed access token that can be parsed as JWT
		refreshedAccessToken := refreshSession.GetAccessToken()
		if refreshedAccessToken == "" {
			t.Error("Session access token is empty after refresh")
		} else {
			claims, err := extractClaims(refreshedAccessToken)
			if err != nil {
				t.Errorf("Failed to parse refreshed access token as JWT: %v", err)
			} else if email, ok := claims["email"].(string); !ok || email != "user@example.com" {
				t.Errorf("Refreshed access token JWT doesn't contain expected email claim")
			}
		}

		// Since Google didn't return a new refresh token, the original should be preserved
		if refreshSession.GetRefreshToken() != "google_refresh_token" {
			t.Errorf("Original refresh token not preserved: got %s, expected google_refresh_token",
				refreshSession.GetRefreshToken())
		}
	})
}

// No need to redefine MockTokenExchanger - it's already defined in main_test.go
