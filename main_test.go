// main_test.go

package traefikoidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/time/rate"
)

type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

type MockSessionStore struct {
	mock.Mock
}

func (m *MockSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	args := m.Called(r, name)
	if session, ok := args.Get(0).(*sessions.Session); ok {
		return session, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	args := m.Called(r, name)
	return args.Get(0).(*sessions.Session), args.Error(1)
}

func (m *MockSessionStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	args := m.Called(r, w, s)
	return args.Error(0)
}

type MockTokenVerifier struct {
	mock.Mock
}

func (m *MockTokenVerifier) VerifyToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

type MockJWTVerifier struct {
	mock.Mock
}

func (m *MockJWTVerifier) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	args := m.Called(jwt, token)
	return args.Error(0)
}

type TraefikOidcTestSuite struct {
	suite.Suite
	oidc              *TraefikOidc
	mockHTTPClient    *MockHTTPClient
	mockStore         *MockSessionStore
	mockTokenVerifier *MockTokenVerifier
	mockJWTVerifier   *MockJWTVerifier
}

func (suite *TraefikOidcTestSuite) SetupTest() {
	suite.mockHTTPClient = new(MockHTTPClient)
	suite.mockStore = new(MockSessionStore)
	suite.mockTokenVerifier = new(MockTokenVerifier)
	suite.mockJWTVerifier = new(MockJWTVerifier)

	config := &Config{
		ProviderURL:          "https://example.com",
		ClientID:             "test-client-id",
		ClientSecret:         "test-client-secret",
		CallbackURL:          "/callback",
		LogoutURL:            "/logout",
		SessionEncryptionKey: "test-encryption-key",
		Scopes:               []string{"openid", "email", "profile"},
	}

	suite.oidc = &TraefikOidc{
		clientID:       config.ClientID,
		clientSecret:   config.ClientSecret,
		redirURLPath:   config.CallbackURL,
		logoutURLPath:  config.LogoutURL,
		store:          suite.mockStore,
		httpClient:     &http.Client{Transport: suite.mockHTTPClient},
		jwkCache:       &JWKCache{},
		tokenBlacklist: NewTokenBlacklist(),
		tokenCache:     NewTokenCache(),
		logger:         NewLogger("info"),
		limiter:        rate.NewLimiter(rate.Every(time.Second), 100),
		authURL:        "https://example.com/auth",
		tokenURL:       "https://example.com/token",
		jwksURL:        "https://example.com/.well-known/jwks.json",
		tokenVerifier:  suite.mockTokenVerifier,
		jwtVerifier:    suite.mockJWTVerifier,
	}
}

func (suite *TraefikOidcTestSuite) TestServeHTTP_AuthenticatedUser() {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["authenticated"] = true

	claims := map[string]interface{}{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	claimsJSON, _ := json.Marshal(claims)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	mockToken := fmt.Sprintf("header.%s.signature", encodedClaims)
	session.Values["id_token"] = mockToken

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	suite.mockTokenVerifier.On("VerifyToken", mockToken).Return(nil)

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	suite.oidc.next = nextHandler

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusOK, rw.Code)
	suite.Equal("OK", rw.Body.String())
}

func (suite *TraefikOidcTestSuite) TestServeHTTP_CallbackPath() {
	req := httptest.NewRequest("GET", "http://example.com"+suite.oidc.redirURLPath+"?code=test_code&state=test_state", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["csrf"] = "test_state"
	session.Values["incoming_path"] = "/original_path"

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	claims := map[string]interface{}{
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"email": "test@example.com",
	}
	claimsJSON, _ := json.Marshal(claims)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	mockToken := fmt.Sprintf("header.%s.signature", encodedClaims)

	tokenResponse := map[string]interface{}{
		"id_token": mockToken,
	}
	tokenResponseJSON, _ := json.Marshal(tokenResponse)

	suite.mockHTTPClient.On("RoundTrip", mock.MatchedBy(func(req *http.Request) bool {
		return strings.Contains(req.URL.String(), "token")
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(tokenResponseJSON))),
	}, nil)

	suite.mockTokenVerifier.On("VerifyToken", mockToken).Return(nil)

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusFound, rw.Code)
	suite.Equal("/original_path", rw.Header().Get("Location"))
}

func (suite *TraefikOidcTestSuite) TestVerifyToken() {
	token := "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkxMjJ9.ZmFrZV9zaWduYXR1cmU"

	suite.mockTokenVerifier.On("VerifyToken", token).Return(nil)

	err := suite.oidc.verifyToken(token)
	suite.Require().NoError(err)
}

func (suite *TraefikOidcTestSuite) TestBuildAuthURL() {
	authURL := suite.oidc.buildAuthURL("http://example.com/callback", "test_state", "test_nonce")
	suite.Contains(authURL, suite.oidc.authURL)
	suite.Contains(authURL, "client_id="+suite.oidc.clientID)
	suite.Contains(authURL, "redirect_uri=http%3A%2F%2Fexample.com%2Fcallback")
	suite.Contains(authURL, "state=test_state")
	suite.Contains(authURL, "nonce=test_nonce")
}

func (suite *TraefikOidcTestSuite) TestJWKToPEM() {
	jwk := &JWK{
		N: base64.RawURLEncoding.EncodeToString(big.NewInt(12345).Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
	}
	pem, err := jwkToPEM(jwk)
	suite.Require().NoError(err)
	suite.NotEmpty(pem)
}

func (suite *TraefikOidcTestSuite) TestTokenBlacklist() {
	tb := NewTokenBlacklist()
	token := "test_token"
	expiration := time.Now().Add(time.Hour)

	tb.Add(token, expiration)
	suite.True(tb.IsBlacklisted(token))

	tb.Cleanup()
	suite.True(tb.IsBlacklisted(token))

	tb.Add("expired_token", time.Now().Add(-time.Hour))
	tb.Cleanup()
	suite.False(tb.IsBlacklisted("expired_token"))
}

func (suite *TraefikOidcTestSuite) TestTokenCache() {
	tc := NewTokenCache()
	token := "test_token"
	expiration := time.Now().Add(time.Hour)

	tc.Set(token, expiration)
	info, exists := tc.Get(token)
	suite.True(exists)
	suite.Equal(token, info.Token)
	suite.Equal(expiration, info.ExpiresAt)

	tc.Delete(token)
	_, exists = tc.Get(token)
	suite.False(exists)

	tc.Set("expired_token", time.Now().Add(-time.Hour))
	tc.Cleanup()
	_, exists = tc.Get("expired_token")
	suite.False(exists)
}

func TestTraefikOidcSuite(t *testing.T) {
	suite.Run(t, new(TraefikOidcTestSuite))
}

func (suite *TraefikOidcTestSuite) TestGenerateNonce() {
	nonce, err := generateNonce()
	suite.NoError(err)
	suite.Len(nonce, 44) // Base64 encoded 32 bytes
}

func (suite *TraefikOidcTestSuite) TestBuildFullURL() {
	url := buildFullURL("https", "example.com", "/path")
	suite.Equal("https://example.com/path", url)

	url = buildFullURL("", "example.com", "/path")
	suite.Equal("http://example.com/path", url)
}

func (suite *TraefikOidcTestSuite) TestExchangeTokens() {
	ctx := context.Background()

	testCases := []struct {
		name          string
		grantType     string
		codeOrToken   string
		redirectURL   string
		expectedToken map[string]interface{}
	}{
		{
			name:        "Authorization Code Exchange",
			grantType:   "authorization_code",
			codeOrToken: "test_code",
			redirectURL: "http://example.com/callback",
			expectedToken: map[string]interface{}{
				"access_token":  "test_access_token",
				"id_token":      "test_id_token",
				"refresh_token": "test_refresh_token",
				"expires_in":    float64(3600),
				"token_type":    "Bearer",
			},
		},
		{
			name:        "Refresh Token Exchange",
			grantType:   "refresh_token",
			codeOrToken: "test_refresh_token",
			redirectURL: "",
			expectedToken: map[string]interface{}{
				"access_token":  "new_access_token",
				"id_token":      "new_id_token",
				"refresh_token": "new_refresh_token",
				"expires_in":    float64(3600),
				"token_type":    "Bearer",
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			tokenJSON, _ := json.Marshal(tc.expectedToken)

			// Set up the mock HTTP client
			suite.mockHTTPClient.On("RoundTrip", mock.AnythingOfType("*http.Request")).Return(&http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(tokenJSON)),
			}, nil).Once()

			token, err := suite.oidc.exchangeTokens(ctx, tc.grantType, tc.codeOrToken, tc.redirectURL)
			suite.NoError(err)
			suite.Equal(tc.expectedToken, token)

			suite.mockHTTPClient.AssertExpectations(suite.T())
		})
	}
}

func (suite *TraefikOidcTestSuite) TestHandleLogout() {
	req := httptest.NewRequest("GET", "http://example.com/logout", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["id_token"] = "test_token"

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	suite.oidc.handleLogout(rw, req)

	suite.Equal(http.StatusForbidden, rw.Code)
	suite.Equal("Logged out\n", rw.Body.String())
}

func (suite *TraefikOidcTestSuite) TestExtractClaims() {
	tokenString := "header.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"
	claims, err := extractClaims(tokenString)
	suite.NoError(err)
	suite.Equal("1234567890", claims["sub"])
	suite.Equal("John Doe", claims["name"])
	suite.Equal(float64(1516239022), claims["iat"])
}

func (suite *TraefikOidcTestSuite) TestDiscoverProviderMetadata() {
	providerURL := "https://example.com"
	expectedMetadata := &ProviderMetadata{
		Issuer:   "https://example.com",
		AuthURL:  "https://example.com/auth",
		TokenURL: "https://example.com/token",
		JWKSURL:  "https://example.com/.well-known/jwks.json",
	}
	metadataJSON, _ := json.Marshal(expectedMetadata)

	httpClient := &http.Client{
		Transport: suite.mockHTTPClient,
	}

	suite.mockHTTPClient.On("RoundTrip", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(metadataJSON)),
	}, nil)

	metadata, err := discoverProviderMetadata(providerURL, *httpClient)
	suite.NoError(err)
	suite.Equal(expectedMetadata, metadata)
}

func (suite *TraefikOidcTestSuite) TestDetermineScheme() {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	scheme := suite.oidc.determineScheme(req)
	suite.Equal("http", scheme)

	req.Header.Set("X-Forwarded-Proto", "https")
	scheme = suite.oidc.determineScheme(req)
	suite.Equal("https", scheme)

	suite.oidc.forceHTTPS = true
	scheme = suite.oidc.determineScheme(req)
	suite.Equal("https", scheme)
}

func (suite *TraefikOidcTestSuite) TestDetermineHost() {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	host := suite.oidc.determineHost(req)
	suite.Equal("example.com", host)

	req.Header.Set("X-Forwarded-Host", "forwarded.example.com")
	host = suite.oidc.determineHost(req)
	suite.Equal("forwarded.example.com", host)
}

func (suite *TraefikOidcTestSuite) TestIsUserAuthenticated() {
	testCases := []struct {
		name            string
		setupSession    func() *sessions.Session
		expectedAuth    bool
		expectedExpired bool
		expectedRefresh bool
	}{
		{
			name: "Valid Token",
			setupSession: func() *sessions.Session {
				session := sessions.NewSession(suite.mockStore, cookieName)
				session.Values["authenticated"] = true
				session.Values["id_token"] = "valid.eyJleHAiOjk5OTk5OTk5OTl9.signature"
				return session
			},
			expectedAuth:    true,
			expectedExpired: false,
			expectedRefresh: false,
		},
		{
			name: "Expired Token",
			setupSession: func() *sessions.Session {
				session := sessions.NewSession(suite.mockStore, cookieName)
				session.Values["authenticated"] = true
				session.Values["id_token"] = "expired.eyJleHAiOjE1OTM1NjE2MDB9.signature"
				return session
			},
			expectedAuth:    false,
			expectedExpired: true,
			expectedRefresh: false,
		},
		{
			name: "Token Needs Refresh",
			setupSession: func() *sessions.Session {
				session := sessions.NewSession(suite.mockStore, cookieName)
				session.Values["authenticated"] = true
				// Set expiration to 4 minutes from now
				exp := time.Now().Add(4 * time.Minute).Unix()
				token := fmt.Sprintf("needsrefresh.%s.signature", base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp))))
				session.Values["id_token"] = token
				return session
			},
			expectedAuth:    true,
			expectedExpired: false,
			expectedRefresh: true,
		},
		{
			name: "Not Authenticated",
			setupSession: func() *sessions.Session {
				session := sessions.NewSession(suite.mockStore, cookieName)
				session.Values["authenticated"] = false
				return session
			},
			expectedAuth:    false,
			expectedExpired: false,
			expectedRefresh: false,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			session := tc.setupSession()
			suite.mockTokenVerifier.On("VerifyToken", mock.AnythingOfType("string")).Return(nil).Maybe()
			authenticated, tokenExpired, needsRefresh := suite.oidc.isUserAuthenticated(session)
			suite.Equal(tc.expectedAuth, authenticated)
			suite.Equal(tc.expectedExpired, tokenExpired)
			suite.Equal(tc.expectedRefresh, needsRefresh)
		})
	}
}

func (suite *TraefikOidcTestSuite) TestInitiateAuthentication() {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	rw := httptest.NewRecorder()
	session := sessions.NewSession(suite.mockStore, cookieName)

	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	suite.oidc.initiateAuthentication(rw, req, session, "http://example.com/callback")

	suite.Equal(http.StatusFound, rw.Code)
	location := rw.Header().Get("Location")
	suite.Contains(location, suite.oidc.authURL)
	suite.Contains(location, "redirect_uri=http%3A%2F%2Fexample.com%2Fcallback")
}

func (suite *TraefikOidcTestSuite) TestRevokeToken() {
	token := "valid.eyJleHAiOjk5OTk5OTk5OTl9.signature"
	suite.oidc.RevokeToken(token)

	_, exists := suite.oidc.tokenCache.Get(token)
	suite.False(exists)
	suite.True(suite.oidc.tokenBlacklist.IsBlacklisted(token))
}

func (suite *TraefikOidcTestSuite) TestServeHTTP_InvalidSession() {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	rw := httptest.NewRecorder()

	suite.mockStore.On("Get", req, cookieName).Return((*sessions.Session)(nil), fmt.Errorf("invalid session"))

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusInternalServerError, rw.Code)
	suite.Contains(rw.Body.String(), "Session error")
}

func (suite *TraefikOidcTestSuite) TestServeHTTP_ExpiredToken() {
	req := httptest.NewRequest("GET", "http://example.com", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["authenticated"] = true
	session.Values["id_token"] = "expired.eyJleHAiOjF9.signature" // expired token

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusFound, rw.Code) // Should redirect to authentication
}

func (suite *TraefikOidcTestSuite) TestHandleCallback_InvalidState() {
	req := httptest.NewRequest("GET", "http://example.com"+suite.oidc.redirURLPath+"?code=test_code&state=invalid_state", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["csrf"] = "valid_state"

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusBadRequest, rw.Code)
	suite.Contains(rw.Body.String(), "Invalid state parameter")
}

func (suite *TraefikOidcTestSuite) TestHandleCallback_TokenExchangeError() {
	req := httptest.NewRequest("GET", "http://example.com"+suite.oidc.redirURLPath+"?code=invalid_code&state=test_state", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["csrf"] = "test_state"

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	suite.mockHTTPClient.On("RoundTrip", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(strings.NewReader(`{"error": "invalid_grant"}`)),
	}, nil)

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusUnauthorized, rw.Code)
	suite.Contains(rw.Body.String(), "Authentication failed")
}

func (suite *TraefikOidcTestSuite) TestVerifyToken_RateLimitExceeded() {
	suite.oidc.limiter = rate.NewLimiter(rate.Every(time.Hour), 1) // Set a very low limit

	// Use up the only allowed request
	suite.oidc.limiter.Allow()

	err := suite.oidc.VerifyToken("some_token")
	suite.Error(err)
	suite.Contains(err.Error(), "rate limit exceeded")
}

func (suite *TraefikOidcTestSuite) TestVerifyToken_BlacklistedToken() {
	token := "blacklisted_token"
	suite.oidc.tokenBlacklist.Add(token, time.Now().Add(time.Hour))

	err := suite.oidc.VerifyToken(token)
	suite.Error(err)
	suite.Contains(err.Error(), "token is blacklisted")
}

func (suite *TraefikOidcTestSuite) TestExtractClaims_InvalidToken() {
	invalidToken := "invalid.token.format"
	claims, err := extractClaims(invalidToken)
	suite.Error(err)
	suite.Nil(claims)
}

func (suite *TraefikOidcTestSuite) TestDiscoverProviderMetadata_HTTPError() {
	providerURL := "https://example.com"
	httpClient := &http.Client{
		Transport: suite.mockHTTPClient,
	}

	suite.mockHTTPClient.On("RoundTrip", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader("Internal Server Error")),
	}, nil)

	metadata, err := discoverProviderMetadata(providerURL, *httpClient)
	suite.Error(err)
	suite.Nil(metadata)
	suite.Contains(err.Error(), "failed to fetch provider metadata: status code 500")
}

func (suite *TraefikOidcTestSuite) TestRevokeToken_InvalidToken() {
	invalidToken := "invalid.token"
	suite.oidc.RevokeToken(invalidToken)

	// Check that the invalid token is not added to the blacklist
	suite.False(suite.oidc.tokenBlacklist.IsBlacklisted(invalidToken))
}

func TestTraefikOidc_ServeHTTP(t *testing.T) {
	type fields struct {
		next           http.Handler
		name           string
		store          sessions.Store
		redirURLPath   string
		logoutURLPath  string
		issuerURL      string
		jwkCache       *JWKCache
		tokenBlacklist *TokenBlacklist
		jwksURL        string
		clientID       string
		clientSecret   string
		authURL        string
		tokenURL       string
		scopes         []string
		limiter        *rate.Limiter
		forceHTTPS     bool
		scheme         string
		tokenCache     *TokenCache
		httpClient     *http.Client
		logger         *Logger
		redirectURL    string
		tokenVerifier  TokenVerifier
		jwtVerifier    JWTVerifier
	}
	type args struct {
		rw  http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &TraefikOidc{
				next:           tt.fields.next,
				name:           tt.fields.name,
				store:          tt.fields.store,
				redirURLPath:   tt.fields.redirURLPath,
				logoutURLPath:  tt.fields.logoutURLPath,
				issuerURL:      tt.fields.issuerURL,
				jwkCache:       tt.fields.jwkCache,
				tokenBlacklist: tt.fields.tokenBlacklist,
				jwksURL:        tt.fields.jwksURL,
				clientID:       tt.fields.clientID,
				clientSecret:   tt.fields.clientSecret,
				authURL:        tt.fields.authURL,
				tokenURL:       tt.fields.tokenURL,
				scopes:         tt.fields.scopes,
				limiter:        tt.fields.limiter,
				forceHTTPS:     tt.fields.forceHTTPS,
				scheme:         tt.fields.scheme,
				tokenCache:     tt.fields.tokenCache,
				httpClient:     tt.fields.httpClient,
				logger:         tt.fields.logger,
				redirectURL:    tt.fields.redirectURL,
				tokenVerifier:  tt.fields.tokenVerifier,
				jwtVerifier:    tt.fields.jwtVerifier,
			}
			tr.ServeHTTP(tt.args.rw, tt.args.req)
		})
	}
}

func (suite *TraefikOidcTestSuite) TestBuildAuthURL_CustomScopes() {
	suite.oidc.scopes = []string{"openid", "email", "custom_scope"}
	authURL := suite.oidc.buildAuthURL("http://example.com/callback", "test_state", "test_nonce")
	suite.Contains(authURL, "scope=openid+email+custom_scope")
}

func (suite *TraefikOidcTestSuite) TestBuildAuthURL_EmptyScopes() {
	suite.oidc.scopes = []string{}
	authURL := suite.oidc.buildAuthURL("http://example.com/callback", "test_state", "test_nonce")
	suite.NotContains(authURL, "scope=")
}

func (suite *TraefikOidcTestSuite) TestDetermineScheme_ForceHTTPS() {
	suite.oidc.forceHTTPS = true
	req := httptest.NewRequest("GET", "http://example.com", nil)
	scheme := suite.oidc.determineScheme(req)
	suite.Equal("https", scheme)
}

func (suite *TraefikOidcTestSuite) TestHandleLogout_CustomLogoutURL() {
	suite.oidc.logoutURLPath = "/custom-logout"
	req := httptest.NewRequest("GET", "http://example.com/custom-logout", nil)
	rw := httptest.NewRecorder()

	session := sessions.NewSession(suite.mockStore, cookieName)
	session.Values["id_token"] = "test_token"

	suite.mockStore.On("Get", req, cookieName).Return(session, nil)
	suite.mockStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	suite.oidc.ServeHTTP(rw, req)

	suite.Equal(http.StatusForbidden, rw.Code)
	suite.Equal("Logged out\n", rw.Body.String())
}

func (suite *TraefikOidcTestSuite) TestVerifyToken_RateLimitReached() {
	suite.oidc.limiter = rate.NewLimiter(rate.Every(time.Hour), 1) // Set a very low limit
	suite.oidc.limiter.Allow()                                     // Use up the only allowed request

	err := suite.oidc.VerifyToken("some_token")
	suite.Error(err)
	suite.Contains(err.Error(), "rate limit exceeded")
}

func (suite *TraefikOidcTestSuite) TestVerifyToken_InvalidJWTFormat() {
	invalidToken := "invalid.jwt.format"
	err := suite.oidc.VerifyToken(invalidToken)
	suite.Error(err)
	suite.Contains(err.Error(), "failed to parse JWT")
}

func (suite *TraefikOidcTestSuite) TestDiscoverProviderMetadata_InvalidURL() {
	invalidURL := "invalid-url"
	httpClient := &http.Client{
		Transport: suite.mockHTTPClient,
	}

	suite.mockHTTPClient.On("RoundTrip", mock.Anything).Return(nil, fmt.Errorf("invalid URL"))

	_, err := discoverProviderMetadata(invalidURL, *httpClient)
	suite.Error(err)
	suite.Contains(err.Error(), "failed to fetch provider metadata")
}
