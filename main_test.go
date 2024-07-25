// main_test.go

package traefikoidc

import (
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
	return args.Get(0).(*http.Response), args.Error(1)
}

type MockSessionStore struct {
	mock.Mock
}

func (m *MockSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	args := m.Called(r, name)
	return args.Get(0).(*sessions.Session), args.Error(1)
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
		logger:         NewLogger("debug"),
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
