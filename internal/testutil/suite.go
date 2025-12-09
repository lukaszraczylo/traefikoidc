package testutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil/fixtures"
	"github.com/lukaszraczylo/traefikoidc/internal/testutil/mocks"
	"github.com/lukaszraczylo/traefikoidc/internal/testutil/servers"
	"github.com/stretchr/testify/suite"
)

// OIDCSuite is a base test suite for OIDC-related tests
type OIDCSuite struct {
	suite.Suite

	// Common fixtures
	TokenFixture *fixtures.TokenFixture

	// Mock OIDC server
	OIDCServer *servers.OIDCServer

	// Mocks
	JWKCacheMock       *mocks.JWKCache
	TokenExchangerMock *mocks.TokenExchanger
	SessionManagerMock *mocks.SessionManager
	CacheMock          *mocks.Cache
	LoggerMock         *mocks.Logger
}

// SetupSuite runs once before all tests in the suite
func (s *OIDCSuite) SetupSuite() {
	var err error
	s.TokenFixture, err = fixtures.NewTokenFixture()
	s.Require().NoError(err, "Failed to create token fixture")
}

// SetupTest runs before each test
func (s *OIDCSuite) SetupTest() {
	// Create fresh mocks for each test
	s.JWKCacheMock = new(mocks.JWKCache)
	s.TokenExchangerMock = new(mocks.TokenExchanger)
	s.SessionManagerMock = new(mocks.SessionManager)
	s.CacheMock = new(mocks.Cache)
	s.LoggerMock = new(mocks.Logger)

	// Create OIDC server with token fixture
	config := servers.DefaultConfig()
	config.TokenFixture = s.TokenFixture
	s.OIDCServer = servers.NewOIDCServer(config)
}

// TearDownTest runs after each test
func (s *OIDCSuite) TearDownTest() {
	if s.OIDCServer != nil {
		s.OIDCServer.Close()
	}
}

// TearDownSuite runs once after all tests in the suite
func (s *OIDCSuite) TearDownSuite() {
	// Cleanup if needed
}

// NewRequest creates a new HTTP request for testing
func (s *OIDCSuite) NewRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	return req
}

// NewRequestWithCookie creates a request with a session cookie
func (s *OIDCSuite) NewRequestWithCookie(method, path, cookieName, cookieValue string) *http.Request {
	req := s.NewRequest(method, path)
	req.AddCookie(&http.Cookie{
		Name:  cookieName,
		Value: cookieValue,
	})
	return req
}

// NewRecorder creates a new response recorder
func (s *OIDCSuite) NewRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// AssertMocksCalled verifies all mock expectations were met
func (s *OIDCSuite) AssertMocksCalled() {
	s.JWKCacheMock.AssertExpectations(s.T())
	s.TokenExchangerMock.AssertExpectations(s.T())
	s.SessionManagerMock.AssertExpectations(s.T())
	s.CacheMock.AssertExpectations(s.T())
	s.LoggerMock.AssertExpectations(s.T())
}

// ValidToken returns a valid JWT token
func (s *OIDCSuite) ValidToken() string {
	token, err := s.TokenFixture.ValidToken(nil)
	s.Require().NoError(err)
	return token
}

// ExpiredToken returns an expired JWT token
func (s *OIDCSuite) ExpiredToken() string {
	token, err := s.TokenFixture.ExpiredToken()
	s.Require().NoError(err)
	return token
}

// TokenWithClaims returns a token with custom claims
func (s *OIDCSuite) TokenWithClaims(claims map[string]interface{}) string {
	token, err := s.TokenFixture.ValidToken(claims)
	s.Require().NoError(err)
	return token
}

// RunSuite runs a test suite
func RunSuite(t *testing.T, s suite.TestingSuite) {
	suite.Run(t, s)
}

// MinimalSuite is a lightweight test suite without OIDC server
type MinimalSuite struct {
	suite.Suite

	// Mocks only
	JWKCacheMock       *mocks.JWKCache
	TokenExchangerMock *mocks.TokenExchanger
	CacheMock          *mocks.Cache
}

// SetupTest runs before each test
func (s *MinimalSuite) SetupTest() {
	s.JWKCacheMock = new(mocks.JWKCache)
	s.TokenExchangerMock = new(mocks.TokenExchanger)
	s.CacheMock = new(mocks.Cache)
}

// AssertMocksCalled verifies all mock expectations were met
func (s *MinimalSuite) AssertMocksCalled() {
	s.JWKCacheMock.AssertExpectations(s.T())
	s.TokenExchangerMock.AssertExpectations(s.T())
	s.CacheMock.AssertExpectations(s.T())
}
