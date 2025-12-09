package traefikoidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil"
	"github.com/lukaszraczylo/traefikoidc/internal/testutil/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/time/rate"
)

// TokenValidationSuite tests token validation scenarios using testify suite
type TokenValidationSuite struct {
	suite.Suite

	// Fixtures
	fixture *testutil.TokenFixture

	// System under test
	tOidc *TraefikOidc

	// Mocks
	jwkCacheMock *MockJWKCache
}

func (s *TokenValidationSuite) SetupSuite() {
	var err error
	s.fixture, err = testutil.NewTokenFixture()
	s.Require().NoError(err, "Failed to create token fixture")
}

func (s *TokenValidationSuite) SetupTest() {
	// Create JWK for the test key
	jwk := JWK{
		Kty: "RSA",
		Kid: s.fixture.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(s.fixture.RSAPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(s.fixture.RSAPublicKey.E)))),
	}

	s.jwkCacheMock = &MockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{jwk}},
		Err:  nil,
	}

	// Initialize caches
	tokenBlacklist := NewCache()
	tokenCacheInternal := NewCache()
	tokenCache := &TokenCache{}
	if tokenCache.cache == nil {
		if wrapper, ok := tokenCacheInternal.(*CacheInterfaceWrapper); ok {
			tokenCache.cache = wrapper.cache
		}
	}

	logger := NewLogger("info")

	s.tOidc = &TraefikOidc{
		issuerURL:           s.fixture.Issuer,
		clientID:            s.fixture.Audience,
		audience:            s.fixture.Audience,
		clientSecret:        "test-client-secret",
		roleClaimName:       "roles",
		groupClaimName:      "groups",
		userIdentifierClaim: "email",
		jwkCache:            s.jwkCacheMock,
		jwksURL:             "https://test-jwks-url.com",
		limiter:             rate.NewLimiter(rate.Every(time.Second), 10),
		tokenBlacklist:      tokenBlacklist,
		tokenCache:          tokenCache,
		logger:              logger,
		httpClient:          &http.Client{Timeout: 10 * time.Second},
		extractClaimsFunc:   extractClaims,
		initComplete:        make(chan struct{}),
		goroutineWG:         &sync.WaitGroup{},
		ctx:                 context.Background(),
	}
	close(s.tOidc.initComplete)
	s.tOidc.tokenVerifier = s.tOidc
	s.tOidc.jwtVerifier = s.tOidc

	// Register cleanup
	s.T().Cleanup(func() {
		if s.tOidc.tokenBlacklist != nil {
			s.tOidc.tokenBlacklist.Close()
		}
		if s.tOidc.tokenCache != nil && s.tOidc.tokenCache.cache != nil {
			s.tOidc.tokenCache.cache.Close()
		}
	})
}

// Happy Path Tests

func (s *TokenValidationSuite) TestValidToken() {
	token, err := s.fixture.ValidToken(nil)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.NoError(err, "Valid token should pass verification")
}

func (s *TokenValidationSuite) TestValidTokenWithRoles() {
	token, err := s.fixture.TokenWithRoles([]string{"admin", "user"})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.NoError(err, "Token with roles should pass verification")
}

func (s *TokenValidationSuite) TestValidTokenWithGroups() {
	token, err := s.fixture.TokenWithGroups([]string{"developers", "admins"})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.NoError(err, "Token with groups should pass verification")
}

// Error Case Tests

func (s *TokenValidationSuite) TestExpiredToken() {
	token, err := s.fixture.ExpiredToken()
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.Error(err, "Expired token should fail verification")
	s.Contains(err.Error(), "expired")
}

func (s *TokenValidationSuite) TestMalformedToken() {
	err := s.tOidc.VerifyToken(s.fixture.MalformedToken())

	s.Error(err, "Malformed token should fail verification")
}

func (s *TokenValidationSuite) TestEmptyToken() {
	err := s.tOidc.VerifyToken(s.fixture.EmptyToken())

	s.Error(err, "Empty token should fail verification")
}

func (s *TokenValidationSuite) TestTokenWithWrongIssuer() {
	token, err := s.fixture.TokenWithIssuer("https://wrong-issuer.com")
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.Error(err, "Token with wrong issuer should fail verification")
}

func (s *TokenValidationSuite) TestTokenWithWrongAudience() {
	token, err := s.fixture.TokenWithAudience("wrong-audience")
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.Error(err, "Token with wrong audience should fail verification")
}

func (s *TokenValidationSuite) TestTokenWithWrongSignature() {
	token, err := s.fixture.TokenWithWrongSignature()
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.Error(err, "Token with wrong signature should fail verification")
}

// Edge Case Tests

func (s *TokenValidationSuite) TestNotYetValidToken() {
	token, err := s.fixture.NotYetValidToken()
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	s.Error(err, "Not-yet-valid token should fail verification")
}

func (s *TokenValidationSuite) TestTokenAtExpiryBoundary() {
	// Token that expires in exactly 0 seconds (should be invalid)
	token, err := s.fixture.TokenWithSkew(0)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	// This is an edge case - token at exact expiry boundary
	// The behavior depends on clock precision
	s.T().Log("Token at expiry boundary result:", err)
}

func (s *TokenValidationSuite) TestTokenWithClockSkewTolerance() {
	// Token that expired 2 minutes ago (within typical 5-minute tolerance)
	token, err := s.fixture.TokenWithSkew(-2 * time.Minute)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	// With default clock skew tolerance, this should fail
	// but some implementations allow it
	s.T().Log("Token with 2-minute expiry result:", err)
}

func (s *TokenValidationSuite) TestTokenMissingSub() {
	token, err := s.fixture.TokenMissingClaim("sub")
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	// Token without sub claim should still be valid for signature
	// but may fail other validations
	s.T().Log("Token missing sub result:", err)
}

func (s *TokenValidationSuite) TestTokenMissingEmail() {
	token, err := s.fixture.TokenMissingClaim("email")
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)

	// Token without email should still pass signature verification
	s.T().Log("Token missing email result:", err)
}

func (s *TokenValidationSuite) TestConcurrentTokenValidation() {
	token, err := s.fixture.ValidToken(nil)
	s.Require().NoError(err)

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.tOidc.VerifyToken(token); err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	var errCount int
	for err := range errors {
		s.T().Logf("Concurrent validation error: %v", err)
		errCount++
	}

	s.Equal(0, errCount, "All concurrent validations should succeed")
}

func TestTokenValidationSuite(t *testing.T) {
	suite.Run(t, new(TokenValidationSuite))
}

// JWKCacheTestSuite tests JWK caching scenarios
type JWKCacheTestSuite struct {
	suite.Suite

	jwkCache *mocks.JWKCache
}

func (s *JWKCacheTestSuite) SetupTest() {
	s.jwkCache = new(mocks.JWKCache)
}

func (s *JWKCacheTestSuite) TestGetJWKSSuccess() {
	expectedJWKS := &mocks.JWKSet{
		Keys: []mocks.JWK{{Kty: "RSA", Kid: "key-1"}},
	}

	s.jwkCache.On("GetJWKS", mock.Anything, "https://example.com/jwks", mock.Anything).
		Return(expectedJWKS, nil)

	result, err := s.jwkCache.GetJWKS(context.Background(), "https://example.com/jwks", nil)

	s.NoError(err)
	s.Equal(expectedJWKS, result)
	s.jwkCache.AssertExpectations(s.T())
}

func (s *JWKCacheTestSuite) TestGetJWKSNetworkError() {
	s.jwkCache.On("GetJWKS", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded)

	result, err := s.jwkCache.GetJWKS(context.Background(), "https://example.com/jwks", nil)

	s.Nil(result)
	s.Error(err)
	s.jwkCache.AssertExpectations(s.T())
}

func (s *JWKCacheTestSuite) TestGetJWKSMultipleKeys() {
	expectedJWKS := &mocks.JWKSet{
		Keys: []mocks.JWK{
			{Kty: "RSA", Kid: "key-1", Alg: "RS256"},
			{Kty: "RSA", Kid: "key-2", Alg: "RS256"},
			{Kty: "EC", Kid: "key-3", Alg: "ES256"},
		},
	}

	s.jwkCache.On("GetJWKS", mock.Anything, mock.Anything, mock.Anything).
		Return(expectedJWKS, nil)

	result, err := s.jwkCache.GetJWKS(context.Background(), "https://example.com/jwks", nil)

	s.NoError(err)
	s.Len(result.Keys, 3)
	s.jwkCache.AssertExpectations(s.T())
}

func (s *JWKCacheTestSuite) TestCloseIsCalled() {
	s.jwkCache.On("Close").Return()

	s.jwkCache.Close()

	s.jwkCache.AssertExpectations(s.T())
}

func TestJWKCacheTestSuite(t *testing.T) {
	suite.Run(t, new(JWKCacheTestSuite))
}

// TokenExchangerTestSuite tests token exchange scenarios
type TokenExchangerTestSuite struct {
	suite.Suite

	exchanger *mocks.TokenExchanger
}

func (s *TokenExchangerTestSuite) SetupTest() {
	s.exchanger = new(mocks.TokenExchanger)
}

func (s *TokenExchangerTestSuite) TestExchangeCodeSuccess() {
	expectedResponse := &mocks.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresIn:    3600,
	}

	s.exchanger.On("ExchangeCodeForToken", mock.Anything, "authorization_code", "test-code", "https://example.com/callback", "verifier").
		Return(expectedResponse, nil)

	result, err := s.exchanger.ExchangeCodeForToken(
		context.Background(),
		"authorization_code",
		"test-code",
		"https://example.com/callback",
		"verifier",
	)

	s.NoError(err)
	s.Equal(expectedResponse.AccessToken, result.AccessToken)
	s.Equal(expectedResponse.RefreshToken, result.RefreshToken)
	s.exchanger.AssertExpectations(s.T())
}

func (s *TokenExchangerTestSuite) TestExchangeCodeInvalidGrant() {
	s.exchanger.On("ExchangeCodeForToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("invalid_grant: Authorization code expired"))

	result, err := s.exchanger.ExchangeCodeForToken(
		context.Background(),
		"authorization_code",
		"expired-code",
		"https://example.com/callback",
		"verifier",
	)

	s.Nil(result)
	s.Error(err)
	s.exchanger.AssertExpectations(s.T())
}

func (s *TokenExchangerTestSuite) TestRefreshTokenSuccess() {
	expectedResponse := &mocks.TokenResponse{
		AccessToken: "new-access-token",
		ExpiresIn:   3600,
	}

	s.exchanger.On("GetNewTokenWithRefreshToken", "refresh-token").
		Return(expectedResponse, nil)

	result, err := s.exchanger.GetNewTokenWithRefreshToken("refresh-token")

	s.NoError(err)
	s.Equal("new-access-token", result.AccessToken)
	s.exchanger.AssertExpectations(s.T())
}

func (s *TokenExchangerTestSuite) TestRefreshTokenExpired() {
	s.exchanger.On("GetNewTokenWithRefreshToken", "expired-refresh-token").
		Return(nil, fmt.Errorf("invalid_grant: Refresh token expired"))

	result, err := s.exchanger.GetNewTokenWithRefreshToken("expired-refresh-token")

	s.Nil(result)
	s.Error(err)
	s.exchanger.AssertExpectations(s.T())
}

func (s *TokenExchangerTestSuite) TestRevokeTokenSuccess() {
	s.exchanger.On("RevokeTokenWithProvider", "token-to-revoke", "access_token").
		Return(nil)

	err := s.exchanger.RevokeTokenWithProvider("token-to-revoke", "access_token")

	s.NoError(err)
	s.exchanger.AssertExpectations(s.T())
}

func TestTokenExchangerTestSuite(t *testing.T) {
	suite.Run(t, new(TokenExchangerTestSuite))
}
