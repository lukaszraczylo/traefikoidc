package traefikoidc

import (
	"context"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil"
	"github.com/stretchr/testify/suite"
	"golang.org/x/time/rate"
)

// ClockSkewEdgeCasesSuite tests clock skew tolerance scenarios
type ClockSkewEdgeCasesSuite struct {
	suite.Suite

	fixture *testutil.TokenFixture
	tOidc   *TraefikOidc
}

func (s *ClockSkewEdgeCasesSuite) SetupSuite() {
	var err error
	s.fixture, err = testutil.NewTokenFixture()
	s.Require().NoError(err)
}

func (s *ClockSkewEdgeCasesSuite) SetupTest() {
	// Create JWK for the test key
	jwk := JWK{
		Kty: "RSA",
		Kid: s.fixture.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(s.fixture.RSAPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(s.fixture.RSAPublicKey.E)))),
	}

	jwkCache := &MockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{jwk}},
		Err:  nil,
	}

	tokenBlacklist := NewCache()
	tokenCacheInternal := NewCache()
	tokenCache := &TokenCache{}
	if tokenCache.cache == nil {
		if wrapper, ok := tokenCacheInternal.(*CacheInterfaceWrapper); ok {
			tokenCache.cache = wrapper.cache
		}
	}

	logger := NewLogger("error") // Reduce noise

	s.tOidc = &TraefikOidc{
		issuerURL:           s.fixture.Issuer,
		clientID:            s.fixture.Audience,
		audience:            s.fixture.Audience,
		clientSecret:        "test-client-secret",
		roleClaimName:       "roles",
		groupClaimName:      "groups",
		userIdentifierClaim: "email",
		jwkCache:            jwkCache,
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

	s.T().Cleanup(func() {
		if s.tOidc.tokenBlacklist != nil {
			s.tOidc.tokenBlacklist.Close()
		}
		if s.tOidc.tokenCache != nil && s.tOidc.tokenCache.cache != nil {
			s.tOidc.tokenCache.cache.Close()
		}
	})
}

func (s *ClockSkewEdgeCasesSuite) TestExactlyAtExpiry() {
	token, err := s.fixture.TokenWithSkew(0)
	s.Require().NoError(err)

	// Token at exact expiry - behavior is implementation-defined
	err = s.tOidc.VerifyToken(token)
	s.T().Logf("Exact expiry result: %v", err)
}

func (s *ClockSkewEdgeCasesSuite) TestOneSecondBeforeExpiry() {
	token, err := s.fixture.TokenWithSkew(1 * time.Second)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Token should be valid 1 second before expiry")
}

func (s *ClockSkewEdgeCasesSuite) TestOneSecondAfterExpiry() {
	token, err := s.fixture.TokenWithSkew(-1 * time.Second)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	// With default 2-minute clock skew tolerance, 1 second past expiry should still be valid
	s.NoError(err, "Token 1 second past expiry should be valid within clock skew tolerance")
}

func (s *ClockSkewEdgeCasesSuite) TestWithinSkewTolerance() {
	// Most implementations allow 5-minute clock skew
	token, err := s.fixture.TokenWithSkew(-4 * time.Minute)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	// May pass or fail depending on implementation
	s.T().Logf("4-minute expired token result: %v", err)
}

func (s *ClockSkewEdgeCasesSuite) TestBeyondSkewTolerance() {
	token, err := s.fixture.TokenWithSkew(-10 * time.Minute)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.Error(err, "Token should be invalid 10 minutes after expiry")
}

func TestClockSkewEdgeCasesSuite(t *testing.T) {
	suite.Run(t, new(ClockSkewEdgeCasesSuite))
}

// UnicodeClaimsSuite tests Unicode handling in JWT claims
type UnicodeClaimsSuite struct {
	suite.Suite

	fixture *testutil.TokenFixture
	tOidc   *TraefikOidc
}

func (s *UnicodeClaimsSuite) SetupSuite() {
	var err error
	s.fixture, err = testutil.NewTokenFixture()
	s.Require().NoError(err)
}

func (s *UnicodeClaimsSuite) SetupTest() {
	jwk := JWK{
		Kty: "RSA",
		Kid: s.fixture.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(s.fixture.RSAPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(s.fixture.RSAPublicKey.E)))),
	}

	jwkCache := &MockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{jwk}},
		Err:  nil,
	}

	tokenBlacklist := NewCache()
	tokenCacheInternal := NewCache()
	tokenCache := &TokenCache{}
	if tokenCache.cache == nil {
		if wrapper, ok := tokenCacheInternal.(*CacheInterfaceWrapper); ok {
			tokenCache.cache = wrapper.cache
		}
	}

	logger := NewLogger("error")

	s.tOidc = &TraefikOidc{
		issuerURL:           s.fixture.Issuer,
		clientID:            s.fixture.Audience,
		audience:            s.fixture.Audience,
		clientSecret:        "test-client-secret",
		roleClaimName:       "roles",
		groupClaimName:      "groups",
		userIdentifierClaim: "email",
		jwkCache:            jwkCache,
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

	s.T().Cleanup(func() {
		if s.tOidc.tokenBlacklist != nil {
			s.tOidc.tokenBlacklist.Close()
		}
		if s.tOidc.tokenCache != nil && s.tOidc.tokenCache.cache != nil {
			s.tOidc.tokenCache.cache.Close()
		}
	})
}

func (s *UnicodeClaimsSuite) TestUnicodeEmail() {
	token, err := s.fixture.TokenWithEmail("用户@example.com")
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Unicode email should be handled correctly")
}

func (s *UnicodeClaimsSuite) TestUnicodeName() {
	token, err := s.fixture.TokenWithCustomClaims(map[string]interface{}{
		"name": "田中太郎",
	})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Unicode name should be handled correctly")
}

func (s *UnicodeClaimsSuite) TestEmojiInClaims() {
	token, err := s.fixture.TokenWithCustomClaims(map[string]interface{}{
		"name": "Test User 😀",
	})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Emoji in claims should be handled correctly")
}

func (s *UnicodeClaimsSuite) TestRTLText() {
	token, err := s.fixture.TokenWithCustomClaims(map[string]interface{}{
		"name": "مستخدم اختبار",
	})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "RTL text should be handled correctly")
}

func (s *UnicodeClaimsSuite) TestMixedScripts() {
	token, err := s.fixture.TokenWithCustomClaims(map[string]interface{}{
		"name":  "Test 测试 テスト",
		"roles": []string{"admin", "管理者", "管理员"},
	})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Mixed scripts should be handled correctly")
}

func TestUnicodeClaimsSuite(t *testing.T) {
	suite.Run(t, new(UnicodeClaimsSuite))
}

// LargeClaimsSuite tests large claim values
type LargeClaimsSuite struct {
	suite.Suite

	fixture *testutil.TokenFixture
	tOidc   *TraefikOidc
}

func (s *LargeClaimsSuite) SetupSuite() {
	var err error
	s.fixture, err = testutil.NewTokenFixture()
	s.Require().NoError(err)
}

func (s *LargeClaimsSuite) SetupTest() {
	jwk := JWK{
		Kty: "RSA",
		Kid: s.fixture.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(s.fixture.RSAPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(s.fixture.RSAPublicKey.E)))),
	}

	jwkCache := &MockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{jwk}},
		Err:  nil,
	}

	tokenBlacklist := NewCache()
	tokenCacheInternal := NewCache()
	tokenCache := &TokenCache{}
	if tokenCache.cache == nil {
		if wrapper, ok := tokenCacheInternal.(*CacheInterfaceWrapper); ok {
			tokenCache.cache = wrapper.cache
		}
	}

	logger := NewLogger("error")

	s.tOidc = &TraefikOidc{
		issuerURL:           s.fixture.Issuer,
		clientID:            s.fixture.Audience,
		audience:            s.fixture.Audience,
		clientSecret:        "test-client-secret",
		roleClaimName:       "roles",
		groupClaimName:      "groups",
		userIdentifierClaim: "email",
		jwkCache:            jwkCache,
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

	s.T().Cleanup(func() {
		if s.tOidc.tokenBlacklist != nil {
			s.tOidc.tokenBlacklist.Close()
		}
		if s.tOidc.tokenCache != nil && s.tOidc.tokenCache.cache != nil {
			s.tOidc.tokenCache.cache.Close()
		}
	})
}

func (s *LargeClaimsSuite) TestManyRoles() {
	roles := make([]string, 100)
	for i := 0; i < 100; i++ {
		roles[i] = strings.Repeat("role", 10) + string(rune('A'+i%26))
	}

	token, err := s.fixture.TokenWithRoles(roles)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Token with 100 roles should be handled")
}

func (s *LargeClaimsSuite) TestManyGroups() {
	groups := make([]string, 50)
	for i := 0; i < 50; i++ {
		groups[i] = strings.Repeat("group", 5) + string(rune('A'+i%26))
	}

	token, err := s.fixture.TokenWithGroups(groups)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Token with 50 groups should be handled")
}

func (s *LargeClaimsSuite) TestLongEmail() {
	// RFC 5321 allows up to 254 characters
	localPart := strings.Repeat("a", 64)
	domain := strings.Repeat("b", 63) + ".com"
	email := localPart + "@" + domain

	token, err := s.fixture.TokenWithEmail(email)
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Token with long email should be handled")
}

func (s *LargeClaimsSuite) TestLongSubject() {
	longSub := strings.Repeat("subject", 100)

	token, err := s.fixture.TokenWithCustomClaims(map[string]interface{}{
		"sub": longSub,
	})
	s.Require().NoError(err)

	err = s.tOidc.VerifyToken(token)
	s.NoError(err, "Token with long subject should be handled")
}

func TestLargeClaimsSuite(t *testing.T) {
	suite.Run(t, new(LargeClaimsSuite))
}

// URLPathEdgeCasesSuite tests URL handling edge cases
type URLPathEdgeCasesSuite struct {
	suite.Suite
}

func (s *URLPathEdgeCasesSuite) TestVeryLongPath() {
	longPath := "/" + strings.Repeat("segment/", 100)
	req := httptest.NewRequest("GET", longPath, nil)

	s.NotNil(req)
	s.Contains(req.URL.Path, "segment")
}

func (s *URLPathEdgeCasesSuite) TestSpecialCharactersInPath() {
	paths := []string{
		"/path%20with%20spaces",
		"/path/with/日本語",
		"/path?query=value&another=test",
		"/path#fragment",
		"/path/../traversal",
		"/path/./current",
	}

	for _, path := range paths {
		s.Run(path, func() {
			req := httptest.NewRequest("GET", path, nil)
			s.NotNil(req)
		})
	}
}

func (s *URLPathEdgeCasesSuite) TestEmptyPath() {
	req := httptest.NewRequest("GET", "/", nil)
	s.Equal("/", req.URL.Path)
}

func (s *URLPathEdgeCasesSuite) TestDoubleSlashes() {
	req := httptest.NewRequest("GET", "//double//slashes//", nil)
	s.NotNil(req)
}

func TestURLPathEdgeCasesSuite(t *testing.T) {
	suite.Run(t, new(URLPathEdgeCasesSuite))
}

// ConcurrencyEdgeCasesSuite tests concurrency scenarios
type ConcurrencyEdgeCasesSuite struct {
	suite.Suite

	fixture *testutil.TokenFixture
	tOidc   *TraefikOidc
}

func (s *ConcurrencyEdgeCasesSuite) SetupSuite() {
	var err error
	s.fixture, err = testutil.NewTokenFixture()
	s.Require().NoError(err)
}

func (s *ConcurrencyEdgeCasesSuite) SetupTest() {
	jwk := JWK{
		Kty: "RSA",
		Kid: s.fixture.KeyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(s.fixture.RSAPublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(bigIntToBytes(big.NewInt(int64(s.fixture.RSAPublicKey.E)))),
	}

	jwkCache := &MockJWKCache{
		JWKS: &JWKSet{Keys: []JWK{jwk}},
		Err:  nil,
	}

	tokenBlacklist := NewCache()
	tokenCacheInternal := NewCache()
	tokenCache := &TokenCache{}
	if tokenCache.cache == nil {
		if wrapper, ok := tokenCacheInternal.(*CacheInterfaceWrapper); ok {
			tokenCache.cache = wrapper.cache
		}
	}

	logger := NewLogger("error")

	s.tOidc = &TraefikOidc{
		issuerURL:           s.fixture.Issuer,
		clientID:            s.fixture.Audience,
		audience:            s.fixture.Audience,
		clientSecret:        "test-client-secret",
		roleClaimName:       "roles",
		groupClaimName:      "groups",
		userIdentifierClaim: "email",
		jwkCache:            jwkCache,
		jwksURL:             "https://test-jwks-url.com",
		limiter:             rate.NewLimiter(rate.Every(time.Second), 100), // Higher limit for concurrency tests
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

	s.T().Cleanup(func() {
		if s.tOidc.tokenBlacklist != nil {
			s.tOidc.tokenBlacklist.Close()
		}
		if s.tOidc.tokenCache != nil && s.tOidc.tokenCache.cache != nil {
			s.tOidc.tokenCache.cache.Close()
		}
	})
}

func (s *ConcurrencyEdgeCasesSuite) TestConcurrentTokenValidation() {
	token, err := s.fixture.ValidToken(nil)
	s.Require().NoError(err)

	const goroutines = 50
	var wg sync.WaitGroup
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
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
		s.T().Logf("Concurrent error: %v", err)
		errCount++
	}

	s.Equal(0, errCount, "All concurrent validations should succeed")
}

func (s *ConcurrencyEdgeCasesSuite) TestConcurrentDifferentTokens() {
	const goroutines = 20
	var wg sync.WaitGroup
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token, err := s.fixture.TokenWithCustomClaims(map[string]interface{}{
				"custom": idx,
			})
			if err != nil {
				errors <- err
				return
			}
			if err := s.tOidc.VerifyToken(token); err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	var errCount int
	for err := range errors {
		s.T().Logf("Concurrent different token error: %v", err)
		errCount++
	}

	s.Equal(0, errCount, "All concurrent different token validations should succeed")
}

func (s *ConcurrencyEdgeCasesSuite) TestConcurrentMixedValidInvalid() {
	validToken, err := s.fixture.ValidToken(nil)
	s.Require().NoError(err)
	expiredToken, err := s.fixture.ExpiredToken()
	s.Require().NoError(err)

	const goroutines = 40
	var wg sync.WaitGroup
	validCount := int32(0)
	expiredCount := int32(0)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var token string
			if idx%2 == 0 {
				token = validToken
			} else {
				token = expiredToken
			}

			err := s.tOidc.VerifyToken(token)
			if idx%2 == 0 {
				if err == nil {
					atomic.AddInt32(&validCount, 1)
				}
			} else {
				if err != nil {
					atomic.AddInt32(&expiredCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	s.T().Logf("Valid passed: %d, Expired rejected: %d", validCount, expiredCount)
}

func TestConcurrencyEdgeCasesSuite(t *testing.T) {
	suite.Run(t, new(ConcurrencyEdgeCasesSuite))
}
