package traefikoidc

import (
	"context"
	"net/http"
	"time"

	"github.com/stretchr/testify/mock"
)

// TestifyJWKCache is a testify mock implementing JWKCacheInterface
type TestifyJWKCache struct {
	mock.Mock
}

// GetJWKS implements JWKCacheInterface
func (m *TestifyJWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	args := m.Called(ctx, jwksURL, httpClient)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*JWKSet), args.Error(1)
}

// Cleanup implements JWKCacheInterface
func (m *TestifyJWKCache) Cleanup() {
	m.Called()
}

// Close implements JWKCacheInterface
func (m *TestifyJWKCache) Close() {
	m.Called()
}

// TestifyTokenVerifier is a testify mock implementing TokenVerifier
type TestifyTokenVerifier struct {
	mock.Mock
}

// VerifyToken implements TokenVerifier
func (m *TestifyTokenVerifier) VerifyToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

// TestifyJWTVerifier is a testify mock implementing JWTVerifier
type TestifyJWTVerifier struct {
	mock.Mock
}

// VerifyJWTSignatureAndClaims implements JWTVerifier
func (m *TestifyJWTVerifier) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	args := m.Called(jwt, token)
	return args.Error(0)
}

// TestifyTokenExchanger is a testify mock implementing TokenExchanger
type TestifyTokenExchanger struct {
	mock.Mock
}

// ExchangeCodeForToken implements TokenExchanger
func (m *TestifyTokenExchanger) ExchangeCodeForToken(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	args := m.Called(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenResponse), args.Error(1)
}

// GetNewTokenWithRefreshToken implements TokenExchanger
func (m *TestifyTokenExchanger) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	args := m.Called(refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenResponse), args.Error(1)
}

// RevokeTokenWithProvider implements TokenExchanger
func (m *TestifyTokenExchanger) RevokeTokenWithProvider(token, tokenType string) error {
	args := m.Called(token, tokenType)
	return args.Error(0)
}

// TestifyCacheInterface is a testify mock implementing CacheInterface
type TestifyCacheInterface struct {
	mock.Mock
}

// Set implements CacheInterface
func (m *TestifyCacheInterface) Set(key string, value any, ttl time.Duration) {
	m.Called(key, value, ttl)
}

// Get implements CacheInterface
func (m *TestifyCacheInterface) Get(key string) (any, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}

// Delete implements CacheInterface
func (m *TestifyCacheInterface) Delete(key string) {
	m.Called(key)
}

// SetMaxSize implements CacheInterface
func (m *TestifyCacheInterface) SetMaxSize(size int) {
	m.Called(size)
}

// Size implements CacheInterface
func (m *TestifyCacheInterface) Size() int {
	args := m.Called()
	return args.Int(0)
}

// Clear implements CacheInterface
func (m *TestifyCacheInterface) Clear() {
	m.Called()
}

// Cleanup implements CacheInterface
func (m *TestifyCacheInterface) Cleanup() {
	m.Called()
}

// Close implements CacheInterface
func (m *TestifyCacheInterface) Close() {
	m.Called()
}

// GetStats implements CacheInterface
func (m *TestifyCacheInterface) GetStats() map[string]any {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(map[string]any)
}

// TestifyHTTPClient is a testify mock for http.Client
type TestifyHTTPClient struct {
	mock.Mock
}

// Do implements a mock HTTP client's Do method
func (m *TestifyHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

// TestifyRoundTripper is a testify mock for http.RoundTripper
type TestifyRoundTripper struct {
	mock.Mock
}

// RoundTrip implements http.RoundTripper
func (m *TestifyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}
