package mocks

import (
	"context"
	"net/http"

	"github.com/stretchr/testify/mock"
)

// JWKSet represents a JSON Web Key Set for testing
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key for testing
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// TokenResponse represents an OAuth token response for testing
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IntrospectionResponse represents a token introspection response
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

// JWKCache is a testify mock for JWK caching operations
type JWKCache struct {
	mock.Mock
}

// GetJWKS retrieves a JWKS from the cache or fetches it
func (m *JWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	args := m.Called(ctx, jwksURL, httpClient)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*JWKSet), args.Error(1)
}

// Close cleans up the cache
func (m *JWKCache) Close() {
	m.Called()
}

// Cleanup performs periodic cleanup
func (m *JWKCache) Cleanup() {
	m.Called()
}

// TokenExchanger is a testify mock for token exchange operations
type TokenExchanger struct {
	mock.Mock
}

// ExchangeCodeForToken exchanges an authorization code for tokens
func (m *TokenExchanger) ExchangeCodeForToken(ctx context.Context, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	args := m.Called(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenResponse), args.Error(1)
}

// GetNewTokenWithRefreshToken refreshes an access token
func (m *TokenExchanger) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	args := m.Called(refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenResponse), args.Error(1)
}

// RevokeTokenWithProvider revokes a token
func (m *TokenExchanger) RevokeTokenWithProvider(token, tokenType string) error {
	args := m.Called(token, tokenType)
	return args.Error(0)
}

// TokenVerifier is a testify mock for token verification
type TokenVerifier struct {
	mock.Mock
}

// VerifyToken verifies a JWT token
func (m *TokenVerifier) VerifyToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

// JWTVerifier is a testify mock for JWT verification
type JWTVerifier struct {
	mock.Mock
}

// VerifyJWT verifies a JWT and returns claims
func (m *JWTVerifier) VerifyJWT(token string) (map[string]interface{}, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

// HTTPClient is a testify mock for HTTP client operations
type HTTPClient struct {
	mock.Mock
}

// Do executes an HTTP request
func (m *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

// RoundTripper is a testify mock for HTTP transport
type RoundTripper struct {
	mock.Mock
}

// RoundTrip executes a single HTTP transaction
func (m *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

// Logger is a testify mock for logging operations
type Logger struct {
	mock.Mock
}

// Debug logs a debug message
func (m *Logger) Debug(msg string) {
	m.Called(msg)
}

// Debugf logs a formatted debug message
func (m *Logger) Debugf(format string, args ...interface{}) {
	m.Called(format, args)
}

// Info logs an info message
func (m *Logger) Info(msg string) {
	m.Called(msg)
}

// Infof logs a formatted info message
func (m *Logger) Infof(format string, args ...interface{}) {
	m.Called(format, args)
}

// Error logs an error message
func (m *Logger) Error(msg string) {
	m.Called(msg)
}

// Errorf logs a formatted error message
func (m *Logger) Errorf(format string, args ...interface{}) {
	m.Called(format, args)
}

// Warn logs a warning message
func (m *Logger) Warn(msg string) {
	m.Called(msg)
}

// Warnf logs a formatted warning message
func (m *Logger) Warnf(format string, args ...interface{}) {
	m.Called(format, args)
}
