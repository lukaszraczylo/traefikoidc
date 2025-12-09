package testutil

import (
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil/fixtures"
	"github.com/lukaszraczylo/traefikoidc/internal/testutil/mocks"
	"github.com/lukaszraczylo/traefikoidc/internal/testutil/servers"
)

// Re-export types for easier access from main package tests
type (
	// Mocks
	JWKCacheMock       = mocks.JWKCache
	TokenExchangerMock = mocks.TokenExchanger
	TokenVerifierMock  = mocks.TokenVerifier
	JWTVerifierMock    = mocks.JWTVerifier
	SessionManagerMock = mocks.SessionManager
	CacheMock          = mocks.Cache
	TokenCacheMock     = mocks.TokenCache
	BlacklistMock      = mocks.Blacklist
	HTTPClientMock     = mocks.HTTPClient
	RoundTripperMock   = mocks.RoundTripper
	LoggerMock         = mocks.Logger

	// Mock types
	JWKSet            = mocks.JWKSet
	JWK               = mocks.JWK
	MockTokenResponse = mocks.TokenResponse
	MockSessionData   = mocks.SessionData
	IntrospectionResp = mocks.IntrospectionResponse

	// Fixtures
	TokenFixture = fixtures.TokenFixture

	// Servers
	OIDCServer       = servers.OIDCServer
	OIDCServerConfig = servers.OIDCServerConfig
	OIDCError        = servers.OIDCError
)

// NewJWKCacheMock creates a new JWK cache mock
func NewJWKCacheMock() *mocks.JWKCache {
	return new(mocks.JWKCache)
}

// NewTokenExchangerMock creates a new token exchanger mock
func NewTokenExchangerMock() *mocks.TokenExchanger {
	return new(mocks.TokenExchanger)
}

// NewTokenVerifierMock creates a new token verifier mock
func NewTokenVerifierMock() *mocks.TokenVerifier {
	return new(mocks.TokenVerifier)
}

// NewJWTVerifierMock creates a new JWT verifier mock
func NewJWTVerifierMock() *mocks.JWTVerifier {
	return new(mocks.JWTVerifier)
}

// NewSessionManagerMock creates a new session manager mock
func NewSessionManagerMock() *mocks.SessionManager {
	return new(mocks.SessionManager)
}

// NewCacheMock creates a new cache mock
func NewCacheMock() *mocks.Cache {
	return new(mocks.Cache)
}

// NewTokenCacheMock creates a new token cache mock
func NewTokenCacheMock() *mocks.TokenCache {
	return new(mocks.TokenCache)
}

// NewBlacklistMock creates a new blacklist mock
func NewBlacklistMock() *mocks.Blacklist {
	return new(mocks.Blacklist)
}

// NewHTTPClientMock creates a new HTTP client mock
func NewHTTPClientMock() *mocks.HTTPClient {
	return new(mocks.HTTPClient)
}

// NewRoundTripperMock creates a new round tripper mock
func NewRoundTripperMock() *mocks.RoundTripper {
	return new(mocks.RoundTripper)
}

// NewLoggerMock creates a new logger mock
func NewLoggerMock() *mocks.Logger {
	return new(mocks.Logger)
}

// NewTokenFixture creates a new token fixture
func NewTokenFixture() (*fixtures.TokenFixture, error) {
	return fixtures.NewTokenFixture()
}

// NewOIDCServer creates a new mock OIDC server
func NewOIDCServer(config *servers.OIDCServerConfig) *servers.OIDCServer {
	return servers.NewOIDCServer(config)
}

// DefaultServerConfig returns a default server configuration
func DefaultServerConfig() *servers.OIDCServerConfig {
	return servers.DefaultConfig()
}

// GoogleServerConfig returns a Google-like server configuration
func GoogleServerConfig() *servers.OIDCServerConfig {
	return servers.GoogleConfig()
}

// AzureServerConfig returns an Azure AD-like server configuration
func AzureServerConfig() *servers.OIDCServerConfig {
	return servers.AzureConfig()
}

// Auth0ServerConfig returns an Auth0-like server configuration
func Auth0ServerConfig() *servers.OIDCServerConfig {
	return servers.Auth0Config()
}

// KeycloakServerConfig returns a Keycloak-like server configuration
func KeycloakServerConfig() *servers.OIDCServerConfig {
	return servers.KeycloakConfig()
}

// SlowServerConfig returns a configuration with delays
func SlowServerConfig(delay time.Duration) *servers.OIDCServerConfig {
	return servers.SlowServerConfig(delay)
}

// RateLimitedServerConfig returns a rate-limited configuration
func RateLimitedServerConfig(afterN int) *servers.OIDCServerConfig {
	return servers.RateLimitedConfig(afterN)
}
