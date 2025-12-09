package traefikoidc

import (
	"context"
	"testing"

	"github.com/lukaszraczylo/traefikoidc/internal/testutil"
	"github.com/lukaszraczylo/traefikoidc/internal/testutil/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// ExampleTestSuite demonstrates the new testify suite pattern
type ExampleTestSuite struct {
	suite.Suite

	fixture    *testutil.TokenFixture
	oidcServer *testutil.OIDCServer
	jwkCache   *mocks.JWKCache
}

func (s *ExampleTestSuite) SetupSuite() {
	var err error
	s.fixture, err = testutil.NewTokenFixture()
	s.Require().NoError(err)
}

func (s *ExampleTestSuite) SetupTest() {
	config := testutil.DefaultServerConfig()
	config.TokenFixture = s.fixture
	s.oidcServer = testutil.NewOIDCServer(config)

	s.jwkCache = testutil.NewJWKCacheMock()
}

func (s *ExampleTestSuite) TearDownTest() {
	if s.oidcServer != nil {
		s.oidcServer.Close()
	}
}

func (s *ExampleTestSuite) TestValidTokenCreation() {
	token, err := s.fixture.ValidToken(nil)

	s.NoError(err)
	s.NotEmpty(token)
}

func (s *ExampleTestSuite) TestTokenWithCustomClaims() {
	token, err := s.fixture.ValidToken(map[string]interface{}{
		"email": "custom@example.com",
		"roles": []string{"admin", "user"},
	})

	s.NoError(err)
	s.NotEmpty(token)
}

func (s *ExampleTestSuite) TestExpiredToken() {
	token, err := s.fixture.ExpiredToken()

	s.NoError(err)
	s.NotEmpty(token)
}

func (s *ExampleTestSuite) TestMockJWKCache() {
	expectedJWKS := s.fixture.GetJWKS()
	jwksSet := &mocks.JWKSet{
		Keys: []mocks.JWK{{Kty: "RSA", Kid: s.fixture.KeyID}},
	}

	s.jwkCache.On("GetJWKS", mock.Anything, mock.Anything, mock.Anything).
		Return(jwksSet, nil)

	result, err := s.jwkCache.GetJWKS(context.Background(), s.oidcServer.URL+"/jwks", nil)

	s.NoError(err)
	s.NotNil(result)
	s.jwkCache.AssertExpectations(s.T())

	// Verify the JWKS has expected structure
	s.NotNil(expectedJWKS["keys"])
}

func (s *ExampleTestSuite) TestOIDCServerDiscovery() {
	// The OIDC server provides all standard endpoints
	s.NotEmpty(s.oidcServer.URL)

	// Server URL is used as issuer
	s.Equal(s.oidcServer.URL, s.oidcServer.Config.Issuer)
}

func TestExampleTestSuite(t *testing.T) {
	suite.Run(t, new(ExampleTestSuite))
}

// TestNewMocksWork verifies the new mock types work correctly
func TestNewMocksWork(t *testing.T) {
	t.Run("JWKCache mock", func(t *testing.T) {
		m := testutil.NewJWKCacheMock()
		m.On("GetJWKS", mock.Anything, mock.Anything, mock.Anything).
			Return(&mocks.JWKSet{Keys: []mocks.JWK{{Kty: "RSA"}}}, nil)

		result, err := m.GetJWKS(context.Background(), "https://example.com/jwks", nil)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Keys, 1)
		m.AssertExpectations(t)
	})

	t.Run("TokenExchanger mock", func(t *testing.T) {
		m := testutil.NewTokenExchangerMock()
		m.On("ExchangeCodeForToken", mock.Anything, "authorization_code", "test-code", mock.Anything, mock.Anything).
			Return(&mocks.TokenResponse{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token",
				IDToken:      "id-token",
				ExpiresIn:    3600,
			}, nil)

		result, err := m.ExchangeCodeForToken(context.Background(), "authorization_code", "test-code", "https://example.com/callback", "")

		require.NoError(t, err)
		assert.Equal(t, "access-token", result.AccessToken)
		m.AssertExpectations(t)
	})

	t.Run("TokenVerifier mock", func(t *testing.T) {
		m := testutil.NewTokenVerifierMock()
		m.On("VerifyToken", "valid-token").Return(nil)

		err := m.VerifyToken("valid-token")

		assert.NoError(t, err)
		m.AssertExpectations(t)
	})

	t.Run("Cache mock", func(t *testing.T) {
		m := testutil.NewCacheMock()
		m.On("Get", "key").Return("value", true)
		m.On("Set", "key2", "value2").Return()

		result, found := m.Get("key")
		assert.True(t, found)
		assert.Equal(t, "value", result)

		m.Set("key2", "value2")
		m.AssertExpectations(t)
	})
}

// TestOIDCServerConfigurations verifies different server configurations
func TestOIDCServerConfigurations(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		server := testutil.NewOIDCServer(nil)
		defer server.Close()

		assert.NotEmpty(t, server.URL)
		assert.Contains(t, server.Config.ScopesSupported, "openid")
	})

	t.Run("google config", func(t *testing.T) {
		config := testutil.GoogleServerConfig()
		assert.Equal(t, "https://accounts.google.com", config.Issuer)
		assert.NotContains(t, config.ScopesSupported, "offline_access")
	})

	t.Run("azure config", func(t *testing.T) {
		config := testutil.AzureServerConfig()
		assert.Contains(t, config.Issuer, "microsoftonline.com")
		assert.Contains(t, config.ScopesSupported, "offline_access")
	})

	t.Run("auth0 config", func(t *testing.T) {
		config := testutil.Auth0ServerConfig()
		assert.Contains(t, config.ScopesSupported, "offline_access")
	})

	t.Run("keycloak config", func(t *testing.T) {
		config := testutil.KeycloakServerConfig()
		assert.Contains(t, config.ScopesSupported, "roles")
		assert.Contains(t, config.ScopesSupported, "groups")
	})
}

// TestTokenFixtureVariants tests various token generation scenarios
func TestTokenFixtureVariants(t *testing.T) {
	fixture, err := testutil.NewTokenFixture()
	require.NoError(t, err)

	t.Run("valid token", func(t *testing.T) {
		token, err := fixture.ValidToken(nil)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("token with roles", func(t *testing.T) {
		token, err := fixture.TokenWithRoles([]string{"admin", "user"})
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("token with groups", func(t *testing.T) {
		token, err := fixture.TokenWithGroups([]string{"developers"})
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("expired token", func(t *testing.T) {
		token, err := fixture.ExpiredToken()
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("token missing claims", func(t *testing.T) {
		token, err := fixture.TokenMissingClaim("email", "sub")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("malformed token", func(t *testing.T) {
		token := fixture.MalformedToken()
		assert.Equal(t, "not.a.valid.jwt", token)
	})

	t.Run("JWKS generation", func(t *testing.T) {
		jwks := fixture.GetJWKS()
		assert.Contains(t, jwks, "keys")
	})
}
