package fixtures

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenFixture(t *testing.T) {
	fixture, err := NewTokenFixture()

	require.NoError(t, err)
	assert.NotNil(t, fixture.RSAPrivateKey)
	assert.NotNil(t, fixture.RSAPublicKey)
	assert.NotNil(t, fixture.ECPrivateKey)
	assert.NotNil(t, fixture.ECPublicKey)
	assert.NotEmpty(t, fixture.KeyID)
	assert.NotEmpty(t, fixture.Issuer)
	assert.NotEmpty(t, fixture.Audience)
}

func TestDefaultClaims(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	claims := fixture.DefaultClaims()

	assert.Equal(t, fixture.Issuer, claims["iss"])
	assert.Equal(t, fixture.Audience, claims["aud"])
	assert.NotEmpty(t, claims["sub"])
	assert.NotEmpty(t, claims["email"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["nbf"])
	assert.NotEmpty(t, claims["jti"])
}

func TestValidToken(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	t.Run("creates valid JWT structure", func(t *testing.T) {
		token, err := fixture.ValidToken(nil)

		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// JWT has 3 parts
		parts := strings.Split(token, ".")
		assert.Len(t, parts, 3)
	})

	t.Run("applies claim overrides", func(t *testing.T) {
		token, err := fixture.ValidToken(map[string]interface{}{
			"email": "custom@example.com",
		})

		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestExpiredToken(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.ExpiredToken()

	require.NoError(t, err)
	assert.NotEmpty(t, token)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

func TestNotYetValidToken(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.NotYetValidToken()

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenWithSkew(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	t.Run("positive skew", func(t *testing.T) {
		token, err := fixture.TokenWithSkew(5 * time.Minute)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("negative skew", func(t *testing.T) {
		token, err := fixture.TokenWithSkew(-5 * time.Minute)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestTokenWithRoles(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithRoles([]string{"admin", "user"})

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenWithGroups(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithGroups([]string{"developers", "admins"})

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenWithEmail(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithEmail("custom@example.com")

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenWithAudience(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithAudience("custom-audience")

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenWithIssuer(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithIssuer("https://custom-issuer.com")

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestTokenMissingClaim(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	t.Run("missing single claim", func(t *testing.T) {
		token, err := fixture.TokenMissingClaim("email")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("missing multiple claims", func(t *testing.T) {
		token, err := fixture.TokenMissingClaim("email", "sub", "nonce")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestTokenWithCustomClaims(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithCustomClaims(map[string]interface{}{
		"custom_claim":  "custom_value",
		"another_claim": 123,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestMalformedToken(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token := fixture.MalformedToken()

	assert.Equal(t, "not.a.valid.jwt", token)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 4) // 4 parts instead of 3
}

func TestEmptyToken(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token := fixture.EmptyToken()

	assert.Empty(t, token)
}

func TestTokenWithWrongSignature(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	token, err := fixture.TokenWithWrongSignature()

	require.NoError(t, err)
	assert.NotEmpty(t, token)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

func TestGetJWKS(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	jwks := fixture.GetJWKS()

	assert.Contains(t, jwks, "keys")
	keys, ok := jwks["keys"].([]map[string]interface{})
	require.True(t, ok)
	assert.Len(t, keys, 1)

	key := keys[0]
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, fixture.KeyID, key["kid"])
	assert.NotEmpty(t, key["n"])
	assert.NotEmpty(t, key["e"])
}

func TestGetJWKSBytes(t *testing.T) {
	fixture, err := NewTokenFixture()
	require.NoError(t, err)

	jwksBytes, err := fixture.GetJWKSBytes()

	require.NoError(t, err)
	assert.NotEmpty(t, jwksBytes)
	assert.Contains(t, string(jwksBytes), "keys")
}
