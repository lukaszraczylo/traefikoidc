package traefikoidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeneratePKCEParameters tests the generatePKCEParameters method
func TestGeneratePKCEParameters(t *testing.T) {
	t.Run("PKCE enabled - successful generation", func(t *testing.T) {
		// Create a TraefikOidc instance with PKCE enabled
		plugin := &TraefikOidc{
			enablePKCE: true,
			logger:     NewLogger("debug"),
		}

		verifier, challenge, err := plugin.generatePKCEParameters()

		require.NoError(t, err)
		assert.NotEmpty(t, verifier, "code verifier should not be empty when PKCE is enabled")
		assert.NotEmpty(t, challenge, "code challenge should not be empty when PKCE is enabled")

		// Verify the challenge is derived from the verifier
		expectedChallenge := deriveCodeChallenge(verifier)
		assert.Equal(t, expectedChallenge, challenge, "challenge should match derived challenge from verifier")
	})

	t.Run("PKCE disabled - returns empty strings", func(t *testing.T) {
		// Create a TraefikOidc instance with PKCE disabled
		plugin := &TraefikOidc{
			enablePKCE: false,
			logger:     NewLogger("debug"),
		}

		verifier, challenge, err := plugin.generatePKCEParameters()

		require.NoError(t, err)
		assert.Empty(t, verifier, "code verifier should be empty when PKCE is disabled")
		assert.Empty(t, challenge, "code challenge should be empty when PKCE is disabled")
	})

	t.Run("PKCE enabled - generates different values each time", func(t *testing.T) {
		plugin := &TraefikOidc{
			enablePKCE: true,
			logger:     NewLogger("debug"),
		}

		verifier1, challenge1, err1 := plugin.generatePKCEParameters()
		require.NoError(t, err1)

		verifier2, challenge2, err2 := plugin.generatePKCEParameters()
		require.NoError(t, err2)

		assert.NotEqual(t, verifier1, verifier2, "verifiers should be different")
		assert.NotEqual(t, challenge1, challenge2, "challenges should be different")
	})

	t.Run("PKCE enabled - verifier and challenge relationship", func(t *testing.T) {
		plugin := &TraefikOidc{
			enablePKCE: true,
			logger:     NewLogger("debug"),
		}

		verifier, challenge, err := plugin.generatePKCEParameters()
		require.NoError(t, err)

		// The challenge should always be derivable from the verifier
		recalculatedChallenge := deriveCodeChallenge(verifier)
		assert.Equal(t, challenge, recalculatedChallenge,
			"challenge should always match the SHA256 hash of verifier")
	})

	t.Run("PKCE enabled - verifier meets RFC 7636 requirements", func(t *testing.T) {
		plugin := &TraefikOidc{
			enablePKCE: true,
			logger:     NewLogger("debug"),
		}

		verifier, _, err := plugin.generatePKCEParameters()
		require.NoError(t, err)

		// RFC 7636 requires verifier to be 43-128 characters
		assert.GreaterOrEqual(t, len(verifier), 43, "verifier should be at least 43 characters")
		assert.LessOrEqual(t, len(verifier), 128, "verifier should be at most 128 characters")
	})

	t.Run("PKCE enabled - challenge meets RFC 7636 requirements", func(t *testing.T) {
		plugin := &TraefikOidc{
			enablePKCE: true,
			logger:     NewLogger("debug"),
		}

		_, challenge, err := plugin.generatePKCEParameters()
		require.NoError(t, err)

		// SHA256 hash base64 encoded should be 43 characters
		assert.Equal(t, 43, len(challenge), "S256 challenge should be exactly 43 characters")
	})
}
