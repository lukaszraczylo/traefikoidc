package traefikoidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateCodeVerifier tests the PKCE code verifier generation
func TestGenerateCodeVerifier(t *testing.T) {
	t.Run("basic generation", func(t *testing.T) {
		verifier, err := generateCodeVerifier()

		require.NoError(t, err)
		assert.NotEmpty(t, verifier)

		// RFC 7636 requires 43-128 characters for code verifier
		// With 32 bytes base64 raw URL encoded, we get 43 characters
		assert.Len(t, verifier, 43, "code verifier should be 43 characters (32 bytes base64 encoded)")
	})

	t.Run("verifier is base64 URL encoded", func(t *testing.T) {
		verifier, err := generateCodeVerifier()

		require.NoError(t, err)

		// Should be valid base64 URL encoding
		_, err = base64.RawURLEncoding.DecodeString(verifier)
		assert.NoError(t, err, "verifier should be valid base64 URL encoding")
	})

	t.Run("multiple generations produce different values", func(t *testing.T) {
		verifier1, err1 := generateCodeVerifier()
		verifier2, err2 := generateCodeVerifier()

		require.NoError(t, err1)
		require.NoError(t, err2)

		assert.NotEqual(t, verifier1, verifier2, "consecutive generations should produce different verifiers")
	})

	t.Run("verifier contains only URL-safe characters", func(t *testing.T) {
		verifier, err := generateCodeVerifier()

		require.NoError(t, err)

		// Base64 URL encoding should only contain A-Z, a-z, 0-9, -, _
		for _, char := range verifier {
			validChar := (char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') ||
				char == '-' || char == '_'
			assert.True(t, validChar, "verifier should only contain URL-safe characters")
		}
	})

	t.Run("no padding characters", func(t *testing.T) {
		verifier, err := generateCodeVerifier()

		require.NoError(t, err)

		// Raw URL encoding should not have padding
		assert.False(t, strings.Contains(verifier, "="), "verifier should not contain padding")
	})
}

// TestDeriveCodeChallenge tests the PKCE code challenge derivation
func TestDeriveCodeChallenge(t *testing.T) {
	t.Run("basic derivation", func(t *testing.T) {
		verifier := "test-verifier-value-1234567890abcdefghij"
		challenge := deriveCodeChallenge(verifier)

		assert.NotEmpty(t, challenge)
		assert.NotEqual(t, verifier, challenge, "challenge should be different from verifier")
	})

	t.Run("challenge is SHA256 hash", func(t *testing.T) {
		verifier := "test-code-verifier"

		// Manually compute expected challenge
		hasher := sha256.New()
		hasher.Write([]byte(verifier))
		expectedHash := hasher.Sum(nil)
		expectedChallenge := base64.RawURLEncoding.EncodeToString(expectedHash)

		challenge := deriveCodeChallenge(verifier)

		assert.Equal(t, expectedChallenge, challenge, "challenge should match SHA256 hash")
	})

	t.Run("same verifier produces same challenge", func(t *testing.T) {
		verifier := "consistent-verifier-12345"

		challenge1 := deriveCodeChallenge(verifier)
		challenge2 := deriveCodeChallenge(verifier)

		assert.Equal(t, challenge1, challenge2, "same verifier should always produce same challenge")
	})

	t.Run("different verifiers produce different challenges", func(t *testing.T) {
		verifier1 := "verifier-one"
		verifier2 := "verifier-two"

		challenge1 := deriveCodeChallenge(verifier1)
		challenge2 := deriveCodeChallenge(verifier2)

		assert.NotEqual(t, challenge1, challenge2, "different verifiers should produce different challenges")
	})

	t.Run("challenge is base64 URL encoded", func(t *testing.T) {
		verifier := "test-verifier"
		challenge := deriveCodeChallenge(verifier)

		// Should be valid base64 URL encoding
		_, err := base64.RawURLEncoding.DecodeString(challenge)
		assert.NoError(t, err, "challenge should be valid base64 URL encoding")
	})

	t.Run("challenge length is correct", func(t *testing.T) {
		verifier := "some-random-verifier"
		challenge := deriveCodeChallenge(verifier)

		// SHA256 produces 32 bytes, which when base64 encoded becomes 43 characters
		assert.Len(t, challenge, 43, "SHA256 hash should produce 43-character base64 string")
	})

	t.Run("no padding in challenge", func(t *testing.T) {
		verifier := "test-verifier-no-padding"
		challenge := deriveCodeChallenge(verifier)

		assert.False(t, strings.Contains(challenge, "="), "challenge should not contain padding")
	})

	t.Run("empty verifier produces valid challenge", func(t *testing.T) {
		verifier := ""
		challenge := deriveCodeChallenge(verifier)

		assert.NotEmpty(t, challenge, "even empty verifier should produce a challenge")
		assert.Len(t, challenge, 43, "challenge should still be 43 characters")
	})
}

// TestPKCEFlowIntegration tests the complete PKCE flow
func TestPKCEFlowIntegration(t *testing.T) {
	t.Run("complete PKCE flow", func(t *testing.T) {
		// Step 1: Generate code verifier
		verifier, err := generateCodeVerifier()
		require.NoError(t, err)

		// Step 2: Derive code challenge
		challenge := deriveCodeChallenge(verifier)

		// Verify challenge was derived from verifier
		expectedChallenge := deriveCodeChallenge(verifier)
		assert.Equal(t, expectedChallenge, challenge)

		// Verify verifier can be used to recreate challenge
		rechallenge := deriveCodeChallenge(verifier)
		assert.Equal(t, challenge, rechallenge, "verifier should consistently produce same challenge")
	})

	t.Run("multiple PKCE flows are independent", func(t *testing.T) {
		// Flow 1
		verifier1, err1 := generateCodeVerifier()
		require.NoError(t, err1)
		challenge1 := deriveCodeChallenge(verifier1)

		// Flow 2
		verifier2, err2 := generateCodeVerifier()
		require.NoError(t, err2)
		challenge2 := deriveCodeChallenge(verifier2)

		// Flows should be independent
		assert.NotEqual(t, verifier1, verifier2)
		assert.NotEqual(t, challenge1, challenge2)

		// Each flow should be internally consistent
		assert.Equal(t, challenge1, deriveCodeChallenge(verifier1))
		assert.Equal(t, challenge2, deriveCodeChallenge(verifier2))
	})

	t.Run("RFC 7636 compliance", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		require.NoError(t, err)

		challenge := deriveCodeChallenge(verifier)

		// RFC 7636 Section 4.2:
		// - code_verifier: high-entropy cryptographic random string
		// - Minimum length: 43 characters
		// - Maximum length: 128 characters
		// - Character set: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
		assert.GreaterOrEqual(t, len(verifier), 43, "verifier should be at least 43 characters")
		assert.LessOrEqual(t, len(verifier), 128, "verifier should be at most 128 characters")

		// RFC 7636 Section 4.2:
		// - code_challenge = BASE64URL(SHA256(code_verifier))
		assert.NotEmpty(t, challenge)
		assert.Len(t, challenge, 43, "S256 challenge should be 43 characters")
	})
}

// TestTokenCacheCleanupAndClose tests the no-op Cleanup and Close methods
func TestTokenCacheCleanupAndClose(t *testing.T) {
	cache := NewTokenCache()
	require.NotNil(t, cache)

	t.Run("cleanup is safe to call", func(t *testing.T) {
		// Should not panic
		assert.NotPanics(t, func() {
			cache.Cleanup()
		})
	})

	t.Run("close is safe to call", func(t *testing.T) {
		// Should not panic
		assert.NotPanics(t, func() {
			cache.Close()
		})
	})

	t.Run("multiple cleanup calls are safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			cache.Cleanup()
			cache.Cleanup()
			cache.Cleanup()
		})
	})

	t.Run("multiple close calls are safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			cache.Close()
			cache.Close()
			cache.Close()
		})
	})

	t.Run("operations work after cleanup", func(t *testing.T) {
		cache.Cleanup()

		// Should still work
		testClaims := map[string]interface{}{"sub": "user123"}
		cache.Set("token1", testClaims, 1*time.Minute)

		claims, found := cache.Get("token1")
		assert.True(t, found)
		assert.Equal(t, testClaims, claims)
	})

	t.Run("operations work after close", func(t *testing.T) {
		cache.Close()

		// Should still work (close is a no-op)
		testClaims := map[string]interface{}{"sub": "user456"}
		cache.Set("token2", testClaims, 1*time.Minute)

		claims, found := cache.Get("token2")
		assert.True(t, found)
		assert.Equal(t, testClaims, claims)
	})
}
