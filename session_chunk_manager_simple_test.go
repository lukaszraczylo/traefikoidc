package traefikoidc

import (
	"strings"
	"testing"
	"time"
)

// TestChunkManagerValidateJWT tests JWT validation in chunk manager
func TestChunkManagerValidateJWT(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cm := NewChunkManager(ts.tOidc.logger)

	// Test valid JWT format (using base64url encoded parts that are long enough)
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	err := cm.validateJWTFormat(validJWT, "test")
	if err != nil {
		t.Errorf("Expected valid JWT to pass, got error: %v", err)
	}

	// Test invalid JWT format - too few parts
	invalidJWT := "header.payload"
	err = cm.validateJWTFormat(invalidJWT, "test")
	if err == nil {
		t.Error("Expected invalid JWT to fail validation")
	}

	// Test invalid JWT format - too many parts
	invalidJWT2 := "header.payload.signature.extra"
	err = cm.validateJWTFormat(invalidJWT2, "test")
	if err == nil {
		t.Error("Expected invalid JWT with extra parts to fail validation")
	}

	// Test empty JWT
	err = cm.validateJWTFormat("", "test")
	if err == nil {
		t.Error("Expected empty JWT to fail validation")
	}
}

// TestChunkManagerValidateOpaqueToken tests opaque token validation
func TestChunkManagerValidateOpaqueToken(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cm := NewChunkManager(ts.tOidc.logger)

	// Test valid opaque token
	validOpaque := "valid_opaque_token_that_is_long_enough"
	err := cm.validateOpaqueToken(validOpaque, "test")
	if err != nil {
		t.Errorf("Expected valid opaque token to pass, got error: %v", err)
	}

	// Test too short opaque token
	shortOpaque := "short"
	err = cm.validateOpaqueToken(shortOpaque, "test")
	if err == nil {
		t.Error("Expected short opaque token to fail validation")
	}

	// Test empty opaque token
	err = cm.validateOpaqueToken("", "test")
	if err == nil {
		t.Error("Expected empty opaque token to fail validation")
	}
}

// TestChunkManagerValidateTokenSize tests token size validation
func TestChunkManagerValidateTokenSize(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cm := NewChunkManager(ts.tOidc.logger)

	// Test normal token size
	normalToken := strings.Repeat("a", 1000)
	err := cm.validateTokenSize(normalToken, AccessTokenConfig)
	if err != nil {
		t.Errorf("Expected normal token to pass size validation, got error: %v", err)
	}

	// Test oversized token
	oversizedToken := strings.Repeat("a", AccessTokenConfig.MaxLength+1)
	err = cm.validateTokenSize(oversizedToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected oversized token to fail validation")
	}

	// Test undersized token
	undersizedToken := "ab"
	err = cm.validateTokenSize(undersizedToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected undersized token to fail validation")
	}
}

// TestChunkManagerValidateTokenContent tests token content validation
func TestChunkManagerValidateTokenContent(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cm := NewChunkManager(ts.tOidc.logger)

	// Test normal token content
	normalToken := "normal_token_content_without_issues"
	err := cm.validateTokenContent(normalToken, AccessTokenConfig)
	if err != nil {
		t.Errorf("Expected normal token to pass content validation, got error: %v", err)
	}

	// Test token with null bytes
	nullByteToken := "token_with\x00null_byte"
	err = cm.validateTokenContent(nullByteToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected token with null bytes to fail validation")
	}

	// Test token with control characters
	controlCharToken := "token_with\x01control"
	err = cm.validateTokenContent(controlCharToken, AccessTokenConfig)
	if err == nil {
		t.Error("Expected token with control characters to fail validation")
	}
}

// TestChunkManagerSingleTokenValidation tests single token validation path
func TestChunkManagerSingleTokenValidation(t *testing.T) {
	ts := NewTestSuite(t)
	ts.Setup()

	cm := NewChunkManager(ts.tOidc.logger)

	// Create a valid JWT token
	validToken, _ := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
		"iss": "https://test-issuer.com",
		"aud": "test-client-id",
		"sub": "test-user",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Test valid token processing
	result := cm.processSingleToken(validToken, false, AccessTokenConfig)
	if result.Error != nil {
		t.Errorf("Expected valid token to process successfully, got error: %v", result.Error)
	}
	if result.Token != validToken {
		t.Error("Expected token to be returned unchanged")
	}

	// Test invalid token processing
	invalidToken := "invalid.token"
	result = cm.processSingleToken(invalidToken, false, IDTokenConfig) // ID tokens require JWT format
	if result.Error == nil {
		t.Error("Expected invalid token to fail processing")
	}
}

// TestTokenConfigValidation tests different token configurations
func TestTokenConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config TokenConfig
	}{
		{
			name:   "AccessTokenConfig",
			config: AccessTokenConfig,
		},
		{
			name:   "RefreshTokenConfig",
			config: RefreshTokenConfig,
		},
		{
			name:   "IDTokenConfig",
			config: IDTokenConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify config has expected fields
			if tt.config.Type == "" {
				t.Error("Expected config to have Type set")
			}
			if tt.config.MaxLength <= 0 {
				t.Error("Expected config to have positive MaxLength")
			}
			if tt.config.MinLength <= 0 {
				t.Error("Expected config to have positive MinLength")
			}
		})
	}
}
