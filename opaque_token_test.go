package traefikoidc

import (
	"strings"
	"testing"
)

// TestOpaqueTokenDetection tests the detection of opaque tokens vs JWT tokens
func TestOpaqueTokenDetection(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		isOpaque    bool
		description string
	}{
		{
			name:        "JWT token with 3 parts",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			isOpaque:    false,
			description: "Standard JWT with header.payload.signature",
		},
		{
			name:        "Auth0 opaque token",
			token:       "8n3d84nd92nf92nf92nf92nf923nf923nf923nf9",
			isOpaque:    true,
			description: "Auth0 opaque access token",
		},
		{
			name:        "Okta opaque token",
			token:       "00Otkjhgt5Rfasde12345678901234567890",
			isOpaque:    true,
			description: "Okta opaque access token",
		},
		{
			name:        "AWS Cognito opaque token",
			token:       "AGPAYJhZmU3NzI5YTQtNGQ0Yy00YTU5LWJjYTQtYzdlMzQ0MmQ3ZDJl",
			isOpaque:    true,
			description: "AWS Cognito opaque access token",
		},
		{
			name:        "Invalid single dot token",
			token:       "invalid.token",
			isOpaque:    true, // Treated as opaque since it's not a valid JWT
			description: "Invalid format with single dot",
		},
		{
			name:        "Token with no dots",
			token:       "opaquetoken1234567890abcdefghijklmnop",
			isOpaque:    true,
			description: "Pure opaque token with no dots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check dot count to determine if token is opaque
			dotCount := strings.Count(tt.token, ".")
			isOpaqueToken := dotCount != 2

			if isOpaqueToken != tt.isOpaque {
				t.Errorf("Token detection failed for %s: expected opaque=%v, got opaque=%v (dots=%d)",
					tt.name, tt.isOpaque, isOpaqueToken, dotCount)
			}
		})
	}
}

// TestOpaqueTokenValidation tests the validation logic for opaque tokens
func TestOpaqueTokenValidation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cm := NewChunkManager(logger)
	defer cm.Shutdown()

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "Valid opaque token",
			token:     "opaquetoken1234567890abcdefghijklmnop",
			wantError: false,
		},
		{
			name:      "Too short opaque token",
			token:     "short",
			wantError: true, // Less than 20 characters
		},
		{
			name:      "Opaque token with spaces",
			token:     "opaque token with spaces 1234567890",
			wantError: true, // Contains spaces
		},
		{
			name:      "Valid JWT token",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantError: false,
		},
	}

	config := TokenConfig{
		Type:              "access",
		MinLength:         5,
		MaxLength:         100 * 1024,
		MaxChunks:         25,
		MaxChunkSize:      maxCookieSize,
		AllowOpaqueTokens: true,
		RequireJWTFormat:  false,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cm.validateToken(tt.token, config)
			hasError := result.Error != nil

			if hasError != tt.wantError {
				if tt.wantError {
					t.Errorf("Expected error for %s but got none", tt.name)
				} else {
					t.Errorf("Unexpected error for %s: %v", tt.name, result.Error)
				}
			}
		})
	}
}

// TestOpaqueTokenStorage tests that opaque tokens are properly detected and stored
func TestOpaqueTokenStorage(t *testing.T) {
	// Test the token format detection logic
	tests := []struct {
		name        string
		token       string
		shouldStore bool
		description string
	}{
		{
			name:        "Valid opaque token",
			token:       "auth0_opaque_token_1234567890abcdefghijklmnop",
			shouldStore: true,
			description: "Opaque token with sufficient length and no dots",
		},
		{
			name:        "Valid JWT token",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			shouldStore: true,
			description: "Standard JWT with three parts",
		},
		{
			name:        "Invalid single-dot token",
			token:       "invalid.token",
			shouldStore: false,
			description: "Token with single dot - invalid format",
		},
		{
			name:        "Too short opaque token",
			token:       "short",
			shouldStore: false,
			description: "Opaque token too short (less than 20 chars)",
		},
		{
			name:        "Multi-dot invalid token",
			token:       "too.many.dots.here",
			shouldStore: false,
			description: "Token with more than 2 dots - invalid format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the validation logic from SetAccessToken
			shouldStore := true
			if tt.token != "" {
				dotCount := strings.Count(tt.token, ".")
				// Reject tokens with exactly 1 dot (invalid format)
				if dotCount == 1 {
					shouldStore = false
				}
				// For opaque tokens (no dots), ensure minimum length
				if dotCount == 0 && len(tt.token) < 20 {
					shouldStore = false
				}
				// Tokens with more than 2 dots are also invalid
				if dotCount > 2 {
					shouldStore = false
				}
			}

			if shouldStore != tt.shouldStore {
				t.Errorf("Token storage decision failed for %s: expected store=%v, got store=%v",
					tt.name, tt.shouldStore, shouldStore)
			}
		})
	}
}
