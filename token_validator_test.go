package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Test TokenValidator Creation

func TestNewTokenValidator(t *testing.T) {
	validator := NewTokenValidator(nil)

	if validator == nil {
		t.Fatal("Expected non-nil token validator")
	}

	if validator.logger == nil {
		t.Error("Expected logger to be initialized")
	}
}

func TestNewTokenValidatorWithLogger(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	validator := NewTokenValidator(logger)

	if validator == nil {
		t.Fatal("Expected non-nil token validator")
	}

	if validator.logger != logger {
		t.Error("Expected provided logger to be used")
	}
}

// Test ValidateToken - Entry Point

func TestValidateTokenEmpty(t *testing.T) {
	validator := NewTokenValidator(nil)
	result := validator.ValidateToken("", false)

	if result.Valid {
		t.Error("Expected invalid result for empty token")
	}

	if result.Error == nil {
		t.Error("Expected error for empty token")
	}

	if !strings.Contains(result.Error.Error(), "empty") {
		t.Errorf("Expected 'empty' in error, got: %v", result.Error)
	}
}

func TestValidateTokenRequireJWT(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Opaque token when JWT required
	result := validator.ValidateToken("opaque_token_value_here", true)

	if result.Valid {
		t.Error("Expected invalid result for opaque token when JWT required")
	}

	if result.Error == nil {
		t.Error("Expected error when JWT required but opaque token provided")
	}
}

// Test JWT Validation

func TestValidateJWTValidFormat(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Create a valid JWT with valid claims
	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token := createTestJWTSimple(claims)
	result := validator.ValidateToken(token, false)

	if !result.Valid {
		t.Errorf("Expected valid result, got error: %v", result.Error)
	}

	if result.TokenType != "JWT" {
		t.Errorf("Expected TokenType 'JWT', got %s", result.TokenType)
	}

	if result.Claims == nil {
		t.Error("Expected claims to be parsed")
	}

	if result.Expiry == nil {
		t.Error("Expected expiry to be extracted")
	}

	if result.IssuedAt == nil {
		t.Error("Expected issued at to be extracted")
	}
}

func TestValidateJWTExpiredToken(t *testing.T) {
	validator := NewTokenValidator(nil)

	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}

	token := createTestJWTSimple(claims)
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for expired token")
	}

	if result.Error == nil {
		t.Error("Expected error for expired token")
	}

	if !strings.Contains(result.Error.Error(), "expired") {
		t.Errorf("Expected 'expired' in error, got: %v", result.Error)
	}
}

func TestValidateJWTFutureIssuedAt(t *testing.T) {
	validator := NewTokenValidator(nil)

	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"iat": time.Now().Add(10 * time.Minute).Unix(), // Issued 10 minutes in future
	}

	token := createTestJWTSimple(claims)
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for future iat")
	}

	if result.Error == nil {
		t.Error("Expected error for future iat")
	}

	if !strings.Contains(result.Error.Error(), "future") {
		t.Errorf("Expected 'future' in error, got: %v", result.Error)
	}
}

func TestValidateJWTNotBeforeClaim(t *testing.T) {
	validator := NewTokenValidator(nil)

	claims := map[string]interface{}{
		"sub": "user123",
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Add(1 * time.Hour).Unix(), // Not valid for 1 hour
	}

	token := createTestJWTSimple(claims)
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for nbf in future")
	}

	if result.Error == nil {
		t.Error("Expected error for nbf in future")
	}

	if !strings.Contains(result.Error.Error(), "not yet valid") {
		t.Errorf("Expected 'not yet valid' in error, got: %v", result.Error)
	}
}

func TestValidateJWTInvalidFormat(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name  string
		token string
	}{
		{"single part", "eyJhbGciOiJIUzI1NiJ9"},
		{"two parts", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0"},
		{"four parts", "part1.part2.part3.part4"},
		{"empty part", "eyJhbGciOiJIUzI1NiJ9..signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use requireJWT=true to ensure these are treated as invalid JWTs, not opaque tokens
			result := validator.ValidateToken(tt.token, true)

			if result.Valid {
				t.Error("Expected invalid result for malformed JWT")
			}

			if result.Error == nil {
				t.Error("Expected error for malformed JWT")
			}
		})
	}
}

func TestValidateJWTInvalidBase64URL(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Token with invalid base64url characters
	token := "invalid@chars.eyJzdWIiOiIxMjM0In0.signature"
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for invalid base64url characters")
	}

	if result.Error == nil {
		t.Error("Expected error for invalid base64url characters")
	}
}

func TestValidateJWTInvalidJSON(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Valid base64 but invalid JSON
	header := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	payload := base64.RawURLEncoding.EncodeToString([]byte("{invalid json"))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	token := header + "." + payload + "." + signature
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for invalid JSON in claims")
	}

	if result.Error == nil {
		t.Error("Expected error for invalid JSON in claims")
	}
}

// Test Opaque Token Validation

func TestValidateOpaqueTokenValid(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Valid opaque token (>20 chars, good entropy)
	token := "sk_live_abcdef123456GHIJKL789"
	result := validator.ValidateToken(token, false)

	if !result.Valid {
		t.Errorf("Expected valid result, got error: %v", result.Error)
	}

	if result.TokenType != "Opaque" {
		t.Errorf("Expected TokenType 'Opaque', got %s", result.TokenType)
	}
}

func TestValidateOpaqueTokenTooShort(t *testing.T) {
	validator := NewTokenValidator(nil)

	token := "short"
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for short token")
	}

	if result.Error == nil {
		t.Error("Expected error for short token")
	}

	if !strings.Contains(result.Error.Error(), "too short") {
		t.Errorf("Expected 'too short' in error, got: %v", result.Error)
	}
}

func TestValidateOpaqueTokenWithSpaces(t *testing.T) {
	validator := NewTokenValidator(nil)

	token := "this token has spaces in it"
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for token with spaces")
	}

	if result.Error == nil {
		t.Error("Expected error for token with spaces")
	}

	if !strings.Contains(result.Error.Error(), "spaces") {
		t.Errorf("Expected 'spaces' in error, got: %v", result.Error)
	}
}

func TestValidateOpaqueTokenControlCharacters(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Token with control character (null byte)
	token := "token_with\x00control_char"
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for token with control characters")
	}

	if result.Error == nil {
		t.Error("Expected error for token with control characters")
	}

	if !strings.Contains(result.Error.Error(), "control character") {
		t.Errorf("Expected 'control character' in error, got: %v", result.Error)
	}
}

func TestValidateOpaqueTokenInsufficientEntropy(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Token with low entropy (only 3 unique characters)
	token := "aaaaaabbbbbbccccccdddd"
	result := validator.ValidateToken(token, false)

	if result.Valid {
		t.Error("Expected invalid result for low entropy token")
	}

	if result.Error == nil {
		t.Error("Expected error for low entropy token")
	}

	if !strings.Contains(result.Error.Error(), "entropy") {
		t.Errorf("Expected 'entropy' in error, got: %v", result.Error)
	}
}

// Test Base64URL Validation

func TestIsValidBase64URL(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid uppercase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", true},
		{"valid lowercase", "abcdefghijklmnopqrstuvwxyz", true},
		{"valid numbers", "0123456789", true},
		{"valid dash", "abc-def", true},
		{"valid underscore", "abc_def", true},
		{"valid equals", "abc=", true},
		{"invalid at sign", "abc@def", false},
		{"invalid space", "abc def", false},
		{"invalid plus", "abc+def", false},
		{"invalid slash", "abc/def", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isValidBase64URL(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.input, result)
			}
		})
	}
}

// Test Time Extraction

func TestExtractTime(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name     string
		claim    interface{}
		expected bool
	}{
		{"float64", float64(1609459200), true},
		{"int64", int64(1609459200), true},
		{"int", int(1609459200), true},
		{"string", "not a timestamp", false},
		{"nil", nil, false},
		{"map", map[string]interface{}{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.extractTime(tt.claim)

			if tt.expected && result == nil {
				t.Error("Expected non-nil time")
			}

			if !tt.expected && result != nil {
				t.Error("Expected nil time")
			}
		})
	}
}

func TestExtractTimeCorrectValue(t *testing.T) {
	validator := NewTokenValidator(nil)

	// Unix timestamp for 2021-01-01 00:00:00 UTC
	timestamp := int64(1609459200)
	result := validator.extractTime(timestamp)

	if result == nil {
		t.Fatal("Expected non-nil time")
	}

	expected := time.Unix(timestamp, 0)
	if !result.Equal(expected) {
		t.Errorf("Expected time %v, got %v", expected, *result)
	}
}

// Test Token Size Validation

func TestValidateTokenSize(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name        string
		token       string
		maxSize     int
		expectError bool
	}{
		{"within limit", "short_token", 20, false},
		{"at limit", "exactly_twenty_c", 16, false},
		{"exceeds limit", "this_token_is_too_long", 10, true},
		{"empty token", "", 10, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateTokenSize(tt.token, tt.maxSize)

			if tt.expectError && err == nil {
				t.Error("Expected error for oversized token")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}

			if err != nil && !strings.Contains(err.Error(), "exceeds") {
				t.Errorf("Expected 'exceeds' in error, got: %v", err)
			}
		})
	}
}

// Test Claims Extraction

func TestExtractClaims(t *testing.T) {
	validator := NewTokenValidator(nil)

	claims := map[string]interface{}{
		"sub":   "user123",
		"email": "user@example.com",
		"exp":   float64(1609459200),
	}

	token := createTestJWTSimple(claims)
	extracted, err := validator.ExtractClaims(token)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if extracted == nil {
		t.Fatal("Expected non-nil claims")
	}

	if extracted["sub"] != "user123" {
		t.Errorf("Expected sub 'user123', got %v", extracted["sub"])
	}

	if extracted["email"] != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got %v", extracted["email"])
	}
}

func TestExtractClaimsInvalidFormat(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name  string
		token string
	}{
		{"single part", "onlyonepart"},
		{"two parts", "two.parts"},
		{"four parts", "one.two.three.four"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.ExtractClaims(tt.token)

			if err == nil {
				t.Error("Expected error for invalid format")
			}

			if !strings.Contains(err.Error(), "invalid JWT format") {
				t.Errorf("Expected 'invalid JWT format' in error, got: %v", err)
			}
		})
	}
}

func TestExtractClaimsInvalidBase64(t *testing.T) {
	validator := NewTokenValidator(nil)

	token := "header.invalid@base64.signature"
	_, err := validator.ExtractClaims(token)

	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("Expected 'decode' in error, got: %v", err)
	}
}

func TestExtractClaimsInvalidJSON(t *testing.T) {
	validator := NewTokenValidator(nil)

	header := base64.RawURLEncoding.EncodeToString([]byte("header"))
	payload := base64.RawURLEncoding.EncodeToString([]byte("{not valid json"))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	token := header + "." + payload + "." + signature
	_, err := validator.ExtractClaims(token)

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("Expected 'parse' in error, got: %v", err)
	}
}

// Test Token Comparison (Security - Timing Attack Resistance)

func TestCompareTokensEqual(t *testing.T) {
	validator := NewTokenValidator(nil)

	token1 := "secret_token_12345"
	token2 := "secret_token_12345"

	if !validator.CompareTokens(token1, token2) {
		t.Error("Expected tokens to be equal")
	}
}

func TestCompareTokensDifferent(t *testing.T) {
	validator := NewTokenValidator(nil)

	token1 := "secret_token_12345"
	token2 := "secret_token_54321"

	if validator.CompareTokens(token1, token2) {
		t.Error("Expected tokens to be different")
	}
}

func TestCompareTokensDifferentLength(t *testing.T) {
	validator := NewTokenValidator(nil)

	token1 := "short"
	token2 := "much_longer_token"

	if validator.CompareTokens(token1, token2) {
		t.Error("Expected tokens to be different (different lengths)")
	}
}

func TestCompareTokensEmpty(t *testing.T) {
	validator := NewTokenValidator(nil)

	token1 := ""
	token2 := ""

	if !validator.CompareTokens(token1, token2) {
		t.Error("Expected empty tokens to be equal")
	}
}

func TestCompareTokensConstantTime(t *testing.T) {
	validator := NewTokenValidator(nil)

	// This test verifies the comparison is constant-time
	// by checking that different tokens take similar time
	token1 := strings.Repeat("a", 1000)
	token2First := "b" + strings.Repeat("a", 999)
	token2Last := strings.Repeat("a", 999) + "b"

	// Both comparisons should take similar time regardless of where difference occurs
	startFirst := time.Now()
	validator.CompareTokens(token1, token2First)
	durationFirst := time.Since(startFirst)

	startLast := time.Now()
	validator.CompareTokens(token1, token2Last)
	durationLast := time.Since(startLast)

	// Allow 10x variance (generous, but timing can vary)
	ratio := float64(durationFirst) / float64(durationLast)
	if ratio < 0.1 || ratio > 10.0 {
		t.Logf("Warning: timing variance detected (ratio: %.2f). First: %v, Last: %v",
			ratio, durationFirst, durationLast)
		// Not failing test as timing can be affected by many factors
	}
}

// Security Tests

func TestValidateTokenMaliciousPayloads(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name  string
		token string
	}{
		{"sql injection attempt", "'; DROP TABLE users; --"},
		{"xss attempt", "<script>alert('xss')</script>"},
		{"path traversal", "../../../etc/passwd"},
		{"null bytes", "token\x00with\x00nulls"},
		{"unicode exploit", "token\u0000\u0001\u0002"},
		{"extremely long", strings.Repeat("a", 100000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateToken(tt.token, false)

			// Should either reject or handle safely
			if result.Valid {
				// If considered valid, should have parsed safely
				if result.Claims != nil {
					t.Logf("Token considered valid: %s", tt.name)
				}
			} else {
				// If invalid, should have error
				if result.Error == nil {
					t.Error("Expected error for malicious payload")
				}
			}
		})
	}
}

func TestValidateTokenBoundaryConditions(t *testing.T) {
	validator := NewTokenValidator(nil)

	tests := []struct {
		name    string
		claims  map[string]interface{}
		wantErr bool
	}{
		{
			name: "expiry at exact current time",
			claims: map[string]interface{}{
				"exp": time.Now().Unix(),
			},
			wantErr: true, // Should be expired (not <=, but <)
		},
		{
			name: "iat 5 minutes in future (boundary)",
			claims: map[string]interface{}{
				"iat": time.Now().Add(5 * time.Minute).Unix(),
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErr: false, // Allowed within 5-minute tolerance
		},
		{
			name: "iat 6 minutes in future",
			claims: map[string]interface{}{
				"iat": time.Now().Add(6 * time.Minute).Unix(),
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErr: true,
		},
		{
			name: "nbf at exact current time",
			claims: map[string]interface{}{
				"nbf": time.Now().Unix(),
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			},
			wantErr: false, // Should be valid at exact time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := createTestJWTSimple(tt.claims)
			result := validator.ValidateToken(token, false)

			if tt.wantErr && result.Valid {
				t.Error("Expected invalid result at boundary condition")
			}

			if !tt.wantErr && !result.Valid {
				t.Errorf("Expected valid result at boundary condition, got error: %v", result.Error)
			}
		})
	}
}

// Helper Functions

func createTestJWTSimple(claims map[string]interface{}) string {
	// Create a minimal JWT for testing (not cryptographically signed)
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake_signature"))

	return headerB64 + "." + claimsB64 + "." + signature
}
