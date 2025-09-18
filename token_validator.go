package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenValidator provides unified token validation functionality
type TokenValidator struct {
	logger *Logger
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(logger *Logger) *TokenValidator {
	if logger == nil {
		logger = GetSingletonNoOpLogger()
	}
	return &TokenValidator{
		logger: logger,
	}
}

// TokenValidationResult contains the result of token validation
type TokenValidationResult struct {
	Valid     bool
	TokenType string
	Claims    map[string]interface{}
	Expiry    *time.Time
	IssuedAt  *time.Time
	Error     error
}

// ValidateToken performs comprehensive token validation
func (v *TokenValidator) ValidateToken(token string, requireJWT bool) TokenValidationResult {
	result := TokenValidationResult{}

	// Basic validation
	if token == "" {
		result.Error = fmt.Errorf("token is empty")
		return result
	}

	// Check if it's a JWT or opaque token
	dotCount := strings.Count(token, ".")
	isJWT := dotCount == 2

	if requireJWT && !isJWT {
		result.Error = fmt.Errorf("token is not a valid JWT (found %d dots, expected 2)", dotCount)
		return result
	}

	if isJWT {
		return v.validateJWT(token)
	} else {
		return v.validateOpaqueToken(token)
	}
}

// validateJWT validates a JWT token
func (v *TokenValidator) validateJWT(token string) TokenValidationResult {
	result := TokenValidationResult{
		TokenType: "JWT",
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		result.Error = fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
		return result
	}

	// Validate each part
	for i, part := range parts {
		if part == "" {
			result.Error = fmt.Errorf("JWT part %d is empty", i)
			return result
		}

		// Check for valid base64url characters
		if !v.isValidBase64URL(part) {
			result.Error = fmt.Errorf("JWT part %d contains invalid base64url characters", i)
			return result
		}
	}

	// Decode and parse claims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		result.Error = fmt.Errorf("failed to decode JWT payload: %w", err)
		return result
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		result.Error = fmt.Errorf("failed to parse JWT claims: %w", err)
		return result
	}

	result.Claims = claims

	// Extract standard claims
	if exp, ok := claims["exp"]; ok {
		expTime := v.extractTime(exp)
		if expTime != nil {
			result.Expiry = expTime
			// Check if expired
			if time.Now().After(*expTime) {
				result.Error = fmt.Errorf("token is expired (expired at %v)", expTime.Format(time.RFC3339))
				return result
			}
		}
	}

	if iat, ok := claims["iat"]; ok {
		iatTime := v.extractTime(iat)
		if iatTime != nil {
			result.IssuedAt = iatTime
			// Check if issued in future
			if iatTime.After(time.Now().Add(5 * time.Minute)) {
				result.Error = fmt.Errorf("token issued in future (iat: %v)", iatTime.Format(time.RFC3339))
				return result
			}
		}
	}

	// Check nbf (not before)
	if nbf, ok := claims["nbf"]; ok {
		nbfTime := v.extractTime(nbf)
		if nbfTime != nil && time.Now().Before(*nbfTime) {
			result.Error = fmt.Errorf("token not yet valid (nbf: %v)", nbfTime.Format(time.RFC3339))
			return result
		}
	}

	result.Valid = true
	return result
}

// validateOpaqueToken validates an opaque token
func (v *TokenValidator) validateOpaqueToken(token string) TokenValidationResult {
	result := TokenValidationResult{
		TokenType: "Opaque",
	}

	// Check minimum length
	if len(token) < 20 {
		result.Error = fmt.Errorf("opaque token too short (length: %d)", len(token))
		return result
	}

	// Check for spaces
	if strings.Contains(token, " ") {
		result.Error = fmt.Errorf("opaque token contains spaces")
		return result
	}

	// Check for control characters
	for i, char := range token {
		if char < 32 || char == 127 {
			result.Error = fmt.Errorf("opaque token contains control character at position %d", i)
			return result
		}
	}

	// Check entropy
	if len(token) >= 20 {
		uniqueChars := make(map[rune]bool)
		for _, char := range token {
			uniqueChars[char] = true
		}
		if len(uniqueChars) < 8 {
			result.Error = fmt.Errorf("opaque token has insufficient entropy (unique chars: %d)", len(uniqueChars))
			return result
		}
	}

	result.Valid = true
	return result
}

// isValidBase64URL checks if a string contains only valid base64url characters
func (v *TokenValidator) isValidBase64URL(s string) bool {
	for _, char := range s {
		if !((char >= 'A' && char <= 'Z') ||
			(char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '=') {
			return false
		}
	}
	return true
}

// extractTime extracts a time.Time from various claim formats
func (v *TokenValidator) extractTime(claim interface{}) *time.Time {
	var timestamp int64

	switch val := claim.(type) {
	case float64:
		timestamp = int64(val)
	case int64:
		timestamp = val
	case int:
		timestamp = int64(val)
	default:
		return nil
	}

	t := time.Unix(timestamp, 0)
	return &t
}

// ValidateTokenSize checks if token size is within acceptable limits
func (v *TokenValidator) ValidateTokenSize(token string, maxSize int) error {
	if len(token) > maxSize {
		return fmt.Errorf("token exceeds maximum size (size: %d, max: %d)", len(token), maxSize)
	}
	return nil
}

// ExtractClaims extracts claims from a JWT without full validation
func (v *TokenValidator) ExtractClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims, nil
}

// CompareTokens safely compares two tokens for equality
func (v *TokenValidator) CompareTokens(token1, token2 string) bool {
	if len(token1) != len(token2) {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	var result byte
	for i := 0; i < len(token1); i++ {
		result |= token1[i] ^ token2[i]
	}
	return result == 0
}
