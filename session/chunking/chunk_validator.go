// Package chunking provides chunk validation functionality
package chunking

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// TokenValidator provides comprehensive validation for tokens and chunks
type TokenValidator struct{}

// NewTokenValidator creates a new token validator
func NewTokenValidator() *TokenValidator {
	return &TokenValidator{}
}

// ValidateTokenSize validates that a token is within size limits
func (tv *TokenValidator) ValidateTokenSize(token string, config TokenConfig) error {
	if len(token) == 0 {
		return nil // Empty token is allowed
	}

	if len(token) < config.MinLength {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "token too short",
			Details: fmt.Sprintf("length %d < minimum %d", len(token), config.MinLength),
		}
	}

	if len(token) > config.MaxLength {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "token too long",
			Details: fmt.Sprintf("length %d > maximum %d", len(token), config.MaxLength),
		}
	}

	return nil
}

// ValidateJWTFormat validates that a token has proper JWT format
func (tv *TokenValidator) ValidateJWTFormat(token string, tokenType string) error {
	if token == "" {
		return nil // Empty token is not an error
	}

	// JWT tokens must have exactly 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &ValidationError{
			Type:    tokenType,
			Reason:  "invalid JWT format",
			Details: fmt.Sprintf("expected 3 parts, got %d", len(parts)),
		}
	}

	// Each part must be non-empty
	for i, part := range parts {
		if part == "" {
			return &ValidationError{
				Type:    tokenType,
				Reason:  "empty JWT part",
				Details: fmt.Sprintf("part %d is empty", i+1),
			}
		}
	}

	// Validate each part is valid base64
	for i, part := range parts {
		if err := tv.validateBase64JWT(part); err != nil {
			return &ValidationError{
				Type:    tokenType,
				Reason:  "invalid base64 in JWT part",
				Details: fmt.Sprintf("part %d: %v", i+1, err),
			}
		}
	}

	return nil
}

// ValidateTokenContent performs comprehensive content validation
func (tv *TokenValidator) ValidateTokenContent(token string, config TokenConfig) error {
	if token == "" {
		return nil
	}

	// Validate character set
	if err := tv.validateCharacterSet(token, config); err != nil {
		return err
	}

	// Validate token structure based on type
	if config.RequireJWTFormat {
		return tv.validateJWTContent(token, config)
	} else if config.AllowOpaqueTokens {
		return tv.validateOpaqueTokenContent(token, config)
	} else {
		// Try JWT first, then fall back to opaque validation
		if err := tv.validateJWTContent(token, config); err != nil {
			return tv.validateOpaqueTokenContent(token, config)
		}
		return nil
	}
}

// validateCharacterSet validates the character set of a token
func (tv *TokenValidator) validateCharacterSet(token string, config TokenConfig) error {
	for i, r := range token {
		if !tv.isValidTokenCharacter(r) {
			return &ValidationError{
				Type:    config.Type,
				Reason:  "invalid character",
				Details: fmt.Sprintf("invalid character at position %d: %c (0x%X)", i, r, r),
			}
		}
	}
	return nil
}

// isValidTokenCharacter checks if a character is valid in a token
func (tv *TokenValidator) isValidTokenCharacter(r rune) bool {
	// Allow alphanumeric characters
	if unicode.IsLetter(r) || unicode.IsNumber(r) {
		return true
	}

	// Allow common token characters
	validChars := ".-_~:/?#[]@!$&'()*+,;="
	return strings.ContainsRune(validChars, r)
}

// validateJWTContent validates the content of a JWT token
func (tv *TokenValidator) validateJWTContent(token string, config TokenConfig) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "invalid JWT structure",
			Details: "JWT must have exactly 3 parts",
		}
	}

	// Validate header
	if err := tv.validateJWTHeader(parts[0], config); err != nil {
		return err
	}

	// Validate payload
	if err := tv.validateJWTPayload(parts[1], config); err != nil {
		return err
	}

	// Validate signature
	if err := tv.validateJWTSignature(parts[2], config); err != nil {
		return err
	}

	return nil
}

// validateJWTHeader validates a JWT header
func (tv *TokenValidator) validateJWTHeader(header string, config TokenConfig) error {
	decoded, err := tv.base64URLDecode(header)
	if err != nil {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "invalid header encoding",
			Details: err.Error(),
		}
	}

	var headerData map[string]interface{}
	if err := json.Unmarshal(decoded, &headerData); err != nil {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "invalid header JSON",
			Details: err.Error(),
		}
	}

	// Check required fields
	if _, ok := headerData["alg"]; !ok {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "missing algorithm",
			Details: "JWT header must contain 'alg' field",
		}
	}

	if _, ok := headerData["typ"]; !ok {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "missing type",
			Details: "JWT header must contain 'typ' field",
		}
	}

	return nil
}

// validateJWTPayload validates a JWT payload
func (tv *TokenValidator) validateJWTPayload(payload string, config TokenConfig) error {
	decoded, err := tv.base64URLDecode(payload)
	if err != nil {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "invalid payload encoding",
			Details: err.Error(),
		}
	}

	var payloadData map[string]interface{}
	if err := json.Unmarshal(decoded, &payloadData); err != nil {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "invalid payload JSON",
			Details: err.Error(),
		}
	}

	// For ID tokens, check required claims
	if config.Type == "id" {
		requiredClaims := []string{"iss", "sub", "aud", "exp", "iat"}
		for _, claim := range requiredClaims {
			if _, ok := payloadData[claim]; !ok {
				return &ValidationError{
					Type:    config.Type,
					Reason:  "missing required claim",
					Details: fmt.Sprintf("ID token must contain '%s' claim", claim),
				}
			}
		}
	}

	return nil
}

// validateJWTSignature validates a JWT signature part
func (tv *TokenValidator) validateJWTSignature(signature string, config TokenConfig) error {
	if signature == "" {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "empty signature",
			Details: "JWT signature cannot be empty",
		}
	}

	// Just validate it's valid base64URL
	_, err := tv.base64URLDecode(signature)
	if err != nil {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "invalid signature encoding",
			Details: err.Error(),
		}
	}

	return nil
}

// validateOpaqueTokenContent validates opaque token content
func (tv *TokenValidator) validateOpaqueTokenContent(token string, config TokenConfig) error {
	if token == "" {
		return nil
	}

	// Basic sanity checks for opaque tokens
	if len(token) < 8 {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "token too short for opaque token",
			Details: "opaque tokens should be at least 8 characters",
		}
	}

	// Check for reasonable entropy
	if tv.hasLowEntropy(token) {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "low entropy",
			Details: "token appears to have low entropy",
		}
	}

	return nil
}

// hasLowEntropy checks if a token has suspiciously low entropy
func (tv *TokenValidator) hasLowEntropy(token string) bool {
	if len(token) < 8 {
		return true
	}

	// Count unique characters
	uniqueChars := make(map[rune]bool)
	for _, r := range token {
		uniqueChars[r] = true
	}

	// If less than 50% of characters are unique, consider it low entropy
	entropyRatio := float64(len(uniqueChars)) / float64(len(token))
	return entropyRatio < 0.5
}

// validateBase64JWT validates base64URL encoding
func (tv *TokenValidator) validateBase64JWT(data string) error {
	_, err := tv.base64URLDecode(data)
	return err
}

// base64URLDecode decodes base64URL encoded data
func (tv *TokenValidator) base64URLDecode(data string) ([]byte, error) {
	// Add padding if needed
	switch len(data) % 4 {
	case 2:
		data += "=="
	case 3:
		data += "="
	}

	// Replace URL-safe characters
	data = strings.ReplaceAll(data, "-", "+")
	data = strings.ReplaceAll(data, "_", "/")

	return base64.StdEncoding.DecodeString(data)
}

// ValidateChunkStructure validates the structure of chunk data
func (tv *TokenValidator) ValidateChunkStructure(chunks []ChunkData, config TokenConfig) error {
	if len(chunks) == 0 {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "no chunks provided",
			Details: "chunk list is empty",
		}
	}

	if len(chunks) > config.MaxChunks {
		return &ValidationError{
			Type:    config.Type,
			Reason:  "too many chunks",
			Details: fmt.Sprintf("got %d chunks, maximum is %d", len(chunks), config.MaxChunks),
		}
	}

	// Validate each chunk
	expectedTotal := chunks[0].Total
	seenIndices := make(map[int]bool)

	for i, chunk := range chunks {
		// Check for duplicate indices
		if seenIndices[chunk.Index] {
			return &ValidationError{
				Type:    config.Type,
				Reason:  "duplicate chunk index",
				Details: fmt.Sprintf("chunk index %d appears multiple times", chunk.Index),
			}
		}
		seenIndices[chunk.Index] = true

		// Validate individual chunk
		if err := tv.validateChunkData(chunk, expectedTotal, config); err != nil {
			return &ValidationError{
				Type:    config.Type,
				Reason:  "invalid chunk data",
				Details: fmt.Sprintf("chunk %d: %v", i, err),
			}
		}
	}

	// Check for missing indices
	for i := 0; i < expectedTotal; i++ {
		if !seenIndices[i] {
			return &ValidationError{
				Type:    config.Type,
				Reason:  "missing chunk index",
				Details: fmt.Sprintf("chunk with index %d is missing", i),
			}
		}
	}

	return nil
}

// validateChunkData validates individual chunk data
func (tv *TokenValidator) validateChunkData(chunk ChunkData, expectedTotal int, config TokenConfig) error {
	if chunk.Index < 0 {
		return fmt.Errorf("negative index: %d", chunk.Index)
	}

	if chunk.Total != expectedTotal {
		return fmt.Errorf("inconsistent total: got %d, expected %d", chunk.Total, expectedTotal)
	}

	if chunk.Index >= chunk.Total {
		return fmt.Errorf("index %d exceeds total %d", chunk.Index, chunk.Total)
	}

	if chunk.Content == "" {
		return fmt.Errorf("empty content")
	}

	if len(chunk.Content) > config.MaxChunkSize {
		return fmt.Errorf("chunk too large: %d > %d", len(chunk.Content), config.MaxChunkSize)
	}

	if chunk.Checksum == "" {
		return fmt.Errorf("empty checksum")
	}

	return nil
}

// ValidationError represents a validation error
type ValidationError struct {
	Type    string
	Reason  string
	Details string
}

// Error implements the error interface
func (ve *ValidationError) Error() string {
	return fmt.Sprintf("%s validation error: %s - %s", ve.Type, ve.Reason, ve.Details)
}
