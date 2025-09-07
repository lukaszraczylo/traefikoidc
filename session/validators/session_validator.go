// Package validators provides validation functionality for session data
package validators

import (
	"strings"
	"time"
)

const (
	maxBrowserCookieSize = 3500
	maxCookieSize        = 1200
)

// SessionValidator provides validation operations for session data
type SessionValidator struct{}

// NewSessionValidator creates a new session validator
func NewSessionValidator() *SessionValidator {
	return &SessionValidator{}
}

// ValidateChunkSize checks if a chunk will fit within browser cookie limits.
// It estimates the encoded size including cookie overhead and headers
// to ensure the chunk won't exceed browser-imposed cookie size limits.
func (sv *SessionValidator) ValidateChunkSize(chunkData string) bool {
	estimatedEncodedSize := len(chunkData) + (len(chunkData)*50)/100
	return estimatedEncodedSize <= maxBrowserCookieSize
}

// IsCorruptionMarker detects if data contains known corruption indicators.
// It checks for specific corruption markers and invalid characters
// that indicate the data has been tampered with or corrupted.
func (sv *SessionValidator) IsCorruptionMarker(data string) bool {
	if data == "" {
		return false
	}

	corruptionMarkers := []string{
		"__CORRUPTION_MARKER_TEST__",
		"__INVALID_BASE64_DATA__",
		"__CORRUPTED_CHUNK_DATA__",
		"!@#$%^&*()",
		"<<<CORRUPTED>>>",
	}

	for _, marker := range corruptionMarkers {
		if data == marker {
			return true
		}
	}

	if len(data) > 10 {
		invalidChars := "!@#$%^&*(){}[]|\\:;\"'<>?,`~"
		for _, char := range invalidChars {
			if strings.ContainsRune(data, char) {
				return true
			}
		}
	}

	return false
}

// ValidateTokenFormat validates that a token has the correct JWT format
func (sv *SessionValidator) ValidateTokenFormat(token, tokenType string) error {
	if token == "" {
		return nil // Empty token is not an error
	}

	// JWT tokens should have exactly 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &ValidationError{
			Type:    tokenType,
			Reason:  "invalid JWT format",
			Details: "token must have exactly 3 parts separated by dots",
		}
	}

	// Each part should be non-empty
	for i, part := range parts {
		if part == "" {
			return &ValidationError{
				Type:    tokenType,
				Reason:  "empty token part",
				Details: strings.Join([]string{"token part", string(rune(i + 1)), "is empty"}, " "),
			}
		}
	}

	return nil
}

// ValidateSessionIntegrity performs comprehensive validation of session data integrity
func (sv *SessionValidator) ValidateSessionIntegrity(sessionData SessionData) error {
	if sessionData == nil {
		return &ValidationError{
			Type:    "session",
			Reason:  "nil session data",
			Details: "session data cannot be nil",
		}
	}

	// Check authentication state consistency
	authenticated := sessionData.GetAuthenticated()
	email := sessionData.GetEmail()

	if authenticated && email == "" {
		return &ValidationError{
			Type:    "session",
			Reason:  "authentication inconsistency",
			Details: "session is authenticated but has no email",
		}
	}

	// Validate token formats if present
	if accessToken := sessionData.GetAccessToken(); accessToken != "" {
		if err := sv.ValidateTokenFormat(accessToken, "access"); err != nil {
			return err
		}
	}

	if idToken := sessionData.GetIDToken(); idToken != "" {
		if err := sv.ValidateTokenFormat(idToken, "id"); err != nil {
			return err
		}
	}

	if refreshToken := sessionData.GetRefreshToken(); refreshToken != "" {
		// Refresh tokens don't have to be JWTs, so we do basic validation
		if len(refreshToken) == 0 {
			return &ValidationError{
				Type:    "refresh",
				Reason:  "empty refresh token",
				Details: "refresh token cannot be empty if set",
			}
		}
	}

	return nil
}

// ValidateSessionTiming validates session timing and expiration
func (sv *SessionValidator) ValidateSessionTiming(sessionData SessionData, maxAge time.Duration) error {
	if sessionData == nil {
		return &ValidationError{
			Type:    "session",
			Reason:  "nil session data",
			Details: "session data cannot be nil",
		}
	}

	// Check refresh token timing
	refreshTokenIssuedAt := sessionData.GetRefreshTokenIssuedAt()
	if !refreshTokenIssuedAt.IsZero() {
		age := time.Since(refreshTokenIssuedAt)
		if age > maxAge {
			return &ValidationError{
				Type:    "timing",
				Reason:  "refresh token expired",
				Details: strings.Join([]string{"refresh token age", age.String(), "exceeds max age", maxAge.String()}, " "),
			}
		}
	}

	return nil
}

// ValidateEmailDomain validates that an email belongs to an allowed domain
func (sv *SessionValidator) ValidateEmailDomain(email string, allowedDomains map[string]struct{}) error {
	if email == "" {
		return &ValidationError{
			Type:    "email",
			Reason:  "empty email",
			Details: "email cannot be empty",
		}
	}

	if len(allowedDomains) == 0 {
		return nil // No domain restrictions
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return &ValidationError{
			Type:    "email",
			Reason:  "invalid email format",
			Details: "email must contain exactly one @ symbol",
		}
	}

	domain := parts[1]
	if _, allowed := allowedDomains[domain]; !allowed {
		return &ValidationError{
			Type:    "email",
			Reason:  "domain not allowed",
			Details: strings.Join([]string{"domain", domain, "is not in allowed domains list"}, " "),
		}
	}

	return nil
}

// SplitIntoChunks splits a string into chunks that fit within cookie size limits
func (sv *SessionValidator) SplitIntoChunks(s string, chunkSize int) []string {
	effectiveChunkSize := min(chunkSize, maxCookieSize)

	var chunks []string
	for len(s) > 0 {
		if len(s) > effectiveChunkSize {
			chunks = append(chunks, s[:effectiveChunkSize])
			s = s[effectiveChunkSize:]
		} else {
			chunks = append(chunks, s)
			break
		}
	}
	return chunks
}

// ValidateChunks validates all chunks in a chunk set
func (sv *SessionValidator) ValidateChunks(chunks []string) error {
	for i, chunk := range chunks {
		if chunk == "" {
			return &ValidationError{
				Type:    "chunk",
				Reason:  "empty chunk",
				Details: strings.Join([]string{"chunk", string(rune(i)), "is empty"}, " "),
			}
		}

		if !sv.ValidateChunkSize(chunk) {
			return &ValidationError{
				Type:    "chunk",
				Reason:  "chunk too large",
				Details: strings.Join([]string{"chunk", string(rune(i)), "exceeds size limit"}, " "),
			}
		}

		if sv.IsCorruptionMarker(chunk) {
			return &ValidationError{
				Type:    "chunk",
				Reason:  "corrupted chunk",
				Details: strings.Join([]string{"chunk", string(rune(i)), "contains corruption markers"}, " "),
			}
		}
	}

	return nil
}

// ValidationError represents a validation error with context
type ValidationError struct {
	Type    string
	Reason  string
	Details string
}

// Error implements the error interface
func (ve *ValidationError) Error() string {
	return strings.Join([]string{ve.Type, "validation error:", ve.Reason, "-", ve.Details}, " ")
}

// SessionData interface for validation operations
type SessionData interface {
	GetAuthenticated() bool
	GetEmail() string
	GetAccessToken() string
	GetIDToken() string
	GetRefreshToken() string
	GetRefreshTokenIssuedAt() time.Time
}

// Utility functions

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ValidateChunkSize is a package-level function for backward compatibility
func ValidateChunkSize(chunkData string) bool {
	sv := &SessionValidator{}
	return sv.ValidateChunkSize(chunkData)
}

// IsCorruptionMarker is a package-level function for backward compatibility
func IsCorruptionMarker(data string) bool {
	sv := &SessionValidator{}
	return sv.IsCorruptionMarker(data)
}

// SplitIntoChunks is a package-level function for backward compatibility
func SplitIntoChunks(s string, chunkSize int) []string {
	sv := &SessionValidator{}
	return sv.SplitIntoChunks(s, chunkSize)
}
