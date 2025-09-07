package validators

import (
	"strings"
	"testing"
	"time"
)

// MockSessionData for testing
type MockSessionData struct {
	authenticated        bool
	email                string
	accessToken          string
	idToken              string
	refreshToken         string
	refreshTokenIssuedAt time.Time
}

func (msd *MockSessionData) GetAuthenticated() bool             { return msd.authenticated }
func (msd *MockSessionData) GetEmail() string                   { return msd.email }
func (msd *MockSessionData) GetAccessToken() string             { return msd.accessToken }
func (msd *MockSessionData) GetIDToken() string                 { return msd.idToken }
func (msd *MockSessionData) GetRefreshToken() string            { return msd.refreshToken }
func (msd *MockSessionData) GetRefreshTokenIssuedAt() time.Time { return msd.refreshTokenIssuedAt }

// TestNewSessionValidator tests validator creation
func TestNewSessionValidator(t *testing.T) {
	validator := NewSessionValidator()
	if validator == nil {
		t.Fatal("NewSessionValidator should not return nil")
	}
}

// TestValidateChunkSize tests chunk size validation
func TestValidateChunkSize(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name        string
		chunkData   string
		expectValid bool
		description string
	}{
		{
			name:        "Small chunk",
			chunkData:   "small_chunk_data",
			expectValid: true,
			description: "Small chunks should be valid",
		},
		{
			name:        "Medium chunk",
			chunkData:   strings.Repeat("a", 1000),
			expectValid: true,
			description: "Medium chunks should be valid",
		},
		{
			name:        "Large chunk",
			chunkData:   strings.Repeat("a", 2000),
			expectValid: true,
			description: "Large chunks within limits should be valid",
		},
		{
			name:        "Oversized chunk",
			chunkData:   strings.Repeat("a", 4000),
			expectValid: false,
			description: "Oversized chunks should be invalid",
		},
		{
			name:        "Empty chunk",
			chunkData:   "",
			expectValid: true,
			description: "Empty chunks should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validator.ValidateChunkSize(tt.chunkData)

			if isValid != tt.expectValid {
				t.Errorf("Validation mismatch for %s: expected valid=%v, got valid=%v",
					tt.description, tt.expectValid, isValid)
			}
		})
	}
}

// TestIsCorruptionMarker tests corruption marker detection
func TestIsCorruptionMarker(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name            string
		data            string
		expectCorrupted bool
		description     string
	}{
		{
			name:            "Normal data",
			data:            "normal_token_data",
			expectCorrupted: false,
			description:     "Normal data should not be marked as corrupted",
		},
		{
			name:            "Empty data",
			data:            "",
			expectCorrupted: false,
			description:     "Empty data should not be marked as corrupted",
		},
		{
			name:            "Corruption marker test",
			data:            "__CORRUPTION_MARKER_TEST__",
			expectCorrupted: true,
			description:     "Known corruption markers should be detected",
		},
		{
			name:            "Invalid base64 marker",
			data:            "__INVALID_BASE64_DATA__",
			expectCorrupted: true,
			description:     "Invalid base64 markers should be detected",
		},
		{
			name:            "Corrupted chunk marker",
			data:            "__CORRUPTED_CHUNK_DATA__",
			expectCorrupted: true,
			description:     "Corrupted chunk markers should be detected",
		},
		{
			name:            "Invalid characters",
			data:            "!@#$%^&*()",
			expectCorrupted: true,
			description:     "Invalid character patterns should be detected",
		},
		{
			name:            "Corrupted tag",
			data:            "<<<CORRUPTED>>>",
			expectCorrupted: true,
			description:     "Corruption tags should be detected",
		},
		{
			name:            "Valid JWT-like token",
			data:            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectCorrupted: false,
			description:     "Valid JWT-like tokens should not be marked as corrupted",
		},
		{
			name:            "Short data with invalid chars",
			data:            "abc!def",
			expectCorrupted: false,
			description:     "Short data with invalid chars should not be marked as corrupted",
		},
		{
			name:            "Long data with invalid chars",
			data:            "this_is_long_data_with!invalid@chars#",
			expectCorrupted: true,
			description:     "Long data with invalid chars should be marked as corrupted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isCorrupted := validator.IsCorruptionMarker(tt.data)

			if isCorrupted != tt.expectCorrupted {
				t.Errorf("Corruption detection mismatch for %s: expected corrupted=%v, got corrupted=%v",
					tt.description, tt.expectCorrupted, isCorrupted)
			}
		})
	}
}

// TestValidateTokenFormat tests token format validation
func TestValidateTokenFormat(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name        string
		token       string
		tokenType   string
		expectError bool
		description string
	}{
		{
			name:        "Valid JWT token",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			tokenType:   "access",
			expectError: false,
			description: "Valid JWT tokens should pass validation",
		},
		{
			name:        "Empty token",
			token:       "",
			tokenType:   "access",
			expectError: false,
			description: "Empty tokens should not cause errors",
		},
		{
			name:        "Token with too few parts",
			token:       "header.payload",
			tokenType:   "access",
			expectError: true,
			description: "Tokens with too few parts should fail validation",
		},
		{
			name:        "Token with too many parts",
			token:       "header.payload.signature.extra",
			tokenType:   "access",
			expectError: true,
			description: "Tokens with too many parts should fail validation",
		},
		{
			name:        "Token with empty part",
			token:       "header..signature",
			tokenType:   "id",
			expectError: true,
			description: "Tokens with empty parts should fail validation",
		},
		{
			name:        "Token with only dots",
			token:       "..",
			tokenType:   "refresh",
			expectError: true,
			description: "Tokens with only dots should fail validation",
		},
		{
			name:        "Single part token",
			token:       "just_one_part",
			tokenType:   "access",
			expectError: true,
			description: "Single part tokens should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateTokenFormat(tt.token, tt.tokenType)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}

			// Check error details if error is expected
			if tt.expectError && err != nil {
				if !strings.Contains(err.Error(), tt.tokenType) {
					t.Errorf("Error should contain token type '%s': %v", tt.tokenType, err)
				}
			}
		})
	}
}

// TestValidateSessionIntegrity tests session integrity validation
func TestValidateSessionIntegrity(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name        string
		sessionData SessionData
		expectError bool
		errorCheck  func(error) bool
		description string
	}{
		{
			name: "Valid authenticated session",
			sessionData: &MockSessionData{
				authenticated: true,
				email:         "user@example.com",
				accessToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
				idToken:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
				refreshToken:  "valid_refresh_token_12345",
			},
			expectError: false,
			description: "Valid authenticated session should pass validation",
		},
		{
			name: "Valid unauthenticated session",
			sessionData: &MockSessionData{
				authenticated: false,
				email:         "",
				accessToken:   "",
				idToken:       "",
				refreshToken:  "",
			},
			expectError: false,
			description: "Valid unauthenticated session should pass validation",
		},
		{
			name: "Authenticated session without email",
			sessionData: &MockSessionData{
				authenticated: true,
				email:         "",
				accessToken:   "some_token",
			},
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "authentication inconsistency")
			},
			description: "Authenticated session without email should fail validation",
		},
		{
			name: "Session with invalid access token format",
			sessionData: &MockSessionData{
				authenticated: true,
				email:         "user@example.com",
				accessToken:   "invalid.token", // Only 2 parts
			},
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "invalid JWT format")
			},
			description: "Session with invalid access token should fail validation",
		},
		{
			name: "Session with invalid ID token format",
			sessionData: &MockSessionData{
				authenticated: true,
				email:         "user@example.com",
				accessToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
				idToken:       "invalid_id_token",
			},
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "invalid JWT format")
			},
			description: "Session with invalid ID token should fail validation",
		},
		{
			name:        "Nil session data",
			sessionData: nil,
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "nil session data")
			},
			description: "Nil session data should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSessionIntegrity(tt.sessionData)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}

			// Check error details if error is expected and errorCheck is provided
			if tt.expectError && err != nil && tt.errorCheck != nil {
				if !tt.errorCheck(err) {
					t.Errorf("Error check failed for %s: %v", tt.description, err)
				}
			}
		})
	}
}

// TestValidateSessionTiming tests session timing validation
func TestValidateSessionTiming(t *testing.T) {
	validator := NewSessionValidator()

	now := time.Now()

	tests := []struct {
		name        string
		sessionData SessionData
		maxAge      time.Duration
		expectError bool
		errorCheck  func(error) bool
		description string
	}{
		{
			name: "Recent refresh token",
			sessionData: &MockSessionData{
				authenticated:        true,
				email:                "user@example.com",
				refreshToken:         "valid_token",
				refreshTokenIssuedAt: now.Add(-1 * time.Hour),
			},
			maxAge:      24 * time.Hour,
			expectError: false,
			description: "Recent refresh tokens should be valid",
		},
		{
			name: "Old but valid refresh token",
			sessionData: &MockSessionData{
				authenticated:        true,
				email:                "user@example.com",
				refreshToken:         "valid_token",
				refreshTokenIssuedAt: now.Add(-12 * time.Hour),
			},
			maxAge:      24 * time.Hour,
			expectError: false,
			description: "Old but valid refresh tokens should be accepted",
		},
		{
			name: "Expired refresh token",
			sessionData: &MockSessionData{
				authenticated:        true,
				email:                "user@example.com",
				refreshToken:         "expired_token",
				refreshTokenIssuedAt: now.Add(-48 * time.Hour),
			},
			maxAge:      24 * time.Hour,
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "expired")
			},
			description: "Expired refresh tokens should fail validation",
		},
		{
			name:        "Nil session data",
			sessionData: nil,
			maxAge:      24 * time.Hour,
			expectError: true,
			errorCheck: func(err error) bool {
				return strings.Contains(err.Error(), "nil session data")
			},
			description: "Nil session data should fail timing validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSessionTiming(tt.sessionData, tt.maxAge)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}

			// Check error details if error is expected and errorCheck is provided
			if tt.expectError && err != nil && tt.errorCheck != nil {
				if !tt.errorCheck(err) {
					t.Errorf("Error check failed for %s: %v", tt.description, err)
				}
			}
		})
	}
}

// TestValidationError tests the ValidationError type
func TestValidationError(t *testing.T) {
	err := &ValidationError{
		Type:    "test",
		Reason:  "test reason",
		Details: "test details",
	}

	expectedMessage := "test validation error: test reason - test details"
	if err.Error() != expectedMessage {
		t.Errorf("Expected error message %q, got %q", expectedMessage, err.Error())
	}
}

// TestCorruptionResistance tests comprehensive corruption resistance
func TestCorruptionResistance(t *testing.T) {
	validator := NewSessionValidator()

	// Test various corruption scenarios
	corruptionScenarios := []struct {
		name        string
		data        string
		description string
	}{
		{
			name:        "Truncated JWT",
			data:        "eyJhbGciOiJIUzI1NiIsInR5cCI",
			description: "Truncated tokens should be handled gracefully",
		},
		{
			name:        "Malformed base64",
			data:        "not_valid_base64!@#$",
			description: "Malformed base64 should be detected",
		},
		{
			name:        "Binary data",
			data:        string([]byte{0, 1, 2, 3, 255}),
			description: "Binary data should be handled",
		},
		{
			name:        "Very long corruption marker",
			data:        strings.Repeat("CORRUPT", 100),
			description: "Long corruption markers should be handled",
		},
	}

	for _, scenario := range corruptionScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Test corruption marker detection
			isCorrupted := validator.IsCorruptionMarker(scenario.data)
			t.Logf("Data marked as corrupted: %v for %s", isCorrupted, scenario.description)

			// Test token format validation
			err := validator.ValidateTokenFormat(scenario.data, "test")
			if err != nil {
				t.Logf("Token format validation failed (expected): %v", err)
			}

			// Test chunk size validation
			isValidSize := validator.ValidateChunkSize(scenario.data)
			t.Logf("Chunk size valid: %v for %s", isValidSize, scenario.description)
		})
	}
}

// BenchmarkValidateChunkSize benchmarks chunk size validation
func BenchmarkValidateChunkSize(b *testing.B) {
	validator := NewSessionValidator()
	testData := strings.Repeat("a", 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateChunkSize(testData)
	}
}

// BenchmarkIsCorruptionMarker benchmarks corruption marker detection
func BenchmarkIsCorruptionMarker(b *testing.B) {
	validator := NewSessionValidator()
	testData := "normal_token_data_that_should_not_be_corrupted"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.IsCorruptionMarker(testData)
	}
}

// BenchmarkValidateTokenFormat benchmarks token format validation
func BenchmarkValidateTokenFormat(b *testing.B) {
	validator := NewSessionValidator()
	testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateTokenFormat(testToken, "access")
	}
}

// TestValidateEmailDomain tests email domain validation
func TestValidateEmailDomain(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name           string
		email          string
		allowedDomains map[string]struct{}
		expectError    bool
		errorCheck     func(error) bool
		description    string
	}{
		{
			name:           "Valid email with allowed domain",
			email:          "user@example.com",
			allowedDomains: map[string]struct{}{"example.com": {}, "test.com": {}},
			expectError:    false,
			description:    "Valid email with allowed domain should pass",
		},
		{
			name:           "Valid email with different allowed domain",
			email:          "admin@test.com",
			allowedDomains: map[string]struct{}{"example.com": {}, "test.com": {}},
			expectError:    false,
			description:    "Valid email with different allowed domain should pass",
		},
		{
			name:           "Empty email",
			email:          "",
			allowedDomains: map[string]struct{}{"example.com": {}},
			expectError:    true,
			errorCheck:     func(err error) bool { return strings.Contains(err.Error(), "empty email") },
			description:    "Empty email should fail validation",
		},
		{
			name:           "Email with disallowed domain",
			email:          "user@forbidden.com",
			allowedDomains: map[string]struct{}{"example.com": {}, "test.com": {}},
			expectError:    true,
			errorCheck:     func(err error) bool { return strings.Contains(err.Error(), "domain not allowed") },
			description:    "Email with disallowed domain should fail validation",
		},
		{
			name:           "Invalid email format - no @ symbol",
			email:          "userexample.com",
			allowedDomains: map[string]struct{}{"example.com": {}},
			expectError:    true,
			errorCheck:     func(err error) bool { return strings.Contains(err.Error(), "invalid email format") },
			description:    "Invalid email format should fail validation",
		},
		{
			name:           "Invalid email format - multiple @ symbols",
			email:          "user@example@com",
			allowedDomains: map[string]struct{}{"example.com": {}},
			expectError:    true,
			errorCheck:     func(err error) bool { return strings.Contains(err.Error(), "invalid email format") },
			description:    "Email with multiple @ symbols should fail validation",
		},
		{
			name:           "Email starting with @",
			email:          "@example.com",
			allowedDomains: map[string]struct{}{"example.com": {}},
			expectError:    false, // splits to ["", "example.com"], domain "example.com" is allowed
			description:    "Email starting with @ should pass if domain is allowed",
		},
		{
			name:           "Email ending with @ - empty domain allowed",
			email:          "user@",
			allowedDomains: map[string]struct{}{"": {}}, // Allow empty domain
			expectError:    false,                       // splits to ["user", ""], domain "" is in allowedDomains
			description:    "Email ending with @ should pass if empty domain is allowed",
		},
		{
			name:           "Email ending with @ - empty domain not allowed",
			email:          "user@",
			allowedDomains: map[string]struct{}{"example.com": {}}, // Empty domain not allowed
			expectError:    true,                                   // splits to ["user", ""], domain "" is not in allowedDomains
			errorCheck:     func(err error) bool { return strings.Contains(err.Error(), "domain not allowed") },
			description:    "Email ending with @ should fail if empty domain is not allowed",
		},
		{
			name:           "Valid email with no domain restrictions",
			email:          "user@anydomain.com",
			allowedDomains: map[string]struct{}{},
			expectError:    false,
			description:    "Email should pass when no domain restrictions exist",
		},
		{
			name:           "Valid email with nil domain restrictions",
			email:          "user@anydomain.com",
			allowedDomains: nil,
			expectError:    false,
			description:    "Email should pass when domain restrictions are nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateEmailDomain(tt.email, tt.allowedDomains)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}

			// Check error details if error is expected and errorCheck is provided
			if tt.expectError && err != nil && tt.errorCheck != nil {
				if !tt.errorCheck(err) {
					t.Errorf("Error check failed for %s: %v", tt.description, err)
				}
			}
		})
	}
}

// TestSplitIntoChunks tests string chunking functionality
func TestSplitIntoChunks(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name           string
		input          string
		chunkSize      int
		expectedChunks int
		description    string
	}{
		{
			name:           "Empty string",
			input:          "",
			chunkSize:      100,
			expectedChunks: 0,
			description:    "Empty string should produce no chunks",
		},
		{
			name:           "Short string",
			input:          "short",
			chunkSize:      100,
			expectedChunks: 1,
			description:    "Short string should produce one chunk",
		},
		{
			name:           "String exactly at chunk size",
			input:          strings.Repeat("a", 100),
			chunkSize:      100,
			expectedChunks: 1,
			description:    "String exactly at chunk size should produce one chunk",
		},
		{
			name:           "String larger than chunk size",
			input:          strings.Repeat("a", 250),
			chunkSize:      100,
			expectedChunks: 3,
			description:    "String larger than chunk size should be split",
		},
		{
			name:           "Large string with small chunks",
			input:          strings.Repeat("x", 1000),
			chunkSize:      50,
			expectedChunks: 20,
			description:    "Large string should be split into many chunks",
		},
		{
			name:           "Chunk size larger than max cookie size",
			input:          strings.Repeat("a", 2000),
			chunkSize:      2000, // Larger than maxCookieSize (1200)
			expectedChunks: 2,    // Should be limited by maxCookieSize
			description:    "Chunk size should be limited to max cookie size",
		},
		{
			name:           "Very small chunk size",
			input:          "testing",
			chunkSize:      1,
			expectedChunks: 7,
			description:    "Very small chunk size should create many chunks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := validator.SplitIntoChunks(tt.input, tt.chunkSize)

			if len(chunks) != tt.expectedChunks {
				t.Errorf("Expected %d chunks for %s, got %d", tt.expectedChunks, tt.description, len(chunks))
			}

			// Verify chunks reconstruct the original string
			reconstructed := strings.Join(chunks, "")
			if reconstructed != tt.input {
				t.Errorf("Reconstructed string doesn't match original for %s", tt.description)
			}

			// Verify no chunk exceeds effective size limit
			effectiveChunkSize := min(tt.chunkSize, maxCookieSize)
			for i, chunk := range chunks {
				if len(chunk) > effectiveChunkSize {
					t.Errorf("Chunk %d exceeds effective size limit (%d): got %d", i, effectiveChunkSize, len(chunk))
				}
			}
		})
	}
}

// TestValidateChunks tests chunk validation
func TestValidateChunks(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name        string
		chunks      []string
		expectError bool
		errorCheck  func(error) bool
		description string
	}{
		{
			name:        "Valid chunks",
			chunks:      []string{"chunk1", "chunk2", "chunk3"},
			expectError: false,
			description: "Valid chunks should pass validation",
		},
		{
			name:        "Empty chunk array",
			chunks:      []string{},
			expectError: false,
			description: "Empty chunk array should pass validation",
		},
		{
			name:        "Single valid chunk",
			chunks:      []string{"single_chunk"},
			expectError: false,
			description: "Single valid chunk should pass validation",
		},
		{
			name:        "Chunks with empty chunk",
			chunks:      []string{"chunk1", "", "chunk3"},
			expectError: true,
			errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "empty chunk") },
			description: "Empty chunk should fail validation",
		},
		{
			name:        "Chunks with oversized chunk",
			chunks:      []string{"chunk1", strings.Repeat("a", 5000), "chunk3"},
			expectError: true,
			errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "chunk too large") },
			description: "Oversized chunk should fail validation",
		},
		{
			name:        "Chunks with corruption marker",
			chunks:      []string{"chunk1", "__CORRUPTION_MARKER_TEST__", "chunk3"},
			expectError: true,
			errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "corrupted chunk") },
			description: "Corrupted chunk should fail validation",
		},
		{
			name:        "Chunks with invalid characters",
			chunks:      []string{"chunk1", "chunk_with_invalid!@#$%^&*()_chars", "chunk3"},
			expectError: true,
			errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "corrupted chunk") },
			description: "Chunk with invalid characters should fail validation",
		},
		{
			name:        "Multiple invalid chunks",
			chunks:      []string{"", strings.Repeat("x", 5000), "__CORRUPTED_CHUNK_DATA__"},
			expectError: true,
			errorCheck:  func(err error) bool { return strings.Contains(err.Error(), "empty chunk") }, // First error encountered
			description: "Multiple invalid chunks should fail on first error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateChunks(tt.chunks)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}

			// Check error details if error is expected and errorCheck is provided
			if tt.expectError && err != nil && tt.errorCheck != nil {
				if !tt.errorCheck(err) {
					t.Errorf("Error check failed for %s: %v", tt.description, err)
				}
			}
		})
	}
}

// TestMinFunction tests the min utility function
func TestMinFunction(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected int
	}{
		{
			name:     "a smaller than b",
			a:        5,
			b:        10,
			expected: 5,
		},
		{
			name:     "b smaller than a",
			a:        15,
			b:        7,
			expected: 7,
		},
		{
			name:     "equal values",
			a:        42,
			b:        42,
			expected: 42,
		},
		{
			name:     "negative values",
			a:        -10,
			b:        -5,
			expected: -10,
		},
		{
			name:     "zero values",
			a:        0,
			b:        0,
			expected: 0,
		},
		{
			name:     "mixed positive and negative",
			a:        -3,
			b:        2,
			expected: -3,
		},
		{
			name:     "large numbers",
			a:        1000000,
			b:        999999,
			expected: 999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := min(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("min(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestPackageLevelFunctions tests package-level backward compatibility functions
func TestPackageLevelFunctions(t *testing.T) {
	t.Run("ValidateChunkSize package function", func(t *testing.T) {
		// Test package-level ValidateChunkSize function
		testData := "test_chunk_data"
		result := ValidateChunkSize(testData)
		if !result {
			t.Error("Package-level ValidateChunkSize should validate small chunks")
		}

		// Test with large data
		largeData := strings.Repeat("a", 5000)
		result = ValidateChunkSize(largeData)
		if result {
			t.Error("Package-level ValidateChunkSize should reject oversized chunks")
		}
	})

	t.Run("IsCorruptionMarker package function", func(t *testing.T) {
		// Test package-level IsCorruptionMarker function
		normalData := "normal_data"
		result := IsCorruptionMarker(normalData)
		if result {
			t.Error("Package-level IsCorruptionMarker should not detect corruption in normal data")
		}

		// Test with corruption marker
		corruptData := "__CORRUPTION_MARKER_TEST__"
		result = IsCorruptionMarker(corruptData)
		if !result {
			t.Error("Package-level IsCorruptionMarker should detect corruption markers")
		}
	})

	t.Run("SplitIntoChunks package function", func(t *testing.T) {
		// Test package-level SplitIntoChunks function
		testString := "test_string_for_chunking"
		chunks := SplitIntoChunks(testString, 5)

		if len(chunks) == 0 {
			t.Error("Package-level SplitIntoChunks should produce chunks")
		}

		// Verify chunks reconstruct original
		reconstructed := strings.Join(chunks, "")
		if reconstructed != testString {
			t.Error("Package-level SplitIntoChunks chunks should reconstruct original string")
		}
	})
}

// TestEdgeCasesAndBoundaryConditions tests various edge cases
func TestEdgeCasesAndBoundaryConditions(t *testing.T) {
	validator := NewSessionValidator()

	t.Run("Chunk size boundary conditions", func(t *testing.T) {
		// Test chunk size exactly at maxBrowserCookieSize estimation
		boundaryData := strings.Repeat("a", 2333) // Should result in ~3500 estimated encoded size
		result := validator.ValidateChunkSize(boundaryData)
		// This should be close to the boundary
		t.Logf("Boundary chunk validation result: %v", result)
	})

	t.Run("Email domain with edge case domains", func(t *testing.T) {
		// Test with very short domain
		err := validator.ValidateEmailDomain("user@a.b", map[string]struct{}{"a.b": {}})
		if err != nil {
			t.Errorf("Should accept very short domains: %v", err)
		}

		// Test with very long domain
		longDomain := strings.Repeat("long", 50) + ".com"
		err = validator.ValidateEmailDomain("user@"+longDomain, map[string]struct{}{longDomain: {}})
		if err != nil {
			t.Errorf("Should accept very long domains: %v", err)
		}
	})

	t.Run("Chunking with exact boundary sizes", func(t *testing.T) {
		// Test with exactly maxCookieSize
		testString := strings.Repeat("a", maxCookieSize)
		chunks := validator.SplitIntoChunks(testString, maxCookieSize)

		if len(chunks) != 1 {
			t.Errorf("String of exactly maxCookieSize should produce 1 chunk, got %d", len(chunks))
		}

		// Test with maxCookieSize + 1
		testString = strings.Repeat("a", maxCookieSize+1)
		chunks = validator.SplitIntoChunks(testString, maxCookieSize)

		if len(chunks) != 2 {
			t.Errorf("String of maxCookieSize+1 should produce 2 chunks, got %d", len(chunks))
		}
	})
}

// TestRefreshTokenValidationEdgeCases tests edge cases for refresh token validation
func TestRefreshTokenValidationEdgeCases(t *testing.T) {
	validator := NewSessionValidator()

	tests := []struct {
		name        string
		sessionData SessionData
		expectError bool
		description string
	}{
		{
			name: "Session with empty refresh token but set",
			sessionData: &MockSessionData{
				authenticated: true,
				email:         "user@example.com",
				refreshToken:  "", // Empty but explicitly set in the test context
			},
			expectError: false, // Empty tokens are not validated for length in current implementation
			description: "Empty refresh token should not cause validation error",
		},
		{
			name: "Session with only refresh token",
			sessionData: &MockSessionData{
				authenticated: true,
				email:         "user@example.com",
				accessToken:   "",
				idToken:       "",
				refreshToken:  "valid_refresh_token_12345",
			},
			expectError: false,
			description: "Session with only refresh token should be valid",
		},
		{
			name: "Session with zero-time refresh token issue time",
			sessionData: &MockSessionData{
				authenticated:        true,
				email:                "user@example.com",
				refreshToken:         "valid_token",
				refreshTokenIssuedAt: time.Time{}, // Zero time
			},
			expectError: false, // Zero time is not validated as expired
			description: "Session with zero-time refresh token issue time should be valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateSessionIntegrity(tt.sessionData)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, got nil", tt.description)
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}
		})
	}
}

// BenchmarkValidateEmailDomain benchmarks email domain validation
func BenchmarkValidateEmailDomain(b *testing.B) {
	validator := NewSessionValidator()
	allowedDomains := map[string]struct{}{
		"example.com": {},
		"test.com":    {},
		"domain.org":  {},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateEmailDomain("user@example.com", allowedDomains)
	}
}

// BenchmarkSplitIntoChunks benchmarks string chunking
func BenchmarkSplitIntoChunks(b *testing.B) {
	validator := NewSessionValidator()
	testString := strings.Repeat("test_data_", 1000) // 10KB string

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.SplitIntoChunks(testString, 100)
	}
}

// BenchmarkValidateChunks benchmarks chunk validation
func BenchmarkValidateChunks(b *testing.B) {
	validator := NewSessionValidator()
	chunks := []string{
		"chunk_1_data",
		"chunk_2_data",
		"chunk_3_data",
		"chunk_4_data",
		"chunk_5_data",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateChunks(chunks)
	}
}

// BenchmarkValidateSessionIntegrity benchmarks session integrity validation
func BenchmarkValidateSessionIntegrity(b *testing.B) {
	validator := NewSessionValidator()
	sessionData := &MockSessionData{
		authenticated: true,
		email:         "user@example.com",
		accessToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		idToken:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		refreshToken:  "valid_refresh_token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateSessionIntegrity(sessionData)
	}
}
