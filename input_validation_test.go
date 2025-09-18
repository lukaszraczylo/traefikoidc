package traefikoidc

import (
	"strings"
	"testing"
)

func TestInputValidator(t *testing.T) {
	config := DefaultInputValidationConfig()
	logger := NewLogger("debug")
	validator, err := NewInputValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	t.Run("Valid token validation", func(t *testing.T) {
		validToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHs3UjpMC6M6FNqI2J-I2NxrragtnDxGxdJUvDERDQVHzeNlVQiuqWDEeO_O-0KptafbfyuGqfQxH_6dp2_MeFpAc"

		result := validator.ValidateToken(validToken)
		if !result.IsValid {
			t.Errorf("Expected valid token to pass validation, got errors: %v", result.Errors)
		}
	})

	t.Run("Invalid token validation", func(t *testing.T) {
		invalidTokens := []string{
			"",              // Empty token
			"invalid.token", // Invalid format
			"a.b",           // Too few parts
			"a.b.c.d",       // Too many parts
		}

		for _, token := range invalidTokens {
			result := validator.ValidateToken(token)
			if result.IsValid {
				t.Errorf("Expected invalid token '%s' to fail validation", token)
			}
		}
	})

	t.Run("Valid email validation", func(t *testing.T) {
		validEmails := []string{
			"user@example.com",
			"test.email@domain.co.uk",
			"user123@test-domain.org",
		}

		for _, email := range validEmails {
			result := validator.ValidateEmail(email)
			if !result.IsValid {
				t.Errorf("Expected valid email '%s' to pass validation, got errors: %v", email, result.Errors)
			}
		}
	})

	t.Run("Invalid email validation", func(t *testing.T) {
		invalidEmails := []string{
			"",                        // Empty
			"invalid",                 // No @ symbol
			"@domain.com",             // No local part
			"user@",                   // No domain
			"user@domain",             // No TLD
			"user..double@domain.com", // Double dots
		}

		for _, email := range invalidEmails {
			result := validator.ValidateEmail(email)
			if result.IsValid {
				t.Errorf("Expected invalid email '%s' to fail validation", email)
			}
		}
	})

	t.Run("Valid URL validation", func(t *testing.T) {
		validURLs := []string{
			"https://example.com",
			"https://sub.domain.com/path",
			"https://localhost:8080/callback",
		}

		for _, url := range validURLs {
			result := validator.ValidateURL(url)
			if !result.IsValid {
				t.Errorf("Expected valid URL '%s' to pass validation, got errors: %v", url, result.Errors)
			}
		}
	})

	t.Run("Invalid URL validation", func(t *testing.T) {
		invalidURLs := []string{
			"",                  // Empty
			"not-a-url",         // Invalid format
			"ftp://example.com", // Wrong scheme
			"https://",          // No host
		}

		for _, url := range invalidURLs {
			result := validator.ValidateURL(url)
			if result.IsValid {
				t.Errorf("Expected invalid URL '%s' to fail validation", url)
			}
		}
	})

	t.Run("Valid username validation", func(t *testing.T) {
		validUsernames := []string{
			"user123",
			"test_user",
			"user-name",
		}

		for _, username := range validUsernames {
			result := validator.ValidateUsername(username)
			if !result.IsValid {
				t.Errorf("Expected valid username '%s' to pass validation, got errors: %v", username, result.Errors)
			}
		}
	})

	t.Run("Invalid username validation", func(t *testing.T) {
		invalidUsernames := []string{
			"",                       // Empty
			"a",                      // Too short
			strings.Repeat("a", 100), // Too long
			"user name",              // Spaces
		}

		for _, username := range invalidUsernames {
			result := validator.ValidateUsername(username)
			if result.IsValid {
				t.Errorf("Expected invalid username '%s' to fail validation", username)
			}
		}
	})

	t.Run("Valid claim validation", func(t *testing.T) {
		validClaims := map[string]string{
			"sub":   "user123",
			"email": "user@example.com",
			"name":  "John Doe",
		}

		for key, value := range validClaims {
			result := validator.ValidateClaim(key, value)
			if !result.IsValid {
				t.Errorf("Expected valid claim '%s'='%s' to pass validation, got errors: %v", key, value, result.Errors)
			}
		}
	})

	t.Run("Invalid claim validation", func(t *testing.T) {
		invalidClaims := map[string]string{
			"":         "value",                    // Empty key
			"long_key": strings.Repeat("a", 10000), // Too long value
		}

		for key, value := range invalidClaims {
			result := validator.ValidateClaim(key, value)
			if result.IsValid {
				t.Errorf("Expected invalid claim '%s'='%s' to fail validation", key, value)
			}
		}
	})

	t.Run("Valid header validation", func(t *testing.T) {
		validHeaders := map[string]string{
			"Authorization": "Bearer token123",
			"Content-Type":  "application/json",
			"X-Custom":      "custom-value",
		}

		for key, value := range validHeaders {
			result := validator.ValidateHeader(key, value)
			if !result.IsValid {
				t.Errorf("Expected valid header '%s'='%s' to pass validation, got errors: %v", key, value, result.Errors)
			}
		}
	})

	t.Run("Invalid header validation", func(t *testing.T) {
		invalidHeaders := map[string]string{
			"":             "value",     // Empty key
			"Invalid\nKey": "value",     // Control characters in key
			"key":          "value\r\n", // Control characters in value
		}

		for key, value := range invalidHeaders {
			result := validator.ValidateHeader(key, value)
			if result.IsValid {
				t.Errorf("Expected invalid header '%s'='%s' to fail validation", key, value)
			}
		}
	})
}

func TestSanitizeInput(t *testing.T) {
	config := DefaultInputValidationConfig()
	logger := NewLogger("debug")
	validator, err := NewInputValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
		maxLen   int
	}{
		{
			name:     "Normal text",
			input:    "Hello World",
			maxLen:   100,
			expected: "Hello World",
		},
		{
			name:     "Control characters",
			input:    "text\x00with\x01control\x02chars",
			maxLen:   100,
			expected: "textwithcontrolchars",
		},
		{
			name:     "Truncation",
			input:    "very long text",
			maxLen:   5,
			expected: "very ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.SanitizeInput(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("Expected sanitized input '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestValidateBoundaryValues(t *testing.T) {
	config := DefaultInputValidationConfig()
	logger := NewLogger("debug")
	validator, err := NewInputValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	t.Run("Valid boundary values", func(t *testing.T) {
		validValues := []interface{}{
			int(50),
			int64(100),
			float64(75.5),
		}

		for _, value := range validValues {
			result := validator.ValidateBoundaryValues(value, 1, 1000)
			if !result.IsValid {
				t.Errorf("Expected valid boundary value %v to pass validation, got errors: %v", value, result.Errors)
			}
		}
	})

	t.Run("Invalid boundary values", func(t *testing.T) {
		invalidValues := []interface{}{
			int(-1),
			int64(2000),
			"not a number",
		}

		for _, value := range invalidValues {
			result := validator.ValidateBoundaryValues(value, 1, 1000)
			if result.IsValid {
				t.Errorf("Expected invalid boundary value %v to fail validation", value)
			}
		}
	})
}

func TestDefaultInputValidationConfig(t *testing.T) {
	config := DefaultInputValidationConfig()

	if config.MaxTokenLength <= 0 {
		t.Error("Expected positive MaxTokenLength")
	}
	if config.MaxEmailLength <= 0 {
		t.Error("Expected positive MaxEmailLength")
	}
	if config.MaxUsernameLength <= 0 {
		t.Error("Expected positive MaxUsernameLength")
	}
	if config.MaxClaimLength <= 0 {
		t.Error("Expected positive MaxClaimLength")
	}
	if config.MaxHeaderLength <= 0 {
		t.Error("Expected positive MaxHeaderLength")
	}
	if !config.StrictMode {
		t.Error("Expected StrictMode to be true by default")
	}
}

func TestInputValidationHelpers(t *testing.T) {
	config := DefaultInputValidationConfig()
	logger := NewLogger("debug")
	validator, err := NewInputValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	t.Run("isValidBase64URL", func(t *testing.T) {
		validBase64URL := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
		if !validator.isValidBase64URL(validBase64URL) {
			t.Error("Expected valid base64url to be recognized")
		}

		invalidBase64URL := "invalid+base64/with+padding="
		if validator.isValidBase64URL(invalidBase64URL) {
			t.Error("Expected invalid base64url to be rejected")
		}
	})

	t.Run("containsNullBytes", func(t *testing.T) {
		withNull := "text\x00with\x00null"
		if !validator.containsNullBytes(withNull) {
			t.Error("Expected string with null bytes to be detected")
		}

		withoutNull := "normal text"
		if validator.containsNullBytes(withoutNull) {
			t.Error("Expected string without null bytes to pass")
		}
	})

	t.Run("containsControlCharacters", func(t *testing.T) {
		withControl := "text\x01with\x02control"
		if !validator.containsControlCharacters(withControl) {
			t.Error("Expected string with control characters to be detected")
		}

		withoutControl := "normal text"
		if validator.containsControlCharacters(withoutControl) {
			t.Error("Expected string without control characters to pass")
		}
	})

	t.Run("containsPathTraversal", func(t *testing.T) {
		withTraversal := "../../../etc/passwd"
		if !validator.containsPathTraversal(withTraversal) {
			t.Error("Expected path traversal to be detected")
		}

		normalPath := "/normal/path"
		if validator.containsPathTraversal(normalPath) {
			t.Error("Expected normal path to pass")
		}
	})

	t.Run("detectSecurityRisk", func(t *testing.T) {
		riskyInputs := []string{
			"<script>alert('xss')</script>",
			"'; DROP TABLE users; --",
			"javascript:alert('xss')",
		}

		for _, input := range riskyInputs {
			if validator.detectSecurityRisk(input) == "" {
				t.Errorf("Expected security risk to be detected in: %s", input)
			}
		}

		safeInput := "normal safe text"
		if validator.detectSecurityRisk(safeInput) != "" {
			t.Error("Expected safe input to pass security check")
		}
	})
}

func TestInputValidationEdgeCases(t *testing.T) {
	config := DefaultInputValidationConfig()
	logger := NewLogger("debug")
	validator, err := NewInputValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	t.Run("Empty inputs", func(t *testing.T) {
		// Most validations should reject empty inputs
		if result := validator.ValidateToken(""); result.IsValid {
			t.Error("Expected empty token to be rejected")
		}
		if result := validator.ValidateEmail(""); result.IsValid {
			t.Error("Expected empty email to be rejected")
		}
		if result := validator.ValidateURL(""); result.IsValid {
			t.Error("Expected empty URL to be rejected")
		}
		if result := validator.ValidateUsername(""); result.IsValid {
			t.Error("Expected empty username to be rejected")
		}
	})

	t.Run("Very long inputs", func(t *testing.T) {
		longString := strings.Repeat("a", 10000)

		if result := validator.ValidateEmail(longString + "@domain.com"); result.IsValid {
			t.Error("Expected very long email to be rejected")
		}
		if result := validator.ValidateUsername(longString); result.IsValid {
			t.Error("Expected very long username to be rejected")
		}
	})

	t.Run("Unicode handling", func(t *testing.T) {
		unicodeEmail := "用户@example.com"
		// Should handle unicode gracefully
		validator.ValidateEmail(unicodeEmail) // Don't fail on unicode

		unicodeUsername := "用户名"
		validator.ValidateUsername(unicodeUsername) // Don't fail on unicode
	})
}

// TestInputValidatorValidateToken tests comprehensive token validation
func TestInputValidatorValidateToken(t *testing.T) {
	config := DefaultInputValidationConfig()
	validator, _ := NewInputValidator(config, newNoOpLogger())

	tests := []struct {
		name        string
		token       string
		expectValid bool
		description string
	}{
		{
			name:        "ValidJWTToken",
			token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjJ9.signature",
			expectValid: true,
			description: "Valid JWT token should pass validation",
		},
		{
			name:        "InvalidOpaqueToken",
			token:       "opaque_access_token_that_is_long_enough_to_pass",
			expectValid: false,
			description: "Opaque token (non-JWT) should fail validation",
		},
		{
			name:        "EmptyToken",
			token:       "",
			expectValid: false,
			description: "Empty token should fail validation",
		},
		{
			name:        "TokenWithNullBytes",
			token:       "token_with_null\x00byte",
			expectValid: false,
			description: "Token with null bytes should fail validation",
		},
		{
			name:        "TokenTooLong",
			token:       strings.Repeat("a", config.MaxTokenLength+1),
			expectValid: false,
			description: "Token exceeding max length should fail validation",
		},
		{
			name:        "TokenWithControlCharacters",
			token:       "token_with_control\x01character",
			expectValid: false,
			description: "Token with control characters should fail validation",
		},
		{
			name:        "TokenWithHighUnicode",
			token:       "token_with_unicode_\uffff",
			expectValid: false,
			description: "Token with high unicode characters should fail validation",
		},
		{
			name:        "MaliciousJWTWithExtraData",
			token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig.malicious_extra",
			expectValid: false,
			description: "JWT with extra malicious data should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateToken(tt.token)

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v. %s", tt.expectValid, result.IsValid, tt.description)
			}
		})
	}
}

// TestInputValidatorValidateEmail tests email validation edge cases
func TestInputValidatorValidateEmail(t *testing.T) {
	config := DefaultInputValidationConfig()
	validator, _ := NewInputValidator(config, newNoOpLogger())

	tests := []struct {
		name        string
		email       string
		expectValid bool
		description string
	}{
		{
			name:        "ValidEmail",
			email:       "user@example.com",
			expectValid: true,
			description: "Valid email should pass validation",
		},
		{
			name:        "ValidEmailWithSubdomain",
			email:       "user@mail.example.com",
			expectValid: true,
			description: "Valid email with subdomain should pass validation",
		},
		{
			name:        "EmptyEmail",
			email:       "",
			expectValid: false,
			description: "Empty email should fail validation",
		},
		{
			name:        "EmailWithoutAtSign",
			email:       "userexample.com",
			expectValid: false,
			description: "Email without @ sign should fail validation",
		},
		{
			name:        "EmailWithNullBytes",
			email:       "user@example\x00.com",
			expectValid: false,
			description: "Email with null bytes should fail validation",
		},
		{
			name:        "EmailTooLong",
			email:       strings.Repeat("a", config.MaxEmailLength-10) + "@example.com",
			expectValid: false,
			description: "Email exceeding max length should fail validation",
		},
		{
			name:        "EmailWithControlCharacters",
			email:       "user\x01@example.com",
			expectValid: false,
			description: "Email with control characters should fail validation",
		},
		{
			name:        "MaliciousEmailWithScriptTag",
			email:       "user<script>@example.com",
			expectValid: false,
			description: "Email with script tag should fail validation",
		},
		{
			name:        "EmailWithUnicodeCharacters",
			email:       "üser@éxample.com",
			expectValid: false,
			description: "Email with unicode should fail basic validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateEmail(tt.email)

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v. %s", tt.expectValid, result.IsValid, tt.description)
			}
		})
	}
}

// TestInputValidatorValidateURL tests URL validation with security focus
func TestInputValidatorValidateURL(t *testing.T) {
	config := DefaultInputValidationConfig()
	validator, _ := NewInputValidator(config, newNoOpLogger())

	tests := []struct {
		name        string
		url         string
		expectValid bool
		description string
	}{
		{
			name:        "ValidHTTPSURL",
			url:         "https://example.com/path",
			expectValid: true,
			description: "Valid HTTPS URL should pass validation",
		},
		{
			name:        "ValidHTTPURL",
			url:         "http://example.com/path",
			expectValid: true,
			description: "Valid HTTP URL should pass validation",
		},
		{
			name:        "EmptyURL",
			url:         "",
			expectValid: false,
			description: "Empty URL should fail validation",
		},
		{
			name:        "InvalidScheme",
			url:         "ftp://example.com",
			expectValid: false,
			description: "URL with invalid scheme should fail validation",
		},
		{
			name:        "URLWithNullBytes",
			url:         "https://example\x00.com",
			expectValid: false,
			description: "URL with null bytes should fail validation",
		},
		{
			name:        "URLTooLong",
			url:         "https://" + strings.Repeat("a", config.MaxURLLength) + ".com",
			expectValid: false,
			description: "URL exceeding max length should fail validation",
		},
		{
			name:        "MalformedURL",
			url:         "https://",
			expectValid: false,
			description: "Malformed URL should fail validation",
		},
		{
			name:        "HTTPSLocalhostURL",
			url:         "https://localhost:8080/path",
			expectValid: true,
			description: "HTTPS localhost URL should be allowed for development",
		},
		{
			name:        "HTTPLocalhostURL",
			url:         "http://localhost:8080/path",
			expectValid: false,
			description: "HTTP localhost URL should fail validation for security",
		},
		{
			name:        "PrivateIPURL",
			url:         "https://192.168.1.1/path",
			expectValid: false,
			description: "Private IP URL should fail validation for security",
		},
		{
			name:        "JavaScriptURL",
			url:         "javascript:alert(1)",
			expectValid: false,
			description: "JavaScript URL should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateURL(tt.url)

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v. %s", tt.expectValid, result.IsValid, tt.description)
			}
		})
	}
}

// TestInputValidatorValidateClaim tests claim validation with security focus
func TestInputValidatorValidateClaim(t *testing.T) {
	config := DefaultInputValidationConfig()
	validator, _ := NewInputValidator(config, newNoOpLogger())

	tests := []struct {
		name        string
		claimName   string
		claimValue  string
		expectValid bool
		description string
	}{
		{
			name:        "ValidStringClaim",
			claimName:   "email",
			claimValue:  "user@example.com",
			expectValid: true,
			description: "Valid string claim should pass validation",
		},
		{
			name:        "ValidNumberClaim",
			claimName:   "exp",
			claimValue:  "1516239022",
			expectValid: true,
			description: "Valid number claim should pass validation",
		},
		{
			name:        "EmptyClaimName",
			claimName:   "",
			claimValue:  "value",
			expectValid: false,
			description: "Empty claim name should fail validation",
		},
		{
			name:        "ClaimWithNullBytes",
			claimName:   "test",
			claimValue:  "value\x00with_null",
			expectValid: false,
			description: "Claim with null bytes should fail validation",
		},
		{
			name:        "ClaimValueTooLong",
			claimName:   "test",
			claimValue:  strings.Repeat("a", config.MaxClaimLength+1),
			expectValid: false,
			description: "Claim value exceeding max length should fail validation",
		},
		{
			name:        "ClaimWithControlCharacters",
			claimName:   "test",
			claimValue:  "value\x01with_control",
			expectValid: false,
			description: "Claim with control characters should fail validation",
		},
		{
			name:        "MaliciousClaimWithHTML",
			claimName:   "test",
			claimValue:  "<script>alert('xss')</script>",
			expectValid: false,
			description: "Claim with HTML/script should fail validation",
		},
		{
			name:        "ClaimWithExcessiveUnicode",
			claimName:   "test",
			claimValue:  strings.Repeat("🚀", 100), // Many unicode chars
			expectValid: false,
			description: "Claim with excessive unicode should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateClaim(tt.claimName, tt.claimValue)

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v. %s", tt.expectValid, result.IsValid, tt.description)
			}
		})
	}
}

// TestInputValidatorValidateHeader tests HTTP header validation
func TestInputValidatorValidateHeader(t *testing.T) {
	config := DefaultInputValidationConfig()
	validator, _ := NewInputValidator(config, newNoOpLogger())

	tests := []struct {
		name        string
		headerName  string
		headerValue string
		expectValid bool
		description string
	}{
		{
			name:        "ValidHeader",
			headerName:  "Authorization",
			headerValue: "Bearer token123",
			expectValid: true,
			description: "Valid header should pass validation",
		},
		{
			name:        "ValidContentType",
			headerName:  "Content-Type",
			headerValue: "application/json",
			expectValid: true,
			description: "Valid content type header should pass validation",
		},
		{
			name:        "EmptyHeaderName",
			headerName:  "",
			headerValue: "value",
			expectValid: false,
			description: "Empty header name should fail validation",
		},
		{
			name:        "HeaderWithNullBytes",
			headerName:  "test",
			headerValue: "value\x00with_null",
			expectValid: false,
			description: "Header with null bytes should fail validation",
		},
		{
			name:        "HeaderValueTooLong",
			headerName:  "test",
			headerValue: strings.Repeat("a", config.MaxHeaderLength+1),
			expectValid: false,
			description: "Header value exceeding max length should fail validation",
		},
		{
			name:        "HeaderWithCRLF",
			headerName:  "test",
			headerValue: "value\r\nMalicious: header",
			expectValid: false,
			description: "Header with CRLF should fail validation to prevent injection",
		},
		{
			name:        "HeaderWithControlCharacters",
			headerName:  "test",
			headerValue: "value\x01with_control",
			expectValid: false,
			description: "Header with control characters should fail validation",
		},
		{
			name:        "MaliciousHeaderWithHTML",
			headerName:  "test",
			headerValue: "<script>alert('xss')</script>",
			expectValid: false,
			description: "Header with HTML/script should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateHeader(tt.headerName, tt.headerValue)

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v. %s", tt.expectValid, result.IsValid, tt.description)
			}
		})
	}
}

// TestInputValidatorValidateUsername tests username validation
func TestInputValidatorValidateUsername(t *testing.T) {
	config := DefaultInputValidationConfig()
	validator, _ := NewInputValidator(config, newNoOpLogger())

	tests := []struct {
		name        string
		username    string
		expectValid bool
		description string
	}{
		{
			name:        "ValidUsername",
			username:    "john_doe",
			expectValid: true,
			description: "Valid username should pass validation",
		},
		{
			name:        "ValidUsernameWithNumbers",
			username:    "user123",
			expectValid: true,
			description: "Valid username with numbers should pass validation",
		},
		{
			name:        "EmptyUsername",
			username:    "",
			expectValid: false,
			description: "Empty username should fail validation",
		},
		{
			name:        "UsernameWithNullBytes",
			username:    "user\x00name",
			expectValid: false,
			description: "Username with null bytes should fail validation",
		},
		{
			name:        "UsernameTooLong",
			username:    strings.Repeat("a", config.MaxUsernameLength+1),
			expectValid: false,
			description: "Username exceeding max length should fail validation",
		},
		{
			name:        "UsernameWithSpecialChars",
			username:    "user@name",
			expectValid: false,
			description: "Username with special characters should fail validation",
		},
		{
			name:        "UsernameWithSpaces",
			username:    "user name",
			expectValid: false,
			description: "Username with spaces should fail validation",
		},
		{
			name:        "UsernameWithControlCharacters",
			username:    "user\x01name",
			expectValid: false,
			description: "Username with control characters should fail validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateUsername(tt.username)

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v. %s", tt.expectValid, result.IsValid, tt.description)
			}
		})
	}
}
