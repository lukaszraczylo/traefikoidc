package traefikoidc

import (
	"strings"
	"testing"
)

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
