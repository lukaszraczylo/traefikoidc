package traefikoidc

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// InputValidator provides comprehensive input validation and sanitization
type InputValidator struct {
	// Configuration
	maxTokenLength    int
	maxURLLength      int
	maxHeaderLength   int
	maxClaimLength    int
	maxEmailLength    int
	maxUsernameLength int

	// Compiled regex patterns
	emailRegex    *regexp.Regexp
	urlRegex      *regexp.Regexp
	tokenRegex    *regexp.Regexp
	usernameRegex *regexp.Regexp

	// Security patterns to detect
	sqlInjectionPatterns  []string
	xssPatterns           []string
	pathTraversalPatterns []string

	logger *Logger
}

// ValidationResult represents the result of input validation
type ValidationResult struct {
	IsValid        bool     `json:"is_valid"`
	Errors         []string `json:"errors,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	SanitizedValue string   `json:"sanitized_value,omitempty"`
	SecurityRisk   string   `json:"security_risk,omitempty"`
}

// InputValidationConfig holds configuration for input validation
type InputValidationConfig struct {
	MaxTokenLength    int  `json:"max_token_length"`
	MaxURLLength      int  `json:"max_url_length"`
	MaxHeaderLength   int  `json:"max_header_length"`
	MaxClaimLength    int  `json:"max_claim_length"`
	MaxEmailLength    int  `json:"max_email_length"`
	MaxUsernameLength int  `json:"max_username_length"`
	StrictMode        bool `json:"strict_mode"`
}

// DefaultInputValidationConfig returns default validation configuration
func DefaultInputValidationConfig() InputValidationConfig {
	return InputValidationConfig{
		MaxTokenLength:    50000, // 50KB for tokens
		MaxURLLength:      2048,  // Standard URL length limit
		MaxHeaderLength:   8192,  // 8KB for headers
		MaxClaimLength:    1024,  // 1KB for individual claims
		MaxEmailLength:    254,   // RFC 5321 limit
		MaxUsernameLength: 64,    // Reasonable username limit
		StrictMode:        true,  // Enable strict validation by default
	}
}

// NewInputValidator creates a new input validator with the given configuration
func NewInputValidator(config InputValidationConfig, logger *Logger) (*InputValidator, error) {
	// Compile regex patterns
	emailRegex, err := regexp.Compile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile email regex: %w", err)
	}

	urlRegex, err := regexp.Compile(`^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?::[0-9]+)?(?:/[^\s]*)?$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile URL regex: %w", err)
	}

	tokenRegex, err := regexp.Compile(`^[A-Za-z0-9._-]+$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile token regex: %w", err)
	}

	usernameRegex, err := regexp.Compile(`^[a-zA-Z0-9._-]+$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile username regex: %w", err)
	}

	return &InputValidator{
		maxTokenLength:    config.MaxTokenLength,
		maxURLLength:      config.MaxURLLength,
		maxHeaderLength:   config.MaxHeaderLength,
		maxClaimLength:    config.MaxClaimLength,
		maxEmailLength:    config.MaxEmailLength,
		maxUsernameLength: config.MaxUsernameLength,
		emailRegex:        emailRegex,
		urlRegex:          urlRegex,
		tokenRegex:        tokenRegex,
		usernameRegex:     usernameRegex,
		sqlInjectionPatterns: []string{
			"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
			"union", "select", "insert", "update", "delete", "drop",
			"create", "alter", "exec", "execute", "script",
		},
		xssPatterns: []string{
			"<script", "</script>", "javascript:", "vbscript:",
			"onload=", "onerror=", "onclick=", "onmouseover=",
			"<iframe", "<object", "<embed", "<link", "<meta",
		},
		pathTraversalPatterns: []string{
			"../", "..\\", "%2e%2e%2f", "%2e%2e%5c",
			"..%2f", "..%5c", "%252e%252e%252f",
		},
		logger: logger,
	}, nil
}

// ValidateToken validates JWT tokens and similar token strings
func (iv *InputValidator) ValidateToken(token string) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	// Check for empty token
	if token == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "token cannot be empty")
		return result
	}

	// Check length limits
	if len(token) > iv.maxTokenLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("token length %d exceeds maximum %d", len(token), iv.maxTokenLength))
		return result
	}

	// Check for minimum reasonable length
	if len(token) < 10 {
		result.IsValid = false
		result.Errors = append(result.Errors, "token is too short to be valid")
		return result
	}

	// Check for valid JWT structure (3 parts separated by dots)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		result.IsValid = false
		result.Errors = append(result.Errors, "token does not have valid JWT structure (expected 3 parts)")
		return result
	}

	// Validate each part is base64url encoded
	for i, part := range parts {
		if !iv.isValidBase64URL(part) {
			result.IsValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("token part %d is not valid base64url", i+1))
			return result
		}
	}

	// Check for suspicious patterns
	if risk := iv.detectSecurityRisk(token); risk != "" {
		result.SecurityRisk = risk
		result.Warnings = append(result.Warnings, fmt.Sprintf("potential security risk detected: %s", risk))
	}

	// Check for null bytes and control characters
	if iv.containsNullBytes(token) {
		result.IsValid = false
		result.Errors = append(result.Errors, "token contains null bytes")
		return result
	}

	if iv.containsControlCharacters(token) {
		result.IsValid = false
		result.Errors = append(result.Errors, "token contains control characters")
		return result
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(token) {
		result.IsValid = false
		result.Errors = append(result.Errors, "token contains invalid UTF-8 sequences")
		return result
	}

	result.SanitizedValue = token
	return result
}

// ValidateEmail validates email addresses
func (iv *InputValidator) ValidateEmail(email string) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	// Check for empty email
	if email == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "email cannot be empty")
		return result
	}

	// Check length limits
	if len(email) > iv.maxEmailLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("email length %d exceeds maximum %d", len(email), iv.maxEmailLength))
		return result
	}

	// Sanitize email (trim whitespace, convert to lowercase)
	sanitized := strings.TrimSpace(strings.ToLower(email))

	// Check regex pattern
	if !iv.emailRegex.MatchString(sanitized) {
		result.IsValid = false
		result.Errors = append(result.Errors, "email format is invalid")
		return result
	}

	// Check for suspicious patterns
	if risk := iv.detectSecurityRisk(sanitized); risk != "" {
		result.SecurityRisk = risk
		result.Warnings = append(result.Warnings, fmt.Sprintf("potential security risk detected: %s", risk))
	}

	// Additional email-specific validations
	parts := strings.Split(sanitized, "@")
	if len(parts) != 2 {
		result.IsValid = false
		result.Errors = append(result.Errors, "email must contain exactly one @ symbol")
		return result
	}

	localPart, domain := parts[0], parts[1]

	// Validate local part
	if len(localPart) == 0 || len(localPart) > 64 {
		result.IsValid = false
		result.Errors = append(result.Errors, "email local part length is invalid")
		return result
	}

	// Validate domain
	if len(domain) == 0 || len(domain) > 253 {
		result.IsValid = false
		result.Errors = append(result.Errors, "email domain length is invalid")
		return result
	}

	// Check for consecutive dots
	if strings.Contains(sanitized, "..") {
		result.IsValid = false
		result.Errors = append(result.Errors, "email contains consecutive dots")
		return result
	}

	result.SanitizedValue = sanitized
	return result
}

// ValidateURL validates URLs
func (iv *InputValidator) ValidateURL(urlStr string) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	// Check for empty URL
	if urlStr == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "URL cannot be empty")
		return result
	}

	// Check length limits
	if len(urlStr) > iv.maxURLLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("URL length %d exceeds maximum %d", len(urlStr), iv.maxURLLength))
		return result
	}

	// Sanitize URL (trim whitespace)
	sanitized := strings.TrimSpace(urlStr)

	// Parse URL
	parsedURL, err := url.Parse(sanitized)
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("URL parsing failed: %v", err))
		return result
	}

	// Check scheme
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		result.IsValid = false
		result.Errors = append(result.Errors, "URL scheme must be http or https")
		return result
	}

	// Prefer HTTPS
	if parsedURL.Scheme == "http" {
		result.Warnings = append(result.Warnings, "HTTP URLs are less secure than HTTPS")
	}

	// Check host
	if parsedURL.Host == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "URL must have a valid host")
		return result
	}

	// Check for suspicious patterns
	if risk := iv.detectSecurityRisk(sanitized); risk != "" {
		result.SecurityRisk = risk
		result.Warnings = append(result.Warnings, fmt.Sprintf("potential security risk detected: %s", risk))
	}

	// Check for path traversal attempts
	if iv.containsPathTraversal(sanitized) {
		result.IsValid = false
		result.Errors = append(result.Errors, "URL contains path traversal patterns")
		return result
	}

	result.SanitizedValue = sanitized
	return result
}

// ValidateUsername validates usernames
func (iv *InputValidator) ValidateUsername(username string) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	// Check for empty username
	if username == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "username cannot be empty")
		return result
	}

	// Check length limits
	if len(username) > iv.maxUsernameLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("username length %d exceeds maximum %d", len(username), iv.maxUsernameLength))
		return result
	}

	// Check minimum length
	if len(username) < 2 {
		result.IsValid = false
		result.Errors = append(result.Errors, "username must be at least 2 characters long")
		return result
	}

	// Sanitize username (trim whitespace)
	sanitized := strings.TrimSpace(username)

	// Check regex pattern
	if !iv.usernameRegex.MatchString(sanitized) {
		result.IsValid = false
		result.Errors = append(result.Errors, "username contains invalid characters (only letters, numbers, dots, underscores, and hyphens allowed)")
		return result
	}

	// Check for suspicious patterns
	if risk := iv.detectSecurityRisk(sanitized); risk != "" {
		result.SecurityRisk = risk
		result.Warnings = append(result.Warnings, fmt.Sprintf("potential security risk detected: %s", risk))
	}

	result.SanitizedValue = sanitized
	return result
}

// ValidateClaim validates individual JWT claims
func (iv *InputValidator) ValidateClaim(claimName, claimValue string) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	// Check claim name
	if claimName == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "claim name cannot be empty")
		return result
	}

	// Check claim value length
	if len(claimValue) > iv.maxClaimLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("claim value length %d exceeds maximum %d", len(claimValue), iv.maxClaimLength))
		return result
	}

	// Check for null bytes and control characters
	if iv.containsNullBytes(claimValue) {
		result.IsValid = false
		result.Errors = append(result.Errors, "claim value contains null bytes")
		return result
	}

	if iv.containsControlCharacters(claimValue) {
		result.Warnings = append(result.Warnings, "claim value contains control characters")
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(claimValue) {
		result.IsValid = false
		result.Errors = append(result.Errors, "claim value contains invalid UTF-8 sequences")
		return result
	}

	// Check for suspicious patterns
	if risk := iv.detectSecurityRisk(claimValue); risk != "" {
		result.SecurityRisk = risk
		result.Warnings = append(result.Warnings, fmt.Sprintf("potential security risk detected: %s", risk))
	}

	// Specific validations based on claim name
	switch claimName {
	case "email":
		emailResult := iv.ValidateEmail(claimValue)
		if !emailResult.IsValid {
			result.IsValid = false
			result.Errors = append(result.Errors, emailResult.Errors...)
		}
		result.Warnings = append(result.Warnings, emailResult.Warnings...)
		result.SanitizedValue = emailResult.SanitizedValue

	case "iss", "aud":
		urlResult := iv.ValidateURL(claimValue)
		if !urlResult.IsValid {
			// For issuer/audience, we're more lenient - just warn
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s claim is not a valid URL: %v", claimName, urlResult.Errors))
		}
		result.SanitizedValue = claimValue

	case "preferred_username", "username":
		usernameResult := iv.ValidateUsername(claimValue)
		if !usernameResult.IsValid {
			result.IsValid = false
			result.Errors = append(result.Errors, usernameResult.Errors...)
		}
		result.Warnings = append(result.Warnings, usernameResult.Warnings...)
		result.SanitizedValue = usernameResult.SanitizedValue

	default:
		// Generic string validation
		result.SanitizedValue = strings.TrimSpace(claimValue)
	}

	return result
}

// ValidateHeader validates HTTP header values
func (iv *InputValidator) ValidateHeader(headerName, headerValue string) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	// Check header name
	if headerName == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "header name cannot be empty")
		return result
	}

	// Check for control characters in header name (including CRLF)
	if iv.containsControlCharacters(headerName) {
		result.IsValid = false
		result.Errors = append(result.Errors, "header name contains control characters")
		return result
	}

	// Check for CRLF injection in header name
	if strings.Contains(headerName, "\r") || strings.Contains(headerName, "\n") {
		result.IsValid = false
		result.Errors = append(result.Errors, "header name contains CRLF characters (potential header injection)")
		return result
	}

	// Check header value length
	if len(headerValue) > iv.maxHeaderLength {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("header value length %d exceeds maximum %d", len(headerValue), iv.maxHeaderLength))
		return result
	}

	// Check for null bytes and control characters (except allowed ones)
	if iv.containsNullBytes(headerValue) {
		result.IsValid = false
		result.Errors = append(result.Errors, "header value contains null bytes")
		return result
	}

	// Check for CRLF injection
	if strings.Contains(headerValue, "\r") || strings.Contains(headerValue, "\n") {
		result.IsValid = false
		result.Errors = append(result.Errors, "header value contains CRLF characters (potential header injection)")
		return result
	}

	// Validate UTF-8 encoding
	if !utf8.ValidString(headerValue) {
		result.IsValid = false
		result.Errors = append(result.Errors, "header value contains invalid UTF-8 sequences")
		return result
	}

	// Check for suspicious patterns
	if risk := iv.detectSecurityRisk(headerValue); risk != "" {
		result.SecurityRisk = risk
		result.Warnings = append(result.Warnings, fmt.Sprintf("potential security risk detected: %s", risk))
	}

	result.SanitizedValue = strings.TrimSpace(headerValue)
	return result
}

// isValidBase64URL checks if a string is valid base64url encoding
func (iv *InputValidator) isValidBase64URL(s string) bool {
	// Base64url uses A-Z, a-z, 0-9, -, _ and no padding
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// containsNullBytes checks if a string contains null bytes
func (iv *InputValidator) containsNullBytes(s string) bool {
	return strings.Contains(s, "\x00")
}

// containsControlCharacters checks if a string contains control characters
func (iv *InputValidator) containsControlCharacters(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return true
		}
	}
	return false
}

// containsPathTraversal checks for path traversal patterns
func (iv *InputValidator) containsPathTraversal(s string) bool {
	lowerS := strings.ToLower(s)
	for _, pattern := range iv.pathTraversalPatterns {
		if strings.Contains(lowerS, pattern) {
			return true
		}
	}
	return false
}

// detectSecurityRisk detects potential security risks in input
func (iv *InputValidator) detectSecurityRisk(input string) string {
	lowerInput := strings.ToLower(input)

	// Check for SQL injection patterns
	for _, pattern := range iv.sqlInjectionPatterns {
		if strings.Contains(lowerInput, pattern) {
			return "sql_injection"
		}
	}

	// Check for XSS patterns
	for _, pattern := range iv.xssPatterns {
		if strings.Contains(lowerInput, pattern) {
			return "xss"
		}
	}

	// Check for path traversal
	if iv.containsPathTraversal(input) {
		return "path_traversal"
	}

	// Check for excessive length (potential DoS)
	if len(input) > 10000 {
		return "excessive_length"
	}

	// Check for suspicious character patterns
	if iv.containsNullBytes(input) {
		return "null_bytes"
	}

	// Check for binary data patterns
	nonPrintableCount := 0
	for _, r := range input {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			nonPrintableCount++
		}
	}
	if nonPrintableCount > len(input)/10 { // More than 10% non-printable
		return "binary_data"
	}

	return ""
}

// SanitizeInput provides general input sanitization
func (iv *InputValidator) SanitizeInput(input string, maxLength int) string {
	// Trim whitespace
	sanitized := strings.TrimSpace(input)

	// Truncate if too long
	if len(sanitized) > maxLength {
		sanitized = sanitized[:maxLength]
	}

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Remove other control characters except tab, newline, carriage return
	var result strings.Builder
	for _, r := range sanitized {
		if !unicode.IsControl(r) || r == '\t' || r == '\n' || r == '\r' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ValidateBoundaryValues validates numeric boundary values
func (iv *InputValidator) ValidateBoundaryValues(value any, min, max int64) ValidationResult {
	result := ValidationResult{IsValid: true, Errors: []string{}, Warnings: []string{}}

	var numValue int64

	switch v := value.(type) {
	case int:
		numValue = int64(v)
	case int32:
		numValue = int64(v)
	case int64:
		numValue = v
	case float64:
		numValue = int64(v)
		if float64(numValue) != v {
			result.Warnings = append(result.Warnings, "floating point value truncated to integer")
		}
	default:
		result.IsValid = false
		result.Errors = append(result.Errors, "value is not a numeric type")
		return result
	}

	if numValue < min {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("value %d is below minimum %d", numValue, min))
	}

	if numValue > max {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("value %d exceeds maximum %d", numValue, max))
	}

	return result
}
