package traefikoidc

import (
	"testing"
)

// Additional tests to reach 75% coverage

// Test InputValidator creation and basic validation
func TestInputValidatorExtended(t *testing.T) {
	config := DefaultInputValidationConfig()
	logger := NewLogger("debug")

	validator, err := NewInputValidator(config, logger)
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	// Test SanitizeInput
	sanitized := validator.SanitizeInput("test\x00with\x01control", 100)
	if sanitized == "" {
		t.Error("SanitizeInput should return sanitized string")
	}

	// Test ValidateBoundaryValues
	result := validator.ValidateBoundaryValues(50, 1, 100)
	if !result.IsValid {
		t.Error("Valid boundary value should pass")
	}

	result = validator.ValidateBoundaryValues(150, 1, 100)
	if result.IsValid {
		t.Error("Invalid boundary value should fail")
	}
}

// Test session manager creation
func TestSessionManagerCreation(t *testing.T) {
	logger := NewLogger("debug")

	// Use a 32-byte encryption key as required
	encryptionKey := "12345678901234567890123456789012"
	sm, err := NewSessionManager(encryptionKey, false, "Lax", logger)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}
	if sm == nil {
		t.Fatal("NewSessionManager returned nil")
	}
}

// Test JWK cache creation
func TestJWKCacheCreation(t *testing.T) {
	cache := NewJWKCache()

	if cache == nil {
		t.Fatal("NewJWKCache returned nil")
	}
}

// Test security monitor creation
func TestSecurityMonitorCreation(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultSecurityMonitorConfig()
	sm := NewSecurityMonitor(config, logger)

	if sm == nil {
		t.Fatal("NewSecurityMonitor returned nil")
	}
}
