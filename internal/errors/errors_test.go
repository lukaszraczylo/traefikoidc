package errors

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestOIDCError_Error(t *testing.T) {
	tests := []struct {
		name     string
		oidcErr  *OIDCError
		expected string
	}{
		{
			name: "Error with details",
			oidcErr: &OIDCError{
				Code:    ErrCodeTokenInvalid,
				Message: "Token validation failed",
				Details: "JWT signature invalid",
			},
			expected: "TOKEN_INVALID: Token validation failed (JWT signature invalid)",
		},
		{
			name: "Error without details",
			oidcErr: &OIDCError{
				Code:    ErrCodeAuthenticationFailed,
				Message: "Authentication failed",
			},
			expected: "AUTH_FAILED: Authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.oidcErr.Error()
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestOIDCError_Unwrap(t *testing.T) {
	internalErr := errors.New("internal error")
	oidcErr := &OIDCError{
		Code:     ErrCodeTokenInvalid,
		Message:  "Token validation failed",
		Internal: internalErr,
	}

	unwrapped := oidcErr.Unwrap()
	if unwrapped != internalErr {
		t.Errorf("Expected internal error, got %v", unwrapped)
	}

	// Test with nil internal error
	oidcErrNoInternal := &OIDCError{
		Code:    ErrCodeTokenInvalid,
		Message: "Token validation failed",
	}

	unwrappedNil := oidcErrNoInternal.Unwrap()
	if unwrappedNil != nil {
		t.Errorf("Expected nil, got %v", unwrappedNil)
	}
}

func TestOIDCError_IsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected bool
	}{
		{"Network timeout", ErrCodeNetworkTimeout, true},
		{"Service unavailable", ErrCodeServiceUnavailable, true},
		{"Provider unreachable", ErrCodeProviderUnreachable, true},
		{"Authentication failed", ErrCodeAuthenticationFailed, false},
		{"Token invalid", ErrCodeTokenInvalid, false},
		{"Rate limited", ErrCodeRateLimited, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidcErr := &OIDCError{Code: tt.code}
			result := oidcErr.IsRetryable()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for code %s", tt.expected, result, tt.code)
			}
		})
	}
}

func TestOIDCError_IsAuthenticationError(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected bool
	}{
		{"Authentication failed", ErrCodeAuthenticationFailed, true},
		{"Token expired", ErrCodeTokenExpired, true},
		{"Token invalid", ErrCodeTokenInvalid, true},
		{"Session expired", ErrCodeSessionExpired, true},
		{"CSRF mismatch", ErrCodeCSRFMismatch, true},
		{"Nonce mismatch", ErrCodeNonceMismatch, true},
		{"Config invalid", ErrCodeConfigInvalid, false},
		{"Domain not allowed", ErrCodeDomainNotAllowed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidcErr := &OIDCError{Code: tt.code}
			result := oidcErr.IsAuthenticationError()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for code %s", tt.expected, result, tt.code)
			}
		})
	}
}

func TestOIDCError_IsAuthorizationError(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected bool
	}{
		{"Domain not allowed", ErrCodeDomainNotAllowed, true},
		{"User not allowed", ErrCodeUserNotAllowed, true},
		{"Role not allowed", ErrCodeRoleNotAllowed, true},
		{"Authentication failed", ErrCodeAuthenticationFailed, false},
		{"Token expired", ErrCodeTokenExpired, false},
		{"Config invalid", ErrCodeConfigInvalid, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidcErr := &OIDCError{Code: tt.code}
			result := oidcErr.IsAuthorizationError()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for code %s", tt.expected, result, tt.code)
			}
		})
	}
}

func TestOIDCError_ToJSON(t *testing.T) {
	tests := []struct {
		name     string
		oidcErr  *OIDCError
		expected map[string]any
	}{
		{
			name: "Error with details",
			oidcErr: &OIDCError{
				Code:    ErrCodeTokenInvalid,
				Message: "Token validation failed",
				Details: "JWT signature invalid",
			},
			expected: map[string]any{
				"error": map[string]any{
					"code":    "TOKEN_INVALID",
					"message": "Token validation failed",
					"details": "JWT signature invalid",
				},
			},
		},
		{
			name: "Error without details",
			oidcErr: &OIDCError{
				Code:    ErrCodeAuthenticationFailed,
				Message: "Authentication failed",
			},
			expected: map[string]any{
				"error": map[string]any{
					"code":    "AUTH_FAILED",
					"message": "Authentication failed",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.oidcErr.ToJSON()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Expected %+v, got %+v", tt.expected, result)
			}
		})
	}
}

func TestNewAuthenticationError(t *testing.T) {
	internalErr := errors.New("internal error")

	tests := []struct {
		name         string
		code         ErrorCode
		message      string
		internal     error
		expectedHTTP int
	}{
		{
			name:         "Regular auth error",
			code:         ErrCodeAuthenticationFailed,
			message:      "Auth failed",
			internal:     internalErr,
			expectedHTTP: http.StatusUnauthorized,
		},
		{
			name:         "Session expired error",
			code:         ErrCodeSessionExpired,
			message:      "Session expired",
			internal:     internalErr,
			expectedHTTP: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAuthenticationError(tt.code, tt.message, tt.internal)

			if err.Code != tt.code {
				t.Errorf("Expected code %s, got %s", tt.code, err.Code)
			}
			if err.Message != tt.message {
				t.Errorf("Expected message '%s', got '%s'", tt.message, err.Message)
			}
			if err.Internal != tt.internal {
				t.Errorf("Expected internal error %v, got %v", tt.internal, err.Internal)
			}
			if err.HTTPStatus != tt.expectedHTTP {
				t.Errorf("Expected HTTP status %d, got %d", tt.expectedHTTP, err.HTTPStatus)
			}
		})
	}
}

func TestNewAuthorizationError(t *testing.T) {
	err := NewAuthorizationError(ErrCodeDomainNotAllowed, "Domain not allowed", "example.com not in whitelist")

	if err.Code != ErrCodeDomainNotAllowed {
		t.Errorf("Expected code %s, got %s", ErrCodeDomainNotAllowed, err.Code)
	}
	if err.Message != "Domain not allowed" {
		t.Errorf("Expected message 'Domain not allowed', got '%s'", err.Message)
	}
	if err.Details != "example.com not in whitelist" {
		t.Errorf("Expected details 'example.com not in whitelist', got '%s'", err.Details)
	}
	if err.HTTPStatus != http.StatusForbidden {
		t.Errorf("Expected HTTP status %d, got %d", http.StatusForbidden, err.HTTPStatus)
	}
}

func TestNewConfigurationError(t *testing.T) {
	internalErr := errors.New("config parse error")
	err := NewConfigurationError(ErrCodeConfigInvalid, "Invalid config", internalErr)

	if err.Code != ErrCodeConfigInvalid {
		t.Errorf("Expected code %s, got %s", ErrCodeConfigInvalid, err.Code)
	}
	if err.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("Expected HTTP status %d, got %d", http.StatusInternalServerError, err.HTTPStatus)
	}
	if err.Internal != internalErr {
		t.Errorf("Expected internal error %v, got %v", internalErr, err.Internal)
	}
}

func TestNewNetworkError(t *testing.T) {
	internalErr := errors.New("network error")

	tests := []struct {
		name         string
		code         ErrorCode
		expectedHTTP int
	}{
		{
			name:         "Rate limited",
			code:         ErrCodeRateLimited,
			expectedHTTP: http.StatusTooManyRequests,
		},
		{
			name:         "Service unavailable",
			code:         ErrCodeServiceUnavailable,
			expectedHTTP: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewNetworkError(tt.code, "Network error", internalErr)

			if err.Code != tt.code {
				t.Errorf("Expected code %s, got %s", tt.code, err.Code)
			}
			if err.HTTPStatus != tt.expectedHTTP {
				t.Errorf("Expected HTTP status %d, got %d", tt.expectedHTTP, err.HTTPStatus)
			}
		})
	}
}

func TestNewValidationError(t *testing.T) {
	err := NewValidationError(ErrCodeValidationFailed, "Validation failed", "field 'email' is required")

	if err.Code != ErrCodeValidationFailed {
		t.Errorf("Expected code %s, got %s", ErrCodeValidationFailed, err.Code)
	}
	if err.HTTPStatus != http.StatusBadRequest {
		t.Errorf("Expected HTTP status %d, got %d", http.StatusBadRequest, err.HTTPStatus)
	}
	if err.Details != "field 'email' is required" {
		t.Errorf("Expected details 'field 'email' is required', got '%s'", err.Details)
	}
}

func TestWrapAuthenticationError(t *testing.T) {
	internalErr := errors.New("original error")
	err := WrapAuthenticationError(internalErr, "Custom auth message")

	if err.Code != ErrCodeAuthenticationFailed {
		t.Errorf("Expected code %s, got %s", ErrCodeAuthenticationFailed, err.Code)
	}
	if err.Message != "Custom auth message" {
		t.Errorf("Expected message 'Custom auth message', got '%s'", err.Message)
	}
	if err.Internal != internalErr {
		t.Errorf("Expected internal error %v, got %v", internalErr, err.Internal)
	}
}

func TestWrapTokenError(t *testing.T) {
	internalErr := errors.New("token error")
	err := WrapTokenError(internalErr, "ID token")

	if err.Code != ErrCodeTokenInvalid {
		t.Errorf("Expected code %s, got %s", ErrCodeTokenInvalid, err.Code)
	}
	if err.Message != "Token validation failed: ID token" {
		t.Errorf("Expected message 'Token validation failed: ID token', got '%s'", err.Message)
	}
	if err.Internal != internalErr {
		t.Errorf("Expected internal error %v, got %v", internalErr, err.Internal)
	}
}

func TestWrapProviderError(t *testing.T) {
	internalErr := errors.New("provider error")
	err := WrapProviderError(internalErr, "https://provider.example.com")

	if err.Code != ErrCodeProviderUnreachable {
		t.Errorf("Expected code %s, got %s", ErrCodeProviderUnreachable, err.Code)
	}
	if err.Message != "Provider communication failed: https://provider.example.com" {
		t.Errorf("Expected specific message, got '%s'", err.Message)
	}
	if err.Internal != internalErr {
		t.Errorf("Expected internal error %v, got %v", internalErr, err.Internal)
	}
}

func TestIsOIDCError(t *testing.T) {
	// Test with OIDCError
	oidcErr := &OIDCError{Code: ErrCodeTokenInvalid, Message: "test"}
	result, ok := IsOIDCError(oidcErr)
	if !ok {
		t.Error("Expected IsOIDCError to return true for OIDCError")
	}
	if result != oidcErr {
		t.Error("Expected to get the same OIDCError back")
	}

	// Test with regular error
	regularErr := errors.New("regular error")
	result, ok = IsOIDCError(regularErr)
	if ok {
		t.Error("Expected IsOIDCError to return false for regular error")
	}
	if result != nil {
		t.Error("Expected nil result for regular error")
	}
}

func TestGetHTTPStatus(t *testing.T) {
	// Test with OIDCError
	oidcErr := &OIDCError{
		Code:       ErrCodeTokenInvalid,
		HTTPStatus: http.StatusUnauthorized,
	}
	status := GetHTTPStatus(oidcErr)
	if status != http.StatusUnauthorized {
		t.Errorf("Expected %d, got %d", http.StatusUnauthorized, status)
	}

	// Test with regular error
	regularErr := errors.New("regular error")
	status = GetHTTPStatus(regularErr)
	if status != http.StatusInternalServerError {
		t.Errorf("Expected %d, got %d", http.StatusInternalServerError, status)
	}
}

func TestFormatUserMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "Domain not allowed",
			err:      &OIDCError{Code: ErrCodeDomainNotAllowed},
			expected: "Your email domain is not authorized for this application",
		},
		{
			name:     "User not allowed",
			err:      &OIDCError{Code: ErrCodeUserNotAllowed},
			expected: "Your account is not authorized for this application",
		},
		{
			name:     "Role not allowed",
			err:      &OIDCError{Code: ErrCodeRoleNotAllowed},
			expected: "You do not have the required permissions for this application",
		},
		{
			name:     "Session expired",
			err:      &OIDCError{Code: ErrCodeSessionExpired},
			expected: "Your session has expired. Please log in again",
		},
		{
			name:     "Token expired",
			err:      &OIDCError{Code: ErrCodeTokenExpired},
			expected: "Your authentication has expired. Please log in again",
		},
		{
			name:     "Provider unreachable",
			err:      &OIDCError{Code: ErrCodeProviderUnreachable},
			expected: "Authentication service is temporarily unavailable. Please try again later",
		},
		{
			name:     "Rate limited",
			err:      &OIDCError{Code: ErrCodeRateLimited},
			expected: "Too many requests. Please wait a moment and try again",
		},
		{
			name:     "Unknown OIDC error",
			err:      &OIDCError{Code: ErrCodeConfigInvalid},
			expected: "Authentication failed. Please try again",
		},
		{
			name:     "Regular error",
			err:      errors.New("regular error"),
			expected: "An unexpected error occurred. Please try again",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatUserMessage(tt.err)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	// Test that all error codes are defined correctly
	codes := []ErrorCode{
		ErrCodeAuthenticationFailed,
		ErrCodeTokenExpired,
		ErrCodeTokenInvalid,
		ErrCodeSessionExpired,
		ErrCodeCSRFMismatch,
		ErrCodeNonceMismatch,
		ErrCodeConfigInvalid,
		ErrCodeProviderUnreachable,
		ErrCodeMetadataFailed,
		ErrCodeNetworkTimeout,
		ErrCodeRateLimited,
		ErrCodeServiceUnavailable,
		ErrCodeValidationFailed,
		ErrCodeDomainNotAllowed,
		ErrCodeUserNotAllowed,
		ErrCodeRoleNotAllowed,
	}

	for _, code := range codes {
		if string(code) == "" {
			t.Errorf("Error code %v is empty", code)
		}
	}
}

func TestErrorConstructorCompleteness(t *testing.T) {
	// Test each constructor function to ensure they set all required fields
	internalErr := errors.New("test error")

	// Test NewAuthenticationError
	authErr := NewAuthenticationError(ErrCodeAuthenticationFailed, "auth message", internalErr)
	if authErr.Code == "" || authErr.Message == "" || authErr.HTTPStatus == 0 {
		t.Error("NewAuthenticationError did not set all required fields")
	}

	// Test NewAuthorizationError
	authzErr := NewAuthorizationError(ErrCodeDomainNotAllowed, "authz message", "details")
	if authzErr.Code == "" || authzErr.Message == "" || authzErr.HTTPStatus == 0 {
		t.Error("NewAuthorizationError did not set all required fields")
	}

	// Test NewConfigurationError
	configErr := NewConfigurationError(ErrCodeConfigInvalid, "config message", internalErr)
	if configErr.Code == "" || configErr.Message == "" || configErr.HTTPStatus == 0 {
		t.Error("NewConfigurationError did not set all required fields")
	}

	// Test NewNetworkError
	netErr := NewNetworkError(ErrCodeNetworkTimeout, "network message", internalErr)
	if netErr.Code == "" || netErr.Message == "" || netErr.HTTPStatus == 0 {
		t.Error("NewNetworkError did not set all required fields")
	}

	// Test NewValidationError
	validErr := NewValidationError(ErrCodeValidationFailed, "validation message", "details")
	if validErr.Code == "" || validErr.Message == "" || validErr.HTTPStatus == 0 {
		t.Error("NewValidationError did not set all required fields")
	}
}
