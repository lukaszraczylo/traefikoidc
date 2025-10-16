// Package errors provides unified error handling for OIDC operations
package errors

import (
	"fmt"
	"net/http"
)

// ErrorCode represents specific error types
type ErrorCode string

const (
	// Authentication errors
	ErrCodeAuthenticationFailed ErrorCode = "AUTH_FAILED"
	ErrCodeTokenExpired         ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenInvalid         ErrorCode = "TOKEN_INVALID"
	ErrCodeSessionExpired       ErrorCode = "SESSION_EXPIRED"
	ErrCodeCSRFMismatch         ErrorCode = "CSRF_MISMATCH"
	ErrCodeNonceMismatch        ErrorCode = "NONCE_MISMATCH"

	// Configuration errors
	ErrCodeConfigInvalid       ErrorCode = "CONFIG_INVALID"
	ErrCodeProviderUnreachable ErrorCode = "PROVIDER_UNREACHABLE"
	ErrCodeMetadataFailed      ErrorCode = "METADATA_FAILED"

	// Network errors
	ErrCodeNetworkTimeout     ErrorCode = "NETWORK_TIMEOUT"
	ErrCodeRateLimited        ErrorCode = "RATE_LIMITED"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"

	// Validation errors
	ErrCodeValidationFailed ErrorCode = "VALIDATION_FAILED"
	ErrCodeDomainNotAllowed ErrorCode = "DOMAIN_NOT_ALLOWED"
	ErrCodeUserNotAllowed   ErrorCode = "USER_NOT_ALLOWED"
	ErrCodeRoleNotAllowed   ErrorCode = "ROLE_NOT_ALLOWED"
)

// OIDCError represents a structured error with context
type OIDCError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details,omitempty"`
	HTTPStatus int       `json:"http_status"`
	Internal   error     `json:"-"` // Internal error, not exposed
}

// Error implements the error interface
func (e *OIDCError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the internal error for error wrapping
func (e *OIDCError) Unwrap() error {
	return e.Internal
}

// IsRetryable indicates if the error is temporary and can be retried
func (e *OIDCError) IsRetryable() bool {
	return e.Code == ErrCodeNetworkTimeout ||
		e.Code == ErrCodeServiceUnavailable ||
		e.Code == ErrCodeProviderUnreachable
}

// IsAuthenticationError indicates if this is an authentication-related error
func (e *OIDCError) IsAuthenticationError() bool {
	return e.Code == ErrCodeAuthenticationFailed ||
		e.Code == ErrCodeTokenExpired ||
		e.Code == ErrCodeTokenInvalid ||
		e.Code == ErrCodeSessionExpired ||
		e.Code == ErrCodeCSRFMismatch ||
		e.Code == ErrCodeNonceMismatch
}

// IsAuthorizationError indicates if this is an authorization-related error
func (e *OIDCError) IsAuthorizationError() bool {
	return e.Code == ErrCodeDomainNotAllowed ||
		e.Code == ErrCodeUserNotAllowed ||
		e.Code == ErrCodeRoleNotAllowed
}

// ToJSON converts the error to a JSON response
func (e *OIDCError) ToJSON() map[string]any {
	result := map[string]any{
		"error": map[string]any{
			"code":    string(e.Code),
			"message": e.Message,
		},
	}

	if e.Details != "" {
		errorMap, _ := result["error"].(map[string]any) // Safe to ignore: type assertion from known type
		errorMap["details"] = e.Details
	}

	return result
}

// Error constructors for common scenarios

// NewAuthenticationError creates an authentication-related error
func NewAuthenticationError(code ErrorCode, message string, internal error) *OIDCError {
	status := http.StatusUnauthorized
	if code == ErrCodeSessionExpired {
		status = http.StatusForbidden
	}

	return &OIDCError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
		Internal:   internal,
	}
}

// NewAuthorizationError creates an authorization-related error
func NewAuthorizationError(code ErrorCode, message string, details string) *OIDCError {
	return &OIDCError{
		Code:       code,
		Message:    message,
		Details:    details,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewConfigurationError creates a configuration-related error
func NewConfigurationError(code ErrorCode, message string, internal error) *OIDCError {
	return &OIDCError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
		Internal:   internal,
	}
}

// NewNetworkError creates a network-related error
func NewNetworkError(code ErrorCode, message string, internal error) *OIDCError {
	status := http.StatusServiceUnavailable
	if code == ErrCodeRateLimited {
		status = http.StatusTooManyRequests
	}

	return &OIDCError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
		Internal:   internal,
	}
}

// NewValidationError creates a validation-related error
func NewValidationError(code ErrorCode, message string, details string) *OIDCError {
	return &OIDCError{
		Code:       code,
		Message:    message,
		Details:    details,
		HTTPStatus: http.StatusBadRequest,
	}
}

// Convenience functions for common error patterns

// WrapAuthenticationError wraps an existing error as an authentication error
func WrapAuthenticationError(err error, message string) *OIDCError {
	return NewAuthenticationError(ErrCodeAuthenticationFailed, message, err)
}

// WrapTokenError wraps a token-related error
func WrapTokenError(err error, tokenType string) *OIDCError {
	message := fmt.Sprintf("Token validation failed: %s", tokenType)
	return NewAuthenticationError(ErrCodeTokenInvalid, message, err)
}

// WrapProviderError wraps a provider communication error
func WrapProviderError(err error, providerURL string) *OIDCError {
	message := fmt.Sprintf("Provider communication failed: %s", providerURL)
	return NewNetworkError(ErrCodeProviderUnreachable, message, err)
}

// IsOIDCError checks if an error is an OIDCError
func IsOIDCError(err error) (*OIDCError, bool) {
	oidcErr, ok := err.(*OIDCError)
	return oidcErr, ok
}

// GetHTTPStatus extracts HTTP status from error, defaulting to 500
func GetHTTPStatus(err error) int {
	if oidcErr, ok := IsOIDCError(err); ok {
		return oidcErr.HTTPStatus
	}
	return http.StatusInternalServerError
}

// FormatUserMessage creates a user-friendly error message
func FormatUserMessage(err error) string {
	if oidcErr, ok := IsOIDCError(err); ok {
		switch oidcErr.Code {
		case ErrCodeDomainNotAllowed:
			return "Your email domain is not authorized for this application"
		case ErrCodeUserNotAllowed:
			return "Your account is not authorized for this application"
		case ErrCodeRoleNotAllowed:
			return "You do not have the required permissions for this application"
		case ErrCodeSessionExpired:
			return "Your session has expired. Please log in again"
		case ErrCodeTokenExpired:
			return "Your authentication has expired. Please log in again"
		case ErrCodeProviderUnreachable:
			return "Authentication service is temporarily unavailable. Please try again later"
		case ErrCodeRateLimited:
			return "Too many requests. Please wait a moment and try again"
		default:
			return "Authentication failed. Please try again"
		}
	}
	return "An unexpected error occurred. Please try again"
}
