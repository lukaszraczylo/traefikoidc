package traefikoidc

import (
	"context"
	"fmt"
	"time"
)

// TokenResilienceConfig centralizes resilience configuration for token operations
type TokenResilienceConfig struct {
	// Circuit breaker configuration for token operations
	CircuitBreakerEnabled bool
	CircuitBreakerConfig  CircuitBreakerConfig

	// Retry configuration for token operations
	RetryEnabled bool
	RetryConfig  RetryConfig

	// Metadata cache progressive grace period configuration
	MetadataCacheConfig MetadataCacheResilienceConfig
}

// MetadataCacheResilienceConfig defines resilience settings for metadata cache
type MetadataCacheResilienceConfig struct {
	// EnableProgressiveGracePeriod allows extending cache TTL on failures
	EnableProgressiveGracePeriod bool

	// InitialGracePeriod is the first extension when service is unavailable (5 minutes)
	InitialGracePeriod time.Duration

	// ExtendedGracePeriod is the second extension for continued failures (15 minutes)
	ExtendedGracePeriod time.Duration

	// MaxGracePeriod is the maximum extension allowed (30 minutes for normal, 15 for security-critical)
	MaxGracePeriod time.Duration

	// SecurityCriticalMaxGracePeriod enforces Allan's security limit for critical metadata
	SecurityCriticalMaxGracePeriod time.Duration

	// SecurityCriticalFields defines which metadata fields are security-critical
	SecurityCriticalFields []string
}

// DefaultTokenResilienceConfig returns the default resilience configuration for token operations
func DefaultTokenResilienceConfig() TokenResilienceConfig {
	return TokenResilienceConfig{
		CircuitBreakerEnabled: true,
		CircuitBreakerConfig: CircuitBreakerConfig{
			MaxFailures:  3,
			Timeout:      30 * time.Second,
			ResetTimeout: 15 * time.Second,
		},
		RetryEnabled: true,
		RetryConfig: RetryConfig{
			MaxAttempts:   3,
			InitialDelay:  250 * time.Millisecond,
			MaxDelay:      2 * time.Second,
			BackoffFactor: 2.0,
			EnableJitter:  true,
			RetryableErrors: []string{
				"connection refused",
				"timeout",
				"temporary failure",
				"network unreachable",
				"connection reset",
				"no route to host",
			},
		},
		MetadataCacheConfig: DefaultMetadataCacheResilienceConfig(),
	}
}

// DefaultMetadataCacheResilienceConfig returns the default metadata cache resilience configuration
func DefaultMetadataCacheResilienceConfig() MetadataCacheResilienceConfig {
	return MetadataCacheResilienceConfig{
		EnableProgressiveGracePeriod:   true,
		InitialGracePeriod:             5 * time.Minute,
		ExtendedGracePeriod:            15 * time.Minute,
		MaxGracePeriod:                 30 * time.Minute,
		SecurityCriticalMaxGracePeriod: 15 * time.Minute, // Allan's security limit
		SecurityCriticalFields: []string{
			"jwks_uri",
			"authorization_endpoint",
			"token_endpoint",
			"revocation_endpoint",
			"end_session_endpoint",
		},
	}
}

// TokenResilienceManager coordinates resilience mechanisms for token operations
type TokenResilienceManager struct {
	config               TokenResilienceConfig
	errorRecoveryManager *ErrorRecoveryManager
	circuitBreaker       *CircuitBreaker
	retryExecutor        *RetryExecutor
	logger               *Logger
}

// NewTokenResilienceManager creates a new token resilience manager
func NewTokenResilienceManager(config TokenResilienceConfig, logger *Logger) *TokenResilienceManager {
	manager := &TokenResilienceManager{
		config: config,
		logger: logger,
	}

	// Initialize error recovery manager
	manager.errorRecoveryManager = NewErrorRecoveryManager(logger)

	// Initialize circuit breaker if enabled
	if config.CircuitBreakerEnabled {
		manager.circuitBreaker = NewCircuitBreaker(config.CircuitBreakerConfig, logger)
	}

	// Initialize retry executor if enabled
	if config.RetryEnabled {
		manager.retryExecutor = NewRetryExecutor(config.RetryConfig, logger)
	}

	return manager
}

// ExecuteTokenOperation executes a token operation with full resilience support
func (trm *TokenResilienceManager) ExecuteTokenOperation(ctx context.Context, operation string, fn func() error) error {
	if trm.logger != nil {
		trm.logger.Debugf("Executing token operation %s with resilience", operation)
	}

	// If no resilience mechanisms are enabled, execute directly
	if !trm.config.CircuitBreakerEnabled && !trm.config.RetryEnabled {
		return fn()
	}

	// Compose resilience mechanisms
	var finalOperation func() error = fn

	// Wrap with circuit breaker if enabled
	if trm.config.CircuitBreakerEnabled && trm.circuitBreaker != nil {
		originalOp := finalOperation
		finalOperation = func() error {
			return trm.circuitBreaker.ExecuteWithContext(ctx, originalOp)
		}
	}

	// Wrap with retry if enabled
	if trm.config.RetryEnabled && trm.retryExecutor != nil {
		originalOp := finalOperation
		finalOperation = func() error {
			return trm.retryExecutor.ExecuteWithContext(ctx, originalOp)
		}
	}

	err := finalOperation()

	if err != nil && trm.logger != nil {
		trm.logger.Errorf("Token operation %s failed after resilience mechanisms: %v", operation, err)
	} else if trm.logger != nil {
		trm.logger.Debugf("Token operation %s completed successfully", operation)
	}

	return err
}

// ExecuteTokenExchange executes token exchange with resilience
func (trm *TokenResilienceManager) ExecuteTokenExchange(ctx context.Context, t *TraefikOidc, grantType, codeOrToken, redirectURL, codeVerifier string) (*TokenResponse, error) {
	var result *TokenResponse
	var err error

	operation := fmt.Sprintf("token_exchange_%s", grantType)

	err = trm.ExecuteTokenOperation(ctx, operation, func() error {
		result, err = t.exchangeTokens(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
		return err
	})

	return result, err
}

// ExecuteTokenRefresh executes token refresh with resilience
func (trm *TokenResilienceManager) ExecuteTokenRefresh(ctx context.Context, t *TraefikOidc, refreshToken string) (*TokenResponse, error) {
	var result *TokenResponse
	var err error

	err = trm.ExecuteTokenOperation(ctx, "token_refresh", func() error {
		// Call exchangeTokens directly to avoid recursion back to getNewTokenWithRefreshToken
		// which would call ExecuteTokenRefresh again, causing infinite loop (issue #67)
		result, err = t.exchangeTokens(ctx, "refresh_token", refreshToken, "", "")
		return err
	})

	return result, err
}

// GetMetrics returns metrics for all resilience mechanisms
func (trm *TokenResilienceManager) GetMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	if trm.circuitBreaker != nil {
		metrics["circuit_breaker"] = trm.circuitBreaker.GetMetrics()
	}

	if trm.retryExecutor != nil {
		metrics["retry_executor"] = trm.retryExecutor.GetMetrics()
	}

	if trm.errorRecoveryManager != nil {
		recoveryMetrics := trm.errorRecoveryManager.GetRecoveryMetrics()
		metrics["error_recovery"] = recoveryMetrics
	}

	return metrics
}

// Reset resets all resilience mechanisms
func (trm *TokenResilienceManager) Reset() {
	if trm.circuitBreaker != nil {
		trm.circuitBreaker.Reset()
	}

	if trm.retryExecutor != nil {
		trm.retryExecutor.Reset()
	}

	if trm.logger != nil {
		trm.logger.Debugf("Token resilience manager has been reset")
	}
}

// IsSecurityCriticalField checks if a metadata field is security-critical
func (config MetadataCacheResilienceConfig) IsSecurityCriticalField(fieldName string) bool {
	for _, criticalField := range config.SecurityCriticalFields {
		if fieldName == criticalField {
			return true
		}
	}
	return false
}

// GetEffectiveMaxGracePeriod returns the effective maximum grace period for a field
// considering Allan's security limits
func (config MetadataCacheResilienceConfig) GetEffectiveMaxGracePeriod(fieldName string) time.Duration {
	if config.IsSecurityCriticalField(fieldName) {
		return config.SecurityCriticalMaxGracePeriod
	}
	return config.MaxGracePeriod
}
