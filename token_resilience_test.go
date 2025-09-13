package traefikoidc

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestTokenResilienceManager(t *testing.T) {
	logger := NewLogger("debug")
	config := DefaultTokenResilienceConfig()

	// Test basic functionality
	t.Run("DefaultConfiguration", func(t *testing.T) {
		manager := NewTokenResilienceManager(config, logger)
		if manager == nil {
			t.Fatal("Expected non-nil manager")
		}

		if manager.config.CircuitBreakerEnabled != true {
			t.Errorf("Expected circuit breaker to be enabled by default")
		}

		if manager.config.RetryEnabled != true {
			t.Errorf("Expected retry to be enabled by default")
		}

		// Test circuit breaker creation
		if manager.circuitBreaker == nil {
			t.Errorf("Expected circuit breaker to be created")
		}

		// Test retry executor creation
		if manager.retryExecutor == nil {
			t.Errorf("Expected retry executor to be created")
		}
	})

	// Test resilience execution
	t.Run("ResilienceExecution", func(t *testing.T) {
		manager := NewTokenResilienceManager(config, logger)

		// Test successful operation
		callCount := 0
		err := manager.ExecuteTokenOperation(context.Background(), "test_operation", func() error {
			callCount++
			return nil
		})

		if err != nil {
			t.Errorf("Expected no error for successful operation, got: %v", err)
		}

		if callCount != 1 {
			t.Errorf("Expected function to be called once, got: %d", callCount)
		}
	})

	// Test retry on failure
	t.Run("RetryOnFailure", func(t *testing.T) {
		manager := NewTokenResilienceManager(config, logger)

		callCount := 0
		err := manager.ExecuteTokenOperation(context.Background(), "test_retry", func() error {
			callCount++
			if callCount < 3 {
				return fmt.Errorf("connection refused") // Retryable error
			}
			return nil
		})

		if err != nil {
			t.Errorf("Expected no error after retry, got: %v", err)
		}

		if callCount != 3 {
			t.Errorf("Expected function to be called 3 times (with retries), got: %d", callCount)
		}
	})

	// Test circuit breaker functionality
	t.Run("CircuitBreakerTrip", func(t *testing.T) {
		// Use config with low failure threshold for testing
		testConfig := config
		testConfig.CircuitBreakerConfig.MaxFailures = 2

		manager := NewTokenResilienceManager(testConfig, logger)

		// Cause failures to trip circuit breaker
		for i := 0; i < 3; i++ {
			err := manager.ExecuteTokenOperation(context.Background(), "test_circuit_trip", func() error {
				return fmt.Errorf("service unavailable")
			})
			if err == nil {
				t.Errorf("Expected error for failed operation")
			}
		}

		// Circuit should now be open, next call should fail immediately
		callCount := 0
		err := manager.ExecuteTokenOperation(context.Background(), "test_circuit_open", func() error {
			callCount++
			return nil // This should not be called due to open circuit
		})

		if err == nil {
			t.Errorf("Expected circuit breaker to block request")
		}

		if callCount > 0 {
			t.Errorf("Expected function not to be called due to circuit breaker, got: %d calls", callCount)
		}
	})

	// Test metrics collection
	t.Run("MetricsCollection", func(t *testing.T) {
		manager := NewTokenResilienceManager(config, logger)

		// Execute some operations to generate metrics
		manager.ExecuteTokenOperation(context.Background(), "metrics_test", func() error {
			return nil
		})

		metrics := manager.GetMetrics()
		if metrics == nil {
			t.Fatal("Expected non-nil metrics")
		}

		if _, exists := metrics["circuit_breaker"]; !exists {
			t.Errorf("Expected circuit breaker metrics")
		}

		if _, exists := metrics["retry_executor"]; !exists {
			t.Errorf("Expected retry executor metrics")
		}
	})
}

func TestMetadataCacheResilienceConfig(t *testing.T) {
	config := DefaultMetadataCacheResilienceConfig()

	// Test security-critical field detection
	t.Run("SecurityCriticalFields", func(t *testing.T) {
		if !config.IsSecurityCriticalField("jwks_uri") {
			t.Errorf("Expected jwks_uri to be security-critical")
		}

		if !config.IsSecurityCriticalField("token_endpoint") {
			t.Errorf("Expected token_endpoint to be security-critical")
		}

		if config.IsSecurityCriticalField("non_critical_field") {
			t.Errorf("Expected non_critical_field to not be security-critical")
		}
	})

	// Test effective max grace period calculation
	t.Run("EffectiveMaxGracePeriod", func(t *testing.T) {
		maxGrace := config.GetEffectiveMaxGracePeriod("jwks_uri")
		expectedMax := 15 * time.Minute // Allan's security limit

		if maxGrace != expectedMax {
			t.Errorf("Expected security-critical field max grace period to be %v, got %v", expectedMax, maxGrace)
		}

		normalMax := config.GetEffectiveMaxGracePeriod("non_critical_field")
		expectedNormal := 30 * time.Minute

		if normalMax != expectedNormal {
			t.Errorf("Expected normal field max grace period to be %v, got %v", expectedNormal, normalMax)
		}
	})

	// Test progressive grace period values
	t.Run("ProgressiveGracePeriods", func(t *testing.T) {
		if config.InitialGracePeriod != 5*time.Minute {
			t.Errorf("Expected initial grace period to be 5 minutes, got %v", config.InitialGracePeriod)
		}

		if config.ExtendedGracePeriod != 15*time.Minute {
			t.Errorf("Expected extended grace period to be 15 minutes, got %v", config.ExtendedGracePeriod)
		}

		if config.MaxGracePeriod != 30*time.Minute {
			t.Errorf("Expected max grace period to be 30 minutes, got %v", config.MaxGracePeriod)
		}

		if config.SecurityCriticalMaxGracePeriod != 15*time.Minute {
			t.Errorf("Expected security-critical max grace period to be 15 minutes (Allan's limit), got %v", config.SecurityCriticalMaxGracePeriod)
		}
	})
}

func TestConnectionPoolingFix(t *testing.T) {
	// Test that token HTTP client uses pooled connections
	t.Run("TokenHTTPClientUsesPool", func(t *testing.T) {
		client1 := CreateTokenHTTPClient()
		client2 := CreateTokenHTTPClient()

		if client1 == nil || client2 == nil {
			t.Fatal("Expected non-nil HTTP clients")
		}

		// Both clients should use the same underlying transport pool
		// This is hard to test directly, but we can verify they're created successfully
		if client1.Transport == nil || client2.Transport == nil {
			t.Error("Expected non-nil transports")
		}

		// Verify timeout configuration
		if client1.Timeout <= 0 {
			t.Errorf("Expected positive timeout, got %v", client1.Timeout)
		}
	})

	// Test that the helper functions use pooled clients
	t.Run("HelperFunctionsUsePooling", func(t *testing.T) {
		// This is a smoke test to ensure the helpers compile and can be called
		// The actual pooling logic is tested by verifying no nil clients are created
		client := CreateTokenHTTPClient()
		if client == nil {
			t.Error("Expected CreateTokenHTTPClient to return non-nil client")
			return
		}

		defaultClient := CreateDefaultHTTPClient()
		if defaultClient == nil {
			t.Error("Expected CreateDefaultHTTPClient to return non-nil client")
			return
		}

		// Test that both have transports (indicating they use the pool)
		if client.Transport == nil {
			t.Error("Expected token client to have non-nil transport")
		}

		if defaultClient.Transport == nil {
			t.Error("Expected default client to have non-nil transport")
		}
	})
}

// Test backward compatibility - ensure old behavior still works when resilience manager is nil
func TestTokenResilienceBackwardCompatibility(t *testing.T) {
	// Create a TraefikOidc instance without token resilience manager
	tOidc := &TraefikOidc{
		logger:                 NewLogger("debug"),
		tokenResilienceManager: nil, // Explicitly nil for backward compatibility test
	}

	// Test that getNewTokenWithRefreshToken still works with nil resilience manager
	t.Run("TokenRefreshFallback", func(t *testing.T) {
		// This should not panic and should use the fallback logic
		_, err := tOidc.getNewTokenWithRefreshToken("test-refresh-token")

		// We expect an error because we don't have a real token endpoint configured,
		// but we should NOT get a panic from nil pointer dereference
		if err == nil {
			t.Log("No error (possibly valid if using mock endpoints)")
		} else {
			t.Logf("Expected error due to missing configuration: %v", err)
		}

		// The important thing is that we get here without panicking
	})

	// Test that exchangeCodeForToken still works with nil resilience manager
	t.Run("CodeExchangeFallback", func(t *testing.T) {
		// This should not panic and should use the fallback logic
		_, err := tOidc.exchangeCodeForToken("test-code", "http://localhost/callback", "")

		// We expect an error because we don't have a real token endpoint configured,
		// but we should NOT get a panic from nil pointer dereference
		if err == nil {
			t.Log("No error (possibly valid if using mock endpoints)")
		} else {
			t.Logf("Expected error due to missing configuration: %v", err)
		}

		// The important thing is that we get here without panicking
	})
}
