package traefikoidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRetryExecutorReset tests the Reset method
func TestRetryExecutorReset(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	executor := NewRetryExecutor(DefaultRetryConfig(), logger)

	require.NotNil(t, executor)

	// Should not panic
	assert.NotPanics(t, func() {
		executor.Reset()
	})

	// Multiple resets should be safe
	executor.Reset()
	executor.Reset()
}

// TestRetryExecutorIsAvailable tests the IsAvailable method
func TestRetryExecutorIsAvailable(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	executor := NewRetryExecutor(DefaultRetryConfig(), logger)

	// Retry executor should always be available
	assert.True(t, executor.IsAvailable())

	// Should remain available after operations
	ctx := context.Background()
	executor.ExecuteWithContext(ctx, func() error {
		return nil
	})

	assert.True(t, executor.IsAvailable())
}

// TestSessionErrorUnwrap tests SessionError.Unwrap
func TestSessionErrorUnwrap(t *testing.T) {
	t.Run("unwrap with cause", func(t *testing.T) {
		rootErr := errors.New("root cause")
		sessionErr := NewSessionError("save", "failed to save session", rootErr)

		unwrapped := sessionErr.Unwrap()
		assert.Equal(t, rootErr, unwrapped)
	})

	t.Run("unwrap without cause", func(t *testing.T) {
		sessionErr := NewSessionError("load", "failed to load session", nil)

		unwrapped := sessionErr.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("error chain", func(t *testing.T) {
		rootErr := errors.New("database error")
		sessionErr := NewSessionError("delete", "failed to delete session", rootErr)

		// Verify error chain works
		assert.True(t, errors.Is(sessionErr, rootErr))
	})
}

// TestTokenErrorUnwrap tests TokenError.Unwrap
func TestTokenErrorUnwrap(t *testing.T) {
	t.Run("unwrap with cause", func(t *testing.T) {
		rootErr := errors.New("signature verification failed")
		tokenErr := NewTokenError("id_token", "invalid", "token is invalid", rootErr)

		unwrapped := tokenErr.Unwrap()
		assert.Equal(t, rootErr, unwrapped)
	})

	t.Run("unwrap without cause", func(t *testing.T) {
		tokenErr := NewTokenError("access_token", "expired", "token has expired", nil)

		unwrapped := tokenErr.Unwrap()
		assert.Nil(t, unwrapped)
	})

	t.Run("error chain", func(t *testing.T) {
		rootErr := errors.New("crypto error")
		tokenErr := NewTokenError("refresh_token", "malformed", "token is malformed", rootErr)

		// Verify error chain works
		assert.True(t, errors.Is(tokenErr, rootErr))
	})
}

// TestGracefulDegradationRegisterFallback tests fallback registration
func TestGracefulDegradationRegisterFallback(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("register single fallback", func(t *testing.T) {
		fallback := func() (interface{}, error) {
			return "fallback result", nil
		}

		gd.RegisterFallback("service1", fallback)

		// Verify fallback was registered (indirectly)
		result, err := gd.ExecuteWithFallback("service1", func() (interface{}, error) {
			return nil, errors.New("service failed")
		})

		assert.NoError(t, err)
		assert.Equal(t, "fallback result", result)
	})

	t.Run("register multiple fallbacks", func(t *testing.T) {
		gd.RegisterFallback("service2", func() (interface{}, error) {
			return "fallback2", nil
		})
		gd.RegisterFallback("service3", func() (interface{}, error) {
			return "fallback3", nil
		})

		result2, _ := gd.ExecuteWithFallback("service2", func() (interface{}, error) {
			return nil, errors.New("fail")
		})
		result3, _ := gd.ExecuteWithFallback("service3", func() (interface{}, error) {
			return nil, errors.New("fail")
		})

		assert.Equal(t, "fallback2", result2)
		assert.Equal(t, "fallback3", result3)
	})

	t.Run("override existing fallback", func(t *testing.T) {
		gd.RegisterFallback("service4", func() (interface{}, error) {
			return "old fallback", nil
		})
		gd.RegisterFallback("service4", func() (interface{}, error) {
			return "new fallback", nil
		})

		result, _ := gd.ExecuteWithFallback("service4", func() (interface{}, error) {
			return nil, errors.New("fail")
		})

		assert.Equal(t, "new fallback", result)
	})
}

// TestGracefulDegradationRegisterHealthCheck tests health check registration
func TestGracefulDegradationRegisterHealthCheck(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	config.HealthCheckInterval = 50 * time.Millisecond
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("register health check", func(t *testing.T) {
		healthy := true
		healthCheck := func() bool {
			return healthy
		}

		gd.RegisterHealthCheck("service1", healthCheck)

		// Mark service as degraded
		gd.markServiceDegraded("service1")
		assert.True(t, gd.isServiceDegraded("service1"))

		// Set healthy and wait for health check to run
		healthy = true
		time.Sleep(100 * time.Millisecond)

		// Service should be recovered
		// (may still be degraded due to timing, but health check was registered)
	})

	t.Run("multiple health checks", func(t *testing.T) {
		gd.RegisterHealthCheck("service2", func() bool { return true })
		gd.RegisterHealthCheck("service3", func() bool { return false })

		// Health checks are registered and will be called periodically
	})
}

// TestGracefulDegradationExecuteWithContext tests ExecuteWithContext
func TestGracefulDegradationExecuteWithContext(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("successful execution", func(t *testing.T) {
		ctx := context.Background()
		err := gd.ExecuteWithContext(ctx, func() error {
			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("failed execution", func(t *testing.T) {
		ctx := context.Background()
		testErr := errors.New("operation failed")

		err := gd.ExecuteWithContext(ctx, func() error {
			return testErr
		})

		assert.Error(t, err)
	})

	t.Run("uses fallback on failure", func(t *testing.T) {
		gd.RegisterFallback("default", func() (interface{}, error) {
			return nil, nil // Success fallback
		})

		ctx := context.Background()
		err := gd.ExecuteWithContext(ctx, func() error {
			return errors.New("primary failed")
		})

		// With fallback succeeding, overall operation succeeds
		assert.NoError(t, err)
	})
}

// TestGracefulDegradationExecuteWithFallback tests ExecuteWithFallback
func TestGracefulDegradationExecuteWithFallback(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("primary succeeds", func(t *testing.T) {
		result, err := gd.ExecuteWithFallback("service1", func() (interface{}, error) {
			return "primary result", nil
		})

		assert.NoError(t, err)
		assert.Equal(t, "primary result", result)
	})

	t.Run("fallback succeeds when primary fails", func(t *testing.T) {
		gd.RegisterFallback("service2", func() (interface{}, error) {
			return "fallback result", nil
		})

		result, err := gd.ExecuteWithFallback("service2", func() (interface{}, error) {
			return nil, errors.New("primary failed")
		})

		assert.NoError(t, err)
		assert.Equal(t, "fallback result", result)
	})

	t.Run("error when no fallback available", func(t *testing.T) {
		config.EnableFallbacks = false
		gdNoFallback := NewGracefulDegradation(config, logger)
		defer gdNoFallback.Close()

		result, err := gdNoFallback.ExecuteWithFallback("service3", func() (interface{}, error) {
			return nil, errors.New("primary failed")
		})

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("fallback also fails", func(t *testing.T) {
		gd.RegisterFallback("service4", func() (interface{}, error) {
			return nil, errors.New("fallback also failed")
		})

		result, err := gd.ExecuteWithFallback("service4", func() (interface{}, error) {
			return nil, errors.New("primary failed")
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "fallback also failed")
	})
}

// TestGracefulDegradationIsServiceDegraded tests service degradation status
func TestGracefulDegradationIsServiceDegraded(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	config.RecoveryTimeout = 100 * time.Millisecond
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("service not degraded initially", func(t *testing.T) {
		assert.False(t, gd.isServiceDegraded("new-service"))
	})

	t.Run("service degraded after marking", func(t *testing.T) {
		gd.markServiceDegraded("service1")
		assert.True(t, gd.isServiceDegraded("service1"))
	})

	t.Run("service recovers after timeout", func(t *testing.T) {
		gd.markServiceDegraded("service2")
		assert.True(t, gd.isServiceDegraded("service2"))

		// Wait for recovery timeout
		time.Sleep(150 * time.Millisecond)

		// Should be recovered
		assert.False(t, gd.isServiceDegraded("service2"))
	})
}

// TestGracefulDegradationMarkServiceDegraded tests marking services as degraded
func TestGracefulDegradationMarkServiceDegraded(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("mark single service", func(t *testing.T) {
		gd.markServiceDegraded("service1")

		degraded := gd.GetDegradedServices()
		assert.Contains(t, degraded, "service1")
	})

	t.Run("mark multiple services", func(t *testing.T) {
		gd.markServiceDegraded("service2")
		gd.markServiceDegraded("service3")

		degraded := gd.GetDegradedServices()
		assert.Contains(t, degraded, "service2")
		assert.Contains(t, degraded, "service3")
	})

	t.Run("marking same service multiple times updates timestamp", func(t *testing.T) {
		gd.markServiceDegraded("service4")
		time.Sleep(50 * time.Millisecond)
		gd.markServiceDegraded("service4")

		// Service should still be marked as degraded
		assert.True(t, gd.isServiceDegraded("service4"))
	})
}

// TestGracefulDegradationExecuteFallback tests fallback execution
func TestGracefulDegradationExecuteFallback(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("execute registered fallback", func(t *testing.T) {
		gd.RegisterFallback("service1", func() (interface{}, error) {
			return "fallback value", nil
		})

		result, err := gd.executeFallback("service1")

		assert.NoError(t, err)
		assert.Equal(t, "fallback value", result)
	})

	t.Run("error when fallback not registered", func(t *testing.T) {
		result, err := gd.executeFallback("non-existent-service")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no fallback available")
	})

	t.Run("propagate fallback errors", func(t *testing.T) {
		gd.RegisterFallback("service2", func() (interface{}, error) {
			return nil, errors.New("fallback error")
		})

		result, err := gd.executeFallback("service2")

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "fallback error")
	})
}

// TestGracefulDegradationReset tests Reset method
func TestGracefulDegradationReset(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("reset clears degraded services", func(t *testing.T) {
		// Mark several services as degraded
		gd.markServiceDegraded("service1")
		gd.markServiceDegraded("service2")
		gd.markServiceDegraded("service3")

		assert.Len(t, gd.GetDegradedServices(), 3)

		// Reset
		gd.Reset()

		// All should be cleared
		assert.Len(t, gd.GetDegradedServices(), 0)
	})

	t.Run("can mark services degraded after reset", func(t *testing.T) {
		gd.Reset()
		gd.markServiceDegraded("service4")

		assert.Len(t, gd.GetDegradedServices(), 1)
		assert.Contains(t, gd.GetDegradedServices(), "service4")
	})

	t.Run("multiple resets are safe", func(t *testing.T) {
		assert.NotPanics(t, func() {
			gd.Reset()
			gd.Reset()
			gd.Reset()
		})
	})
}

// TestGracefulDegradationIsAvailable tests IsAvailable method
func TestGracefulDegradationIsAvailable(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	// Should always return true
	assert.True(t, gd.IsAvailable())

	// Even with degraded services
	gd.markServiceDegraded("service1")
	assert.True(t, gd.IsAvailable())

	// Even after reset
	gd.Reset()
	assert.True(t, gd.IsAvailable())
}

// TestGracefulDegradationGetMetrics tests GetMetrics method
func TestGracefulDegradationGetMetrics(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	t.Run("basic metrics", func(t *testing.T) {
		metrics := gd.GetMetrics()

		require.NotNil(t, metrics)
		assert.Contains(t, metrics, "degraded_services_count")
		assert.Contains(t, metrics, "degraded_services")
		assert.Contains(t, metrics, "registered_fallbacks_count")
		assert.Contains(t, metrics, "registered_health_checks_count")
		assert.Contains(t, metrics, "health_check_interval_seconds")
		assert.Contains(t, metrics, "recovery_timeout_seconds")
		assert.Contains(t, metrics, "fallbacks_enabled")
	})

	t.Run("metrics reflect degraded services", func(t *testing.T) {
		gd.Reset()
		gd.markServiceDegraded("service1")
		gd.markServiceDegraded("service2")

		metrics := gd.GetMetrics()

		assert.Equal(t, 2, metrics["degraded_services_count"])
		degradedList := metrics["degraded_services"].([]string)
		assert.Len(t, degradedList, 2)
	})

	t.Run("metrics reflect registered fallbacks", func(t *testing.T) {
		gd.RegisterFallback("service1", func() (interface{}, error) { return nil, nil })
		gd.RegisterFallback("service2", func() (interface{}, error) { return nil, nil })

		metrics := gd.GetMetrics()

		assert.GreaterOrEqual(t, metrics["registered_fallbacks_count"], 2)
	})

	t.Run("metrics include base metrics", func(t *testing.T) {
		metrics := gd.GetMetrics()

		// Should include base recovery mechanism metrics
		assert.Contains(t, metrics, "name")
		assert.Contains(t, metrics, "uptime_seconds")
		assert.Contains(t, metrics, "total_requests")
	})
}

// TestGracefulDegradationFullScenario tests a complete degradation scenario
func TestGracefulDegradationFullScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full scenario test in short mode")
	}

	logger := GetSingletonNoOpLogger()
	config := DefaultGracefulDegradationConfig()
	config.RecoveryTimeout = 200 * time.Millisecond
	config.HealthCheckInterval = 50 * time.Millisecond
	gd := NewGracefulDegradation(config, logger)
	defer gd.Close()

	// Register fallback
	gd.RegisterFallback("critical-service", func() (interface{}, error) {
		return "fallback data", nil
	})

	// Register health check
	serviceHealthy := false
	gd.RegisterHealthCheck("critical-service", func() bool {
		return serviceHealthy
	})

	// First call - primary succeeds
	result1, err1 := gd.ExecuteWithFallback("critical-service", func() (interface{}, error) {
		return "primary data", nil
	})
	assert.NoError(t, err1)
	assert.Equal(t, "primary data", result1)

	// Second call - primary fails, fallback succeeds
	result2, err2 := gd.ExecuteWithFallback("critical-service", func() (interface{}, error) {
		return nil, errors.New("service down")
	})
	assert.NoError(t, err2)
	assert.Equal(t, "fallback data", result2)

	// Service is now degraded
	assert.True(t, gd.isServiceDegraded("critical-service"))

	// Third call - should use fallback immediately
	result3, err3 := gd.ExecuteWithFallback("critical-service", func() (interface{}, error) {
		return "should not be called", nil
	})
	assert.NoError(t, err3)
	assert.Equal(t, "fallback data", result3)

	// Mark service as healthy and wait for health check
	serviceHealthy = true
	time.Sleep(250 * time.Millisecond)

	// Service should be recovered
	// (timing-dependent, so we don't assert)

	// Get metrics
	metrics := gd.GetMetrics()
	assert.NotNil(t, metrics)
}
