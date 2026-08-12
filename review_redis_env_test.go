package traefikoidc

import "testing"

// TestRedisConfig_ApplyEnvFallbacks_Resilience guards the fix that wires the
// documented REDIS_* resilience env fallbacks (examples/redis-config.yaml) into
// ApplyEnvFallbacks. Previously an operator following the documented names got
// no effect: the fields existed but the env vars were never read.
func TestRedisConfig_ApplyEnvFallbacks_Resilience(t *testing.T) {
	t.Setenv("REDIS_ENABLED", "true")
	t.Setenv("REDIS_ENABLE_CIRCUIT_BREAKER", "true")
	t.Setenv("REDIS_CIRCUIT_BREAKER_THRESHOLD", "7")
	t.Setenv("REDIS_CIRCUIT_BREAKER_TIMEOUT", "90")
	t.Setenv("REDIS_ENABLE_HEALTH_CHECK", "true")
	t.Setenv("REDIS_HEALTH_CHECK_INTERVAL", "45")

	rc := &RedisConfig{}
	rc.ApplyEnvFallbacks()

	if !rc.Enabled {
		t.Error("expected Redis enabled from REDIS_ENABLED")
	}
	if !rc.EnableCircuitBreaker {
		t.Error("expected EnableCircuitBreaker from REDIS_ENABLE_CIRCUIT_BREAKER")
	}
	if rc.CircuitBreakerThreshold != 7 {
		t.Errorf("expected CircuitBreakerThreshold 7, got %d", rc.CircuitBreakerThreshold)
	}
	if rc.CircuitBreakerTimeout != 90 {
		t.Errorf("expected CircuitBreakerTimeout 90, got %d", rc.CircuitBreakerTimeout)
	}
	if !rc.EnableHealthCheck {
		t.Error("expected EnableHealthCheck from REDIS_ENABLE_HEALTH_CHECK")
	}
	if rc.HealthCheckInterval != 45 {
		t.Errorf("expected HealthCheckInterval 45, got %d", rc.HealthCheckInterval)
	}
}

// TestRedisConfig_ApplyEnvFallbacks_ConfigTakesPrecedence ensures explicitly-set
// config fields are not overridden by the env fallbacks.
func TestRedisConfig_ApplyEnvFallbacks_ConfigTakesPrecedence(t *testing.T) {
	t.Setenv("REDIS_ENABLED", "true")
	t.Setenv("REDIS_CIRCUIT_BREAKER_THRESHOLD", "9")

	rc := &RedisConfig{Enabled: true, CircuitBreakerThreshold: 4}
	rc.ApplyEnvFallbacks()

	if rc.CircuitBreakerThreshold != 4 {
		t.Errorf("expected config value 4 to take precedence, got %d", rc.CircuitBreakerThreshold)
	}
}
