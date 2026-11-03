package traefikoidc

import (
	"math"
	"testing"
	"time"
)

func boundsTestConfig() *Config {
	cfg := CreateConfig()
	cfg.ProviderURL = "https://auth.example.com"
	cfg.CallbackURL = "/callback"
	cfg.ClientID = "test-client"
	cfg.ClientSecret = "test-client-secret"
	cfg.SessionEncryptionKey = "test-encryption-key-32-bytes-long!!"
	return cfg
}

const maxWholeSeconds = math.MaxInt64 / int64(time.Second)

func TestConfigValidateRejectsDurationOverflow(t *testing.T) {
	cases := map[string]func(c *Config){
		"maxTokenAgeSeconds wraps negative": func(c *Config) { c.MaxTokenAgeSeconds = maxWholeSeconds + 1 },
		"maxTokenAgeSeconds wraps to zero":  func(c *Config) { c.MaxTokenAgeSeconds = 1 << 55 },
		"bearerFailureWindowSeconds":        func(c *Config) { c.BearerFailureWindowSeconds = int(maxWholeSeconds + 1) },
		"bearerFailurePenaltySeconds":       func(c *Config) { c.BearerFailurePenaltySeconds = int(maxWholeSeconds + 1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := boundsTestConfig()
			mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate accepted an overflowing duration")
			}
		})
	}
	t.Run("max exact value still valid", func(t *testing.T) {
		cfg := boundsTestConfig()
		cfg.MaxTokenAgeSeconds = maxWholeSeconds
		if err := cfg.Validate(); err != nil {
			t.Fatalf("boundary value rejected: %v", err)
		}
	})
}

func TestRedisConfigValidateRejectsOverflowAndHugePool(t *testing.T) {
	base := func() *RedisConfig {
		rc := &RedisConfig{Enabled: true, Address: "localhost:6379"}
		return rc
	}
	cases := map[string]func(rc *RedisConfig){
		"healthCheckInterval wraps to zero": func(rc *RedisConfig) { rc.HealthCheckInterval = 1 << 55 },
		"circuitBreakerTimeout wraps":       func(rc *RedisConfig) { rc.CircuitBreakerTimeout = int(maxWholeSeconds + 1) },
		"circuitBreakerThreshold narrows":   func(rc *RedisConfig) { rc.CircuitBreakerThreshold = math.MaxInt32 + 1 },
		"poolSize absurd":                   func(rc *RedisConfig) { rc.PoolSize = 1_000_000_000 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rc := base()
			mutate(rc)
			if err := rc.Validate(); err == nil {
				t.Fatal("Validate accepted an unsafe value")
			}
		})
	}
	t.Run("defaults and sane values stay valid", func(t *testing.T) {
		rc := base()
		rc.PoolSize, rc.CircuitBreakerThreshold, rc.HealthCheckInterval = 50, 5, 30
		if err := rc.Validate(); err != nil {
			t.Fatalf("sane config rejected: %v", err)
		}
	})
}
