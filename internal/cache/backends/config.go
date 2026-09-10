package backends

import "time"

// BackendType represents the type of cache backend
type BackendType string

const (
	BackendTypeRedis BackendType = "redis"

	// TypeRedis is an alias for backward compatibility
	TypeRedis BackendType = "redis"
)

// Config provides common configuration for cache backends
type Config struct {
	L2Config             *Config
	L1Config             *Config
	RedisPrefix          string
	Type                 BackendType
	RedisAddr            string
	RedisPassword        string
	TLSServerName        string
	PoolSize             int
	RedisDB              int
	CleanupInterval      time.Duration
	MaxMemoryBytes       int64
	MaxSize              int
	HealthCheckInterval  time.Duration
	AsyncWrites          bool
	EnableCircuitBreaker bool
	EnableHealthCheck    bool
	EnableMetrics        bool
	EnableTLS            bool
	TLSSkipVerify        bool
}

// DefaultRedisConfig returns a default configuration for Redis caching
func DefaultRedisConfig(addr string) *Config {
	return &Config{
		Type:                 BackendTypeRedis,
		RedisAddr:            addr,
		RedisDB:              0,
		RedisPrefix:          "traefikoidc:",
		PoolSize:             10,
		EnableCircuitBreaker: true,
		EnableHealthCheck:    true,
		HealthCheckInterval:  30 * time.Second,
		EnableMetrics:        true,
	}
}
