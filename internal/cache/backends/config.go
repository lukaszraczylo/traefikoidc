package backends

import "time"

// BackendType represents the type of cache backend
type BackendType string

const (
	BackendTypeMemory BackendType = "memory"
	BackendTypeRedis  BackendType = "redis"
	BackendTypeHybrid BackendType = "hybrid"

	// Aliases for backward compatibility
	TypeMemory BackendType = "memory"
	TypeRedis  BackendType = "redis"
	TypeHybrid BackendType = "hybrid"
)

// Config provides common configuration for cache backends
type Config struct {
	L2Config             *Config
	L1Config             *Config
	RedisPrefix          string
	Type                 BackendType
	RedisAddr            string
	RedisPassword        string
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
}

// DefaultConfig returns a default configuration for in-memory caching
func DefaultConfig() *Config {
	return &Config{
		Type:            BackendTypeMemory,
		MaxSize:         1000,
		MaxMemoryBytes:  50 * 1024 * 1024, // 50MB
		CleanupInterval: 5 * time.Minute,
		EnableMetrics:   true,
	}
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

// DefaultHybridConfig returns a default configuration for hybrid caching
func DefaultHybridConfig(redisAddr string) *Config {
	return &Config{
		Type: BackendTypeHybrid,
		L1Config: &Config{
			Type:            BackendTypeMemory,
			MaxSize:         500,
			MaxMemoryBytes:  10 * 1024 * 1024, // 10MB for L1
			CleanupInterval: 1 * time.Minute,
		},
		L2Config:      DefaultRedisConfig(redisAddr),
		AsyncWrites:   true,
		EnableMetrics: true,
	}
}
