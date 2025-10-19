// Package config provides configuration structures for the Traefik OIDC plugin.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// RedisMode represents the Redis deployment mode
type RedisMode string

const (
	// RedisModeStandalone represents a single Redis instance
	RedisModeStandalone RedisMode = "standalone"

	// RedisModeCluster represents Redis cluster mode
	RedisModeCluster RedisMode = "cluster"

	// RedisModeSentinel represents Redis sentinel mode
	RedisModeSentinel RedisMode = "sentinel"
)

// RedisConfig holds Redis cache backend configuration
type RedisConfig struct {
	// Enabled indicates if Redis backend should be used
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// Mode specifies the Redis deployment mode
	Mode RedisMode `json:"mode,omitempty" yaml:"mode,omitempty"`

	// === Standalone Configuration ===
	// Addr is the Redis server address (host:port)
	Addr string `json:"addr,omitempty" yaml:"addr,omitempty"`

	// Password for Redis authentication
	Password string `json:"password,omitempty" yaml:"password,omitempty"`

	// DB is the database number (0-15)
	DB int `json:"db,omitempty" yaml:"db,omitempty"`

	// === Cluster Configuration ===
	// ClusterAddrs is the list of cluster node addresses
	ClusterAddrs []string `json:"clusterAddrs,omitempty" yaml:"clusterAddrs,omitempty"`

	// === Sentinel Configuration ===
	// MasterName is the name of the master instance
	MasterName string `json:"masterName,omitempty" yaml:"masterName,omitempty"`

	// SentinelAddrs is the list of sentinel addresses
	SentinelAddrs []string `json:"sentinelAddrs,omitempty" yaml:"sentinelAddrs,omitempty"`

	// SentinelPassword is the password for sentinel authentication
	SentinelPassword string `json:"sentinelPassword,omitempty" yaml:"sentinelPassword,omitempty"`

	// === Connection Pool Settings ===
	// PoolSize is the maximum number of socket connections
	PoolSize int `json:"poolSize,omitempty" yaml:"poolSize,omitempty"`

	// MinIdleConns is the minimum number of idle connections
	MinIdleConns int `json:"minIdleConns,omitempty" yaml:"minIdleConns,omitempty"`

	// MaxRetries is the maximum number of retries before giving up
	MaxRetries int `json:"maxRetries,omitempty" yaml:"maxRetries,omitempty"`

	// === Timeouts ===
	// DialTimeout is the timeout for establishing new connections
	DialTimeout time.Duration `json:"dialTimeout,omitempty" yaml:"dialTimeout,omitempty"`

	// ReadTimeout is the timeout for socket reads
	ReadTimeout time.Duration `json:"readTimeout,omitempty" yaml:"readTimeout,omitempty"`

	// WriteTimeout is the timeout for socket writes
	WriteTimeout time.Duration `json:"writeTimeout,omitempty" yaml:"writeTimeout,omitempty"`

	// PoolTimeout is the timeout for connection pool
	PoolTimeout time.Duration `json:"poolTimeout,omitempty" yaml:"poolTimeout,omitempty"`

	// ConnMaxIdleTime is the maximum amount of time a connection may be idle
	ConnMaxIdleTime time.Duration `json:"connMaxIdleTime,omitempty" yaml:"connMaxIdleTime,omitempty"`

	// ConnMaxLifetime is the maximum lifetime of a connection
	ConnMaxLifetime time.Duration `json:"connMaxLifetime,omitempty" yaml:"connMaxLifetime,omitempty"`

	// === Key Management ===
	// KeyPrefix is the prefix for all Redis keys
	KeyPrefix string `json:"keyPrefix,omitempty" yaml:"keyPrefix,omitempty"`

	// === TLS Configuration ===
	// TLSEnabled enables TLS for Redis connections
	TLSEnabled bool `json:"tlsEnabled,omitempty" yaml:"tlsEnabled,omitempty"`

	// TLSInsecureSkipVerify skips TLS certificate verification
	TLSInsecureSkipVerify bool `json:"tlsInsecureSkipVerify,omitempty" yaml:"tlsInsecureSkipVerify,omitempty"`

	// === Resilience Settings ===
	// EnableCircuitBreaker enables circuit breaker for Redis operations
	EnableCircuitBreaker bool `json:"enableCircuitBreaker,omitempty" yaml:"enableCircuitBreaker,omitempty"`

	// CircuitBreakerMaxFailures is the number of failures before opening circuit
	CircuitBreakerMaxFailures int `json:"circuitBreakerMaxFailures,omitempty" yaml:"circuitBreakerMaxFailures,omitempty"`

	// CircuitBreakerTimeout is how long the circuit stays open
	CircuitBreakerTimeout time.Duration `json:"circuitBreakerTimeout,omitempty" yaml:"circuitBreakerTimeout,omitempty"`

	// EnableHealthCheck enables periodic health checks
	EnableHealthCheck bool `json:"enableHealthCheck,omitempty" yaml:"enableHealthCheck,omitempty"`

	// HealthCheckInterval is how often to check Redis health
	HealthCheckInterval time.Duration `json:"healthCheckInterval,omitempty" yaml:"healthCheckInterval,omitempty"`
}

// DefaultRedisConfig returns default Redis configuration
func DefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		Enabled:                   false,
		Mode:                      RedisModeStandalone,
		Addr:                      "localhost:6379",
		DB:                        0,
		PoolSize:                  10,
		MinIdleConns:              2,
		MaxRetries:                3,
		DialTimeout:               5 * time.Second,
		ReadTimeout:               3 * time.Second,
		WriteTimeout:              3 * time.Second,
		PoolTimeout:               4 * time.Second,
		ConnMaxIdleTime:           5 * time.Minute,
		ConnMaxLifetime:           30 * time.Minute,
		KeyPrefix:                 "traefikoidc:",
		TLSEnabled:                false,
		TLSInsecureSkipVerify:     false,
		EnableCircuitBreaker:      true,
		CircuitBreakerMaxFailures: 5,
		CircuitBreakerTimeout:     30 * time.Second,
		EnableHealthCheck:         true,
		HealthCheckInterval:       30 * time.Second,
	}
}

// LoadFromEnv loads Redis configuration from environment variables
func (c *RedisConfig) LoadFromEnv() {
	// Enable Redis if environment variable is set
	if enabled := os.Getenv("REDIS_ENABLED"); enabled != "" {
		c.Enabled = strings.ToLower(enabled) == "true"
	}

	// Mode
	if mode := os.Getenv("REDIS_MODE"); mode != "" {
		c.Mode = RedisMode(strings.ToLower(mode))
	}

	// Standalone configuration
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		c.Addr = addr
	}
	if password := os.Getenv("REDIS_PASSWORD"); password != "" {
		c.Password = password
	}
	if db := os.Getenv("REDIS_DB"); db != "" {
		if dbNum, err := strconv.Atoi(db); err == nil {
			c.DB = dbNum
		}
	}

	// Cluster configuration
	if clusterAddrs := os.Getenv("REDIS_CLUSTER_ADDRS"); clusterAddrs != "" {
		c.ClusterAddrs = strings.Split(clusterAddrs, ",")
		for i := range c.ClusterAddrs {
			c.ClusterAddrs[i] = strings.TrimSpace(c.ClusterAddrs[i])
		}
	}

	// Sentinel configuration
	if masterName := os.Getenv("REDIS_MASTER_NAME"); masterName != "" {
		c.MasterName = masterName
	}
	if sentinelAddrs := os.Getenv("REDIS_SENTINEL_ADDRS"); sentinelAddrs != "" {
		c.SentinelAddrs = strings.Split(sentinelAddrs, ",")
		for i := range c.SentinelAddrs {
			c.SentinelAddrs[i] = strings.TrimSpace(c.SentinelAddrs[i])
		}
	}
	if sentinelPassword := os.Getenv("REDIS_SENTINEL_PASSWORD"); sentinelPassword != "" {
		c.SentinelPassword = sentinelPassword
	}

	// Connection pool settings
	if poolSize := os.Getenv("REDIS_POOL_SIZE"); poolSize != "" {
		if size, err := strconv.Atoi(poolSize); err == nil {
			c.PoolSize = size
		}
	}
	if minIdleConns := os.Getenv("REDIS_MIN_IDLE_CONNS"); minIdleConns != "" {
		if conns, err := strconv.Atoi(minIdleConns); err == nil {
			c.MinIdleConns = conns
		}
	}
	if maxRetries := os.Getenv("REDIS_MAX_RETRIES"); maxRetries != "" {
		if retries, err := strconv.Atoi(maxRetries); err == nil {
			c.MaxRetries = retries
		}
	}

	// Timeouts
	if dialTimeout := os.Getenv("REDIS_DIAL_TIMEOUT"); dialTimeout != "" {
		if timeout, err := time.ParseDuration(dialTimeout); err == nil {
			c.DialTimeout = timeout
		}
	}
	if readTimeout := os.Getenv("REDIS_READ_TIMEOUT"); readTimeout != "" {
		if timeout, err := time.ParseDuration(readTimeout); err == nil {
			c.ReadTimeout = timeout
		}
	}
	if writeTimeout := os.Getenv("REDIS_WRITE_TIMEOUT"); writeTimeout != "" {
		if timeout, err := time.ParseDuration(writeTimeout); err == nil {
			c.WriteTimeout = timeout
		}
	}

	// Key prefix
	if keyPrefix := os.Getenv("REDIS_KEY_PREFIX"); keyPrefix != "" {
		c.KeyPrefix = keyPrefix
	}

	// TLS settings
	if tlsEnabled := os.Getenv("REDIS_TLS_ENABLED"); tlsEnabled != "" {
		c.TLSEnabled = strings.ToLower(tlsEnabled) == "true"
	}
	if tlsInsecure := os.Getenv("REDIS_TLS_INSECURE_SKIP_VERIFY"); tlsInsecure != "" {
		c.TLSInsecureSkipVerify = strings.ToLower(tlsInsecure) == "true"
	}

	// Resilience settings
	if enableCB := os.Getenv("REDIS_ENABLE_CIRCUIT_BREAKER"); enableCB != "" {
		c.EnableCircuitBreaker = strings.ToLower(enableCB) == "true"
	}
	if cbMaxFailures := os.Getenv("REDIS_CIRCUIT_BREAKER_MAX_FAILURES"); cbMaxFailures != "" {
		if failures, err := strconv.Atoi(cbMaxFailures); err == nil {
			c.CircuitBreakerMaxFailures = failures
		}
	}
	if cbTimeout := os.Getenv("REDIS_CIRCUIT_BREAKER_TIMEOUT"); cbTimeout != "" {
		if timeout, err := time.ParseDuration(cbTimeout); err == nil {
			c.CircuitBreakerTimeout = timeout
		}
	}
	if enableHC := os.Getenv("REDIS_ENABLE_HEALTH_CHECK"); enableHC != "" {
		c.EnableHealthCheck = strings.ToLower(enableHC) == "true"
	}
	if hcInterval := os.Getenv("REDIS_HEALTH_CHECK_INTERVAL"); hcInterval != "" {
		if interval, err := time.ParseDuration(hcInterval); err == nil {
			c.HealthCheckInterval = interval
		}
	}
}

// Validate checks if the configuration is valid
func (c *RedisConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	switch c.Mode {
	case RedisModeStandalone:
		if c.Addr == "" {
			return &ConfigError{Field: "addr", Message: "Redis address is required for standalone mode"}
		}
	case RedisModeCluster:
		if len(c.ClusterAddrs) == 0 {
			return &ConfigError{Field: "clusterAddrs", Message: "At least one cluster address is required"}
		}
	case RedisModeSentinel:
		if c.MasterName == "" {
			return &ConfigError{Field: "masterName", Message: "Master name is required for sentinel mode"}
		}
		if len(c.SentinelAddrs) == 0 {
			return &ConfigError{Field: "sentinelAddrs", Message: "At least one sentinel address is required"}
		}
	default:
		return &ConfigError{Field: "mode", Message: "Invalid Redis mode"}
	}

	return nil
}

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field   string
	Message string
}

// Error implements the error interface
func (e *ConfigError) Error() string {
	return "redis config error: " + e.Field + ": " + e.Message
}
