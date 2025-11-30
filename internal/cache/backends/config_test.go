//go:build !yaegi

package backends

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultHybridConfig verifies the default hybrid configuration
func TestDefaultHybridConfig(t *testing.T) {
	redisAddr := "localhost:6379"

	config := DefaultHybridConfig(redisAddr)

	require.NotNil(t, config)

	// Verify top-level config
	assert.Equal(t, BackendTypeHybrid, config.Type)
	assert.True(t, config.AsyncWrites)
	assert.True(t, config.EnableMetrics)

	// Verify L1 (memory) config
	require.NotNil(t, config.L1Config)
	assert.Equal(t, BackendTypeMemory, config.L1Config.Type)
	assert.Equal(t, 500, config.L1Config.MaxSize)
	assert.Equal(t, int64(10*1024*1024), config.L1Config.MaxMemoryBytes) // 10MB
	assert.Equal(t, 1*time.Minute, config.L1Config.CleanupInterval)

	// Verify L2 (Redis) config exists
	require.NotNil(t, config.L2Config)
	assert.Equal(t, BackendTypeRedis, config.L2Config.Type)
}

func TestDefaultHybridConfig_DifferentRedisAddr(t *testing.T) {
	tests := []struct {
		name      string
		redisAddr string
	}{
		{"localhost", "localhost:6379"},
		{"remote host", "redis.example.com:6379"},
		{"IP address", "192.168.1.100:6379"},
		{"custom port", "localhost:6380"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultHybridConfig(tt.redisAddr)

			require.NotNil(t, config)
			assert.Equal(t, BackendTypeHybrid, config.Type)
			assert.NotNil(t, config.L1Config)
			assert.NotNil(t, config.L2Config)
		})
	}
}
