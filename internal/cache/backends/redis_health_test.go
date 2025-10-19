package backends

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHealthMonitor_BasicOperation tests basic health monitoring
func TestHealthMonitor_BasicOperation(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	// Create health monitor with fast check interval for testing
	hmConfig := &HealthMonitorConfig{
		CheckInterval:      100 * time.Millisecond,
		Timeout:            1 * time.Second,
		UnhealthyThreshold: 2,
	}

	hm := NewHealthMonitor(pool, hmConfig)
	require.NotNil(t, hm)

	// Initially should be healthy
	assert.True(t, hm.IsHealthy())

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for a few checks
	time.Sleep(500 * time.Millisecond)

	// Should still be healthy
	assert.True(t, hm.IsHealthy())

	// Check stats
	stats := hm.GetStats()
	require.NotNil(t, stats)
	assert.True(t, stats["healthy"].(bool))
	assert.Greater(t, stats["total_checks"].(int64), int64(0))
	assert.Equal(t, int64(0), stats["consecutive_failures"].(int64))
}

// TestHealthMonitor_HealthyToUnhealthy tests transition to unhealthy state
func TestHealthMonitor_HealthyToUnhealthy(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
		ConnectTimeout: 100 * time.Millisecond,
		ReadTimeout:    100 * time.Millisecond,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	var healthChangedCalled atomic.Bool
	hmConfig := &HealthMonitorConfig{
		CheckInterval:      50 * time.Millisecond,
		Timeout:            100 * time.Millisecond,
		UnhealthyThreshold: 2,
		OnHealthChange: func(healthy bool) {
			if !healthy {
				healthChangedCalled.Store(true)
			}
		},
	}

	hm := NewHealthMonitor(pool, hmConfig)
	hm.Start()
	defer hm.Stop()

	// Initially healthy
	assert.True(t, hm.IsHealthy())

	// Simulate Redis errors
	mr.SetError("ERR server is down")

	// Wait for health checks to detect failure (2 failures * 50ms + buffer)
	time.Sleep(350 * time.Millisecond)

	// Should now be unhealthy
	assert.False(t, hm.IsHealthy(), "Health monitor should detect server failure")
	assert.True(t, healthChangedCalled.Load(), "OnHealthChange callback should be called")

	// Check stats
	stats := hm.GetStats()
	assert.False(t, stats["healthy"].(bool))
	assert.GreaterOrEqual(t, stats["consecutive_failures"].(int64), int64(2))
	assert.Greater(t, stats["total_failures"].(int64), int64(0))
}

// TestHealthMonitor_UnhealthyToHealthy tests recovery to healthy state
func TestHealthMonitor_UnhealthyToHealthy(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
		ConnectTimeout: 100 * time.Millisecond,
		ReadTimeout:    100 * time.Millisecond,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	var recoveryDetected atomic.Bool
	hmConfig := &HealthMonitorConfig{
		CheckInterval:      50 * time.Millisecond,
		Timeout:            100 * time.Millisecond,
		UnhealthyThreshold: 2,
		OnHealthChange: func(healthy bool) {
			if healthy {
				recoveryDetected.Store(true)
			}
		},
	}

	hm := NewHealthMonitor(pool, hmConfig)
	hm.Start()
	defer hm.Stop()

	// Initially healthy
	assert.True(t, hm.IsHealthy())

	// Simulate Redis errors
	mr.SetError("ERR server is down")

	// Wait for health checks to detect failure
	time.Sleep(350 * time.Millisecond)

	// Should now be unhealthy
	assert.False(t, hm.IsHealthy(), "Should detect server failure")

	// Clear error to simulate recovery
	mr.ClearError()

	// Wait for recovery
	time.Sleep(350 * time.Millisecond)

	// Should be healthy again
	assert.True(t, hm.IsHealthy(), "Should recover after server restart")
	assert.True(t, recoveryDetected.Load(), "Recovery callback should be called")

	// Consecutive failures should be reset
	stats := hm.GetStats()
	assert.True(t, stats["healthy"].(bool))
	assert.Equal(t, int64(0), stats["consecutive_failures"].(int64))
}

// TestHealthMonitor_StartStop tests start/stop behavior
func TestHealthMonitor_StartStop(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	hm := NewHealthMonitor(pool, DefaultHealthMonitorConfig())

	// Start monitoring
	hm.Start()
	assert.True(t, hm.running.Load())

	// Starting again should be no-op
	hm.Start()
	assert.True(t, hm.running.Load())

	// Stop monitoring
	hm.Stop()
	assert.False(t, hm.running.Load())

	// Stopping again should be no-op
	hm.Stop()
	assert.False(t, hm.running.Load())
}

// TestHealthMonitor_MultipleMonitors tests multiple health monitors
func TestHealthMonitor_MultipleMonitors(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 10,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	// Create multiple monitors
	hm1 := NewHealthMonitor(pool, &HealthMonitorConfig{
		CheckInterval:      100 * time.Millisecond,
		Timeout:            1 * time.Second,
		UnhealthyThreshold: 2,
	})

	hm2 := NewHealthMonitor(pool, &HealthMonitorConfig{
		CheckInterval:      150 * time.Millisecond,
		Timeout:            1 * time.Second,
		UnhealthyThreshold: 3,
	})

	// Start both
	hm1.Start()
	hm2.Start()

	// Both should be healthy
	time.Sleep(200 * time.Millisecond)
	assert.True(t, hm1.IsHealthy())
	assert.True(t, hm2.IsHealthy())

	// Stop both
	hm1.Stop()
	hm2.Stop()

	// Verify they stopped
	assert.False(t, hm1.running.Load())
	assert.False(t, hm2.running.Load())
}

// TestHealthMonitor_StatsAccuracy tests stats tracking
func TestHealthMonitor_StatsAccuracy(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	hm := NewHealthMonitor(pool, &HealthMonitorConfig{
		CheckInterval:      100 * time.Millisecond,
		Timeout:            1 * time.Second,
		UnhealthyThreshold: 2,
	})

	hm.Start()
	defer hm.Stop()

	// Wait for some checks
	time.Sleep(550 * time.Millisecond)

	stats := hm.GetStats()

	// Should have performed multiple checks
	totalChecks := stats["total_checks"].(int64)
	assert.GreaterOrEqual(t, totalChecks, int64(4))

	// All checks should succeed
	assert.Equal(t, int64(0), stats["total_failures"].(int64))
	assert.Equal(t, int64(0), stats["consecutive_failures"].(int64))

	// Last check time should be recent (within check interval + buffer)
	lastCheck := stats["last_check"].(time.Time)
	assert.WithinDuration(t, time.Now(), lastCheck, 1*time.Second)
}

// TestHealthMonitor_DefaultConfig tests default configuration
func TestHealthMonitor_DefaultConfig(t *testing.T) {
	config := DefaultHealthMonitorConfig()

	assert.Equal(t, 5*time.Second, config.CheckInterval)
	assert.Equal(t, 3*time.Second, config.Timeout)
	assert.Equal(t, 3, config.UnhealthyThreshold)
	assert.Nil(t, config.OnHealthChange)
}

// TestHealthMonitor_PoolExhaustion tests behavior when pool is exhausted
func TestHealthMonitor_PoolExhaustion(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 1, // Very small pool
		ConnectTimeout: 100 * time.Millisecond,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	hm := NewHealthMonitor(pool, &HealthMonitorConfig{
		CheckInterval:      100 * time.Millisecond,
		Timeout:            50 * time.Millisecond, // Short timeout
		UnhealthyThreshold: 2,
	})

	hm.Start()
	defer hm.Stop()

	// Get the only connection, blocking health checks
	ctx := context.Background()
	conn, err := pool.Get(ctx)
	require.NoError(t, err)

	// Wait for health check attempts
	time.Sleep(350 * time.Millisecond)

	// Health monitor might mark as unhealthy due to timeouts
	stats := hm.GetStats()
	t.Logf("Stats with blocked pool: %+v", stats)

	// Return connection
	pool.Put(conn)

	// Wait for recovery
	time.Sleep(300 * time.Millisecond)

	// Should recover
	assert.True(t, hm.IsHealthy())
}

// TestConnectionPool_WithHealthChecks tests pool with health checks enabled
func TestConnectionPool_WithHealthChecks(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:           mr.GetAddr(),
		MaxConnections:    5,
		ConnectTimeout:    5 * time.Second,
		EnableHealthCheck: true,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Get a connection
	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Connection should be healthy
	assert.True(t, pool.isConnectionHealthy(conn))

	// Use connection
	resp, err := conn.Do("PING")
	require.NoError(t, err)
	assert.Equal(t, "PONG", resp)

	// Return to pool
	pool.Put(conn)

	// Get again - should reuse and validate
	conn2, err := pool.Get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn2)

	pool.Put(conn2)
}

// TestConnectionPool_StaleConnectionRemoval tests stale connection handling
func TestConnectionPool_StaleConnectionRemoval(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:           mr.GetAddr(),
		MaxConnections:    3,
		ConnectTimeout:    5 * time.Second,
		EnableHealthCheck: true,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Get and return a connection
	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	pool.Put(conn)

	initialTotal := pool.totalConns.Load()

	// Close the connection manually to make it stale
	conn.Close()

	// Get another connection - should detect stale and create new
	conn2, err := pool.Get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn2)

	// Connection should be healthy
	assert.True(t, pool.isConnectionHealthy(conn2))

	pool.Put(conn2)

	// Total connections might be same or less (stale removed)
	finalTotal := pool.totalConns.Load()
	assert.LessOrEqual(t, finalTotal, initialTotal+1)
}
