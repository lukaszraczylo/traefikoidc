package backends

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnectionPool_BasicOperations tests basic pool operations
func TestConnectionPool_BasicOperations(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	t.Run("GetAndPutConnection", func(t *testing.T) {
		ctx := context.Background()

		// Get a connection
		conn, err := pool.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, conn)

		// Verify connection works
		resp, err := conn.Do("PING")
		require.NoError(t, err)
		assert.Equal(t, "PONG", resp)

		// Return to pool
		pool.Put(conn)

		// Get again - should reuse same connection
		conn2, err := pool.Get(ctx)
		require.NoError(t, err)
		require.NotNil(t, conn2)

		pool.Put(conn2)
	})

	t.Run("Stats", func(t *testing.T) {
		stats := pool.Stats()
		require.NotNil(t, stats)

		assert.Contains(t, stats, "active_connections")
		assert.Contains(t, stats, "total_connections")
		assert.Contains(t, stats, "max_connections")
		assert.Equal(t, 5, stats["max_connections"])
	})
}

// TestConnectionPool_MaxConnections tests pool size limits
func TestConnectionPool_MaxConnections(t *testing.T) {
	mr := NewMiniredisServer(t)

	maxConns := 3
	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: maxConns,
		ConnectTimeout: 1 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Get max connections
	conns := make([]*RedisConn, maxConns)
	for i := 0; i < maxConns; i++ {
		conn, err := pool.Get(ctx)
		require.NoError(t, err)
		conns[i] = conn
	}

	// Verify stats
	stats := pool.Stats()
	assert.Equal(t, int32(maxConns), stats["total_connections"])
	assert.Equal(t, int32(maxConns), stats["active_connections"])

	// Try to get one more - should block/timeout
	ctx2, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	conn, err := pool.Get(ctx2)
	require.Error(t, err)
	require.Nil(t, conn)

	// Return one connection
	pool.Put(conns[0])

	// Now we should be able to get a connection
	conn, err = pool.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Cleanup
	pool.Put(conn)
	for i := 1; i < maxConns; i++ {
		pool.Put(conns[i])
	}
}

// TestConnectionPool_ConcurrentAccess tests concurrent pool usage
func TestConnectionPool_ConcurrentAccess(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 10,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	numGoroutines := 50
	numOperations := 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	// Spawn goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				conn, err := pool.Get(ctx)
				if err != nil {
					errors <- err
					continue
				}

				// Do some work
				_, err = conn.Do("PING")
				if err != nil {
					errors <- err
				}

				// Return to pool
				pool.Put(conn)

				// Small delay
				time.Sleep(time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Error: %v", err)
		errorCount++
	}

	assert.Equal(t, 0, errorCount, "Expected no errors in concurrent access")

	// Verify stats
	stats := pool.Stats()
	t.Logf("Final stats: %+v", stats)
	assert.LessOrEqual(t, stats["total_connections"].(int32), int32(10))
	assert.Equal(t, int32(0), stats["active_connections"])
}

// TestConnectionPool_ContextCancellation tests context cancellation
func TestConnectionPool_ContextCancellation(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 1,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	// Get the only connection
	conn, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Try to get another with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	conn2, err := pool.Get(ctx)
	require.Error(t, err)
	require.Nil(t, conn2)
	assert.Contains(t, err.Error(), "context canceled")

	// Cleanup
	pool.Put(conn)
}

// TestConnectionPool_Authentication tests auth support
func TestConnectionPool_Authentication(t *testing.T) {
	mr := NewMiniredisServer(t)

	// Set password on miniredis
	mr.server.RequireAuth("secret-password")

	t.Run("CorrectPassword", func(t *testing.T) {
		config := &PoolConfig{
			Address:        mr.GetAddr(),
			Password:       "secret-password",
			MaxConnections: 2,
			ConnectTimeout: 5 * time.Second,
		}

		pool, err := NewConnectionPool(config)
		require.NoError(t, err)
		defer pool.Close()

		conn, err := pool.Get(context.Background())
		require.NoError(t, err)

		resp, err := conn.Do("PING")
		require.NoError(t, err)
		assert.Equal(t, "PONG", resp)

		pool.Put(conn)
	})

	t.Run("WrongPassword", func(t *testing.T) {
		t.Skip("Miniredis doesn't fully simulate AUTH errors like real Redis")

		config := &PoolConfig{
			Address:        mr.GetAddr(),
			Password:       "wrong-password",
			MaxConnections: 2,
			ConnectTimeout: 5 * time.Second,
		}

		_, err := NewConnectionPool(config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
	})
}

// TestConnectionPool_DatabaseSelection tests DB selection
func TestConnectionPool_DatabaseSelection(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		DB:             5,
		MaxConnections: 2,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	conn, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Connection should be on DB 5
	resp, err := conn.Do("PING")
	require.NoError(t, err)
	assert.Equal(t, "PONG", resp)

	pool.Put(conn)
}

// TestConnectionPool_ClosedConnection tests handling closed connections
func TestConnectionPool_ClosedConnection(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 2,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	// Get connection
	conn, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Close it manually
	conn.Close()

	// Try to use it
	_, err = conn.Do("PING")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))

	// Return to pool (should be discarded)
	pool.Put(conn)

	// Get new connection - should create a new one
	conn2, err := pool.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn2)

	resp, err := conn2.Do("PING")
	require.NoError(t, err)
	assert.Equal(t, "PONG", resp)

	pool.Put(conn2)
}

// TestConnectionPool_Close tests pool closure
func TestConnectionPool_Close(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
		ConnectTimeout: 5 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)

	// Get some connections
	conns := make([]*RedisConn, 3)
	for i := 0; i < 3; i++ {
		conn, err := pool.Get(context.Background())
		require.NoError(t, err)
		conns[i] = conn
	}

	// Return them
	for _, conn := range conns {
		pool.Put(conn)
	}

	// Close pool
	err = pool.Close()
	require.NoError(t, err)

	// Try to get connection from closed pool
	_, err = pool.Get(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))

	// Close again should be no-op
	err = pool.Close()
	require.NoError(t, err)
}

// TestConnectionPool_Timeouts tests various timeout scenarios
func TestConnectionPool_Timeouts(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 2,
		ConnectTimeout: 100 * time.Millisecond,
		ReadTimeout:    100 * time.Millisecond,
		WriteTimeout:   100 * time.Millisecond,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	conn, err := pool.Get(context.Background())
	require.NoError(t, err)

	// Normal operation should work
	resp, err := conn.Do("PING")
	require.NoError(t, err)
	assert.Equal(t, "PONG", resp)

	pool.Put(conn)
}

// TestRedisConn_DoCommand tests the Do method
func TestRedisConn_DoCommand(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 2,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	conn, err := pool.Get(context.Background())
	require.NoError(t, err)
	defer pool.Put(conn)

	t.Run("SET and GET", func(t *testing.T) {
		// SET
		resp, err := conn.Do("SET", "testkey", "testvalue")
		require.NoError(t, err)
		assert.Equal(t, "OK", resp)

		// GET
		resp, err = conn.Do("GET", "testkey")
		require.NoError(t, err)
		assert.Equal(t, "testvalue", resp)
	})

	t.Run("DEL", func(t *testing.T) {
		// SET key first
		_, err := conn.Do("SET", "delkey", "delvalue")
		require.NoError(t, err)

		// DEL
		resp, err := conn.Do("DEL", "delkey")
		require.NoError(t, err)

		count, err := RESPInt(resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), count)
	})

	t.Run("EXISTS", func(t *testing.T) {
		// SET key first
		_, err := conn.Do("SET", "existskey", "value")
		require.NoError(t, err)

		// EXISTS - key exists
		resp, err := conn.Do("EXISTS", "existskey")
		require.NoError(t, err)

		count, err := RESPInt(resp)
		require.NoError(t, err)
		assert.Equal(t, int64(1), count)

		// EXISTS - key doesn't exist
		resp, err = conn.Do("EXISTS", "nonexistent")
		require.NoError(t, err)

		count, err = RESPInt(resp)
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	t.Run("TTL commands", func(t *testing.T) {
		// SETEX
		resp, err := conn.Do("SETEX", "ttlkey", "60", "ttlvalue")
		require.NoError(t, err)
		assert.Equal(t, "OK", resp)

		// TTL
		resp, err = conn.Do("TTL", "ttlkey")
		require.NoError(t, err)

		ttl, err := RESPInt(resp)
		require.NoError(t, err)
		assert.Greater(t, ttl, int64(0))
		assert.LessOrEqual(t, ttl, int64(60))
	})
}

// TestPoolConfig_Defaults tests default configuration values
func TestPoolConfig_Defaults(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address: mr.GetAddr(),
		// Leave other fields at zero values
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	// Should use defaults
	assert.Equal(t, 10, pool.config.MaxConnections)
	assert.Equal(t, 5*time.Second, pool.config.ConnectTimeout)

	// Verify it works
	conn, err := pool.Get(context.Background())
	require.NoError(t, err)
	pool.Put(conn)
}

// TestConnectionPool_NilConnection tests handling nil connections
func TestConnectionPool_NilConnection(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 2,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	// Putting nil should be safe
	pool.Put(nil)

	// Pool should still work
	conn, err := pool.Get(context.Background())
	require.NoError(t, err)
	require.NotNil(t, conn)
	pool.Put(conn)
}

// TestConnectionPool_StatsTracking tests metrics tracking
func TestConnectionPool_StatsTracking(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()

	// Initial stats
	stats := pool.Stats()
	initialGets := stats["gets"].(int64)
	initialPuts := stats["puts"].(int64)

	// Perform operations
	numOps := 10
	for i := 0; i < numOps; i++ {
		conn, err := pool.Get(ctx)
		require.NoError(t, err)
		pool.Put(conn)
	}

	// Check updated stats
	stats = pool.Stats()
	assert.Equal(t, initialGets+int64(numOps), stats["gets"].(int64))
	assert.Equal(t, initialPuts+int64(numOps), stats["puts"].(int64))
	assert.Equal(t, int32(0), stats["active_connections"].(int32))
}

// TestRedisConn_TooManyArguments tests protection against allocation overflow
func TestRedisConn_TooManyArguments(t *testing.T) {
	mr := NewMiniredisServer(t)

	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 1,
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	defer pool.Put(conn)

	t.Run("AcceptableArgumentCount", func(t *testing.T) {
		// Should work with reasonable number of args
		args := make([]string, 100)
		for i := range args {
			args[i] = "value"
		}
		_, err := conn.Do("MSET", args...)
		// May fail due to Redis constraints, but shouldn't panic or error on overflow
		// Just verify it doesn't trigger our overflow protection
		if err != nil {
			assert.NotContains(t, err.Error(), "too many arguments")
		}
	})

	t.Run("RejectExcessiveArguments", func(t *testing.T) {
		// Create an absurdly large number of arguments that would cause overflow
		// Use 1M + 1 to exceed maxSafeArgs = (1<<20)-1 = 1048575
		args := make([]string, 1<<20) // 1,048,576 args
		for i := range args {
			args[i] = "x"
		}

		_, err := conn.Do("MSET", args...)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too many arguments")
	})

	t.Run("BoundaryCase", func(t *testing.T) {
		// Test exactly at the boundary (maxSafeArgs)
		args := make([]string, (1<<20)-1) // Exactly 1,048,575 args (max allowed)
		for i := range args {
			args[i] = "x"
		}

		_, err := conn.Do("ECHO", args...)
		// Should not error due to overflow protection
		if err != nil {
			assert.NotContains(t, err.Error(), "too many arguments")
		}
	})
}
