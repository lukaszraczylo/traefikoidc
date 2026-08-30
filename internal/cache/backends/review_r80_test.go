package backends

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestExecuteWithRetry_ReturnsConnOnPanic is a regression: executeWithRetry
// returned the borrowed connection imperatively with no defer, so an operation
// panic leaked the Redis connection out of the pool and desynced its counters.
// The fix guarantees the connection is returned on all exit paths including
// panic.
func TestExecuteWithRetry_ReturnsConnOnPanic(t *testing.T) {
	pool, err := NewConnectionPool(&PoolConfig{MaxConnections: 1, ConnectTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewConnectionPool: %v", err)
	}

	// Seed one available connection so executeWithRetry's Get succeeds without
	// dialing (no Redis server needed).
	pc, sw := net.Pipe()
	defer sw.Close()
	rc := &RedisConn{conn: pc, readTimeout: time.Second, writeTimeout: time.Second}
	pool.Put(rc)

	if got := len(pool.connections); got != 1 {
		t.Fatalf("setup: expected one seeded connection, got %d", got)
	}

	r := &RedisBackend{pool: pool}

	func() {
		defer func() {
			if v := recover(); v == nil {
				t.Fatalf("expected operation to panic")
			}
		}()
		_ = r.executeWithRetry(context.Background(), func(c *RedisConn) error {
			panic("boom")
		})
	}()

	if got := len(pool.connections); got != 1 {
		t.Fatalf("expected connection returned to pool after operation panic, got %d", got)
	}
}
