package backends

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestConnectionPool_CapHeldUnderBurst regresses the connection-pool cap
// being non-atomic: ConnectionPool.Get checked `totalConns < MaxConnections`
// and THEN dialed a new socket, so concurrent Gets could each pass the check
// and spike the live connection count far above MaxConnections (FD / Redis
// maxclients exhaustion under burst load). The cap must now be held
// atomically so at most MaxConnections sockets are ever created at once.
func TestConnectionPool_CapHeldUnderBurst(t *testing.T) {
	mr := NewMiniredisServer(t)

	maxConns := 3
	pool, err := NewConnectionPool(&PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: maxConns,
		ConnectTimeout: 80 * time.Millisecond,
		ReadTimeout:    50 * time.Millisecond,
		WriteTimeout:   50 * time.Millisecond,
	})
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	const workers = 50

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _ := pool.Get(ctx)
			if conn != nil {
				// Hold the connection (simulate an in-flight request) so the
				// pool stays under pressure and the count is stable.
				_ = conn
			}
		}()
	}
	wg.Wait()

	stats := pool.Stats()
	total := stats["total_connections"].(int32)
	require.LessOrEqual(t, total, int32(maxConns),
		"burst Gets must not create more than MaxConnections sockets (got %d)", total)
}
