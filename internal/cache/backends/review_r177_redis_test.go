package backends

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestR177_RedisCommandErrorDoesNotCloseConn regresses the RESP command-error
// conflation: a Redis '-' (command error) reply, e.g. WRONGTYPE or OOM, is
// a valid protocol response — it does not mean the connection is dead.
// Previously Do and Pipeline treated it as an IO error, marking the healthy
// pooled connection closed (and for pipelines aborting the whole batch),
// discarding a perfectly reusable connection.
func TestR177_RedisCommandErrorDoesNotCloseConn(t *testing.T) {
	mr := NewMiniredisServer(t)
	config := &PoolConfig{
		Address:        mr.GetAddr(),
		MaxConnections: 5,
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
	}
	ctx := context.Background()

	pool, err := NewConnectionPool(config)
	require.NoError(t, err)
	defer pool.Close()

	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	defer pool.Put(conn)

	t.Run("single command error leaves conn healthy", func(t *testing.T) {
		mr.SetError("ERR artificial") // every command returns '-ERR artificial'

		_, err := conn.Do("GET", "k")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrCommandReply),
			"expected a Redis command-reply error, got %v", err)

		mr.SetError("") // clear; the connection must still be reusable

		// On the buggy path Do marked the conn closed above, so this
		// PING fails with "connection closed"; on the fixed path the
		// conn is untouched and PING succeeds.
		resp, err := conn.Do("PING")
		require.NoError(t, err)
		require.Equal(t, "PONG", resp)
	})

	t.Run("pipeline command error reads full batch and keeps conn", func(t *testing.T) {
		mr.SetError("ERR artificial")

		p := conn.NewPipeline()
		p.Queue("SET", "k1", "v1")
		p.Queue("SET", "k2", "v2")

		// On the buggy path Execute returned after the first error (1
		// response) and closed the conn; on the fixed path all replies
		// are read (healthy conn), the batch is not aborted.
		responses, err := p.Execute()
		require.NoError(t, err, "batch must complete with per-command errors")
		require.Len(t, responses, 2)
		for i, r := range responses {
			er, ok := r.(error)
			require.True(t, ok, "response %d should carry an error value", i)
			require.True(t, errors.Is(er, ErrCommandReply), "response %d should be a command-reply error", i)
		}

		mr.SetError("")
		resp, err := conn.Do("PING")
		require.NoError(t, err)
		require.Equal(t, "PONG", resp)
	})
}
