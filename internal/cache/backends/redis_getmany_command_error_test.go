package backends

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedisBackend_GetMany_CommandErrorReplyIsNotAMiss is a regression test
// for the review finding that RedisBackend.GetMany silently counted a Redis
// command-error reply (for example WRONGTYPE) as a cache miss instead of
// surfacing it as an error. Pipeline.Execute stores such a reply as an
// error value in the responses slice; GetMany must recognize that value and
// report it, not swallow it as "key not found".
func TestRedisBackend_GetMany_CommandErrorReplyIsNotAMiss(t *testing.T) {
	t.Parallel()

	mr, backend := setupTestRedis(t)
	ctx := context.Background()

	require.NoError(t, backend.Set(ctx, "good-key", []byte("good-value"), time.Minute))

	// Create a key holding a list, so a GET against it returns a RESP
	// command-error reply (WRONGTYPE), not a nil/missing response.
	_, err := mr.Lpush("test:bad-key", "listval")
	require.NoError(t, err)

	results, err := backend.GetMany(ctx, []string{"good-key", "bad-key"})

	require.Error(t, err, "GetMany must surface the WRONGTYPE command-error reply instead of masking it as a miss")
	assert.Contains(t, err.Error(), "bad-key")
	assert.Equal(t, []byte("good-value"), results["good-key"], "a command error on one key must not drop a good key's result")
	assert.NotContains(t, results, "bad-key")
}
