package backends

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRedisSetTTLNeverZeroOrEarly(t *testing.T) {
	mr := NewMiniredisServer(t)
	b, err := NewRedisBackend(DefaultRedisConfig(mr.GetAddr()))
	require.NoError(t, err)
	defer b.Close()
	ctx := context.Background()

	t.Run("sub-millisecond ttl is accepted", func(t *testing.T) {
		require.NoError(t, b.Set(ctx, "sub", []byte("v"), 500*time.Microsecond))
	})
	t.Run("sub-millisecond ttl accepted by SetMany", func(t *testing.T) {
		require.NoError(t, b.SetMany(ctx, map[string][]byte{"sub-many": []byte("v")}, 500*time.Microsecond))
	})
	t.Run("fractional seconds are not rounded down", func(t *testing.T) {
		require.NoError(t, b.Set(ctx, "frac", []byte("v"), 1999*time.Millisecond))
		_, ttl, ok, err := b.Get(ctx, "frac")
		require.NoError(t, err)
		require.True(t, ok)
		require.Greater(t, ttl, time.Second, "1999ms ttl must not be stored as 1s")
	})
	t.Run("fractional seconds SetMany", func(t *testing.T) {
		require.NoError(t, b.SetMany(ctx, map[string][]byte{"frac-many": []byte("v")}, 1999*time.Millisecond))
		_, ttl, ok, err := b.Get(ctx, "frac-many")
		require.NoError(t, err)
		require.True(t, ok)
		require.Greater(t, ttl, time.Second)
	})
	t.Run("whole seconds still work", func(t *testing.T) {
		require.NoError(t, b.Set(ctx, "whole", []byte("v"), 5*time.Second))
		_, ttl, ok, err := b.Get(ctx, "whole")
		require.NoError(t, err)
		require.True(t, ok)
		require.Greater(t, ttl, 3*time.Second)
	})
}
