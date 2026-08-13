//go:build !yaegi

package backends

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// gatedSetBackend wraps a mockBackend whose Set blocks until release is
// closed (once). Lets the test park the backfill worker mid-flight.
type gatedSetBackend struct {
	*mockBackend
	startOnce sync.Once
	started   chan struct{}
	release   chan struct{}
}

func (b *gatedSetBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	b.startOnce.Do(func() { close(b.started) })
	<-b.release
	return b.mockBackend.Set(ctx, key, value, ttl)
}

// TestHybridBackend_L1Backfill_NoResurrectAfterDelete regresses the L1
// backfill worker resurrecting a key that was deleted after the L2 read
// (Get) captured its value. The worker must re-check L2 and not write a
// value into L1 for a key that is gone from L2.
func TestHybridBackend_L1Backfill_NoResurrectAfterDelete(t *testing.T) {
	const key = "k"

	inner := newMockBackend()
	gated := &gatedSetBackend{mockBackend: inner, started: make(chan struct{}), release: make(chan struct{})}
	secondary := newMockBackend()

	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         gated,
		Secondary:       secondary,
		AsyncBufferSize: 64,
	})
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()

	// Park the worker on a filler backfill first so `key` (enqueued after
	// the filler) is processed only once we delete it.
	require.NoError(t, secondary.Set(ctx, "filler", []byte("x"), time.Minute))
	_, _, exists, err := hybrid.Get(ctx, "filler")
	require.NoError(t, err)
	require.True(t, exists)

	select {
	case <-gated.started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker never parked on filler Set")
	}

	// Now trigger a backfill for `key` (this appends it behind the parked
	// filler), then delete it before the worker can reach it.
	require.NoError(t, secondary.Set(ctx, key, []byte("v"), time.Minute))
	_, _, exists, err = hybrid.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, exists)
	_, err = hybrid.Delete(ctx, key)
	require.NoError(t, err)

	close(gated.release)

	// Wait for the worker to drain, failing if the deleted key ever appears
	// in L1 (resurrection). On the fixed code it re-checks L2 and skips;
	// on the buggy code it writes the stale value shortly after release.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, ok, _ := inner.Get(ctx, key); ok {
			t.Fatal("deleted key was resurrected into L1 by the backfill worker")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
