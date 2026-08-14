package backends

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// r94CtxProbeBackend records whether any operation was handed a canceled
// context. Set is the only method the async L2 write path exercises.
type r94CtxProbeBackend struct {
	setSeen   *atomic.Bool
	setHadErr *atomic.Bool
}

func (b *r94CtxProbeBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	b.setSeen.Store(true)
	if ctx.Err() != nil {
		b.setHadErr.Store(true)
	}
	return nil
}
func (b *r94CtxProbeBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	return nil, 0, false, nil
}
func (b *r94CtxProbeBackend) Delete(ctx context.Context, key string) (bool, error) { return false, nil }
func (b *r94CtxProbeBackend) Exists(ctx context.Context, key string) (bool, error) { return false, nil }
func (b *r94CtxProbeBackend) Clear(ctx context.Context) error                      { return nil }
func (b *r94CtxProbeBackend) GetStats() map[string]interface{}                     { return nil }
func (b *r94CtxProbeBackend) Close() error                                         { return nil }
func (b *r94CtxProbeBackend) Ping(ctx context.Context) error                       { return nil }

// TestHybridBackend_AsyncWriteUsesDetachedContext is an R94 regression: the
// async L2 write-through must be executed with a detached context, never the
// originating request's context. The L2 write runs after the request has
// returned; if it carried the (now-canceled) request context the write
// would be silently dropped, so non-critical keys never reach L2. Before
// the fix the worker used the request ctx and recorded a canceled context.
func TestHybridBackend_AsyncWriteUsesDetachedContext(t *testing.T) {
	primary := &r94CtxProbeBackend{setSeen: &atomic.Bool{}, setHadErr: &atomic.Bool{}}
	secondary := &r94CtxProbeBackend{setSeen: &atomic.Bool{}, setHadErr: &atomic.Bool{}}

	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:             primary,
		Secondary:           secondary,
		SyncWriteCacheTypes: map[string]bool{
			// empty set: no type is sync, so writes are async
		},
	})
	require.NoError(t, err)
	defer hybrid.Close()

	reqCtx, cancel := context.WithCancel(context.Background())
	err = hybrid.Set(reqCtx, "general:key1", []byte("test-value"), time.Minute)
	require.NoError(t, err)

	// The request has returned: cancel its context before the async worker
	// gets a chance to run the L2 write.
	cancel()

	// Wait for the async L2 write to be attempted.
	deadline := time.Now().Add(2 * time.Second)
	for !secondary.setSeen.Load() {
		if time.Now().After(deadline) {
			t.Fatal("async L2 write was never attempted")
		}
		time.Sleep(5 * time.Millisecond)
	}

	require.False(t, secondary.setHadErr.Load(),
		"async L2 write must use a detached (non-canceled) context")
}
