package backends

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestHybridBackend_Clear_DrainsAsyncWrites is a regression for Hybrid.Clear
// landing buffered async L2 writes AFTER the wipe — a key from a Set that
// preceded Clear being resurrected into L2. Clear must flush the pending
// async-write buffer (and block the worker) before clearing both levels.
// We queue many non-critical keys (routed to the async L2 write path),
// immediately Clear, then assert none ever reappears.
func TestHybridBackend_Clear_DrainsAsyncWrites(t *testing.T) {
	primary := newMockBackend()
	secondary := newMockBackend()
	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         primary,
		Secondary:       secondary,
		AsyncBufferSize: 4096,
		Logger:          NewTestLogger(t),
	})
	require.NoError(t, err)
	defer hybrid.Close()

	ctx := context.Background()
	const n = 400
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("r78-clear-%d", i)
		keys = append(keys, k)
		require.NoError(t, hybrid.Set(ctx, k, []byte("v"), time.Minute), "Set")
	}
	// No sleep: Clear itself must drain the pending buffer.
	require.NoError(t, hybrid.Clear(ctx), "Clear")

	// Poll long enough that a stray post-Clear write would surface; fail the
	// moment any key reappears. On the buggy code the async worker writes
	// the buffered keys into L2 after Clear and they show up here.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, k := range keys {
			ex, err := hybrid.Exists(ctx, k)
			require.NoError(t, err)
			if ex {
				t.Fatalf("key %q resurrected after Clear", k)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}
