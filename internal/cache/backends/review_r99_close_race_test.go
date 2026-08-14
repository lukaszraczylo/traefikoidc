//go:build !yaegi

package backends

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestHybridBackend_CloseConcurrentSet_NoPanic regresses a send-on-closed-
// channel panic in HybridBackend. Close() used to close asyncWriteBuffer
// while a concurrent Set() may be mid-select on
// `h.asyncWriteBuffer <- item`, which can panic ("send on closed
// channel") and crash the process at shutdown. This exercises many
// Close+Set cycles concurrently and asserts no panic escapes.
func TestHybridBackend_CloseConcurrentSet_NoPanic(t *testing.T) {
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		primary := newMockBackend()
		secondary := newMockBackend()

		h, err := NewHybridBackend(&HybridConfig{
			Primary:   primary,
			Secondary: secondary,
		})
		if err != nil {
			t.Fatalf("new hybrid: %v", err)
		}

		var wg sync.WaitGroup
		var panicked sync.Map

		// Writers hammer Set concurrently with Close using async (non-
		// critical) cache type so the send goes through asyncWriteBuffer.
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						panicked.Store(true, fmt.Sprintf("writer %d: %v", w, r))
					}
				}()
				for k := 0; k < 200; k++ {
					// "session:" prefix is not blacklist/token -> async path.
					_ = h.Set(ctx, fmt.Sprintf("session:user%d:%d", w, k), []byte("value"), time.Minute)
				}
			}(w)
		}

		// Close concurrently with the writers.
		_ = h.Close()

		wg.Wait()

		if v, ok := panicked.Load(true); ok {
			t.Fatalf("panic during Close+concurrent Set: %v", v)
		}
	}
}
