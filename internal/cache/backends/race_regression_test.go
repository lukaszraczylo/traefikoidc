package backends

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestCache_TTLReadUnderConcurrentExpire exercises get/exists/ttl fast
// paths racing with an in-place Expire that mutates expiresAt. Before
// the fix the fast paths read expiresAt outside the lock, so under -race
// this reports a data race on memoryCacheItem.expiresAt.
func TestCache_TTLReadUnderConcurrentExpire(t *testing.T) {
	c := NewMemoryCacheBackend(10000, 1024*1024*64, 0)
	defer c.Close()

	ctx := context.Background()
	if err := c.Set(ctx, "k", "v", time.Hour); err != nil {
		t.Fatalf("set: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = c.Get(ctx, "k")
				_, _ = c.Exists(ctx, "k")
				_, _ = c.TTL(ctx, "k")
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = c.Expire(ctx, "k", time.Hour)
		}
		close(stop)
	}()
	wg.Wait()
}
