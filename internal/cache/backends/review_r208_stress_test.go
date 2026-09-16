package backends

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestRedisBackendStressCloseConcurrent hammers a miniredis-backed
// RedisBackend (pooled connections) from many goroutines while Close runs,
// the pooled-conn use-after-close race class (R208).
func TestRedisBackendStressCloseConcurrent(t *testing.T) {
	mr := NewMiniredisServer(t)
	backend, err := NewRedisBackend(DefaultRedisConfig(mr.GetAddr()))
	if err != nil {
		t.Fatalf("NewRedisBackend: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprintf("redis:k:%d:%d", id, i%256)
				if i%2 == 0 {
					_ = backend.Set(context.Background(), key, []byte("v"), time.Minute)
				} else {
					_, _, _, _ = backend.Get(context.Background(), key)
				}
			}
		}(g)
	}

	time.Sleep(20 * time.Millisecond)
	_ = backend.Close()
	close(stop)
	wg.Wait()
}
