package backends

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestBackendStressCloseConcurrent hammers a HybridBackend (which has an
// async in-flight L2-write worker) with concurrent reads/writes from many
// goroutines while Close runs at the same time — the classic scenario for a
// use-after-close or worker-leak race that sequential tests miss. Run under
// -race to detect any data race or panic (R208).
func TestBackendStressCloseConcurrent(t *testing.T) {
	l1, _ := NewMemoryBackend(&Config{CleanupInterval: time.Second})
	l2, _ := NewMemoryBackend(&Config{CleanupInterval: time.Second})
	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         l1,
		Secondary:       l2,
		AsyncBufferSize: 256,
	})
	if err != nil {
		t.Fatalf("NewHybridBackend: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Writers + readers hammer the backend.
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
				key := fmt.Sprintf("k:%d:%d", id, i%256)
				if i%2 == 0 {
					_ = hybrid.Set(context.Background(), key, []byte("value"), time.Minute)
				} else {
					_, _, _, _ = hybrid.Get(context.Background(), key)
				}
			}
		}(g)
	}

	time.Sleep(20 * time.Millisecond) // let workers spin up
	_ = hybrid.Close()                // close while ops are in-flight
	close(stop)
	wg.Wait()
}

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
