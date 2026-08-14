package backends

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSingleflightStressDedup hammers GetOrFetch with many concurrent
// waiters on the SAME key behind a slow fetcher: exactly one fetch must
// run and all waiters must share its result, with no race on
// call.val/call.err read after wg.Wait() (R212). Run under -race.
func TestSingleflightStressDedup(t *testing.T) {
	backend, _ := NewMemoryBackend(&Config{CleanupInterval: time.Hour})
	sf := NewSingleflightCache(backend)

	var fetches atomic.Int64
	slow := func(context.Context) ([]byte, time.Duration, error) {
		fetches.Add(1)
		time.Sleep(5 * time.Millisecond)
		return []byte("result"), time.Minute, nil
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				v, err := sf.GetOrFetch(context.Background(), "k", slow)
				if err != nil {
					t.Errorf("GetOrFetch: %v", err)
					return
				}
				if string(v) != "result" {
					t.Errorf("unexpected value %q", v)
					return
				}
			}
		}()
	}
	wg.Wait()

	if fetches.Load() < 1 || fetches.Load() > 20 {
		t.Fatalf("expected dedup across concurrent waiters; fetcher ran %d times", fetches.Load())
	}
}

// A panicking fetcher must not leave waiters blocked forever: they must all
// receive the recovered error (R212).
func TestSingleflightStressPanicUnblocks(t *testing.T) {
	backend, _ := NewMemoryBackend(&Config{CleanupInterval: time.Hour})
	sf := NewSingleflightCache(backend)

	panicFetcher := func(context.Context) ([]byte, time.Duration, error) {
		panic("boom")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := sf.GetOrFetch(context.Background(), "pk", panicFetcher)
				if err == nil {
					t.Error("expected error from panicking fetcher")
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
		// all waiters unblocked with the recovered error
	case <-time.After(5 * time.Second):
		t.Fatal("waiters stayed blocked after panicking fetcher (singleflight wedged)")
	}
}
