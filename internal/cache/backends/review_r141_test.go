package backends

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestSingleflightCache_PanickingFetcherDoesNotDeadlock verifies that a
// fetcher which panics (routines in this codebase treat panics as a normal
// failure mode) does not wedge the singleflight entry: the leading caller
// yields an error and waiting callers are released instead of blocking on
// call.wg forever (R141).
func TestSingleflightCache_PanickingFetcherDoesNotDeadlock(t *testing.T) {
	mr := NewMiniredisServer(t)
	backend, err := NewRedisBackend(DefaultRedisConfig(mr.GetAddr()))
	requireNoErrorFatal(t, err)
	defer backend.Close()

	cache := NewSingleflightCache(backend)
	ctx := context.Background()
	key := "panic-key"

	panicFetcher := func(ctx context.Context) ([]byte, time.Duration, error) {
		panic("boom")
	}

	var wg sync.WaitGroup
	var doneA, doneB = make(chan struct{}), make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }() // tolerate old code's out-of-band panic
		_, _ = cache.GetOrFetch(ctx, key, panicFetcher)
		close(doneA)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = cache.GetOrFetch(ctx, key, panicFetcher)
		close(doneB)
	}()

	select {
	case <-doneB:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent waiter hung on a panicking singleflight fetcher")
	}
	select {
	case <-doneA:
	case <-time.After(3 * time.Second):
		t.Fatal("leading caller hung on its own panicking fetcher")
	}
	wg.Wait()

	// After the entry is cleaned up, a well-behaved fetcher for the same
	// key must execute normally (proves the entry was not permanently
	// wedged by the panic).
	ran := false
	good := func(ctx context.Context) ([]byte, time.Duration, error) {
		ran = true
		return []byte("ok"), time.Minute, nil
	}
	// Poll until the deferred cleanup goroutine (singleflight.go's
	// time.Sleep(100ms) + delete) has released the key, instead of sleeping
	// a fixed margin over that 100ms delay (FIX-22): a late-firing cleanup
	// timer under load let the next GetOrFetch join the finished call and
	// receive its stale panic error back, making the fixed-sleep version
	// flaky on loaded CI runners.
	deadline := time.Now().Add(2 * time.Second)
	for {
		cache.mu.Lock()
		_, stillPresent := cache.calls[key]
		cache.mu.Unlock()
		if !stillPresent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("singleflight entry for key was never released after the panicking fetcher completed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := cache.GetOrFetch(ctx, key, good); err != nil {
		t.Fatalf("well-behaved fetcher after panic returned error: %v", err)
	}
	if !ran {
		t.Fatal("well-behaved fetcher after panic did not execute")
	}
}

func requireNoErrorFatal(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
