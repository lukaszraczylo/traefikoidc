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
	backend, err := NewMemoryBackend(DefaultConfig())
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
	// Give the deferred cleanup a moment to release the key.
	time.Sleep(200 * time.Millisecond)
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
