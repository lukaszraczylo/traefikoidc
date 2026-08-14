package backends

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingWriteBackend is a cache backend whose Set blocks until released,
// used to hold an async L2 write in-flight while Delete runs.
type blockingWriteBackend struct {
	mu         sync.Mutex
	data       map[string]string
	setStarted chan struct{}
	release    chan struct{}
	written    chan struct{}
	once       sync.Once
}

func (b *blockingWriteBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	select {
	case <-b.setStarted:
	default:
		close(b.setStarted)
	}
	select {
	case <-b.release:
	case <-b.written: // never
	case <-ctx.Done():
		return nil
	}
	b.mu.Lock()
	b.data[key] = string(value)
	b.mu.Unlock()
	b.once.Do(func() { close(b.written) })
	return nil
}

func (b *blockingWriteBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.data[key]
	if !ok {
		return nil, 0, false, nil
	}
	return []byte(v), time.Minute, true, nil
}

func (b *blockingWriteBackend) Delete(ctx context.Context, key string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[key]
	delete(b.data, key)
	return ok, nil
}

func (b *blockingWriteBackend) Exists(ctx context.Context, key string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.data[key]
	return ok, nil
}

func (b *blockingWriteBackend) Clear(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = map[string]string{}
	return nil
}

func (b *blockingWriteBackend) GetStats() map[string]interface{} { return nil }
func (b *blockingWriteBackend) Close() error                     { return nil }
func (b *blockingWriteBackend) Ping(ctx context.Context) error   { return nil }

// TestHybrid_DeleteWaitsForAsyncWrite guards the R124 fix to hybrid.go
// Delete: an in-flight async L2 write (from a non-critical Set) could land
// after Delete's L2 DEL, resurrecting the just-deleted key with a stale
// value. Delete must wait for in-flight async writes before the L2 delete.
func TestHybrid_DeleteWaitsForAsyncWrite(t *testing.T) {
	sec := &blockingWriteBackend{
		data:       map[string]string{},
		setStarted: make(chan struct{}),
		release:    make(chan struct{}),
		written:    make(chan struct{}),
	}
	primary := newMockBackend()

	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         primary,
		Secondary:       sec,
		AsyncBufferSize: 16,
	})
	if err != nil {
		t.Fatalf("hybrid: %v", err)
	}
	defer hybrid.Close()

	ctx := context.Background()

	// Non-critical Set -> async L2 write that blocks in-flight.
	if err := hybrid.Set(ctx, "k", []byte("stale"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	select {
	case <-sec.setStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("async L2 write never started")
	}

	// Issue Delete while the async write is in-flight.
	done := make(chan struct{})
	go func() {
		_, _ = hybrid.Delete(ctx, "k")
		close(done)
	}()

	// OLD behavior: Delete returns immediately (no wait for async writes);
	// it performs its L2 delete and closes done. NEW behavior: Delete
	// blocks in asyncWg.Wait until the in-flight write finishes, so done
	// does not fire until released. Distinguish the two before releasing.
	oldImmediate := false
	select {
	case <-done:
		oldImmediate = true
	case <-time.After(50 * time.Millisecond):
		// NEW: Delete is blocked waiting for the async write. 50ms is
		// far longer than OLD's immediate (non-waiting) return needs,
		// and far shorter than the worker's 500ms writeCtx, so the
		// in-flight write reliably survives to be released.
	}
	// Release the in-flight L2 write (well within the worker's writeCtx
	// timeout) so it actually lands.
	close(sec.release)

	if oldImmediate {
		// OLD: the worker write now lands AFTER Delete's L2 delete,
		// resurrecting the key.
		select {
		case <-sec.written:
		case <-time.After(2 * time.Second):
			t.Fatal("async L2 write never landed")
		}
	} else {
		// NEW: Delete waited for the write, then removed it from L2.
		select {
		case <-sec.written:
		case <-time.After(2 * time.Second):
			t.Fatal("async L2 write never landed")
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Delete did not return")
		}
	}

	if _, _, exists, _ := sec.Get(ctx, "k"); exists {
		t.Fatal("L2 must not contain key after Delete: the in-flight async Set resurrected it")
	}
}

// existsAlwaysBackend reports the key always present in L1 (so a backfill
// must be skipped) and counts Set calls; setCalled is closed once Set runs,
// letting the test observe a (OLD) backfill write deterministically.
type existsAlwaysBackend struct {
	setCalls  int32
	setCalled chan struct{}
	once      sync.Once
}

func newExistsAlwaysBackend() *existsAlwaysBackend {
	return &existsAlwaysBackend{setCalled: make(chan struct{})}
}

func (b *existsAlwaysBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	atomic.AddInt32(&b.setCalls, 1)
	b.once.Do(func() { close(b.setCalled) })
	return nil
}
func (b *existsAlwaysBackend) Get(ctx context.Context, key string) ([]byte, time.Duration, bool, error) {
	return nil, 0, false, nil
}
func (b *existsAlwaysBackend) Delete(ctx context.Context, key string) (bool, error) {
	return false, nil
}
func (b *existsAlwaysBackend) Exists(ctx context.Context, key string) (bool, error) { return true, nil }
func (b *existsAlwaysBackend) Clear(ctx context.Context) error                      { return nil }
func (b *existsAlwaysBackend) GetStats() map[string]interface{}                     { return nil }
func (b *existsAlwaysBackend) Close() error                                         { return nil }
func (b *existsAlwaysBackend) Ping(ctx context.Context) error                       { return nil }

// TestHybrid_BackfillDoesNotClobberFreshL1 guards the R124 fix to
// hybrid.go l1BackfillWorker: the backfill only checked L2 key
// existence, so a stale L2-captured value would overwrite a fresher L1
// value written concurrently by Set. When L1 already holds the key, the
// backfill must be skipped.
func TestHybrid_BackfillDoesNotClobberFreshL1(t *testing.T) {
	primary := newExistsAlwaysBackend()
	secondary := newMockBackend()
	ctx := context.Background()
	if err := secondary.Set(ctx, "k", []byte("stale"), time.Minute); err != nil {
		t.Fatalf("seed L2: %v", err)
	}

	hybrid, err := NewHybridBackend(&HybridConfig{
		Primary:         primary,
		Secondary:       secondary,
		AsyncBufferSize: 16,
	})
	if err != nil {
		t.Fatalf("hybrid: %v", err)
	}
	defer hybrid.Close()

	// Queue a stale backfill for a key L1 already holds (fresher).
	hybrid.queueL1Backfill("k", []byte("stale"), time.Minute)

	// Wait for the worker to drain the backfill buffer.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(hybrid.l1BackfillBuffer) == 0 {
			time.Sleep(20 * time.Millisecond) // let the worker act (write or skip)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Deterministically observe an OLD backfill write: if the worker
	// writes, setCalled closes and setCalls becomes 1. On NEW the
	// worker skips, so nothing fires.
	select {
	case <-primary.setCalled:
	case <-time.After(500 * time.Millisecond):
	}

	if atomic.LoadInt32(&primary.setCalls) != 0 {
		t.Fatal("backfill must not overwrite the fresher L1 value (primary already had the key)")
	}
}
