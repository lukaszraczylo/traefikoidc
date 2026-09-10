package pool

import (
	"sync"
	"testing"
)

// resetGlobalTransportPoolForTest clears the process-global transport pool so the
// next call to GetTransportPool returns a fresh instance, and cancels the
// current pool's cleanup goroutine. Required for order-independent tests that
// replace the global pool: the singleton is sync.Once-guarded, so without a
// reset a consumed Once leaves GetTransportPool returning nil and later callers
// panic on a nil receiver (see TestCreateHTTPClient_Fallback).
//
// Test-only: kept in a _test.go file so it never compiles into the plugin
// binary that imports this package (FIX-39).
func resetGlobalTransportPoolForTest() {
	if globalTransportPool != nil && globalTransportPool.cancel != nil {
		globalTransportPool.cancel()
	}
	transportPoolOnce = sync.Once{}
	globalTransportPool = nil
}

// TestGetTransportPool_ConcurrentFirstCall pins FIX-39: GetTransportPool must
// not read globalTransportPool outside the sync.Once guard. An unsynchronized
// nil pre-check races the write inside Once.Do when two goroutines call
// GetTransportPool for the first time concurrently, so this test only passes
// under -race once the pre-check is removed.
func TestGetTransportPool_ConcurrentFirstCall(t *testing.T) {
	resetGlobalTransportPoolForTest()
	defer resetGlobalTransportPoolForTest()

	const n = 50
	results := make([]*TransportPool, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = GetTransportPool()
		}(i)
	}
	wg.Wait()

	if results[0] == nil {
		t.Fatal("GetTransportPool returned nil")
	}
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("GetTransportPool returned different instances across concurrent first calls: results[0]=%p results[%d]=%p", results[0], i, results[i])
		}
	}
}
