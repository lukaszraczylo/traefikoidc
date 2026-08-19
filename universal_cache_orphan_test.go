package traefikoidc

import (
	"testing"
	"time"
)

// newOrphanTestCache builds a Token-type cache with background cleanup disabled
// so the test fully controls lruList/items state.
func newOrphanTestCache(maxMem int64) *UniversalCache {
	return NewUniversalCache(UniversalCacheConfig{
		Type:              CacheTypeToken,
		DefaultTTL:        time.Hour,
		MaxSize:           1_000_000, // large: keep the size-branch out of the way
		MaxMemoryBytes:    maxMem,
		EnableMemoryLimit: maxMem > 0,
		SkipAutoCleanup:   true,
		EnableAutoCleanup: false,
	})
}

// TestUpdateLocalCache_NoOrphanElements is the direct red test: repeatedly
// populating the SAME key via updateLocalCache (the per-request Get->backend-hit
// path) must NOT leave dangling lruList elements. Today updateLocalCache blindly
// PushFronts + overwrites c.items[key] without removing the prior element, so the
// list grows one orphan per call while items stays at 1 entry.
func TestUpdateLocalCache_NoOrphanElements(t *testing.T) {
	c := newOrphanTestCache(0) // memory limit off: isolate the orphan, no eviction
	const key = "same-key"

	for range 5 {
		if err := c.updateLocalCache(key, "v", time.Hour); err != nil {
			t.Fatalf("updateLocalCache: %v", err)
		}
	}

	c.mu.RLock()
	listLen := c.lruList.Len()
	itemCount := len(c.items)
	c.mu.RUnlock()

	if itemCount != 1 {
		t.Fatalf("items: got %d want 1", itemCount)
	}
	if listLen != 1 {
		t.Fatalf("ORPHAN BUG: lruList.Len()=%d but items=%d (one list element per key expected)", listLen, itemCount)
	}
}

// TestUpdateLocalCache_EvictionTerminates is the convoy reproducer: once orphans
// for a key exist and the memory-eviction loop runs, evictOldest() deletes the
// key from items on the first eviction, after which every remaining orphan at
// Back() has a key absent from items -> evictOldest() no-ops while lruList.Len()>0
// stays true -> infinite loop while holding c.mu.Lock(). That is the 100%-CPU
// holder + write-lock convoy observed in pprof.
func TestUpdateLocalCache_EvictionTerminates(t *testing.T) {
	c := newOrphanTestCache(0) // start with memory limit OFF to accumulate orphans
	const key = "same-key"

	// Build 3 same-key list elements (3 orphans, items={key}).
	for range 3 {
		if err := c.updateLocalCache(key, "v", time.Hour); err != nil {
			t.Fatalf("seed updateLocalCache: %v", err)
		}
	}

	// Arm the trap: tiny memory limit so the next call enters the eviction loop.
	c.mu.Lock()
	c.config.MaxMemoryBytes = 1
	c.mu.Unlock()

	done := make(chan struct{})
	go func() {
		_ = c.updateLocalCache(key, "v", time.Hour) // triggers the eviction loop
		close(done)
	}()

	select {
	case <-done:
		// fix present: loop made forward progress and returned
	case <-time.After(2 * time.Second):
		t.Fatal("INFINITE LOOP: eviction loop did not terminate within 2s (orphan whose key was deleted is never removed from lruList)")
	}
}
