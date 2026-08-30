package backends

import (
	"context"
	"testing"
	"time"
)

// TestR177_MemoryBackendReplacementDoesNotEvictUnrelatedAtCapacity verifies
// that MemoryCacheBackend's GLOBAL limit enforcer is replacement-aware. The
// shard-level path (cacheShard.set, R139 F2) was already fixed, but
// enforceGlobalLimits ran before the shard write and counted every Set as a
// new entry, so at global capacity a pure key replacement evicted an
// unrelated live entry from the globally-oldest shard (count stays flat).
func TestR177_MemoryBackendReplacementDoesNotEvictUnrelatedAtCapacity(t *testing.T) {
	// maxSize=2 forces shardCount down to 1; the single shard's own
	// limit (2x average = 4) is loose, so the GLOBAL maxSize=2 is the
	// binding constraint that the buggy enforcer used to over-evict.
	m := NewMemoryCacheBackend(2, 0, time.Minute)
	ctx := context.Background()

	if err := m.Set(ctx, "a", "va", time.Minute); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := m.Set(ctx, "b", "vb", time.Minute); err != nil {
		t.Fatalf("Set b: %v", err)
	}
	// Make `a` the most-recently-used entry so `b` is the global LRU.
	if _, err := m.Get(ctx, "a"); err != nil {
		t.Fatalf("Get a: %v", err)
	}
	// Replace `a` while at global capacity. On the buggy path the global
	// enforcer sees totalSize>=maxSize and evicts the LRU `b`; on the
	// fixed path the replacement is count- and size-neutral.
	if err := m.Set(ctx, "a", "va2", time.Minute); err != nil {
		t.Fatalf("Set a (replacement): %v", err)
	}

	if _, err := m.Get(ctx, "b"); err != nil {
		t.Fatalf("replacing existing key must not evict unrelated live entry `b`: %v", err)
	}
	if v, err := m.Get(ctx, "a"); err != nil || v != "va2" {
		t.Fatalf("replaced key `a` should hold the new value, got %v err=%v", v, err)
	}
}
