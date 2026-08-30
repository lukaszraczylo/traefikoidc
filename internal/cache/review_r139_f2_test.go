package cache

import (
	"testing"
	"time"
)

// TestSet_RefreshExistingDoesNotEvictAtCapacity verifies that replacing an
// existing key at capacity does not evict an unrelated live entry. The
// eviction decision must account for the replacement (count stays flat), so
// refreshing the most-recent key must leave the LRU sibling in place
// (R139 F2).
func TestSet_RefreshExistingDoesNotEvictAtCapacity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSize = 2
	cfg.EnableMemoryLimit = false
	c := New(cfg)
	defer c.Close()

	if err := c.Set("a", "va", time.Minute); err != nil {
		t.Fatalf("set a: %v", err)
	}
	if err := c.Set("b", "vb", time.Minute); err != nil {
		t.Fatalf("set b: %v", err)
	}

	// Refresh the most-recent key while at capacity. On the buggy path
	// the LRU sibling `a` is evicted; on the fixed path the replacement
	// is free so both entries survive.
	if err := c.Set("b", "vb2", time.Minute); err != nil {
		t.Fatalf("refresh b: %v", err)
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("refreshing an existing key must not evict an unrelated live entry `a`")
	}
	if got := c.Size(); got != 2 {
		t.Fatalf("size should remain 2 after an in-place refresh, got %d", got)
	}
	if v, ok := c.Get("b"); !ok || v != "vb2" {
		t.Fatalf("refreshed key `b` should hold the new value, got %v ok=%v", v, ok)
	}
}
