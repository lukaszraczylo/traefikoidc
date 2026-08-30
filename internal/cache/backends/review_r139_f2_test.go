package backends

import (
	"testing"
	"time"
)

// TestCacheShard_SetRefreshExistingDoesNotEvictAtCapacity verifies the shard
// set path does not evict an unrelated LRU entry when replacing an existing
// key at capacity (count stays flat) (R139 F2). Mirrors the Cache.Set fix.
func TestCacheShard_SetRefreshExistingDoesNotEvictAtCapacity(t *testing.T) {
	s := newCacheShard(2, 0) // maxSize=2, no memory bound
	exp := time.Now().Add(time.Minute)

	s.set("a", "va", exp, 1) // becomes LRU
	s.set("b", "vb", exp, 1) // MRU

	// Refresh the most-recent key while at capacity. On the buggy path the
	// LRU sibling `a` is evicted; on the fixed path the replacement is free.
	s.set("b", "vb2", exp, 1)

	if _, exists, _ := s.get("a"); !exists {
		t.Fatal("refreshing an existing key must not evict an unrelated live entry `a`")
	}
	if v, exists, _ := s.get("b"); !exists || v != "vb2" {
		t.Fatalf("refreshed key `b` should hold the new value, got %v exists=%v", v, exists)
	}
}
