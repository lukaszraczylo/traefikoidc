package cache

import (
	"testing"
	"time"
)

// TestSet_NegativeTTLIsNoOp verifies Cache.Set with a negative TTL does not
// store an entry (no slot consumed), matching the memory/redis backends'
// negative-TTL convention. Previously cacheVerifiedToken fed an
// already-expired entry (negative duration) into the hot token cache,
// wasting a slot and misreporting currentSize (R138).
func TestSet_NegativeTTLIsNoOp(t *testing.T) {
	c := New(DefaultConfig())
	defer c.Close()

	// Negative TTL must not consume a cache slot.
	if err := c.Set("neg", "v", -1*time.Second); err != nil {
		t.Fatalf("Set with negative TTL returned error: %v", err)
	}
	if size := c.Size(); size != 0 {
		t.Fatalf("negative-TTL Set must not grow cache size; got %d", size)
	}
	if _, exists := c.Get("neg"); exists {
		t.Fatal("negative-TTL value must not be retrievable (should be a no-op)")
	}

	// Control: positive TTL still consumes a slot and is retrievable.
	if err := c.Set("pos", "v", time.Minute); err != nil {
		t.Fatalf("Set with positive TTL returned error: %v", err)
	}
	if size := c.Size(); size != 1 {
		t.Fatalf("positive-TTL Set should grow cache size to 1; got %d", size)
	}
	if _, exists := c.Get("pos"); !exists {
		t.Fatal("positive-TTL value should be retrievable")
	}
}
