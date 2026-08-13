package traefikoidc

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestReplayCache_SetIfAbsentIsAtomic verifies that SetIfAbsent is an atomic
// check-and-set under the per-shard lock: when many goroutines race to
// record the same key, exactly one wins. This closes the double-accept
// race in JWT replay detection where the old Exists()+Set() check-then-act
// let two concurrent requests carrying the same fresh JTI both observe it
// absent and both be accepted.
func TestReplayCache_SetIfAbsentIsAtomic(t *testing.T) {
	c := NewShardedCache(8, 10000)
	const (
		key = "shared-jti-abc"
		n   = 200
		ttl = time.Hour
	)

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.SetIfAbsent(key, true, ttl) {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if winners != 1 {
		t.Fatalf("expected exactly one SetIfAbsent winner, got %d (double-accept race)", winners)
	}
	if !c.Exists(key) {
		t.Fatal("key should be present after a single winner")
	}

	// A later arrival with the same key must still be rejected.
	if c.SetIfAbsent(key, true, ttl) {
		t.Fatal("SetIfAbsent should return false for an already-present key")
	}
}

// TestReplayCache_SetIfAbsentReplacesExpired verifies that an entry that has
// expired is treated as absent (so a fresh record replaces it rather than
// being spuriously reported as a replay).
func TestReplayCache_SetIfAbsentReplacesExpired(t *testing.T) {
	c := NewShardedCache(8, 10000)
	key := fmt.Sprintf("exp-jti-%d", time.Now().UnixNano())

	if !c.SetIfAbsent(key, true, time.Millisecond) {
		t.Fatal("first insert should succeed")
	}
	time.Sleep(10 * time.Millisecond) // let the entry expire
	if !c.SetIfAbsent(key, true, time.Hour) {
		t.Fatal("second insert of an expired key should succeed (replaces it)")
	}
}
