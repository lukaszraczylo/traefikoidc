package traefikoidc

import (
	"fmt"
	"testing"
	"time"
)

// TestShardedCacheFIFOEvictionRetainsNewest guards against the pre-fix eviction
// policy in evictFromShardLocked, which (a) over-evicted by +10 per Set at
// capacity (each shard sat ~9 slots under its cap) and (b) deleted entries in
// random Go map-iteration order, so a just-written, still-valid-TTL entry
// (e.g. a fresh replay-protection JTI) could be dropped immediately —
// truncating the replay window.
func TestShardedCacheFIFOEvictionRetainsNewest(t *testing.T) {
	cache := NewShardedCache(4, 400) // maxPerShard = 100

	// Collect 100 filler keys + 1 trigger key that all hash into ONE shard,
	// giving deterministic control over capacity pressure.
	var shard *cacheShard
	fillers := make([]string, 0, 100)
	var trigger string
	for i := 0; len(fillers) < 100 || trigger == ""; i++ {
		k := fmt.Sprintf("key-%d", i)
		s := cache.getShard(k)
		if shard == nil {
			shard = s
			continue
		}
		if s == shard {
			if len(fillers) < 100 {
				fillers = append(fillers, k)
			} else if trigger == "" {
				trigger = k
			}
		}
	}

	for _, k := range fillers {
		cache.Set(k, true, time.Minute)
	}

	// This write hits the shard at capacity: it must evict the OLDEST and
	// place the newcomer, keeping the shard full.
	cache.Set(trigger, true, time.Minute)

	if !cache.Exists(trigger) {
		t.Fatalf("capacity-triggering write evicted the just-written newest entry (random over-eviction)")
	}
	if n := cache.Size(); n != 100 {
		t.Fatalf("shard size = %d, want 100 (old code over-evicted below capacity)", n)
	}
}
