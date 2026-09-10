package traefikoidc

// R4 cache review, round 2 (major, universal_cache.go:1193): the
// legacyBlacklistMissUntil map added to bound checkLegacyBlacklistMarker's
// Redis cost had no size cap of its own. Its keys are raw token strings, and
// recordLegacyBlacklistMiss runs on every blacklist Get miss BEFORE
// signature verification — a caller-controlled input reaching a request
// path. Pruning only happened in cleanup(), which the manager runs on a
// 5-minute ticker, so each unique key (or unique raw token, since a miss is
// keyed by the raw lookup key) stayed in memory for up to ~5.5 minutes
// regardless of how many distinct ones arrived. The blacklist's own local
// LRU is capped at MaxSize (1000 by default); this map had no such limit at
// all, adding unbounded memory an attacker who can send unique bearer
// tokens fully controls.
//
// Fix: cap legacyBlacklistMissUntil at c.config.MaxSize (already >0 for
// every cache — see createUniversalCache), pruning expired entries inline
// when the cap is hit before deciding whether there is still room, and
// keying by a fixed-size sha256 digest instead of the raw string so entry
// size does not grow with token length.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestR4_LegacyBlacklistMiss_BoundedByMaxSize pins the cap: a burst of
// unique-key misses, well beyond the configured cap, must never grow
// legacyBlacklistMissUntil past that cap — and a genuine legacy marker must
// still be honored afterward, even while the map sits at capacity.
// Fail-on-old: legacyBlacklistMissUntil has no cap at all, so it grows to
// exactly the number of unique misses made (20), not <= the configured cap
// (5).
func TestR4_LegacyBlacklistMiss_BoundedByMaxSize(t *testing.T) {
	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	const capSize = 5
	cfg := newBlacklistCacheConfig(logger)
	cfg.MaxSize = capSize
	blacklistCache := NewUniversalCacheWithBackend(cfg, shared)
	defer blacklistCache.Close()

	// Far more unique misses than the cap: each is a distinct raw token
	// that was never revoked and has no legacy-namespace entry either, so
	// every one of these is a genuine miss through checkLegacyBlacklistMarker.
	const uniqueMisses = capSize * 4
	for i := 0; i < uniqueMisses; i++ {
		key := fmt.Sprintf("never-revoked-raw-token-%d", i)
		if _, found := blacklistCache.Get(key); found {
			t.Fatalf("unexpected hit for key %q that was never set", key)
		}
	}

	blacklistCache.legacyBlacklistMissMu.Lock()
	got := len(blacklistCache.legacyBlacklistMissUntil)
	blacklistCache.legacyBlacklistMissMu.Unlock()
	if got > capSize {
		t.Fatalf("legacyBlacklistMissUntil has %d entries after %d unique misses, want <= %d (the cache's configured MaxSize)", got, uniqueMisses, capSize)
	}

	// A genuine legacy marker for a DIFFERENT key must still be honored,
	// even with the miss map sitting at (or near) capacity.
	legacyKey := "actually-revoked-jti"
	data, err := blacklistCache.serialize(true)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := shared.Set(context.Background(), legacyBlacklistPrefix+legacyKey, data, time.Hour); err != nil {
		t.Fatalf("simulated legacy write failed: %v", err)
	}

	value, found := blacklistCache.Get(legacyKey)
	if !found {
		t.Fatalf("a genuine legacy marker for %q must still be found while the miss-cache is at capacity", legacyKey)
	}
	if value != true {
		t.Fatalf("Get(%q) = %v, want true", legacyKey, value)
	}
}
