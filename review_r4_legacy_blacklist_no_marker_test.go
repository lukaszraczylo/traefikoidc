package traefikoidc

// R4 cache review, round 2 (minor, universal_cache.go:1193): the fast byte
// compare added to checkLegacyBlacklistMarker (legacyBlacklistTrueMarker,
// {0x01,'t','r','u','e'}) recognizes only the CURRENT serialize() encoding
// — a leading 0x01 marker byte followed by json.Marshal(true). Code before
// #117 (commit 775de2a, 2026-01-08; every tag up to and including v0.8.17)
// wrote plain json.Marshal(true) with NO marker byte, i.e. the 4 bytes
// `true`. deserialize's "Legacy data without marker" fallback still accepts
// that encoding today, so the OLD checkLegacyBlacklistMarker (via
// deserialize) honored those markers — the new byte-compare does not. A
// Redis-mode upgrade straight from v0.8.17 or earlier would silently drop
// revocations written up to the blacklist's TTL (24h) before the upgrade,
// contradicting decision (c): "old token: markers are still honored."
//
// Fix: also accept the 4-byte legacy encoding with no marker byte at all
// (legacyBlacklistTrueMarker[1:]).

import (
	"context"
	"testing"
	"time"
)

// TestR4_LegacyBlacklistMarker_HonoursPreMarkerEncoding pins the
// pre-#117 encoding: a legacy marker written as raw json.Marshal(true) —
// the 4 bytes `true`, with no leading type-marker byte — must still be
// found as blacklisted.
// Fail-on-old: checkLegacyBlacklistMarker's byte compare only matches
// {0x01,'t','r','u','e'} (5 bytes), so the 4-byte marker is treated as "not
// the boolean marker" and the lookup reports not-found.
func TestR4_LegacyBlacklistMarker_HonoursPreMarkerEncoding(t *testing.T) {
	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	blacklistCache := NewUniversalCacheWithBackend(newBlacklistCacheConfig(logger), shared)
	defer blacklistCache.Close()

	legacyKey := "pre-117-revoked-jti"
	// The pre-#117 encoding: json.Marshal(true) with no leading marker byte.
	preMarkerData := []byte("true")
	if err := shared.Set(context.Background(), legacyBlacklistPrefix+legacyKey, preMarkerData, time.Hour); err != nil {
		t.Fatalf("simulated pre-#117 legacy write failed: %v", err)
	}

	value, found := blacklistCache.Get(legacyKey)
	if !found {
		t.Fatalf("a pre-#117 legacy marker (raw %q, no type-marker byte) must still be found as blacklisted", preMarkerData)
	}
	if value != true {
		t.Fatalf("Get(%q) = %v, want true", legacyKey, value)
	}
}
