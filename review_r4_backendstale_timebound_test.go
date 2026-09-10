package traefikoidc

// R4 cache review, round 2 (major, universal_cache.go:546): the FIX-04
// backend-stale mark (markBackendStale/backendStaleLocalValue) was fixed for
// cross-replica correctness only for NUMERIC values comparable by
// backendValueIsNewer. For any value that comparison cannot decode — a
// string, a map, a struct — Get kept serving the stale-marked local value
// over every later backend value for as long as the local entry stayed
// live. The finding named the DCR client-credentials cache (a JSON string
// under CacheTypeGeneral, TTL up to 100*365 days) as a concrete instance:
// one replica's timed-out write could pin a stale credential over a value a
// different replica legitimately wrote, for the life of the local entry.
//
// Fix: staleBackend now records WHEN each key was marked, and
// backendStaleLocalValue treats a mark older than backendStaleMarkTTL as
// expired — deleting it and reporting "not stale" so the (now current)
// backend value is trusted again. This bounds the mark's protection window
// for every value backendValueIsNewer cannot compare, while still covering
// the timeout race FIX-04 exists for (a Set that timed out may have landed
// moments later).
//
// Both tests below use a CacheTypeGeneral cache (MonotonicMarkers is NOT
// set) and a JSON-string value, exactly the shape backendValueIsNewer
// reports "not comparable" for — so neither test exercises the numeric
// newer-wins comparison at all.

import (
	"context"
	"testing"
	"time"
)

// TestR4_BackendStale_StringValue_WithinBound_KeepsLocalValue pins the FIX-04
// protection this bound must not weaken: while the mark is still fresh, a
// backend value written by another replica does not clobber the local write
// that survived a timed-out Set — even though the two values are strings
// backendValueIsNewer cannot compare.
// Fail-on-old (pre-bound code): passes today because the mark never expires
// at all; this test alone does not distinguish "bounded and still fresh"
// from "never expires". TestR4_BackendStale_StringValue_AfterBound_ServesNewerBackend
// is the one that requires the bound to exist.
func TestR4_BackendStale_StringValue_WithinBound_KeepsLocalValue(t *testing.T) {
	orig := backendStaleMarkTTL
	backendStaleMarkTTL = 200 * time.Millisecond
	t.Cleanup(func() { backendStaleMarkTTL = orig })

	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          logger,
		Type:            CacheTypeGeneral,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, shared)
	defer replicaA.Close()

	// Replica A's own write of a non-numeric (string) value times out —
	// Redis may or may not have applied it — so Set marks the key
	// backend-stale and keeps the fresh value locally.
	shared.failOnce = context.DeadlineExceeded
	if err := replicaA.Set("dcr:client-x", `{"client_id":"A"}`, time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	// A different replica writes directly to the shared backend right away,
	// while A's mark is still fresh.
	data, err := replicaA.serialize(`{"client_id":"B"}`)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := shared.Set(context.Background(), replicaA.prefixKey("dcr:client-x"), data, time.Minute); err != nil {
		t.Fatalf("simulated other-replica write failed: %v", err)
	}

	value, ok := replicaA.Get("dcr:client-x")
	if !ok {
		t.Fatal("Get: key not found")
	}
	if value != `{"client_id":"A"}` {
		t.Fatalf("Get returned %v, want the local value %q — the fresh backend-stale mark must still protect a same-replica write that survived a timed-out Set", value, `{"client_id":"A"}`)
	}
}

// TestR4_BackendStale_StringValue_AfterBound_ServesNewerBackend is the
// decisive regression test: once the mark's bound elapses, a value written
// by another replica must be served — for a value type (JSON string)
// backendValueIsNewer cannot ever compare, so only the time bound can
// recover this, not the numeric newer-wins branch.
// Fail-on-old: staleBackend has no time bound at all (map[string]struct{},
// no markBackendStale timestamp), so the local value "A" is served forever
// and this test times out waiting for "B".
func TestR4_BackendStale_StringValue_AfterBound_ServesNewerBackend(t *testing.T) {
	orig := backendStaleMarkTTL
	backendStaleMarkTTL = 50 * time.Millisecond
	t.Cleanup(func() { backendStaleMarkTTL = orig })

	shared := &r4SharedBackend{m: map[string][]byte{}}
	logger := NewLogger("error")

	replicaA := NewUniversalCacheWithBackend(UniversalCacheConfig{
		Logger:          logger,
		Type:            CacheTypeGeneral,
		DefaultTTL:      time.Minute,
		SkipAutoCleanup: true,
	}, shared)
	defer replicaA.Close()

	shared.failOnce = context.DeadlineExceeded
	if err := replicaA.Set("dcr:client-x", `{"client_id":"A"}`, time.Minute); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	data, err := replicaA.serialize(`{"client_id":"B"}`)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if err := shared.Set(context.Background(), replicaA.prefixKey("dcr:client-x"), data, time.Minute); err != nil {
		t.Fatalf("simulated other-replica write failed: %v", err)
	}

	// Let the mark's bound elapse.
	time.Sleep(backendStaleMarkTTL + 150*time.Millisecond)

	value, ok := replicaA.Get("dcr:client-x")
	if !ok {
		t.Fatal("Get: key not found")
	}
	if value != `{"client_id":"B"}` {
		t.Fatalf("Get returned %v, want the newer backend value %q once the backend-stale mark's bound has elapsed — a non-numeric value must not stay pinned to the local write forever", value, `{"client_id":"B"}`)
	}
}
