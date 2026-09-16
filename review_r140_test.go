package traefikoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestGetPublicKeyFresh_RespectsForceRefreshCooldown verifies that
// getPublicKeyFresh (the signature-failure retry path) performs at most one
// live upstream JWKS fetch per cooldown window per URL. The FIRST call
// after an in-place rotation fetches (picking up the new key, R109); a
// repeated signature failure within the window must be served from the
// cached keyset without another fetch (R140). Without the gate, an
// attacker presenting a valid kid with a bogus signature would trigger one
// upstream fetch per request, bypassing the anti-amplification bound.
func TestGetPublicKeyFresh_RespectsForceRefreshCooldown(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	const kid = "cooldown-kid"

	var fetches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		writeJWKS(t, w, kid, &key.PublicKey)
	}))
	defer srv.Close()

	cache := NewJWKCache()

	// First signature-failure refresh MUST fetch (picks up a rotated key)
	// and records the dedicated cooldown.
	if _, err := cache.getPublicKeyFresh(context.Background(), srv.URL, kid, srv.Client()); err != nil {
		t.Fatalf("first refresh should fetch the key: %v", err)
	}

	// A repeated signature-failure within the cooldown window must serve the
	// cached keyset without another upstream fetch.
	before := atomic.LoadInt32(&fetches)
	if _, err := cache.getPublicKeyFresh(context.Background(), srv.URL, kid, srv.Client()); err != nil {
		t.Fatalf("getPublicKeyFresh within cooldown should serve cached key: %v", err)
	}
	after := atomic.LoadInt32(&fetches)
	if after != before {
		t.Fatalf("getPublicKeyFresh within cooldown must not fetch upstream; got %d fetch(es)", after-before)
	}
}

func TestJoinBoundedClaimHeader(t *testing.T) {
	// A small well-formed list is joined normally with commas.
	if got := joinBoundedClaimHeader([]string{"a", "b", "c"}); got != "a,b,c" {
		t.Fatalf("small list: got %q", got)
	}
	// Single value within budget is passed through.
	if got := joinBoundedClaimHeader([]string{"group-1"}); got != "group-1" {
		t.Fatalf("single value: got %q", got)
	}
	// Empty input yields empty output.
	if got := joinBoundedClaimHeader(nil); got != "" {
		t.Fatalf("nil input: got %q", got)
	}
	// Many large-but-per-value-valid entries must be bounded to
	// headerTemplateMaxLen instead of being joined unbounded.
	long := string(make([]byte, headerTemplateMaxLen/4)) // ~2KB each
	in := []string{long, long, long, long, long}
	got := joinBoundedClaimHeader(in)
	if len(got) > headerTemplateMaxLen {
		t.Fatalf("joined header length %d exceeds cap %d", len(got), headerTemplateMaxLen)
	}
	if got == "" || len(got) < len(long) {
		t.Fatalf("expected leading values to survive: got %d bytes", len(got))
	}
	// A single value that alone exceeds the budget fails closed to empty
	// (caller drops the header) rather than emitting an oversized one.
	huge := string(make([]byte, headerTemplateMaxLen+1))
	if got := joinBoundedClaimHeader([]string{huge}); got != "" {
		t.Fatalf("oversized single value must drop the header; got %d bytes", len(got))
	}
}
