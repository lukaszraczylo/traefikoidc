package traefikoidc

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// TestProcessChunkedTokenDropsStaleExcessChunks guards token recombining when
// a session token was rewritten with fewer chunks than before. Set*Token
// writes chunks 0..n-1 but never clears the higher-index chunk cookies left
// behind by a previously larger token; on the next read getTokenChunkSessions
// picks those up, and the old code treated any len(chunks)!=token_total as
// truncation and forced a re-auth, discarding the still-valid new token.
// token_total is the authoritative count, so excess higher chunks are stale
// and must be dropped, while genuine trailing loss (len < total) still errors.
func TestProcessChunkedTokenDropsStaleExcessChunks(t *testing.T) {
	cm := NewChunkManager(NewLogger(DefaultLogLevel))
	config := TokenConfig{
		Type:         "access",
		MinLength:    5,
		MaxLength:    100 * 1024,
		MaxChunks:    25,
		MaxChunkSize: maxCookieSize,
	}

	// A new, smaller token was written: chunk 0 says token_total=2, but
	// stale chunks 2..4 from a previous larger token are still present.
	chunks := map[int]*sessions.Session{
		0: {Values: map[interface{}]interface{}{"token_chunk": "aaaa", "token_total": 2}},
		1: {Values: map[interface{}]interface{}{"token_chunk": "bbbb", "token_total": 2}},
		2: {Values: map[interface{}]interface{}{"token_chunk": "cccc"}},
		3: {Values: map[interface{}]interface{}{"token_chunk": "dddd"}},
		4: {Values: map[interface{}]interface{}{"token_chunk": "eeee"}},
	}

	res := cm.GetToken("", false, chunks, config)
	if res.Error != nil {
		t.Fatalf("stale excess chunks must be dropped, not fail: %v", res.Error)
	}
	if res.Token != "aaaabbbb" {
		t.Fatalf("expected reassembled token from the authoritative %d chunks, got %q", 2, res.Token)
	}
}

// azureNonceToken builds an Azure-style access token whose parse succeeds but
// whose signature is unverifiable (proprietary nonce header), carrying the
// given exp claim.
func azureNonceToken(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","nonce":"abc"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp)))
	return header + "." + payload + ".sig"
}

// TestAzureRSUnverifiableToken_ExpiredRejected guards the RS Azure path where
// an unverifiable access token (no corroborating id token) was previously
// accepted with authenticated=true and NO signature OR expiry check. It still
// carries exp, so authenticate only while unexpired; an expired (or
// unparseable) value must trigger refresh or re-auth instead of authenticating
// indefinitely until the session itself expired.
func TestAzureRSUnverifiableToken_ExpiredRejected(t *testing.T) {
	tObj := &TraefikOidc{}

	past := &requestState{authenticated: true, accessToken: azureNonceToken(time.Now().Add(-time.Hour).Unix())}
	auth, refresh, reauth := tObj.validateAzureTokensRS(past)
	if auth {
		t.Fatalf("expired unverifiable Azure access token must not authenticate (auth=%v refresh=%v reauth=%v)", auth, refresh, reauth)
	}

	// Control: a still-valid unverifiable Azure token with no id token keeps
	// authenticating (the pre-existing behavior for the legitimate case).
	future := &requestState{authenticated: true, accessToken: azureNonceToken(time.Now().Add(time.Hour).Unix())}
	auth, _, _ = tObj.validateAzureTokensRS(future)
	if !auth {
		t.Fatalf("valid unverifiable Azure access token should still authenticate")
	}

	// Unparseable value (not a valid JWT) must fail closed, not authenticate.
	bad := &requestState{authenticated: true, accessToken: "not-a-jwt-at-all"}
	auth, _, _ = tObj.validateAzureTokensRS(bad)
	if auth {
		t.Fatalf("unparseable Azure access token must not authenticate")
	}

	// Missing exp (or non-numeric) on an unverifiable token must also fail
	// closed: with no exp the token can't be bounded, so authenticating it
	// would be zero-verification (R130 gap in the R129 fix).
	noexp := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	noExpToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","nonce":"abc"}`)) + "." + noexp + ".sig"
	noExpRS := &requestState{authenticated: true, accessToken: noExpToken}
	auth, _, _ = tObj.validateAzureTokensRS(noExpRS)
	if auth {
		t.Fatalf("unverifiable Azure access token with missing exp must not authenticate")
	}
}

// TestShardedCache_LazyRemovePreservesFreshCovers the Get lazy-removal path of
// ShardedCache (the replay/JTI cache used by jwt.go). An expired entry is
// removed on read, but only if it is still the same entry: the delete is
// conditional under the shard lock (mirroring deleteIfExpired in
// internal/cache/backends/memory_shard.go), so a concurrent Set that
// refreshed the key is never clobbered. Without this a freshly-recorded
// replay JTI could be deleted, allowing a duplicate token to pass (R129).
// The exact interleave is racy and can't be forced deterministically, so
// this verifies the expired-removal branch runs and that a value injected
// after expiry is returned (not deleted).
func TestShardedCache_LazyRemovePreservesFresh(t *testing.T) {
	c := NewShardedCache(1, 100)
	c.Set("k", "old", 1*time.Nanosecond) // immediately expired
	time.Sleep(time.Millisecond)

	if _, ok := c.Get("k"); ok {
		t.Fatalf("expired entry should be lazily removed on Get")
	}

	// Re-insert a fresh value after expiry; it must be retrievable and not
	// swept away by any lingering expired-entry delete.
	c.Set("k", "fresh", time.Hour)
	v, ok := c.Get("k")
	if !ok || v != "fresh" {
		t.Fatalf("fresh value must survive lazy removal: got ok=%v v=%v", ok, v)
	}
}
