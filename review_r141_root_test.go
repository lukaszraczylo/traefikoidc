package traefikoidc

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"
	"time"
)

// TestConfigValidate_SessionMaxAgeUpperBound verifies that an oversized
// sessionMaxAge (which overflows the time.Duration (ns) conversion and
// wraps negative, locking every session out) is rejected at Validate time
// rather than failing at runtime (R141).
func TestConfigValidate_SessionMaxAgeUpperBound(t *testing.T) {
	base := func() *Config {
		c := CreateConfig()
		c.ProviderURL = "https://provider.example.com"
		c.ClientID = "test-client"
		c.ClientSecret = "test-secret"
		c.SessionEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		c.CallbackURL = "/callback"
		return c
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("baseline config should validate: %v", err)
	}

	// ~317 years in seconds: overflows int64 nanoseconds -> would wrap
	// negative without the upper bound.
	c := base()
	c.SessionMaxAge = 10_000_000_000
	err := c.Validate()
	if err == nil {
		t.Fatal("oversized sessionMaxAge must be rejected by Validate")
	}
}

// TestUniversalCache_UpdateAtMaxSizeDoesNotEvictLiveEntry verifies that an
// in-place update of an existing key at MaxSize does NOT evict an unrelated
// live LRU entry (there is no net growth), mirroring the shard backend fix
// (R141).
func TestUniversalCache_UpdateAtMaxSizeDoesNotEvictLiveEntry(t *testing.T) {
	c := NewUniversalCache(UniversalCacheConfig{
		Type:           CacheTypeToken,
		MaxSize:        2,
		MaxMemoryBytes: 1 << 20,
	})
	defer c.Close()

	if err := c.SetLocal("B", "v2", time.Minute); err != nil {
		t.Fatalf("set B: %v", err)
	}
	if err := c.SetLocal("A", "v1", time.Minute); err != nil {
		t.Fatalf("set A: %v", err)
	}
	// Cache is full, and A is the most-recently-used entry (front of the
	// LRU). Updating A is a pure in-place update (no net size change); it
	// must not evict the least-recently-used live entry B.
	if err := c.SetLocal("A", "v2", time.Minute); err != nil {
		t.Fatalf("update A: %v", err)
	}
	if got := c.Size(); got != 2 {
		t.Fatalf("Size()=%d, want 2 (in-place update evicted a live entry)", got)
	}
	if _, ok := c.GetLocal("B"); !ok {
		t.Fatal("B was evicted by the in-place update of A")
	}
}

// TestDCR_BuildRegistrationRequest_ValidatesURIMetadata verifies that the
// optional URI metadata fields (logo_uri, client_uri, policy_uri,
// tos_uri, jwks_uri) are validated as absolute http(s) URLs like
// redirect_uris, so a malformed jwks_uri cannot reach the IdP (R141).
func TestDCR_BuildRegistrationRequest_ValidatesURIMetadata(t *testing.T) {
	base := func() *DynamicClientRegistrationConfig {
		return &DynamicClientRegistrationConfig{
			ClientMetadata: &ClientRegistrationMetadata{
				RedirectURIs: []string{"https://app.example.com/callback"},
			},
		}
	}

	// A relative jwks_uri must be rejected.
	cfg := base()
	cfg.ClientMetadata.JWKSURI = "example.com/keys"
	if _, err := NewDynamicClientRegistrar(nil, nil, cfg, "").buildRegistrationRequest(); err == nil {
		t.Fatal("relative jwks_uri must be rejected as a non-absolute URL")
	}

	// A javascript: client_uri must be rejected.
	cfg = base()
	cfg.ClientMetadata.ClientURI = "javascript:alert(1)"
	if _, err := NewDynamicClientRegistrar(nil, nil, cfg, "").buildRegistrationRequest(); err == nil {
		t.Fatal("javascript: client_uri must be rejected")
	}

	// A valid full set must be accepted unchanged.
	cfg = base()
	cfg.ClientMetadata.LogoURI = "https://app.example.com/logo.png"
	cfg.ClientMetadata.TOSURI = "https://app.example.com/tos"
	if _, err := NewDynamicClientRegistrar(nil, nil, cfg, "").buildRegistrationRequest(); err != nil {
		t.Fatalf("valid URI metadata should be accepted: %v", err)
	}
}

// TestDecompressTokenInternal_RoundTrip guards the decompression change
// (drop the single-Read shortcut for the pooled buffer) by confirming a
// gzip round-trip still returns the exact original bytes (R141).
func TestDecompressTokenInternal_RoundTrip(t *testing.T) {
	original := "header.payload.signature-part-with-extra-length"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(original)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	compressed := base64.StdEncoding.EncodeToString(buf.Bytes())
	if got := decompressToken(compressed); got != original {
		t.Fatalf("decompress round-trip mismatch:\n got %q\nwant %q", got, original)
	}
}
