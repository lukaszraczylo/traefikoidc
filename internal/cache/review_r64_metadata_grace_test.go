package cache

import (
	"testing"
	"time"
)

// TestMetadataSetGraceCappedByMaxGrace verifies that MetadataCache.Set caps the
// applied grace period by the configured MaxGracePeriod (and, for
// security-critical metadata containing an operator-listed field, by
// SecurityCriticalMaxGracePeriod). Previously only GracePeriod was applied and
// the caps were configured but never read, so stale discovery metadata
// (issuer, jwks_uri) could be served fresh beyond the intended bound.
func TestMetadataSetGraceCappedByMaxGrace(t *testing.T) {
	t.Run("grace capped by MaxGracePeriod", func(t *testing.T) {
		base := New(DefaultConfig())
		defer base.Close()

		mc := NewMetadataCache(base, MetadataConfig{
			GracePeriod:    time.Hour,
			MaxGracePeriod: 5 * time.Minute,
		})

		start := time.Now()
		baseTTL := time.Minute
		if err := mc.Set("https://issuer.example", &ProviderMetadata{Issuer: "https://issuer.example"}, baseTTL); err != nil {
			t.Fatal(err)
		}

		item, ok := base.items["metadata:https://issuer.example"]
		if !ok {
			t.Fatalf("metadata not cached")
		}
		// Grace must be capped at 5m, not the full 1h.
		want := start.Add(baseTTL + 5*time.Minute)
		if item.ExpiresAt.After(want.Add(2 * time.Second)) {
			t.Fatalf("grace not capped by MaxGracePeriod: ExpiresAt=%v want ~%v", item.ExpiresAt, want)
		}
	})

	t.Run("security-critical metadata uses tighter cap", func(t *testing.T) {
		base := New(DefaultConfig())
		defer base.Close()

		mc := NewMetadataCache(base, MetadataConfig{
			GracePeriod:                    time.Hour,
			MaxGracePeriod:                 5 * time.Minute,
			SecurityCriticalMaxGracePeriod: time.Minute,
			SecurityCriticalFields:         []string{"issuer", "jwks_uri"},
		})

		start := time.Now()
		baseTTL := time.Minute
		// Metadata carries the security-critical issuer field.
		if err := mc.Set("https://secure.example", &ProviderMetadata{Issuer: "https://secure.example", JWKSUri: "https://secure.example/jwks"}, baseTTL); err != nil {
			t.Fatal(err)
		}

		item, ok := base.items["metadata:https://secure.example"]
		if !ok {
			t.Fatalf("metadata not cached")
		}
		// Grace must be capped at 1m (the security-critical cap), not 5m or 1h.
		want := start.Add(baseTTL + time.Minute)
		if item.ExpiresAt.After(want.Add(2 * time.Second)) {
			t.Fatalf("security-critical grace not capped by SecurityCriticalMaxGracePeriod: ExpiresAt=%v want ~%v", item.ExpiresAt, want)
		}
	})
}
