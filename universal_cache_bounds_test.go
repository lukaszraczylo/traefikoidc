package traefikoidc

import (
	"math"
	"testing"
	"time"
)

func newBoundsCache(t *testing.T, cfg UniversalCacheConfig) *UniversalCache {
	t.Helper()
	cfg.CleanupInterval = time.Hour
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = time.Hour
	}
	c := NewUniversalCache(cfg)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// Grace extensions must stay within MaxGracePeriod of the ORIGINAL expiry.
func TestGraceNeverServesPastOriginalExpiryBound(t *testing.T) {
	c := newBoundsCache(t, UniversalCacheConfig{
		Type: CacheTypeMetadata, MaxSize: 10,
		MetadataConfig: &MetadataCacheConfig{
			GracePeriod: 20 * time.Millisecond, ExtendedGracePeriod: 20 * time.Millisecond,
			MaxGracePeriod: 100 * time.Millisecond, SecurityCriticalMaxGracePeriod: 100 * time.Millisecond,
		},
	})
	if err := c.Set("k", "v", 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	c.ActivateGracePeriod("k")
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		if _, ok := c.Get("k"); !ok {
			return
		}
	}
	t.Fatal("stale entry still served 600ms after a 100ms max grace")
}

func TestSetMaxSizeNegativeTerminates(t *testing.T) {
	c := newBoundsCache(t, UniversalCacheConfig{Type: CacheTypeGeneral, MaxSize: 10})
	for _, k := range []string{"a", "b", "c"} {
		_ = c.Set(k, "v", time.Hour)
	}
	done := make(chan struct{})
	go func() { c.SetMaxSize(-1); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SetMaxSize(-1) did not return")
	}
}

// One oversized value must not flush the other live entries.
func TestOversizedValueDoesNotFlushCache(t *testing.T) {
	c := newBoundsCache(t, UniversalCacheConfig{
		Type: CacheTypeGeneral, MaxSize: 10, MaxMemoryBytes: 1000, EnableMemoryLimit: true,
	})
	_ = c.Set("live", "x", time.Hour)
	_ = c.Set("big", make([]byte, 5000), time.Hour)
	if _, ok := c.Get("live"); !ok {
		t.Fatal("oversized insert evicted a live entry")
	}
	c.mu.RLock()
	mem := c.currentMemory
	c.mu.RUnlock()
	if mem > 1000 {
		t.Fatalf("currentMemory=%d exceeds cap 1000", mem)
	}
}

// Out-of-range or non-finite nbf/iat must be rejected, not wrapped into the past.
func TestTimeClaimsRejectOutOfRange(t *testing.T) {
	for _, v := range []float64{1e19, 1e300, math.Inf(1), math.Inf(-1), math.NaN()} {
		if verifyNotBefore(v) == nil {
			t.Errorf("nbf=%v accepted", v)
		}
		if verifyIssuedAt(v) == nil {
			t.Errorf("iat=%v accepted", v)
		}
		if verifyExpiration(v) == nil {
			t.Errorf("exp=%v accepted", v)
		}
	}
}
