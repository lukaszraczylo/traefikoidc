package dcrstorage

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recordingCache captures the TTL each Set received, so a test can assert the
// exact TTL semantic without depending on wall-clock time.
type recordingCache struct {
	mu      sync.Mutex
	setTTLs map[string]time.Duration
}

func newRecordingCache() *recordingCache {
	return &recordingCache{setTTLs: make(map[string]time.Duration)}
}

func (c *recordingCache) Get(key string) (any, bool) { return nil, false }
func (c *recordingCache) Delete(key string)          {}
func (c *recordingCache) Set(key string, value any, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setTTLs[key] = ttl
	return nil
}

// TestRedisStore_NoExpiry_EffectivePermanent guards the R116 fix: an IdP that
// reports client_secret_expires_at == 0 (RFC 7591: never expires) must be
// persisted effectively-permanently. Previously such credentials were given a
// 30-day default TTL, so a valid non-expiring credential was evicted mid-use,
// forcing a needless re-registration and orphaning the old client at the IdP.
func TestRedisStore_NoExpiry_EffectivePermanent(t *testing.T) {
	t.Parallel()

	cache := newRecordingCache()
	store := NewRedisStore(cache, "", nil)

	creds := &ClientRegistrationResponse{
		ClientID:              "noexp",
		ClientSecret:          "secret",
		ClientSecretExpiresAt: 0, // never expires
	}

	if err := store.Save(context.Background(), "https://noexp.example.com", creds); err != nil {
		t.Fatalf("failed to save: %v", err)
	}

	key := store.makeKey("https://noexp.example.com")
	cache.mu.Lock()
	ttl, ok := cache.setTTLs[key]
	cache.mu.Unlock()
	if !ok {
		t.Fatal("expected credential to be written to cache")
	}

	// Effective permanence: well beyond any realistic rotation horizon. The
	// old behavior was a 30-day default, so require >= 1 year.
	if ttl < 365*24*time.Hour {
		t.Fatalf("expected effectively-permanent TTL (>=1y) for exp==0, got %v", ttl)
	}
}
