package backends

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMemoryBackend_NegativeTTLNotStored guards the R125 fix to memory.go:
// a negative TTL must mean "already expired" (the stack's convention, per
// redis.go) and NOT store a permanent entry. Previously ttl<=0 fell
// through to a permanent entry, diverging from redis and universal_cache,
// so a value whose validity had passed was kept forever in the memory
// tier.
func TestMemoryBackend_NegativeTTLNotStored(t *testing.T) {
	b := NewMemoryCacheBackend(1000, 0, 0)
	defer b.Close()

	ctx := context.Background()
	if err := b.Set(ctx, "k", []byte("v"), -1*time.Second); err != nil {
		t.Fatalf("set with negative TTL: %v", err)
	}

	if _, err := b.Get(ctx, "k"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Get after negative-TTL Set = %v, want %v (negative TTL must be treated as already-expired, not stored)", err, ErrCacheMiss)
	}
}
