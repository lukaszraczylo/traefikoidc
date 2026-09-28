package traefikoidc

// Round-2 verifier regression (minor): when the distributed jti-claim write
// reaches Redis but its reply is lost, UniversalCache.SetIfAbsent (through
// RedisBackend.SetNX) now reports backends.ErrSetNXAmbiguous rather than
// (false, nil) — see internal/cache/backends'
// review_r2_fix17_setnx_reply_dropped_test.go for that half of the fix.
// checkAndMarkLogoutJTIProcessed must treat that specific error as "this
// call's own write may already be in the shared backend" and accept the
// token, NOT fall through to the backchannelLogoutJTIMu-guarded Get+Set
// fallback: that fallback's Get would find the ambiguous write's own key
// already present and misreport a first-ever logout token as a replay.

import (
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/cache/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ambiguousFirstClaimCache simulates a cache whose SetIfAbsent's underlying
// SET NX applied (the key is now present) but whose reply was lost, so it
// reports (false, backends.ErrSetNXAmbiguous) — exactly what
// RedisBackend.SetNX now returns for a dropped SET NX reply.
type ambiguousFirstClaimCache struct {
	mu       sync.Mutex
	data     map[string]interface{}
	getCalls int
}

func (c *ambiguousFirstClaimCache) SetIfAbsent(key string, value interface{}, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[string]interface{})
	}
	if _, exists := c.data[key]; !exists {
		c.data[key] = value
	}
	return false, backends.ErrSetNXAmbiguous
}

func (c *ambiguousFirstClaimCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCalls++
	v, ok := c.data[key]
	return v, ok
}

func (c *ambiguousFirstClaimCache) Set(key string, value interface{}, _ time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[string]interface{})
	}
	c.data[key] = value
}

func (c *ambiguousFirstClaimCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}
func (c *ambiguousFirstClaimCache) SetMaxSize(int)                   {}
func (c *ambiguousFirstClaimCache) Size() int                        { return 0 }
func (c *ambiguousFirstClaimCache) Clear()                           {}
func (c *ambiguousFirstClaimCache) Cleanup()                         {}
func (c *ambiguousFirstClaimCache) Close()                           {}
func (c *ambiguousFirstClaimCache) GetStats() map[string]interface{} { return nil }

// TestFIX17R2_CheckAndMarkLogoutJTIProcessed_AmbiguousSetNX_AcceptsWithoutGetFallback
// pins that an ambiguous SetIfAbsent result is accepted as a successful
// claim, and that the Get+Set fallback is never consulted for it — falling
// through to Get would see this call's own possibly-applied write and
// reject a first-ever logout token as a replay.
func TestFIX17R2_CheckAndMarkLogoutJTIProcessed_AmbiguousSetNX_AcceptsWithoutGetFallback(t *testing.T) {
	cache := &ambiguousFirstClaimCache{}
	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		sessionInvalidationCache: cache,
	}

	err := oidc.checkAndMarkLogoutJTIProcessed("fix17-r2-ambiguous-jti", time.Now().Unix())

	require.NoError(t, err, "an ambiguous SetNX outcome must be accepted, not rejected as a replay")
	assert.Equal(t, 0, cache.getCalls, "the Get+Set fallback must not run for an ambiguous SetNX result — it would see this call's own possible write and misreport a first-ever token as a replay")
}
