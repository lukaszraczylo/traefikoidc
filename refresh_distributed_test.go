package traefikoidc

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// inMemoryCache is the smallest CacheInterface that satisfies the cross-
// replica dedup contract: Set/Get with TTL. Used in place of the universal
// cache singleton so these tests stay hermetic.
type inMemoryCache struct {
	entries map[string]inMemoryCacheEntry
	mu      sync.Mutex
}

type inMemoryCacheEntry struct {
	expiresAt time.Time
	value     interface{}
}

func newInMemoryCache() *inMemoryCache {
	return &inMemoryCache{entries: make(map[string]inMemoryCacheEntry)}
}

func (c *inMemoryCache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = inMemoryCacheEntry{value: value, expiresAt: time.Now().Add(ttl)}
}

func (c *inMemoryCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return e.value, true
}

func (c *inMemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *inMemoryCache) SetMaxSize(int) {}
func (c *inMemoryCache) Cleanup()       {}
func (c *inMemoryCache) Close()         {}
func (c *inMemoryCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
func (c *inMemoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]inMemoryCacheEntry{}
}
func (c *inMemoryCache) GetStats() map[string]any { return map[string]any{} }

// erroringTokenExchanger always errors - simulates an IdP rejection.
type erroringTokenExchanger struct {
	calls int32
}

func (e *erroringTokenExchanger) ExchangeCodeForToken(_ context.Context, _, _, _, _ string) (*TokenResponse, error) {
	return nil, errors.New("not used")
}

func (e *erroringTokenExchanger) GetNewTokenWithRefreshToken(_ string) (*TokenResponse, error) {
	atomic.AddInt32(&e.calls, 1)
	return nil, errors.New("invalid_grant")
}

func (e *erroringTokenExchanger) RevokeTokenWithProvider(_, _ string) error { return nil }

// TestCoordinatedTokenRefresh_CrossReplicaCacheHit simulates a peer Traefik
// replica having just refreshed: the shared cache already has the result, so
// this pod must reuse it without ever calling the IdP.
func TestCoordinatedTokenRefresh_CrossReplicaCacheHit(t *testing.T) {
	stub := &stubTokenExchanger{
		resp: &TokenResponse{AccessToken: "should_not_be_called"},
	}

	logger := NewLogger("error")
	cache := newInMemoryCache()
	preExisting := &TokenResponse{
		AccessToken:  "from_peer",
		RefreshToken: "rotated_by_peer",
		IDToken:      "id_from_peer",
	}
	rt := "shared_refresh_token"
	cache.Set(refreshResultCacheKey(refreshCoordinatorSessionID(rt)), preExisting, refreshResultCacheTTL)

	oidc := &TraefikOidc{
		logger:             logger,
		tokenExchanger:     stub,
		refreshCoordinator: NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), logger),
		refreshResultCache: cache,
	}
	defer oidc.refreshCoordinator.Shutdown()

	resp, err := oidc.coordinatedTokenRefresh(httptest.NewRequest("GET", "/", nil), rt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "from_peer" {
		t.Fatalf("expected peer-provided response, got %+v", resp)
	}
	if got := atomic.LoadInt32(&stub.calls); got != 0 {
		t.Fatalf("expected 0 upstream calls (peer already refreshed), got %d", got)
	}
}

// TestCoordinatedTokenRefresh_PopulatesCrossReplicaCache verifies that on a
// cache miss the leader stores its result for peers to find within the TTL.
func TestCoordinatedTokenRefresh_PopulatesCrossReplicaCache(t *testing.T) {
	stub := &stubTokenExchanger{
		resp: &TokenResponse{AccessToken: "fresh_grant"},
	}

	logger := NewLogger("error")
	cache := newInMemoryCache()

	oidc := &TraefikOidc{
		logger:             logger,
		tokenExchanger:     stub,
		refreshCoordinator: NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), logger),
		refreshResultCache: cache,
	}
	defer oidc.refreshCoordinator.Shutdown()

	rt := "fresh_refresh_token"
	resp, err := oidc.coordinatedTokenRefresh(nil, rt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.AccessToken != "fresh_grant" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got := atomic.LoadInt32(&stub.calls); got != 1 {
		t.Fatalf("expected 1 upstream call, got %d", got)
	}

	v, ok := cache.Get(refreshResultCacheKey(refreshCoordinatorSessionID(rt)))
	if !ok {
		t.Fatal("expected refresh result to be cached after upstream success")
	}
	if tr, ok := v.(*TokenResponse); !ok || tr.AccessToken != "fresh_grant" {
		t.Fatalf("cached value malformed: %+v", v)
	}
}

// TestCoordinatedTokenRefresh_ErrorIsNotCached makes sure we don't poison the
// dedup cache when the IdP rejects the grant. Peers must run their own
// refresh; they cannot inherit an error.
func TestCoordinatedTokenRefresh_ErrorIsNotCached(t *testing.T) {
	failing := &erroringTokenExchanger{}
	logger := NewLogger("error")
	cache := newInMemoryCache()

	oidc := &TraefikOidc{
		logger:             logger,
		tokenExchanger:     failing,
		refreshCoordinator: NewRefreshCoordinator(DefaultRefreshCoordinatorConfig(), logger),
		refreshResultCache: cache,
	}
	defer oidc.refreshCoordinator.Shutdown()

	if _, err := oidc.coordinatedTokenRefresh(nil, "doomed_refresh_token"); err == nil {
		t.Fatal("expected an error from the failing exchanger")
	}
	if cache.Size() != 0 {
		t.Fatalf("error result must not be cached, size=%d", cache.Size())
	}
}
