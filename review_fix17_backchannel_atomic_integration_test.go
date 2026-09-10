package traefikoidc

// End-to-end pin for the remaining half of FIX-17: logout.go's
// checkAndMarkLogoutJTIProcessed must reach UniversalCache.SetIfAbsent (see
// review_fix17_setifabsent_test.go for the primitive itself) rather than the
// legacy backchannelLogoutJTIMu-guarded Get-then-Set whenever the cache
// supports it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// instrumentedAtomicCache is a CacheInterface fake that also implements
// AtomicSetIfAbsentCache with a correct, mutex-protected SetIfAbsent, and
// counts calls to the legacy Get/Set path. checkAndMarkLogoutJTIProcessed
// must prefer SetIfAbsent whenever the cache provides it and never fall
// through to Get/Set — at head (before this fix) it does not know about
// SetIfAbsent at all and always uses Get/Set, which this test catches via
// the call counts, independent of whether the outcome happens to still be
// correct under the process-local mutex.
type instrumentedAtomicCache struct {
	mu       sync.Mutex
	data     map[string]interface{}
	getCalls int32
	setCalls int32
}

func (c *instrumentedAtomicCache) SetIfAbsent(key string, value interface{}, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[string]interface{})
	}
	if _, exists := c.data[key]; exists {
		return false, nil
	}
	c.data[key] = value
	return true, nil
}

func (c *instrumentedAtomicCache) Get(key string) (interface{}, bool) {
	atomic.AddInt32(&c.getCalls, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	return v, ok
}

func (c *instrumentedAtomicCache) Set(key string, value interface{}, ttl time.Duration) {
	atomic.AddInt32(&c.setCalls, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[string]interface{})
	}
	c.data[key] = value
}

func (c *instrumentedAtomicCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}
func (c *instrumentedAtomicCache) SetMaxSize(int)                   {}
func (c *instrumentedAtomicCache) Size() int                        { return 0 }
func (c *instrumentedAtomicCache) Clear()                           {}
func (c *instrumentedAtomicCache) Cleanup()                         {}
func (c *instrumentedAtomicCache) Close()                           {}
func (c *instrumentedAtomicCache) GetStats() map[string]interface{} { return nil }

// TestFIX17_BackchannelLogout20ConcurrentSameJTI_UsesAtomicSetIfAbsent
// drives 20 concurrent backchannel-logout submissions of the same valid
// logout token (same jti) through the production validateLogoutToken path.
// It asserts both properties FIX-17 requires: exactly one is accepted, and
// the jti check reached that result through SetIfAbsent alone, never the
// legacy Get/Set fallback.
func TestFIX17_BackchannelLogout20ConcurrentSameJTI_UsesAtomicSetIfAbsent(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())
	jwkCache := &staticJWKCache{jwks: &JWKSet{Keys: []JWK{{
		Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256",
	}}}}

	cache := &instrumentedAtomicCache{}
	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		sessionInvalidationCache: cache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 jwkCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	token := signFix17LogoutToken(t, privateKey, "fix17-20-concurrent-jti")

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = oidc.validateLogoutToken(token)
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	assert.Equal(t, 1, successes, "exactly one of %d concurrent same-jti backchannel-logout submissions must be accepted", n)
	assert.Equal(t, int32(0), atomic.LoadInt32(&cache.getCalls), "jti check must use SetIfAbsent, not the legacy Get fallback, when the cache supports it")
	assert.Equal(t, int32(0), atomic.LoadInt32(&cache.setCalls), "jti check must use SetIfAbsent, not the legacy Set fallback, when the cache supports it")
}
