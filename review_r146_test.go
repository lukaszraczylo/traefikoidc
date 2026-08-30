package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

// mapCache is a minimal thread-safe CacheInterface for seeding caches in
// bearer-invalidation tests.
type mapCache struct {
	mu sync.Mutex
	m  map[string]any
}

func newMapCache() *mapCache { return &mapCache{m: map[string]any{}} }
func (c *mapCache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	c.m[key] = value
	c.mu.Unlock()
}
func (c *mapCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}
func (c *mapCache) Delete(key string)        { c.mu.Lock(); delete(c.m, key); c.mu.Unlock() }
func (c *mapCache) SetMaxSize(size int)      {}
func (c *mapCache) Size() int                { return 0 }
func (c *mapCache) Clear()                   {}
func (c *mapCache) Cleanup()                 {}
func (c *mapCache) Close()                   {}
func (c *mapCache) GetStats() map[string]any { return nil }

// TestBearer_LogoutInvalidatedSubjectRejected guards the R146 fix in
// bearer_auth.go buildPrincipalFromBearerToken: IdP-initiated
// (backchannel/front-channel) logout only wrote sid/sub markers into the
// session-invalidation cache, which the bearer path never consulted — a
// still-cryptographically-valid bearer access token for a logged-out
// subject kept returning 200 (with requireTokenIntrospection, a cached
// positive verdict extended the stale window). The bearer path must now
// honor the invalidation cache, mirroring the cookie path.
func TestBearer_LogoutInvalidatedSubjectRejected(t *testing.T) {
	nextCalled := false
	oidc := makeBearerOIDC(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	now := time.Now()
	token := r146BearerToken(now.Add(-time.Minute)) // issued BEFORE the logout below
	seedVerified(t, oidc, token, map[string]interface{}{"sub": "user-123"})

	inv := newMapCache()
	oidc.sessionInvalidationCache = inv
	inv.Set(oidc.buildSessionInvalidationKey("sub", "user-123"), now.Unix(), time.Minute)

	if _, bErr := oidc.buildPrincipalFromBearerToken(token); bErr == nil {
		t.Fatal("bearer for a logged-out subject must be rejected (session invalidation honored)")
	}
	if nextCalled {
		t.Fatal("rejected bearer must not be forwarded downstream")
	}
}

// r146BearerToken builds a real base64url-urlencoded 3-segment JWT string
// with the given claims and iat, suitable for parseJWT.
func r146BearerToken(iat time.Time) string {
	payload, _ := json.Marshal(map[string]any{
		"sub": "user-123",
		"exp": float64(iat.Add(time.Hour).Unix()),
		"iat": float64(iat.Unix()),
	})
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// TestBearer_FreshlyIssuedTokenAfterLogoutPasses guards the positive side:
// a bearer issued AFTER the logout must still be accepted (no false
// rejection of legitimate post-logout tokens).
func TestBearer_FreshlyIssuedTokenAfterLogoutPasses(t *testing.T) {
	oidc := makeBearerOIDC(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	now := time.Now()
	token := r146BearerToken(now) // issued at/after the logout
	seedVerified(t, oidc, token, map[string]interface{}{"sub": "user-123"})

	inv := newMapCache()
	oidc.sessionInvalidationCache = inv
	inv.Set(oidc.buildSessionInvalidationKey("sub", "user-123"), now.Add(-time.Minute).Unix(), time.Minute)

	if _, bErr := oidc.buildPrincipalFromBearerToken(token); bErr != nil {
		t.Fatalf("a bearer issued after the logout must pass, got: %v", bErr)
	}
}

// TestValidateDiscoveredEndpoint_SchemeDowngradeRejected guards the R146
// fix in url_helpers.go validateDiscoveredEndpoint: a provider served
// over HTTPS must hand out HTTPS endpoints; a legacy or poisoned
// discovery document downgrading a credential-bearing endpoint to
// plaintext HTTP would otherwise ship secrets over an unauthenticated
// channel.
func TestValidateDiscoveredEndpoint_SchemeDowngradeRejected(t *testing.T) {
	oidc := &TraefikOidc{
		providerURL: "https://provider.example.com",
		logger:      newNoOpLogger(),
	}

	if err := oidc.validateDiscoveredEndpoint("http://provider.example.com/token", false); err == nil {
		t.Fatal("an http endpoint for an https provider must be rejected (scheme downgrade)")
	}
	if err := oidc.validateDiscoveredEndpoint("https://provider.example.com/token", false); err != nil {
		t.Fatalf("an https endpoint for an https provider must pass, got: %v", err)
	}

	// A local (http) provider must still be allowed to use http endpoints.
	local := &TraefikOidc{
		providerURL: "http://localhost:8080",
		logger:      newNoOpLogger(),
	}
	if err := local.validateDiscoveredEndpoint("http://localhost:8080/jwks", true); err != nil {
		t.Fatalf("an http provider with an http endpoint must pass, got: %v", err)
	}
}
