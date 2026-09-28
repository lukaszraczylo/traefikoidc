package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// slowFirstGetCache is a CacheInterface fake whose FIRST Get call for any
// key snapshots the result immediately but delays returning it, modeling a
// slow round trip to a distributed cache (e.g. Redis via UniversalCache).
// It lets a test force two concurrent Get-then-Set sequences to both
// observe a miss before either Set lands, without depending on lucky
// goroutine scheduling.
type slowFirstGetCache struct {
	mu        sync.Mutex
	data      map[string]interface{}
	delayNext bool
	delay     time.Duration
}

func (c *slowFirstGetCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	v, ok := c.data[key]
	delay := c.delayNext
	c.delayNext = false
	d := c.delay
	c.mu.Unlock()
	if delay {
		time.Sleep(d)
	}
	return v, ok
}
func (c *slowFirstGetCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil {
		c.data = make(map[string]interface{})
	}
	c.data[key] = value
}
func (c *slowFirstGetCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}
func (c *slowFirstGetCache) SetMaxSize(int) {}
func (c *slowFirstGetCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}
func (c *slowFirstGetCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]interface{})
}
func (c *slowFirstGetCache) Cleanup()                         {}
func (c *slowFirstGetCache) Close()                           {}
func (c *slowFirstGetCache) GetStats() map[string]interface{} { return nil }

// signFix17LogoutToken builds an ES256-signed OIDC logout token, mirroring
// TestBackchannelLogoutIntegration's construction (logout_test.go), for a
// given jti so two calls can share the same jti.
func signFix17LogoutToken(t *testing.T, key *ecdsa.PrivateKey, jti string) string {
	t.Helper()
	header := map[string]interface{}{"alg": "ES256", "typ": "logout+jwt", "kid": "test-key-1"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": now,
		"exp": time.Now().Add(time.Hour).Unix(),
		"jti": jti,
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-to-logout",
	}
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign test logout token: %v", err)
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return headerB64 + "." + claimsB64 + "." + sigB64
}

// TestValidateLogoutToken_JTIReplayCheckIsAtomic pins the remaining part
// of FIX-17: the backchannel-logout jti replay check (OIDC Back-Channel
// Logout 1.0 §2.5) must be an atomic check-and-set, not a plain Get
// followed by a separate Set. At head, a slow first Get (modeling a
// distributed-cache round trip) lets a second, concurrent call for the
// SAME jti also observe "not yet processed" before the first call's Set
// lands, so both calls succeed - double-processing one logout token.
func TestValidateLogoutToken_JTIReplayCheckIsAtomic(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())
	jwkCache := &staticJWKCache{jwks: &JWKSet{Keys: []JWK{{
		Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256",
	}}}}

	cache := &slowFirstGetCache{delayNext: true, delay: 300 * time.Millisecond}
	oidc := &TraefikOidc{
		logger:                   NewLogger("error"),
		sessionInvalidationCache: cache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 jwkCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	token := signFix17LogoutToken(t, privateKey, "fix17-shared-jti")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = oidc.validateLogoutToken(token) // hits the delayed Get
	}()
	// Generous head start relative to the 300ms internal delay above, so
	// goroutine 0 has deterministically already reached (and started
	// waiting inside) its Get call before goroutine 1 starts.
	time.Sleep(50 * time.Millisecond)
	go func() {
		defer wg.Done()
		_, errs[1] = oidc.validateLogoutToken(token)
	}()
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one of two concurrent same-jti logout tokens to be accepted, got %d successes (errs: %v, %v)",
			successes, errs[0], errs[1])
	}
}
