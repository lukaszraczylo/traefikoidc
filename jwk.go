package traefikoidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// parsedKeysSuffix marks the parallel UniversalCache entry that stores
// pre-parsed public keys for a given JWKS URL.
const parsedKeysSuffix = ":parsed"

// parsedJWKS holds keys decoded from a JWKSet, indexed by kid. Storing the
// already-parsed crypto.PublicKey avoids re-running the DER/PEM round trip
// on every JWT verification — a costly operation under the yaegi interpreter
// that hosts Traefik plugins.
type parsedJWKS struct {
	keys map[string]crypto.PublicKey
}

// JWK represents a JSON Web Key as defined in RFC 7517.
// It can represent different key types including RSA, EC, and symmetric keys.
type JWK struct {
	Kty    string   `json:"kty"`
	Use    string   `json:"use,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	Kid    string   `json:"kid,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

// JWKSet represents a set of JSON Web Keys.
// Typically fetched from an OIDC provider's JWKS endpoint.
type JWKSet struct {
	// Keys contains the array of JWK objects
	Keys []JWK `json:"keys"`
}

// JWKCache provides thread-safe caching of JWKS using UniversalCache.
//
// inflightFetches deduplicates concurrent fetches for the same JWKS URL.
// It replaces a global sync.RWMutex that was previously held for the entire
// HTTP round-trip in GetJWKS: on a cold cache (cold pod, JWK rotation, brief
// network blip) every concurrent request piled up on that single Lock(), and
// under Yaegi each Lock acquisition costs 10-50ms of interpreter-dispatch
// overhead. The singleflight pattern keeps the cold-cache cost O(1) HTTP
// fetch regardless of how many requests are waiting.
type JWKCache struct {
	cache           *UniversalCache
	inflightFetches sync.Map // map[jwksURL string]*jwksFetch

	// forceMu guards lastForceRefresh: per-URL timestamps used to bound the
	// live refresh triggered when a kid is missing from the cached derived
	// keyset (see forceJWKSRefresh). Without the bound, an attacker who
	// presents many tokens with unknown kid values could amplify N requests
	// into N upstream JWKS fetches.
	forceMu          sync.Mutex
	lastForceRefresh map[string]time.Time
	// lastSignatureRefresh (guarded by forceMu) bounds how often the
	// signature-failure path (getPublicKeyFresh) performs a live JWKS
	// fetch per URL. Kept distinct from lastForceRefresh so the first
	// signature failure after an in-place rotation still fetches once
	// (R109) while repeated failures don't amplify up upstream load (R140).
	lastSignatureRefresh map[string]time.Time

	// lastUngatedPickup bounds the R124 immediate refresh (see
	// GetPublicKey): when the gated forceJWKSRefresh serves a cached set
	// within the cooldown, GetPublicKey does one ungated live fetch to
	// pick up an in-place-rotated key. Without a bound that ungated fetch
	// would run on EVERY absent-kid request within the window (re-sliding
	// lastForceRefresh) and defeat R54's anti-amplification cooldown —
	// N bogus-kid requests → N upstream JWKS fetch calls (R130).
	lastUngatedPickup map[string]time.Time
}

// jwksFetch represents an in-flight JWKS fetch. Done is closed when the fetch
// completes; jwks and err carry the result (one of them is set, never both).
type jwksFetch struct {
	done chan struct{}
	jwks *JWKSet
	err  error
}

// JWKCacheInterface defines the contract for JWK caching implementations.
type JWKCacheInterface interface {
	GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error)
	GetPublicKey(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error)
	getPublicKeyFresh(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error)
	Cleanup()
	Close()
}

// NewJWKCache creates a new JWK cache using the global cache manager
func NewJWKCache() *JWKCache {
	manager := GetUniversalCacheManager(nil)
	return &JWKCache{
		cache:                manager.GetJWKCache(),
		lastForceRefresh:     make(map[string]time.Time),
		lastSignatureRefresh: make(map[string]time.Time),
	}
}

// GetJWKS retrieves JWKS from cache or fetches from the remote URL if not cached.
//
// The entry is stored locally only via SetLocal/GetLocal. Going through a
// distributed backend defeats the cache: JSON round-tripping turns *JWKSet
// into map[string]interface{}, the type assertion below fails, and every
// request refetches from the upstream. JWK rotation is rare and a per-replica
// HTTP fetch on cold cache is cheap, so cross-replica coherence buys nothing.
func (c *JWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	// Fast path: cache hit.
	if cachedValue, found := c.cache.GetLocal(jwksURL); found {
		if jwks, ok := cachedValue.(*JWKSet); ok {
			return jwks, nil
		}
	}

	// Singleflight: dedupe concurrent fetches per URL key. The first arrival
	// performs the HTTP fetch; any later arrival for the same URL waits on
	// its done channel and shares the result. No global lock is held during
	// the fetch.
	candidate := &jwksFetch{done: make(chan struct{})}
	if existing, loaded := c.inflightFetches.LoadOrStore(jwksURL, candidate); loaded {
		f, _ := existing.(*jwksFetch)
		select {
		case <-f.done:
			return f.jwks, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// We're the leader. Make absolutely sure the result fields and the
	// in-flight map entry are cleaned up before any waiter unblocks.
	defer func() {
		c.inflightFetches.Delete(jwksURL)
		close(candidate.done)
	}()

	// Re-check the cache in case a concurrent fetch completed between our
	// initial miss and our LoadOrStore win.
	if cachedValue, found := c.cache.GetLocal(jwksURL); found {
		if jwks, ok := cachedValue.(*JWKSet); ok {
			candidate.jwks = jwks
			return jwks, nil
		}
	}

	jwks, err := fetchJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		candidate.err = err
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		candidate.err = fmt.Errorf("JWKS response contains no keys")
		return nil, candidate.err
	}

	// Cache for 1 hour.
	_ = c.cache.SetLocal(jwksURL, jwks, 1*time.Hour) // Safe to ignore: cache failures are non-critical

	candidate.jwks = jwks
	return jwks, nil
}

// jwksForceRefreshCooldown bounds how often GetPublicKey forces a live JWKS
// fetch when the requested kid is missing from the cached derived keyset.
// Rotation is picked up on the first new-kid request; the cooldown
// prevents an attacker presenting many bogus kids from amplifying a flood of
// requests into a flood of upstream JWKS fetches.
const jwksForceRefreshCooldown = 30 * time.Second

// forceJWKSRefresh performs a live singleflighted JWKS fetch, bypassing the
// fast-path cache, so an IdP key rotation is picked up promptly. It is
// bounded by jwksForceRefreshCooldown per URL: within the window it falls
// back to the (freshly refetched) cached set rather than fetching again.
// On success the result is written to the raw cache so subsequent fast-path
// GetJWKS calls and other replicas-benefits see the rotated keys.
// The boolean reports whether a live fetch was performed (true) or the
// cached set was served (false).
// doLiveRefresh performs a singleflighted live JWKS fetch (no cooldown
// gate) and updates the raw + parsed caches on success, recording the force
// cooldown so the normal forced path shares this fetch. On error the raw
// cache is left untouched. Used by forceJWKSRefresh (after its cooldown
// gate) and by refresh-on-signature-failure.
func (c *JWKCache) doLiveRefresh(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	// Singleflight a live fetch (no fast-path cache read).
	candidate := &jwksFetch{done: make(chan struct{})}
	if existing, loaded := c.inflightFetches.LoadOrStore(jwksURL, candidate); loaded {
		f, _ := existing.(*jwksFetch)
		select {
		case <-f.done:
			return f.jwks, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer func() {
		c.inflightFetches.Delete(jwksURL)
		close(candidate.done)
	}()

	jwks, err := fetchJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		candidate.err = err
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		candidate.err = fmt.Errorf("JWKS response contains no keys")
		return nil, candidate.err
	}
	_ = c.cache.SetLocal(jwksURL, jwks, 1*time.Hour) // Safe to ignore: cache failures are non-critical
	// Record the cooldown only AFTER a successful fetch. Recording it
	// first meant a transient failure (5xx / network blip) consumed the
	// whole cooldown window, so new-kid requests were served the stale
	// cached keyset (missing the new kid) as 401 with no upstream retry
	// for up to jwksForceRefreshCooldown (R100).
	c.forceMu.Lock()
	if c.lastForceRefresh == nil {
		c.lastForceRefresh = make(map[string]time.Time)
	}
	c.lastForceRefresh[jwksURL] = time.Now()
	c.forceMu.Unlock()
	candidate.jwks = jwks
	return jwks, nil
}

func (c *JWKCache) forceJWKSRefresh(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, bool, error) {
	c.forceMu.Lock()
	if c.lastForceRefresh == nil {
		c.lastForceRefresh = make(map[string]time.Time)
	}
	last := c.lastForceRefresh[jwksURL]
	now := time.Now()
	if now.Sub(last) < jwksForceRefreshCooldown {
		c.forceMu.Unlock()
		jwks, err := c.GetJWKS(ctx, jwksURL, httpClient)
		return jwks, false, err // served cached set, not a live fetch
	}
	c.forceMu.Unlock()

	jwks, err := c.doLiveRefresh(ctx, jwksURL, httpClient)
	return jwks, true, err // performed a live fetch
}

// GetPublicKey returns the parsed public key for a given kid, fetching and
// caching the JWKS plus its derived parsedJWKS on miss. The parsed entry is
// stored alongside the raw JWKSet under a sibling cache key with the same
// 1-hour TTL, so both invalidate together when the upstream JWKS rotates.
//
// parsedJWKS is stored locally only (SetLocal/GetLocal). Its values are
// crypto.PublicKey interfaces wrapping *rsa.PublicKey/*ecdsa.PublicKey,
// which contain *big.Int that marshals to a hundreds-digit JSON number.
// On a distributed backend round-trip, json.Unmarshal into interface{} would
// try to fit that into float64 and fail with UnmarshalTypeError. Under yaegi
// the unexported parsedJWKS.keys field is exposed via an X-prefixed name on
// Marshal, leaking the modulus into the cached payload (issue #134).
//
// If the requested kid is not in the cached derived keyset, GetJWKS would
// still hand back the stale (within-TTL) cached JWKS, so a post-rotation
// token with a NEW kid would fail "no matching public key" for up to the
// 1-hour TTL. Instead, on a kid miss we force a bounded live refresh so
// rotation is picked up on the first new-kid request.
func (c *JWKCache) GetPublicKey(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error) {
	parsedKey := jwksURL + parsedKeysSuffix
	if v, found := c.cache.GetLocal(parsedKey); found {
		if pj, ok := v.(*parsedJWKS); ok {
			if k, ok := pj.keys[kid]; ok {
				return k, nil
			}
		}
	}

	jwks, fresh, err := c.forceJWKSRefresh(ctx, jwksURL, httpClient)
	if err != nil {
		return nil, err
	}

	pj := buildParsedJWKS(jwks)
	_ = c.cache.SetLocal(parsedKey, pj, 1*time.Hour) // Safe to ignore: cache failures are non-critical

	if k, ok := pj.keys[kid]; ok {
		return k, nil
	}
	// If the gated refresh served a CACHED set (within the cooldown
	// window), a provider that lagged behind its own rotation at the
	// last live fetch would leave us serving a kid-lacking set as 401
	// for up to the whole window. Do one ungated live refresh to pick
	// up the now-rotated key on this request (R124). When the gated
	// refresh JUST performed a live fetch and the kid is still missing,
	// another immediate fetch is redundant — the kid truly is absent
	// (e.g. an attacker's bogus kid).
	if !fresh {
		// Bound the immediate pick-up to once per cooldown window (in
		// addition to the gated live refresh) so repeated absent-kid
		// requests can't each trigger an upstream JWKS fetch, defeating
		// R54's anti-amplification cooldown.
		c.forceMu.Lock()
		if c.lastUngatedPickup == nil {
			c.lastUngatedPickup = make(map[string]time.Time)
		}
		if prev, had := c.lastUngatedPickup[jwksURL]; had && time.Since(prev) < jwksForceRefreshCooldown {
			c.forceMu.Unlock()
			return nil, fmt.Errorf("no matching public key found for kid: %s", kid)
		}
		c.lastUngatedPickup[jwksURL] = time.Now()
		c.forceMu.Unlock()
		return c.getPublicKeyFresh(ctx, jwksURL, kid, httpClient)
	}
	return nil, fmt.Errorf("no matching public key found for kid: %s", kid)
}

// getPublicKeyFresh returns the parsed public key for kid from an
// unconditional live JWKS fetch (no fast-path cache read, no cooldown
// gate), updating both caches. Used when signature verification just
// failed against a cached key: in-place key rotation that reuses the same
// kid (or a stale cached keyset) otherwise yields 401s until the 1h cache
// TTL expires, because GetPublicKey's fast path serves the cached key.
func (c *JWKCache) getPublicKeyFresh(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error) {
	// Bound signature-failure refreshes with their own per-URL cooldown,
	// distinct from lastForceRefresh (which the normal key-lookup path
	// already consumes). The FIRST signature failure after an in-place key
	// rotation still fetches once so the new key is picked up immediately
	// (R109); subsequent signature failures within the window are served
	// from the cached keyset instead of firing one upstream fetch per
	// request — which an attacker holding a valid kid alongside a bogus
	// signature could otherwise use to amplify load on the IdP's JWKS
	// endpoint (R140).
	c.forceMu.Lock()
	withinCooldown := c.lastSignatureRefresh != nil &&
		time.Since(c.lastSignatureRefresh[jwksURL]) < jwksForceRefreshCooldown
	c.forceMu.Unlock()

	if withinCooldown {
		// Serve the cached keyset; do not fetch upstream again.
		if cached, found := c.cache.GetLocal(jwksURL); found {
			if jwks, ok := cached.(*JWKSet); ok {
				if k, ok := buildParsedJWKS(jwks).keys[kid]; ok {
					return k, nil
				}
			}
		}
		return nil, fmt.Errorf("no matching public key found for kid after forced refresh: %s", kid)
	}

	jwks, err := c.doLiveRefresh(ctx, jwksURL, httpClient)
	if err != nil {
		return nil, err
	}
	c.forceMu.Lock()
	if c.lastSignatureRefresh == nil {
		c.lastSignatureRefresh = make(map[string]time.Time)
	}
	c.lastSignatureRefresh[jwksURL] = time.Now()
	c.forceMu.Unlock()
	pj := buildParsedJWKS(jwks)
	parsedKey := jwksURL + parsedKeysSuffix
	_ = c.cache.SetLocal(parsedKey, pj, 1*time.Hour) // Safe to ignore: cache failures are non-critical
	if k, ok := pj.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no matching public key found for kid after forced refresh: %s", kid)
}

// buildParsedJWKS pre-parses every JWK in the set into the matching
// crypto.PublicKey, indexed by kid. Errors on individual keys are skipped so
// a single bad key does not block the rest of the keyset.
func buildParsedJWKS(jwks *JWKSet) *parsedJWKS {
	out := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for i := range jwks.Keys {
		k := &jwks.Keys[i]
		if k.Kid == "" {
			continue
		}
		// Skip keys that are not intended for signature verification.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if len(k.KeyOps) > 0 {
			hasVerify := false
			for _, op := range k.KeyOps {
				if op == "verify" {
					hasVerify = true
					break
				}
			}
			if !hasVerify {
				continue
			}
		}
		var pub crypto.PublicKey
		var err error
		switch k.Kty {
		case "RSA":
			pub, err = k.ToRSAPublicKey()
		case "EC":
			pub, err = k.ToECDSAPublicKey()
		default:
			continue
		}
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	return &parsedJWKS{keys: out}
}

// Cleanup is a no-op as cleanup is handled by UniversalCache
func (c *JWKCache) Cleanup() {
	// Handled internally by UniversalCache
}

// Close is a no-op as the cache is managed globally
func (c *JWKCache) Close() {
	// Managed by global cache manager
}

// fetchJWKS fetches JWKS from a remote URL
func fetchJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating JWKS request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // Safe to ignore: closing body on defer

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024)) // Safe to ignore: reading error body for diagnostics
		return nil, fmt.Errorf("JWKS fetch failed with status %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("error reading JWKS response: %w", err)
	}
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("JWKS response exceeds 1 MiB limit")
	}

	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("error parsing JWKS: %w", err)
	}

	return &jwks, nil
}

// ToRSAPublicKey converts a JWK to an RSA public key.
// Returns an error if the JWK is not an RSA key or if the key data is invalid.
func (jwk *JWK) ToRSAPublicKey() (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("not an RSA key")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("error decoding modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("error decoding exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	if len(eBytes) <= 8 {
		// Pad to 8 bytes for uint64
		paddedE := make([]byte, 8)
		copy(paddedE[8-len(eBytes):], eBytes)
		eUint64 := binary.BigEndian.Uint64(paddedE)
		// RSA exponents are typically small (65537 is common), so overflow is not a concern
		// #nosec G115 -- RSA public exponents are small values that fit in int
		e = int(eUint64)
	} else {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// ToECDSAPublicKey converts a JWK to an ECDSA public key.
// Returns an error if the JWK is not an EC key or if the key data is invalid.
func (jwk *JWK) ToECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("not an EC key")
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("error decoding X coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("error decoding Y coordinate: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// GetKey finds a key by its ID (kid) in the JWKSet.
// Returns nil if no key with the given ID is found.
func (jwks *JWKSet) GetKey(kid string) *JWK {
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid {
			return &jwks.Keys[i]
		}
	}
	return nil
}

// jwkToPEM converts a JWK to PEM format for signature verification
func jwkToPEM(jwk *JWK) ([]byte, error) {
	var publicKey interface{}
	var err error

	switch jwk.Kty {
	case "RSA":
		publicKey, err = jwk.ToRSAPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to convert RSA JWK: %w", err)
		}
	case "EC":
		publicKey, err = jwk.ToECDSAPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to convert EC JWK: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	// Marshal the public key to DER format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}
