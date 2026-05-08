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

// JWKCache provides thread-safe caching of JWKS using UniversalCache
type JWKCache struct {
	cache *UniversalCache
	mutex sync.RWMutex
}

// JWKCacheInterface defines the contract for JWK caching implementations.
type JWKCacheInterface interface {
	GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error)
	GetPublicKey(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error)
	Cleanup()
	Close()
}

// NewJWKCache creates a new JWK cache using the global cache manager
func NewJWKCache() *JWKCache {
	manager := GetUniversalCacheManager(nil)
	return &JWKCache{
		cache: manager.GetJWKCache(),
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
	// Check cache first
	if cachedValue, found := c.cache.GetLocal(jwksURL); found {
		if jwks, ok := cachedValue.(*JWKSet); ok {
			return jwks, nil
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Double-check after acquiring lock
	if cachedValue, found := c.cache.GetLocal(jwksURL); found {
		if jwks, ok := cachedValue.(*JWKSet); ok {
			return jwks, nil
		}
	}

	// Fetch from URL
	jwks, err := fetchJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("JWKS response contains no keys")
	}

	// Cache for 1 hour
	_ = c.cache.SetLocal(jwksURL, jwks, 1*time.Hour) // Safe to ignore: cache failures are non-critical

	return jwks, nil
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
func (c *JWKCache) GetPublicKey(ctx context.Context, jwksURL, kid string, httpClient *http.Client) (crypto.PublicKey, error) {
	parsedKey := jwksURL + parsedKeysSuffix
	if v, found := c.cache.GetLocal(parsedKey); found {
		if pj, ok := v.(*parsedJWKS); ok {
			if k, ok := pj.keys[kid]; ok {
				return k, nil
			}
		}
	}

	jwks, err := c.GetJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		return nil, err
	}

	pj := buildParsedJWKS(jwks)
	_ = c.cache.SetLocal(parsedKey, pj, 1*time.Hour) // Safe to ignore: cache failures are non-critical

	if k, ok := pj.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no matching public key found for kid: %s", kid)
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
		body, _ := io.ReadAll(resp.Body) // Safe to ignore: reading error body for diagnostics
		return nil, fmt.Errorf("JWKS fetch failed with status %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading JWKS response: %w", err)
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
