package traefikoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWK represents a JSON Web Key used for verifying
// JWT signatures. Supports both RSA and ECDSA key types.
type JWK struct {
	// Kty specifies the key type ("RSA" or "EC")
	Kty string `json:"kty"`
	// Kid is the unique identifier for this key
	Kid string `json:"kid"`
	// Use indicates the intended use of the key ("sig" for signature)
	Use string `json:"use"`
	// N is the RSA public key modulus (base64url-encoded)
	N string `json:"n"`
	// E is the RSA public key exponent (base64url-encoded)
	E string `json:"e"`
	// Alg specifies the algorithm intended for use with this key
	Alg string `json:"alg"`
	// Crv specifies the elliptic curve for EC keys (P-256, P-384, P-521)
	Crv string `json:"crv"`
	// X is the x coordinate for EC public keys (base64url-encoded)
	X string `json:"x"`
	// Y is the y coordinate for EC public keys (base64url-encoded)
	Y string `json:"y"`
}

// JWKSet represents a collection of JSON Web Keys from a JWKS endpoint.
// OIDC providers publish multiple keys in a set to support key rotation.
type JWKSet struct {
	// Keys contains the array of JWK objects
	Keys []JWK `json:"keys"`
}

// JWKCache provides thread-safe caching of JWKS (JSON Web Key Sets)
// with automatic expiration and the ability to fetch new keys and
// refresh when keys expire.
type JWKCache struct {
	// internalCache stores the cached JWKS data
	internalCache *Cache
	// CacheLifetime defines how long keys are cached before refresh
	CacheLifetime time.Duration
	// maxSize limits the number of cached JWKS entries
	maxSize int
	// mutex protects concurrent access to the cache
	mutex sync.RWMutex
}

// JWKCacheInterface defines the contract for JWK caching implementations.
// It provides methods for fetching JWKS, cache maintenance, and graceful shutdown.
type JWKCacheInterface interface {
	// GetJWKS fetches or retrieves cached JWKS from the given URL
	GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error)
	// Cleanup performs cache maintenance (removing expired entries)
	Cleanup()
	// Close shuts down the cache and releases resources
	Close()
}

// NewJWKCache creates a new JWK cache with default configuration.
// It initializes a cache with a 1-hour lifetime and maximum size of 100 entries.
func NewJWKCache() *JWKCache {
	cache := &JWKCache{
		CacheLifetime: 1 * time.Hour,
		maxSize:       100,
		internalCache: NewCache(),
	}
	return cache
}

// GetJWKS retrieves JWKS from cache or fetches from the remote URL if not cached.
// It uses double-checked locking to prevent concurrent fetches of the same JWKS.
// Parameters:
//   - ctx: Context for request cancellation and deadlines
//   - jwksURL: The JWKS endpoint URL to fetch from
//   - httpClient: HTTP client to use for the request
//
// Returns:
//   - *JWKSet: The retrieved or cached JWKS
//   - error: Any error encountered during fetch or cache operations
func (c *JWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	if c.internalCache != nil {
		if cachedJwks, found := c.internalCache.Get(jwksURL); found {
			return cachedJwks.(*JWKSet), nil
		}
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.internalCache != nil {
		if cachedJwks, found := c.internalCache.Get(jwksURL); found {
			return cachedJwks.(*JWKSet), nil
		}
	}

	jwks, err := fetchJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		return nil, err
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("JWKS response contains no keys")
	}

	lifetime := c.CacheLifetime
	if lifetime == 0 {
		lifetime = 1 * time.Hour
	}

	if c.internalCache != nil {
		c.internalCache.Set(jwksURL, jwks, lifetime)
	}

	return jwks, nil
}

// Cleanup removes expired entries from the JWK cache to free memory.
// It delegates to the internal cache's cleanup method.
func (c *JWKCache) Cleanup() {
	if c != nil && c.internalCache != nil {
		c.internalCache.Cleanup()
	}
}

// Close shuts down the JWK cache and releases all resources.
// It stops auto-cleanup routines and closes the internal cache.
func (c *JWKCache) Close() {
	if c.internalCache != nil {
		c.internalCache.Close()
	}
}

// SetMaxSize configures the maximum number of JWKS entries to cache.
// This helps prevent unbounded memory growth in long-running applications.
func (c *JWKCache) SetMaxSize(size int) {
	c.maxSize = size
	if c.internalCache != nil {
		c.internalCache.maxSize = size
	}
}

// fetchJWKS retrieves JWKS from a remote URL using the provided HTTP client.
// It handles request creation, response validation, and JSON decoding.
// Parameters:
//   - ctx: Context for request cancellation and timeouts
//   - jwksURL: The JWKS endpoint URL to fetch from
//   - httpClient: HTTP client configured with appropriate timeouts
//
// Returns:
//   - *JWKSet: The decoded JWKS response
//   - An error if the request fails, the status code is not OK, or the response body cannot be decoded
func fetchJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: unexpected status code %d", resp.StatusCode)
	}

	var jwks JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	return &jwks, nil
}

// jwkToPEM converts a JSON Web Key to PEM-encoded public key format.
// Supports RSA and ECDSA key types for JWT signature verification.
// Parameters:
//   - jwk: The JWK to convert
//
// Returns:
//   - []byte: PEM-encoded public key
//   - An error if the key type is unsupported or conversion fails
func jwkToPEM(jwk *JWK) ([]byte, error) {
	converter, ok := jwkConverters[jwk.Kty]
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	return converter(jwk)
}

// jwkToPEMConverter defines the function signature for JWK to PEM conversion functions.
type jwkToPEMConverter func(*JWK) ([]byte, error)

// jwkConverters maps JWK key types to their respective PEM conversion functions.
var jwkConverters = map[string]jwkToPEMConverter{
	"RSA": rsaJWKToPEM,
	"EC":  ecJWKToPEM,
}

// rsaJWKToPEM converts an RSA JSON Web Key to PEM format.
// It decodes the base64url-encoded modulus (n) and exponent (e) parameters
// and constructs a standard RSA public key structure.
// Parameters:
//   - jwk: The RSA JWK to convert
//
// Returns:
//   - []byte: PEM-encoded RSA public key
//   - An error if decoding parameters fails or key marshaling fails
func rsaJWKToPEM(jwk *JWK) ([]byte, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'n' parameter: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'e' parameter: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}

// ecJWKToPEM converts an Elliptic Curve JSON Web Key to PEM format.
// It decodes the base64url-encoded x and y coordinates and supports
// standard NIST curves (P-256, P-384, P-521).
// Parameters:
//   - jwk: The EC JWK to convert
//
// Returns:
//   - []byte: PEM-encoded EC public key
//   - An error if decoding parameters fails, the curve is unsupported, or key marshaling fails
func ecJWKToPEM(jwk *JWK) ([]byte, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'x' parameter: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'y' parameter: %w", err)
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
		return nil, fmt.Errorf("unsupported elliptic curve: %s", jwk.Crv)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}
