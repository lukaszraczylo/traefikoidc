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
	"math/big"
	"net/http"
	"sync"
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWKCache struct {
	jwks      *JWKSet
	expiresAt time.Time
	mutex     sync.RWMutex
	// CacheLifetime is configurable to determine how long the JWKS is cached.
	CacheLifetime time.Duration
}

type JWKCacheInterface interface {
	GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error)
	Cleanup()
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) from the cache or fetches it from the provider.
// It first checks if a valid, non-expired JWKS is present in the cache. If so, it returns the cached version.
// Otherwise, it attempts to fetch the JWKS from the specified jwksURL using the provided httpClient.
// If the fetch is successful, the JWKS is stored in the cache with an expiration time based on CacheLifetime
// (defaulting to 1 hour if not set) and returned.
// This method uses double-checked locking to minimize contention when the cache needs refreshing.
//
// Parameters:
//   - ctx: Context for the HTTP request if fetching is required.
//   - jwksURL: The URL of the OIDC provider's JWKS endpoint.
//   - httpClient: The HTTP client to use for fetching the JWKS.
//
// Returns:
//   - A pointer to the JWKSet containing the keys.
//   - An error if fetching fails or the response cannot be decoded.
func (c *JWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	c.mutex.RLock()
	if c.jwks != nil && time.Now().Before(c.expiresAt) {
		defer c.mutex.RUnlock()
		return c.jwks, nil
	}
	c.mutex.RUnlock()

	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.jwks != nil && time.Now().Before(c.expiresAt) {
		return c.jwks, nil
	}

	jwks, err := fetchJWKS(ctx, jwksURL, httpClient)
	if err != nil {
		return nil, err
	}

	c.jwks = jwks
	lifetime := c.CacheLifetime
	if lifetime == 0 {
		lifetime = 1 * time.Hour
	}
	c.expiresAt = time.Now().Add(lifetime)

	return jwks, nil
}

// Cleanup removes the cached JWKS if it has expired.
// This is intended to be called periodically to ensure stale JWKS data is cleared.
func (c *JWKCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	if c.jwks != nil && now.After(c.expiresAt) {
		c.jwks = nil
	}
}

// fetchJWKS retrieves the JSON Web Key Set (JWKS) from the specified URL.
// It uses the provided context and HTTP client to make the request.
//
// Parameters:
//   - ctx: Context for the HTTP request.
//   - jwksURL: The URL of the OIDC provider's JWKS endpoint.
//   - httpClient: The HTTP client to use for the request.
//
// Returns:
//   - A pointer to the fetched JWKSet.
//   - An error if the request fails, the status code is not OK, or the response body cannot be decoded.
func fetchJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	// Create a request with context to enforce timeout
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: unexpected status code %d", resp.StatusCode)
	}

	var jwks JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	return &jwks, nil
}

// jwkToPEM converts a JWK (JSON Web Key) object into PEM (Privacy-Enhanced Mail) format.
// It selects the appropriate conversion function based on the JWK's key type ("kty").
// Currently supports "RSA" and "EC" key types.
//
// Parameters:
//   - jwk: A pointer to the JWK object to convert.
//
// Returns:
//   - A byte slice containing the public key in PEM format.
//   - An error if the key type is unsupported or conversion fails.
func jwkToPEM(jwk *JWK) ([]byte, error) {
	converter, ok := jwkConverters[jwk.Kty]
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
	return converter(jwk)
}

type jwkToPEMConverter func(*JWK) ([]byte, error)

var jwkConverters = map[string]jwkToPEMConverter{
	"RSA": rsaJWKToPEM,
	"EC":  ecJWKToPEM,
}

// rsaJWKToPEM converts an RSA JWK into PEM format.
// It decodes the modulus (n) and exponent (e) from base64 URL encoding,
// constructs an rsa.PublicKey, marshals it into PKIX format, and then
// encodes it as a PEM block.
//
// Parameters:
//   - jwk: A pointer to the RSA JWK object (must have "kty": "RSA").
//
// Returns:
//   - A byte slice containing the RSA public key in PEM format.
//   - An error if decoding parameters fails or key marshaling fails.
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

// ecJWKToPEM converts an EC (Elliptic Curve) JWK into PEM format.
// It decodes the X and Y coordinates from base64 URL encoding, determines the
// elliptic curve based on the "crv" parameter (P-256, P-384, P-521),
// constructs an ecdsa.PublicKey, marshals it into PKIX format, and then
// encodes it as a PEM block.
//
// Parameters:
//   - jwk: A pointer to the EC JWK object (must have "kty": "EC").
//
// Returns:
//   - A byte slice containing the EC public key in PEM format.
//   - An error if decoding parameters fails, the curve is unsupported, or key marshaling fails.
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
