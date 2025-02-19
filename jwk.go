package traefikoidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// JWK represents a JSON Web Key as defined in RFC 7517.
// It contains the cryptographic key information used for token verification.
type JWK struct {
	// Kty is the key type (e.g., "RSA", "EC")
	Kty string `json:"kty"`

	// Kid is the unique key identifier
	Kid string `json:"kid"`

	// Use specifies the intended use of the key (e.g., "sig" for signature)
	Use string `json:"use"`

	// N is the modulus for RSA keys
	N string `json:"n"`

	// E is the exponent for RSA keys
	E string `json:"e"`

	// Alg is the algorithm intended for use with the key
	Alg string `json:"alg"`

	// Crv is the curve for EC keys (e.g., "P-256", "P-384", "P-521")
	Crv string `json:"crv"`

	// X is the x-coordinate for EC keys
	X string `json:"x"`

	// Y is the y-coordinate for EC keys
	Y string `json:"y"`
}

// JWKSet represents a set of JSON Web Keys as returned by the JWKS endpoint.
// OIDC providers typically expose multiple keys to support key rotation.
type JWKSet struct {
	// Keys is the array of JSON Web Keys
	Keys []JWK `json:"keys"`
}

// JWKCache provides a thread-safe caching mechanism for JWK sets.
// It caches the keys for a configurable duration to reduce load on the OIDC provider
// while ensuring keys are refreshed periodically to handle key rotation.
type JWKCache struct {
	// jwks holds the cached set of JSON Web Keys
	jwks *JWKSet

	// expiresAt is the timestamp when the cached keys should be refreshed
	expiresAt time.Time

	// mutex protects concurrent access to the cache
	mutex sync.RWMutex
}

// JWKCacheInterface defines the interface for JWK caching operations.
// This interface allows for different caching implementations while
// maintaining consistent behavior in the token verification process.
type JWKCacheInterface interface {
	GetJWKS(jwksURL string, httpClient *http.Client) (*JWKSet, error)
	Cleanup() // Add Cleanup method to the interface
}

// GetJWKS retrieves the JSON Web Key Set, either from cache or by fetching it
// from the OIDC provider. It implements a thread-safe double-checked locking
// pattern to prevent multiple simultaneous fetches of the same keys.
// Parameters:
//   - jwksURL: The URL of the JWKS endpoint
//   - httpClient: The HTTP client to use for fetching keys
//
// Returns:
//   - The JSON Web Key Set
//   - An error if the keys cannot be retrieved or parsed
func (c *JWKCache) GetJWKS(jwksURL string, httpClient *http.Client) (*JWKSet, error) {
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

	jwks, err := fetchJWKS(jwksURL, httpClient)
	if err != nil {
		return nil, err
	}

	c.jwks = jwks
	c.expiresAt = time.Now().Add(1 * time.Hour)

	return jwks, nil
}

// Cleanup removes expired JWKs from the cache.
func (c *JWKCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	if c.jwks != nil && now.After(c.expiresAt) {
		c.jwks = nil
	}
}

// fetchJWKS retrieves the JSON Web Key Set from the OIDC provider's JWKS endpoint.
// It handles HTTP communication and JSON parsing of the response.
// Parameters:
//   - jwksURL: The URL of the JWKS endpoint
//   - httpClient: The HTTP client to use for the request
//
// Returns:
//   - The parsed JSON Web Key Set
//   - An error if the request fails or the response is invalid
func fetchJWKS(jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	resp, err := httpClient.Get(jwksURL)
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

// jwkToPEM converts a JSON Web Key to PEM format for use with standard
// cryptographic functions. It supports both RSA and EC keys, delegating
// to the appropriate converter based on the key type.
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

// rsaJWKToPEM converts an RSA JSON Web Key to PEM format.
// It handles base64url decoding of the modulus and exponent,
// constructs an RSA public key, and encodes it in PEM format.
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

// ecJWKToPEM converts an EC (Elliptic Curve) JSON Web Key to PEM format.
// It supports the P-256, P-384, and P-521 curves as defined in the
// OIDC specification, decoding the x and y coordinates and encoding
// the resulting public key in PEM format.
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
