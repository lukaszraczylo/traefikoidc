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

// JWK represents a JSON Web Key
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

// JWKSet represents a set of JWKs
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKCache caches the JWKs
type JWKCache struct {
	jwks      *JWKSet
	expiresAt time.Time
	mutex     sync.RWMutex
}

// JWKCacheInterface defines the interface for the JWK cache
type JWKCacheInterface interface {
	GetJWKS(jwksURL string, httpClient *http.Client) (*JWKSet, error)
}

// GetJWKS gets the JWKS, either from cache or by fetching it
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

// fetchJWKS fetches the JWKS from the provider
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

// jwkToPEM converts a JWK to PEM format
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

// rsaJWKToPEM converts an RSA JWK to PEM
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

// ecJWKToPEM converts an EC JWK to PEM
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
