package traefikoidc

import (
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
}

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

func verifyAudience(tokenAudience interface{}, expectedAudience string) error {
	switch aud := tokenAudience.(type) {
	case string:
		if aud != expectedAudience {
			return fmt.Errorf("invalid audience")
		}
	case []interface{}:
		found := false
		for _, v := range aud {
			if str, ok := v.(string); ok && str == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid audience")
		}
	default:
		return fmt.Errorf("invalid 'aud' claim type")
	}
	return nil
}

func verifyIssuer(tokenIssuer, expectedIssuer string) error {
	if tokenIssuer != expectedIssuer {
		return fmt.Errorf("invalid issuer")
	}
	return nil
}

func jwkToPEM(jwk *JWK) ([]byte, error) {
	switch jwk.Kty {
	case "RSA":
		return rsaJWKToPEM(jwk)
	case "EC":
		return ecJWKToPEM(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func rsaJWKToPEM(jwk *JWK) ([]byte, error) {
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'n' parameter: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'e' parameter: %w", err)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

func ecJWKToPEM(jwk *JWK) ([]byte, error) {
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'x' parameter: %w", err)
	}

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
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

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}
