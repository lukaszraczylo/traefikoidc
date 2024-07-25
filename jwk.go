package traefikoidc

import (
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

func verifyNonce(tokenNonce, expectedNonce string) error {
	if tokenNonce != expectedNonce {
		return fmt.Errorf("invalid nonce")
	}
	return nil
}

func verifyAudience(tokenAudience, expectedAudience string) error {
	if tokenAudience != expectedAudience {
		return fmt.Errorf("invalid audience")
	}
	return nil
}

func verifyTokenTimes(issuedAt, expiration int64, allowedClockSkew time.Duration) error {
	now := time.Now().Unix()
	if now < issuedAt-int64(allowedClockSkew.Seconds()) {
		return fmt.Errorf("token used before issued")
	}
	if now > expiration+int64(allowedClockSkew.Seconds()) {
		return fmt.Errorf("token is expired")
	}
	return nil
}

func verifyIssuer(tokenIssuer, expectedIssuer string) error {
	if tokenIssuer != expectedIssuer {
		return fmt.Errorf("invalid issuer")
	}
	return nil
}

func validateClaims(claims map[string]interface{}) error {
	requiredClaims := []string{"sub", "iss", "aud", "exp", "iat"}
	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}
	return nil
}

func jwkToPEM(jwk *JWK) ([]byte, error) {
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
