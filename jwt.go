package traefikoidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type JWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature string
}

func parseJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	return &JWT{
		Header:    header,
		Claims:    claims,
		Signature: parts[2],
	}, nil
}

func (j *JWT) Verify(issuerURL, clientID string) error {
	claims := j.Claims

	if err := verifyIssuer(claims["iss"].(string), issuerURL); err != nil {
		return err
	}

	if err := verifyAudience(claims["aud"].(string), clientID); err != nil {
		return err
	}

	if err := verifyExpiration(claims["exp"].(float64)); err != nil {
		return err
	}

	if err := verifyIssuedAt(claims["iat"].(float64)); err != nil {
		return err
	}

	return nil
}

func verifyExpiration(expiration float64) error {
	expirationTime := time.Unix(int64(expiration), 0)
	if time.Now().After(expirationTime) {
		return fmt.Errorf("token has expired")
	}
	return nil
}

func (t *TraefikOidc) verifySignatureConcurrently(token string, publicKeys map[string][]byte) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	signedContent := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	var eg errgroup.Group
	var mu sync.Mutex
	var verificationSuccess bool

	for _, publicKeyPEM := range publicKeys {
		publicKeyPEM := publicKeyPEM // Create a new variable for the goroutine
		eg.Go(func() error {
			err := verifySignature(signedContent, signature, publicKeyPEM)
			if err == nil {
				mu.Lock()
				verificationSuccess = true
				mu.Unlock()
			}
			return nil // Always return nil to continue checking other keys
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	if !verificationSuccess {
		return fmt.Errorf("signature verification failed for all keys")
	}

	return nil
}

func verifySignature(signedContent string, signature []byte, publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	hash := sha256.Sum256([]byte(signedContent))
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}

	return nil
}

func verifyIssuedAt(issuedAt float64) error {
	issuedAtTime := time.Unix(int64(issuedAt), 0)
	if time.Now().Before(issuedAtTime) {
		return fmt.Errorf("token used before issued")
	}
	return nil
}

func decodeSegment(seg string) (map[string]interface{}, error) {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode segment: %w", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal segment: %w", err)
	}

	return result, nil
}

func (t *TraefikOidc) verifyAndCacheToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

func (t *TraefikOidc) verifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	return t.jwtVerifier.VerifyJWTSignatureAndClaims(jwt, token)
}

func getPublicKeyPEM(jwks *JWKSet, kid string) ([]byte, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return jwkToPEM(&key)
		}
	}
	return nil, fmt.Errorf("unable to find matching public key")
}
