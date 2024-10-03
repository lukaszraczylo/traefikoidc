package traefikoidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type JWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature string
}

func parseJWT(tokenString string) (*JWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	jwt := &JWT{}

	// Decode and unmarshal the header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode header: %v", err)
	}
	if err := json.Unmarshal(headerBytes, &jwt.Header); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal header: %v", err)
	}

	// Decode and unmarshal the claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode claims: %v", err)
	}
	if err := json.Unmarshal(claimsBytes, &jwt.Claims); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal claims: %v", err)
	}

	// Set the signature
	jwt.Signature = parts[2]

	return jwt, nil
}

func (j *JWT) Verify(issuerURL, clientID string) error {
	claims := j.Claims

	iss, ok := claims["iss"].(string)
	if !ok {
		return fmt.Errorf("missing 'iss' claim")
	}
	if err := verifyIssuer(iss, issuerURL); err != nil {
		return err
	}

	aud, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("missing 'aud' claim")
	}
	if err := verifyAudience(aud, clientID); err != nil {
		return err
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing or invalid 'exp' claim")
	}
	if err := verifyExpiration(exp); err != nil {
		return err
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("missing or invalid 'iat' claim")
	}
	if err := verifyIssuedAt(iat); err != nil {
		return err
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return fmt.Errorf("missing or empty 'sub' claim")
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

func verifySignature(signedContent string, signature []byte, publicKeyPEM []byte, alg string) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	var hashFunc crypto.Hash

	switch alg {
	case "RS256", "PS256", "ES256":
		hashFunc = crypto.SHA256
	case "RS384", "PS384", "ES384":
		hashFunc = crypto.SHA384
	case "RS512", "PS512", "ES512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write([]byte(signedContent))
	hashed := h.Sum(nil)

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		if strings.HasPrefix(alg, "ES") {
			// ECDSA signature handling
			keyBytes := (pub.Params().BitSize + 7) / 8
			if len(signature) != 2*keyBytes {
				return fmt.Errorf("invalid signature length: expected %d bytes, got %d bytes", 2*keyBytes, len(signature))
			}
			r := new(big.Int).SetBytes(signature[:keyBytes])
			s := new(big.Int).SetBytes(signature[keyBytes:])

			if ecdsa.Verify(pub, hashed, r, s) {
				return nil
			}
			return fmt.Errorf("invalid ECDSA signature")
		}
		return fmt.Errorf("algorithm %s is not compatible with ECDSA public key", alg)
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "RS") {
			err := rsa.VerifyPKCS1v15(pub, hashFunc, hashed, signature)
			if err != nil {
				return fmt.Errorf("RSA signature verification failed: %w", err)
			}
			return nil
		}
		return fmt.Errorf("algorithm %s is not compatible with RSA public key", alg)
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func verifyIssuedAt(issuedAt float64) error {
	issuedAtTime := time.Unix(int64(issuedAt), 0)
	if time.Now().Before(issuedAtTime) {
		return fmt.Errorf("token used before issued")
	}
	return nil
}
