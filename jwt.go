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

	var hash crypto.Hash
	var verifyFunc func(publicKey interface{}, hashed []byte, signature []byte, hash crypto.Hash) error

	switch alg {
	case "RS256", "RS384", "RS512":
		hash = crypto.SHA256 // SHA384 and SHA512 are used for RS384 and RS512 respectively.
		verifyFunc = rsaVerifyPKCS1v15
	case "PS256", "PS384", "PS512":
		hash = crypto.SHA256 // SHA384 and SHA512 are used for PS384 and PS512 respectively.
		verifyFunc = rsaVerifyPSS
	case "ES256", "ES384", "ES512":
		hash = crypto.SHA256 // SHA384 and SHA512 are used for ES384 and ES512 respectively.
		verifyFunc = ecdsaVerify
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hash.New()
	h.Write([]byte(signedContent))
	hashed := h.Sum(nil)

	return verifyFunc(pubKey, hashed, signature, hash)
}

func rsaVerifyPKCS1v15(publicKey interface{}, hashed []byte, signature []byte, hash crypto.Hash) error {
	pubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key type for RSA: %T", publicKey)
	}
	return rsa.VerifyPKCS1v15(pubKey, hash, hashed, signature)
}

func rsaVerifyPSS(publicKey interface{}, hashed []byte, signature []byte, hash crypto.Hash) error {
	pubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key type for RSA: %T", publicKey)
	}
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(pubKey, crypto.SHA256, hashed, signature, opts)
}

func ecdsaVerify(publicKey interface{}, hashed []byte, signature []byte, hash crypto.Hash) error {
	pubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key type for ECDSA: %T", publicKey)
	}
	keyBytes := (pubKey.Params().BitSize + 7) / 8
	if len(signature) != 2*keyBytes {
		return fmt.Errorf("invalid signature length for ECDSA: expected %d bytes, got %d bytes", 2*keyBytes, len(signature))
	}
	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])

	if ecdsa.Verify(pubKey, hashed, r, s) {
		return nil
	}
	return fmt.Errorf("invalid ECDSA signature")
}

func verifyIssuedAt(issuedAt float64) error {
	issuedAtTime := time.Unix(int64(issuedAt), 0)
	if time.Now().Before(issuedAtTime) {
		return fmt.Errorf("token used before issued")
	}
	return nil
}
