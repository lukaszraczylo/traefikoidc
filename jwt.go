package traefikoidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	ErrInvalidJWTFormat      = errors.New("invalid JWT format")
	ErrInvalidAudience       = errors.New("invalid audience")
	ErrInvalidIssuer         = errors.New("invalid issuer")
	ErrTokenExpired          = errors.New("token has expired")
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")
	ErrMissingClaim          = errors.New("missing claim")
	ErrInvalidClaimType      = errors.New("invalid claim type")
	ErrUnsupportedAlgorithm  = errors.New("unsupported algorithm")
	ErrInvalidSignature      = errors.New("invalid signature")
)

// JWT represents a JSON Web Token
type JWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature []byte
	Token     string
}

// parseJWT parses a JWT token string into a JWT struct
func parseJWT(tokenString string) (*JWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", ErrInvalidJWTFormat, len(parts))
	}

	jwt := &JWT{Token: tokenString}

	if err := decodeJSONPart(parts[0], &jwt.Header); err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	if err := decodeJSONPart(parts[1], &jwt.Claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var err error
	jwt.Signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return jwt, nil
}

func decodeJSONPart(part string, target interface{}) error {
	bytes, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, target)
}

// Verify verifies the standard claims in the JWT
func (j *JWT) Verify(issuerURL, clientID string) error {
	if err := verifyIssuer(j.Claims["iss"], issuerURL); err != nil {
		return err
	}

	if err := verifyAudience(j.Claims["aud"], clientID); err != nil {
		return err
	}

	if err := verifyExpiration(j.Claims["exp"]); err != nil {
		return err
	}

	if err := verifyIssuedAt(j.Claims["iat"]); err != nil {
		return err
	}

	if sub, ok := j.Claims["sub"].(string); !ok || sub == "" {
		return fmt.Errorf("%w: sub", ErrMissingClaim)
	}

	return nil
}

func verifyAudience(tokenAudience interface{}, expectedAudience string) error {
	switch aud := tokenAudience.(type) {
	case string:
		if aud != expectedAudience {
			return ErrInvalidAudience
		}
	case []interface{}:
		for _, v := range aud {
			if str, ok := v.(string); ok && str == expectedAudience {
				return nil
			}
		}
		return ErrInvalidAudience
	default:
		return fmt.Errorf("%w: aud", ErrInvalidClaimType)
	}
	return nil
}

func verifyIssuer(tokenIssuer interface{}, expectedIssuer string) error {
	iss, ok := tokenIssuer.(string)
	if !ok {
		return fmt.Errorf("%w: iss", ErrMissingClaim)
	}
	if iss != expectedIssuer {
		return ErrInvalidIssuer
	}
	return nil
}

func verifyExpiration(expiration interface{}) error {
	exp, ok := expiration.(float64)
	if !ok {
		return fmt.Errorf("%w: exp", ErrInvalidClaimType)
	}
	if time.Now().After(time.Unix(int64(exp), 0)) {
		return ErrTokenExpired
	}
	return nil
}

func verifyIssuedAt(issuedAt interface{}) error {
	iat, ok := issuedAt.(float64)
	if !ok {
		return fmt.Errorf("%w: iat", ErrInvalidClaimType)
	}
	if time.Now().Before(time.Unix(int64(iat), 0)) {
		return ErrTokenUsedBeforeIssued
	}
	return nil
}

func verifySignature(tokenString string, publicKeyPEM []byte, alg string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return ErrInvalidJWTFormat
	}
	signedContent := parts[0] + "." + parts[1]

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}

	hashFunc, err := getHashFunc(alg)
	if err != nil {
		return err
	}

	hashed := hashFunc.New().Sum([]byte(signedContent))

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return verifyRSASignature(pubKey, hashFunc, hashed, signature, alg)
	case *ecdsa.PublicKey:
		return verifyECDSASignature(pubKey, hashed, signature)
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

func parsePublicKey(publicKeyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func getHashFunc(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

func verifyRSASignature(pubKey *rsa.PublicKey, hashFunc crypto.Hash, hashed, signature []byte, alg string) error {
	if strings.HasPrefix(alg, "RS") {
		return rsa.VerifyPKCS1v15(pubKey, hashFunc, hashed, signature)
	} else if strings.HasPrefix(alg, "PS") {
		return rsa.VerifyPSS(pubKey, hashFunc, hashed, signature, nil)
	}
	return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
}

func verifyECDSASignature(pubKey *ecdsa.PublicKey, hashed, signature []byte) error {
	sigLen := len(signature)
	if sigLen%2 != 0 {
		return errors.New("invalid ECDSA signature length")
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:sigLen/2])
	s.SetBytes(signature[sigLen/2:])
	if ecdsa.Verify(pubKey, hashed, r, s) {
		return nil
	}
	return ErrInvalidSignature
}
