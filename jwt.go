package traefikoidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

type JWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature string
}

func parseJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, err
	}

	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
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
		return errors.New("token has expired")
	}
	return nil
}

func verifySignature(token string, publicKeyPEM []byte) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	rsaPublicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("not an RSA public key")
	}

	signedContent := parts[0] + "." + parts[1]
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])

	hash := sha256.Sum256([]byte(signedContent))
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return errors.New("invalid token signature")
	}

	return nil
}

func verifyIssuedAt(issuedAt float64) error {
	issuedAtTime := time.Unix(int64(issuedAt), 0)
	if time.Now().Before(issuedAtTime) {
		return errors.New("token used before issued")
	}
	return nil
}

func decodeSegment(seg string) (map[string]interface{}, error) {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
