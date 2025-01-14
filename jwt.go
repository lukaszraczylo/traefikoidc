package traefikoidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"
	"strings"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"time"
)

// JWT represents a JSON Web Token as defined in RFC 7519.
// It contains the three parts of a JWT: header, claims (payload),
// and signature, along with the original token string.
type JWT struct {
	// Header contains the token metadata (algorithm, key ID, etc.)
	Header map[string]interface{}

	// Claims contains the token claims (subject, expiration, etc.)
	Claims map[string]interface{}

	// Signature contains the raw signature bytes
	Signature []byte

	// Token is the original JWT string
	Token string
}

// parseJWT parses a JWT token string into a JWT struct.
// It validates the token format and decodes the three parts
// (header, claims, signature) using base64url decoding.
// Parameters:
//   - tokenString: The raw JWT token string
// Returns:
//   - A parsed JWT struct
//   - An error if the token format is invalid or parsing fails
func parseJWT(tokenString string) (*JWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	jwt := &JWT{
		Token: tokenString,
	}

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

	// Decode the signature
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode signature: %v", err)
	}
	jwt.Signature = signatureBytes

	return jwt, nil
}

// Verify validates the standard JWT claims as defined in RFC 7519.
// It checks:
//   - issuer (iss) matches the expected issuer URL
//   - audience (aud) includes the client ID
//   - expiration time (exp) is in the future (with clock skew tolerance)
//   - issued at time (iat) is in the past (with clock skew tolerance)
//   - not before time (nbf) is in the past (with clock skew tolerance)
//   - subject (sub) is present and not empty
//   - algorithm matches expected value to prevent algorithm switching attacks
// Returns an error if any validation fails.
func (j *JWT) Verify(issuerURL, clientID string) error {
	// Validate algorithm to prevent algorithm switching attacks
	alg, ok := j.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing 'alg' header")
	}
	// List of supported algorithms - should match those in verifySignature
	supportedAlgs := map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"PS256": true, "PS384": true, "PS512": true,
		"ES256": true, "ES384": true, "ES512": true,
	}
	if !supportedAlgs[alg] {
		return fmt.Errorf("unsupported algorithm")
	}

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

	// Validate nbf (not before) claim if present
	if nbf, ok := claims["nbf"].(float64); ok {
		if err := verifyNotBefore(nbf); err != nil {
			return err
		}
	}

	// Validate jti (JWT ID) claim if present to prevent replay attacks
	if _, ok := claims["jti"].(string); !ok {
		return fmt.Errorf("missing 'jti' claim")
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return fmt.Errorf("missing or empty 'sub' claim")
	}

	return nil
}

// verifyAudience validates the token's audience claim.
// The audience can be either a single string or an array of strings.
// For array audiences, the expected audience must match any one value.
// Parameters:
//   - tokenAudience: The audience claim from the token
//   - expectedAudience: The expected audience value
// Returns an error if validation fails.
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

// verifyIssuer validates the token's issuer claim.
// The issuer URL must exactly match the expected issuer.
// Parameters:
//   - tokenIssuer: The issuer claim from the token
//   - expectedIssuer: The expected issuer URL
// Returns an error if validation fails.
func verifyIssuer(tokenIssuer, expectedIssuer string) error {
	if tokenIssuer != expectedIssuer {
		return fmt.Errorf("invalid issuer")
	}
	return nil
}

// Clock skew tolerance for time-based validations
const clockSkewTolerance = 2 * time.Minute

// verifyExpiration checks if the token's expiration time has passed.
// The expiration time is compared against the current time with clock skew tolerance.
// Parameters:
//   - expiration: The expiration timestamp from the token
// Returns an error if the token has expired.
func verifyExpiration(expiration float64) error {
	expirationTime := time.Unix(int64(expiration), 0)
	if time.Now().Add(clockSkewTolerance).After(expirationTime) {
		return fmt.Errorf("token has expired")
	}
	return nil
}

// verifyIssuedAt validates the token's issued-at time.
// Ensures the token wasn't issued in the future, accounting for clock skew.
// Parameters:
//   - issuedAt: The issued-at timestamp from the token
// Returns an error if the token was issued in the future.
func verifyIssuedAt(issuedAt float64) error {
	issuedAtTime := time.Unix(int64(issuedAt), 0)
	if time.Now().Add(-clockSkewTolerance).Before(issuedAtTime) {
		return fmt.Errorf("token used before issued")
	}
	return nil
}

// verifyNotBefore validates the token's not-before time if present.
// Ensures the token is not used before its valid time period, accounting for clock skew.
// Parameters:
//   - notBefore: The not-before timestamp from the token
// Returns an error if the token is not yet valid.
func verifyNotBefore(notBefore float64) error {
	notBeforeTime := time.Unix(int64(notBefore), 0)
	if time.Now().Add(-clockSkewTolerance).Before(notBeforeTime) {
		return fmt.Errorf("token not yet valid")
	}
	return nil
}

// verifySignature validates the token's cryptographic signature.
// Supports multiple signature algorithms:
//   - RSA: RS256, RS384, RS512 (PKCS#1 v1.5)
//   - RSA-PSS: PS256, PS384, PS512
//   - ECDSA: ES256, ES384, ES512
// Parameters:
//   - tokenString: The complete JWT token string
//   - publicKeyPEM: The PEM-encoded public key for verification
//   - alg: The signature algorithm identifier
// Returns an error if signature verification fails.
func verifySignature(tokenString string, publicKeyPEM []byte, alg string) error {
	// Split the token into its three parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}
	signedContent := parts[0] + "." + parts[1]

	// Decode the signature from the token
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Decode the PEM-encoded public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Determine the hash function to use based on the algorithm
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

	// Hash the signed content
	h := hashFunc.New()
	h.Write([]byte(signedContent))
	hashed := h.Sum(nil)

	// Verify the signature based on the key type and algorithm
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "RS") {
			// RSA PKCS#1 v1.5 signature
			return rsa.VerifyPKCS1v15(pubKey, hashFunc, hashed, signature)
		} else if strings.HasPrefix(alg, "PS") {
			// RSA PSS signature
			return rsa.VerifyPSS(pubKey, hashFunc, hashed, signature, nil)
		} else {
			return fmt.Errorf("unexpected key type for algorithm %s", alg)
		}
	case *ecdsa.PublicKey:
		if strings.HasPrefix(alg, "ES") {
			// ECDSA signature
			var r, s big.Int
			sigLen := len(signature)
			if sigLen%2 != 0 {
				return fmt.Errorf("invalid ECDSA signature length")
			}
			r.SetBytes(signature[:sigLen/2])
			s.SetBytes(signature[sigLen/2:])
			if ecdsa.Verify(pubKey, hashed, &r, &s) {
				return nil
			} else {
				return fmt.Errorf("invalid ECDSA signature")
			}
		} else {
			return fmt.Errorf("unexpected key type for algorithm %s", alg)
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}
