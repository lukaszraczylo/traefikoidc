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
	"sync"
	"time"
)

var replayCacheMu sync.Mutex
var replayCache = make(map[string]time.Time)

func cleanupReplayCache() {
	now := time.Now()
	for token, expiry := range replayCache {
		if expiry.Before(now) {
			delete(replayCache, token)
		}
	}
}

// ClockSkewTolerance is configurable to adjust time-based validations.
var ClockSkewTolerance = 2 * time.Minute

// JWT represents a JSON Web Token as defined in RFC 7519.
type JWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature []byte
	Token     string
}

// parseJWT parses a JWT token string into a JWT struct.
func parseJWT(tokenString string) (*JWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	jwt := &JWT{
		Token: tokenString,
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode header: %v", err)
	}
	if err := json.Unmarshal(headerBytes, &jwt.Header); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal header: %v", err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode claims: %v", err)
	}
	if err := json.Unmarshal(claimsBytes, &jwt.Claims); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal claims: %v", err)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode signature: %v", err)
	}
	jwt.Signature = signatureBytes

	return jwt, nil
}

// Verify validates the standard JWT claims as defined in RFC 7519.
// Verify validates the standard JWT claims as defined in RFC 7519.
func (j *JWT) Verify(issuerURL, clientID string) error {
	// Validate algorithm to prevent algorithm switching attacks
	alg, ok := j.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing 'alg' header")
	}
	supportedAlgs := map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"PS256": true, "PS384": true, "PS512": true,
		"ES256": true, "ES384": true, "ES512": true,
	}
	if !supportedAlgs[alg] {
		return fmt.Errorf("unsupported algorithm: %s", alg)
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

	if nbf, ok := claims["nbf"].(float64); ok {
		if err := verifyNotBefore(nbf); err != nil {
			return err
		}
	}

	// Implement replay protection by checking the jti (JWT ID)
	if jti, ok := claims["jti"].(string); ok {
		// Skip replay detection for tokens that are being verified from the cache
		if j.Token == "" {
			// This is a parsed JWT without the original token string,
			// which means it's likely from a cached token verification
			return nil
		}

		replayCacheMu.Lock()
		cleanupReplayCache()
		if _, exists := replayCache[jti]; exists {
			replayCacheMu.Unlock()
			return fmt.Errorf("token replay detected")
		}
		expFloat, ok := claims["exp"].(float64)
		var expTime time.Time
		if ok {
			expTime = time.Unix(int64(expFloat), 0)
		} else {
			expTime = time.Now().Add(10 * time.Minute)
		}
		replayCache[jti] = expTime
		replayCacheMu.Unlock()
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return fmt.Errorf("missing or empty 'sub' claim")
	}

	return nil
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
		return fmt.Errorf("invalid issuer (token: %s, expected: %s)", tokenIssuer, expectedIssuer)
	}
	return nil
}

// verifyTimeConstraint is a generic function to verify time-based claims
func verifyTimeConstraint(unixTime float64, claimName string, future bool) error {
	claimTime := time.Unix(int64(unixTime), 0)
	now := time.Now().Truncate(time.Second)

	// For expiration (future=true), we add skew to now (making now later)
	// For iat/nbf (future=false), we subtract skew from now (making now earlier)
	skewDirection := 1
	if !future {
		skewDirection = -1
	}
	skewedNow := now.Add(time.Duration(skewDirection) * ClockSkewTolerance)

	if claimTime.Equal(now) {
		return nil
	}

	// For expiration: if skewedNow (later) is after expiration, token expired
	// For iat/nbf: if skewedNow (earlier) is before claim time, token not yet valid
	if (future && skewedNow.After(claimTime)) || (!future && skewedNow.Before(claimTime)) {
		var reason string
		if future {
			reason = "has expired"
		} else {
			if claimName == "iat" {
				reason = "used before issued"
			} else {
				reason = "not yet valid"
			}
		}
		return fmt.Errorf("token %s (%s: %v, now: %v)", reason, claimName, claimTime.UTC(), now.UTC())
	}

	return nil
}

func verifyExpiration(expiration float64) error {
	return verifyTimeConstraint(expiration, "exp", true)
}

func verifyIssuedAt(issuedAt float64) error {
	return verifyTimeConstraint(issuedAt, "iat", false)
}

func verifyNotBefore(notBefore float64) error {
	return verifyTimeConstraint(notBefore, "nbf", false)
}

func verifySignature(tokenString string, publicKeyPEM []byte, alg string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}
	signedContent := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
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
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "RS") {
			return rsa.VerifyPKCS1v15(pubKey, hashFunc, hashed, signature)
		} else if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(pubKey, hashFunc, hashed, signature, nil)
		} else {
			return fmt.Errorf("unexpected key type for algorithm %s", alg)
		}
	case *ecdsa.PublicKey:
		if strings.HasPrefix(alg, "ES") {
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
