package traefikoidc

import (
	"context"
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

var (
	replayCacheMu   sync.RWMutex // Use RWMutex for better read performance
	replayCache     *Cache       // Replace unbounded map with bounded Cache
	replayCacheOnce sync.Once
)

// initReplayCache initializes the global replay cache for JWT ID tracking.
// It uses sync.Once to ensure thread-safe single initialization.
// The cache is bounded to 10,000 entries to prevent unbounded memory growth.
func initReplayCache() {
	replayCacheOnce.Do(func() {
		replayCache = NewCache()
		replayCache.SetMaxSize(10000)
	})
}

// cleanupReplayCache gracefully shuts down the replay cache.
// It acquires a write lock, closes the cache, and sets it to nil
// to ensure proper cleanup during shutdown.
func cleanupReplayCache() {
	replayCacheMu.Lock()
	defer replayCacheMu.Unlock()

	if replayCache != nil {
		replayCache.Close()
		replayCache = nil
		// Reset the once to allow re-initialization
		replayCacheOnce = sync.Once{}
	}
}

// getReplayCacheStats returns current statistics about the replay cache.
// Due to sync.Pool limitations, it returns 0 for current size and the
// configured maximum size of 10,000.
//
// Returns:
//   - size: Current number of entries (always 0 due to implementation).
//   - maxSize: Maximum allowed entries (10,000).
func getReplayCacheStats() (size int, maxSize int) {
	replayCacheMu.RLock()
	defer replayCacheMu.RUnlock()

	if replayCache == nil {
		return 0, 0
	}

	return 0, 10000
}

// startReplayCacheCleanup initiates a background goroutine that periodically
// cleans up expired entries from the replay cache. It runs every 5 minutes
// and logs cache statistics if a logger is provided.
//
// Parameters:
//   - ctx: Context for cancellation.
//   - logger: Logger for debug output (can be nil).
func startReplayCacheCleanup(ctx context.Context, logger *Logger) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				size, maxSize := getReplayCacheStats()
				if logger != nil {
					logger.Debugf("Replay cache stats: size=%d, maxSize=%d", size, maxSize)
				}

				replayCacheMu.RLock()
				if replayCache != nil {
					replayCache.Cleanup()
				}
				replayCacheMu.RUnlock()

			case <-ctx.Done():
				cleanupReplayCache()
				if logger != nil {
					logger.Debug("Replay cache cleanup goroutine stopped due to context cancellation")
				}
				return
			}
		}
	}()
}

var ClockSkewToleranceFuture = 2 * time.Minute

var ClockSkewTolerancePast = 10 * time.Second

var ClockSkewTolerance = ClockSkewToleranceFuture

// JWT represents a JSON Web Token as defined in RFC 7519.
// JWT represents a parsed JSON Web Token with its three components.
// It provides structured access to the header, claims, and signature
// for validation and processing within the OIDC middleware.
type JWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Token     string
	Signature []byte
}

// parseJWT decodes a raw JWT string into its constituent parts: header, claims, and signature.
// It splits the token string by '.', decodes each part using base64 URL decoding,
// and unmarshals the header and claims JSON into maps. The raw signature bytes are stored.
// It performs basic format validation (expecting 3 parts).
// Note: This function does *not* validate the signature or the claims.
//
// Parameters:
//   - tokenString: The raw JWT string.
//
// Returns:
//   - A pointer to a JWT struct containing the decoded parts.
//   - An error if the token format is invalid or decoding/unmarshaling fails.
func parseJWT(tokenString string) (*JWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Use memory pool for efficient buffer management
	pools := GetGlobalMemoryPools()
	jwtBuf := pools.GetJWTParsingBuffer()
	defer pools.PutJWTParsingBuffer(jwtBuf)

	jwt := &JWT{
		Token: tokenString,
	}

	// Decode header using pooled buffer
	headerLen := base64.RawURLEncoding.DecodedLen(len(parts[0]))
	if headerLen > cap(jwtBuf.HeaderBuf) {
		jwtBuf.HeaderBuf = make([]byte, headerLen)
	} else {
		jwtBuf.HeaderBuf = jwtBuf.HeaderBuf[:headerLen]
	}

	n, err := base64.RawURLEncoding.Decode(jwtBuf.HeaderBuf, []byte(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode header: %v", err)
	}
	headerBytes := jwtBuf.HeaderBuf[:n]

	if err := json.Unmarshal(headerBytes, &jwt.Header); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal header: %v", err)
	}

	if jwt.Header == nil {
		return nil, fmt.Errorf("invalid JWT format: header is nil after unmarshaling")
	}

	// Decode claims using pooled buffer
	claimsLen := base64.RawURLEncoding.DecodedLen(len(parts[1]))
	if claimsLen > cap(jwtBuf.PayloadBuf) {
		jwtBuf.PayloadBuf = make([]byte, claimsLen)
	} else {
		jwtBuf.PayloadBuf = jwtBuf.PayloadBuf[:claimsLen]
	}

	n, err = base64.RawURLEncoding.Decode(jwtBuf.PayloadBuf, []byte(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode claims: %v", err)
	}
	claimsBytes := jwtBuf.PayloadBuf[:n]

	if err := json.Unmarshal(claimsBytes, &jwt.Claims); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal claims: %v", err)
	}

	if jwt.Claims == nil {
		return nil, fmt.Errorf("invalid JWT format: claims is nil after unmarshaling")
	}

	// Decode signature using pooled buffer
	sigLen := base64.RawURLEncoding.DecodedLen(len(parts[2]))
	if sigLen > cap(jwtBuf.SignatureBuf) {
		jwtBuf.SignatureBuf = make([]byte, sigLen)
	} else {
		jwtBuf.SignatureBuf = jwtBuf.SignatureBuf[:sigLen]
	}

	n, err = base64.RawURLEncoding.Decode(jwtBuf.SignatureBuf, []byte(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode signature: %v", err)
	}

	// Copy signature to JWT struct (create new slice to avoid pool retention)
	jwt.Signature = make([]byte, n)
	copy(jwt.Signature, jwtBuf.SignatureBuf[:n])

	return jwt, nil
}

// Verify performs standard claim validation on the JWT according to RFC 7519.
// It checks the following:
// - Algorithm ('alg') is supported.
// - Issuer ('iss') matches the expected issuerURL.
// - Audience ('aud') contains the expected clientID.
// - Expiration time ('exp') is in the future (within tolerance).
// - Issued at time ('iat') is in the past (within tolerance).
// - Not before time ('nbf'), if present, is in the past (within tolerance).
// - Subject ('sub') claim exists and is not empty.
// - JWT ID ('jti'), if present, is checked against a replay cache to prevent token reuse.
//
// Parameters:
//   - issuerURL: The expected issuer URL (e.g., "https://accounts.google.com").
//   - clientID: The expected audience value (the client ID of this application).
//   - skipReplayCheck: If true, skips JTI replay detection (used for revalidation of cached tokens).
//
// Returns:
//   - nil if all standard claims are valid.
//   - An error describing the first validation failure encountered.
func (j *JWT) Verify(issuerURL, clientID string, skipReplayCheck ...bool) error {
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

	shouldSkipReplay := len(skipReplayCheck) > 0 && skipReplayCheck[0]

	if jti, ok := claims["jti"].(string); ok && !shouldSkipReplay {
		if j.Token == "" {
			return nil
		}

		initReplayCache()

		replayCacheMu.RLock()
		_, exists := replayCache.Get(jti)
		replayCacheMu.RUnlock()

		if exists {
			return fmt.Errorf("token replay detected (jti: %s)", jti)
		}

		expFloat, ok := claims["exp"].(float64)
		var expTime time.Time
		if ok {
			expTime = time.Unix(int64(expFloat), 0)
		} else {
			expTime = time.Now().Add(10 * time.Minute)
		}

		duration := time.Until(expTime)
		if duration > 0 {
			replayCacheMu.Lock()
			if replayCache != nil {
				replayCache.Set(jti, true, duration)
			}
			replayCacheMu.Unlock()
		}
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return fmt.Errorf("missing or empty 'sub' claim")
	}

	return nil
}

// verifyAudience checks if the expected audience is present in the token's 'aud' claim.
// The 'aud' claim can be a single string or an array of strings.
//
// Parameters:
//   - tokenAudience: The 'aud' claim value extracted from the token (can be string or []interface{}).
//   - expectedAudience: The audience value expected for this application (client ID).
//
// Returns:
//   - nil if the expected audience is found.
//   - An error if the claim type is invalid or the expected audience is not present.
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

// verifyIssuer checks if the token's 'iss' claim matches the expected issuer URL.
//
// Parameters:
//   - tokenIssuer: The 'iss' claim value from the token.
//   - expectedIssuer: The expected issuer URL configured for the OIDC provider.
//
// Returns:
//   - nil if the issuers match.
//   - An error if the issuers do not match.
func verifyIssuer(tokenIssuer, expectedIssuer string) error {
	if tokenIssuer != expectedIssuer {
		return fmt.Errorf("invalid issuer (token: %s, expected: %s)", tokenIssuer, expectedIssuer)
	}
	return nil
}

// verifyTimeConstraint checks time-based claims ('exp', 'iat', 'nbf') against the current time,
// allowing for configurable clock skew. It uses different tolerances for past and future checks.
//
// Parameters:
//   - unixTime: The timestamp value from the claim (as a float64 Unix time).
//   - claimName: The name of the claim being verified ("exp", "iat", "nbf").
//   - future: A boolean indicating the direction of the check (true for 'exp', false for 'iat'/'nbf').
//
// Returns:
//   - nil if the time constraint is met within the allowed tolerance.
//   - An error describing the failure (e.g., "token has expired", "token used before issued").
func verifyTimeConstraint(unixTime float64, claimName string, future bool) error {
	claimTime := time.Unix(int64(unixTime), 0)
	now := time.Now()

	var err error
	if future {
		allowedExpiry := claimTime.Add(ClockSkewToleranceFuture)
		if now.After(allowedExpiry) {
			err = fmt.Errorf("token has expired (exp: %v, now: %v, allowed_until: %v)", claimTime.UTC(), now.UTC(), allowedExpiry.UTC())
		}
	} else {
		allowedStart := claimTime.Add(-ClockSkewTolerancePast)
		if now.Before(allowedStart) {
			reason := "not yet valid"
			if claimName == "iat" {
				reason = "used before issued"
			}
			err = fmt.Errorf("token %s (%s: %v, now: %v, allowed_from: %v)", reason, claimName, claimTime.UTC(), now.UTC(), allowedStart.UTC())
		}
	}

	return err
}

// verifyExpiration checks the 'exp' (Expiration Time) claim.
// It calls verifyTimeConstraint with future=true.
func verifyExpiration(expiration float64) error {
	return verifyTimeConstraint(expiration, "exp", true)
}

// verifyIssuedAt checks the 'iat' (Issued At) claim.
// It calls verifyTimeConstraint with future=false.
func verifyIssuedAt(issuedAt float64) error {
	return verifyTimeConstraint(issuedAt, "iat", false)
}

// verifyNotBefore checks the 'nbf' (Not Before) claim.
// It calls verifyTimeConstraint with future=false.
func verifyNotBefore(notBefore float64) error {
	return verifyTimeConstraint(notBefore, "nbf", false)
}

// verifySignature validates the JWT's signature using the provided public key.
// It parses the public key from PEM format, selects the appropriate hashing algorithm
// based on the 'alg' parameter (SHA256/384/512), hashes the token's signing input
// (header + "." + payload), and then verifies the signature against the hash using
// the corresponding RSA (PKCS1v15 or PSS) or ECDSA verification method.
//
// Parameters:
//   - tokenString: The raw, complete JWT string.
//   - publicKeyPEM: The public key corresponding to the private key used for signing, in PEM format.
//   - alg: The algorithm specified in the JWT header (e.g., "RS256", "ES384").
//
// Returns:
//   - nil if the signature is valid.
//   - An error if the token format is invalid, decoding fails, key parsing fails,
//     the algorithm is unsupported, or the signature verification fails.
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
