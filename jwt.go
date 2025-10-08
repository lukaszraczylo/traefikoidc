package traefikoidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/pool"
)

// Replay attack protection cache and synchronization primitives.
// This cache tracks JWT IDs (jti claims) to prevent token reuse attacks.
var (
	// replayCacheMu protects access to the replay cache instance
	replayCacheMu sync.RWMutex
	// replayCache stores JWT IDs with expiration to prevent replay attacks
	replayCache CacheInterface
	// replayCacheOnce ensures the replay cache is initialized only once
	replayCacheOnce sync.Once
	// replayCacheCleanupWG waits for cleanup goroutine to finish
	replayCacheCleanupWG sync.WaitGroup
	// replayCacheCancel cancels the cleanup context
	replayCacheCancel context.CancelFunc
	// replayCacheCleanupMu protects cleanup operations
	replayCacheCleanupMu sync.Mutex
)

// initReplayCache initializes the JWT replay protection cache with bounded size.
// The cache is bounded to 10,000 entries to prevent unbounded memory growth.
// This function uses sync.Once to ensure thread-safe single initialization.
func initReplayCache() {
	replayCacheOnce.Do(func() {
		replayCache = NewCache()
		replayCache.SetMaxSize(10000)
	})
}

// cleanupReplayCache performs graceful shutdown of the replay cache system.
// It cancels the cleanup context, waits for background goroutines to finish,
// and properly closes the cache to ensure proper cleanup during shutdown.
func cleanupReplayCache() {
	replayCacheCleanupMu.Lock()
	shouldWait := replayCacheCancel != nil
	if replayCacheCancel != nil {
		replayCacheCancel()
		replayCacheCancel = nil
	}
	replayCacheCleanupMu.Unlock()

	// Only wait if there was a cleanup routine running
	if shouldWait {
		replayCacheCleanupWG.Wait()
	}

	replayCacheMu.Lock()
	defer replayCacheMu.Unlock()

	if replayCache != nil {
		replayCache.Close()
		replayCache = nil
		replayCacheOnce = sync.Once{}
	}
}

// getReplayCacheStats returns statistics about the replay cache state.
// Returns:
//   - size: Current number of entries in the cache (currently always 0 due to interface limitations)
//   - maxSize: Maximum allowed entries (10,000)
func getReplayCacheStats() (size int, maxSize int) {
	replayCacheMu.RLock()
	defer replayCacheMu.RUnlock()

	if replayCache == nil {
		return 0, 10000
	}

	return 0, 10000
}

// startReplayCacheCleanup starts a background goroutine for periodic cache maintenance.
// The goroutine runs every 5 minutes to clean expired entries and log cache statistics.
// Uses the global task registry with circuit breaker pattern to prevent duplicate tasks.
// Parameters:
//   - ctx: Parent context for cancellation
//   - logger: Logger for debug output (can be nil)
func startReplayCacheCleanup(ctx context.Context, logger *Logger) {
	registry := GetGlobalTaskRegistry()

	// Define the cleanup task function
	cleanupFunc := func() {
		size, maxSize := getReplayCacheStats()
		if logger != nil {
			logger.Debugf("Replay cache stats: size=%d, maxSize=%d", size, maxSize)
		}

		replayCacheMu.RLock()
		if replayCache != nil {
			replayCache.Cleanup()
		}
		replayCacheMu.RUnlock()
	}

	// Create or get singleton cleanup task
	task, err := registry.CreateSingletonTask(
		"replay-cache-cleanup",
		5*time.Minute,
		cleanupFunc,
		logger,
		&replayCacheCleanupWG,
	)

	if err != nil {
		if logger != nil {
			logger.Debugf("Replay cache cleanup task already exists or circuit breaker limit reached: %v (this is expected with multiple instances)", err)
		}
		return
	}

	// Start the task
	task.Start()

	if logger != nil {
		logger.Debug("Started replay cache cleanup task with circuit breaker protection")
	}
}

// ClockSkewToleranceFuture defines the maximum allowable clock skew for future time validation.
// Tokens are considered valid for an additional 2 minutes past their expiration time.
var ClockSkewToleranceFuture = 2 * time.Minute

// ClockSkewTolerancePast defines the maximum allowable clock skew for past time validation.
// Tokens are considered valid if issued up to 10 seconds in the future.
var ClockSkewTolerancePast = 10 * time.Second

// ClockSkewTolerance is an alias for ClockSkewToleranceFuture for backward compatibility.
var ClockSkewTolerance = ClockSkewToleranceFuture

// JWT represents a parsed JSON Web Token with its constituent parts.
// It provides a structured representation of JWT components
// for validation and processing within the OIDC middleware.
type JWT struct {
	// Header contains the JWT header claims (alg, typ, kid, etc.)
	Header map[string]interface{}
	// Claims contains the JWT payload claims (iss, sub, aud, exp, etc.)
	Claims map[string]interface{}
	// Token is the original JWT token string
	Token string
	// Signature contains the decoded JWT signature bytes
	Signature []byte
}

// parseJWT parses a JWT token string into its constituent parts.
// It decodes the base64url-encoded header, claims, and signature components
// and unmarshals the JSON data into structured maps. Uses memory pools
// for efficient memory allocation during parsing.
// Parameters:
//   - tokenString: The JWT token string to parse
//
// Returns:
//   - *JWT: Parsed JWT structure with header, claims, and signature
//   - An error if the token format is invalid or decoding/unmarshaling fails
func parseJWT(tokenString string) (*JWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	pm := pool.Get()
	jwtBuf := pm.GetJWTBuffer()
	defer pm.PutJWTBuffer(jwtBuf)

	jwt := &JWT{
		Token: tokenString,
	}

	headerLen := base64.RawURLEncoding.DecodedLen(len(parts[0]))
	if headerLen > cap(jwtBuf.Header) {
		jwtBuf.Header = make([]byte, headerLen)
	} else {
		jwtBuf.Header = jwtBuf.Header[:headerLen]
	}

	n, err := base64.RawURLEncoding.Decode(jwtBuf.Header, []byte(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode header: %v", err)
	}
	headerBytes := jwtBuf.Header[:n]

	decoder := pm.GetJSONDecoder(bytes.NewReader(headerBytes))
	defer pm.PutJSONDecoder(decoder)
	if err := decoder.Decode(&jwt.Header); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal header: %v", err)
	}

	if jwt.Header == nil {
		return nil, fmt.Errorf("invalid JWT format: header is nil after unmarshaling")
	}

	claimsLen := base64.RawURLEncoding.DecodedLen(len(parts[1]))
	if claimsLen > cap(jwtBuf.Payload) {
		jwtBuf.Payload = make([]byte, claimsLen)
	} else {
		jwtBuf.Payload = jwtBuf.Payload[:claimsLen]
	}

	n, err = base64.RawURLEncoding.Decode(jwtBuf.Payload, []byte(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode claims: %v", err)
	}
	claimsBytes := jwtBuf.Payload[:n]

	decoder2 := pm.GetJSONDecoder(bytes.NewReader(claimsBytes))
	defer pm.PutJSONDecoder(decoder2)
	if err := decoder2.Decode(&jwt.Claims); err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to unmarshal claims: %v", err)
	}

	if jwt.Claims == nil {
		return nil, fmt.Errorf("invalid JWT format: claims is nil after unmarshaling")
	}

	sigLen := base64.RawURLEncoding.DecodedLen(len(parts[2]))
	if sigLen > cap(jwtBuf.Signature) {
		jwtBuf.Signature = make([]byte, sigLen)
	} else {
		jwtBuf.Signature = jwtBuf.Signature[:sigLen]
	}

	n, err = base64.RawURLEncoding.Decode(jwtBuf.Signature, []byte(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT format: failed to decode signature: %v", err)
	}

	// Reuse the signature buffer if it's large enough, otherwise allocate
	if cap(jwtBuf.Signature) >= n {
		jwt.Signature = jwtBuf.Signature[:n:n] // Use slice trick to prevent aliasing
	} else {
		jwt.Signature = make([]byte, n)
		copy(jwt.Signature, jwtBuf.Signature[:n])
	}

	return jwt, nil
}

// Verify performs comprehensive JWT token validation according to OIDC specifications.
// It validates the token signature algorithm, issuer, audience, expiration, issued-at time,
// not-before time (if present), and prevents replay attacks using JTI claims.
// Parameters:
//   - issuerURL: Expected issuer URL to validate against
//   - expectedAudience: Expected audience to validate against (can be clientID or custom audience)
//   - skipReplayCheck: Optional parameter to skip replay attack protection
//
// Returns:
//   - An error describing the first validation failure encountered
func (j *JWT) Verify(issuerURL, expectedAudience string, skipReplayCheck ...bool) error {
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
	if err := verifyAudience(aud, expectedAudience); err != nil {
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

	jtiValue, jtiOk := claims["jti"].(string)

	if jtiOk && !shouldSkipReplay && jtiValue != "" {
		initReplayCache()

		replayCacheMu.RLock()
		_, exists := replayCache.Get(jtiValue)
		replayCacheMu.RUnlock()

		if exists {
			return fmt.Errorf("token replay detected (jti: %s)", jtiValue)
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
				replayCache.Set(jtiValue, true, duration)
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

// verifyAudience validates the JWT audience claim against the expected client ID.
// The audience claim can be either a single string or an array of strings.
// Parameters:
//   - tokenAudience: The audience claim from the JWT (string or []interface{})
//   - expectedAudience: The expected audience value (typically the OAuth client ID)
//
// Returns:
//   - An error if the claim type is invalid or the expected audience is not present
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

// verifyIssuer validates the JWT issuer claim against the expected issuer URL.
// Parameters:
//   - tokenIssuer: The issuer claim from the JWT
//   - expectedIssuer: The expected issuer URL from OIDC configuration
//
// Returns:
//   - An error if the issuers do not match
func verifyIssuer(tokenIssuer, expectedIssuer string) error {
	if tokenIssuer != expectedIssuer {
		return fmt.Errorf("invalid issuer (token: %s, expected: %s)", tokenIssuer, expectedIssuer)
	}
	return nil
}

// verifyTimeConstraint validates time-based JWT claims with clock skew tolerance.
// It handles both future constraints (exp) and past constraints (iat, nbf).
// Parameters:
//   - unixTime: The Unix timestamp from the JWT claim
//   - claimName: Name of the claim being validated (for error messages)
//   - future: If true, validates against future tolerance; if false, against past tolerance
//
// Returns:
//   - An error describing the failure (e.g., "token has expired", "token used before issued")
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

// verifyExpiration validates the JWT expiration time (exp claim) with clock skew tolerance.
// It calls verifyTimeConstraint with future=true.
func verifyExpiration(expiration float64) error {
	return verifyTimeConstraint(expiration, "exp", true)
}

// verifyIssuedAt validates the JWT issued-at time (iat claim) with clock skew tolerance.
// It calls verifyTimeConstraint with future=false.
func verifyIssuedAt(issuedAt float64) error {
	return verifyTimeConstraint(issuedAt, "iat", false)
}

// verifyNotBefore validates the JWT not-before time (nbf claim) with clock skew tolerance.
// It calls verifyTimeConstraint with future=false.
func verifyNotBefore(notBefore float64) error {
	return verifyTimeConstraint(notBefore, "nbf", false)
}

// verifySignature verifies the JWT signature using the provided public key.
// Supports RSA (RS256/384/512, PS256/384/512) and ECDSA (ES256/384/512) algorithms.
// Parameters:
//   - tokenString: The complete JWT token string
//   - publicKeyPEM: The public key in PEM format
//   - alg: The signing algorithm specified in the JWT header
//
// Returns:
//   - An error if the key parsing fails, the algorithm is unsupported,
//     or the signature verification fails
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
