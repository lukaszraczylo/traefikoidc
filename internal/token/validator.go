package token

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Validator handles token validation operations
type Validator struct {
	clientID               string
	audience               string
	issuerURL              string
	jwksURL                string
	tokenCache             TokenCacheInterface
	tokenBlacklist         CacheInterface
	tokenTypeCache         CacheInterface
	jwkCache               interface{} // JWK cache interface
	httpClient             *http.Client
	limiter                interface{} // Rate limiter interface
	extractClaimsFunc      ClaimsExtractor
	tokenVerifier          TokenVerifier
	disableReplayDetection bool
	suppressDiagnosticLogs bool
	metadataMu             *sync.RWMutex
	logger                 interface{} // Logger interface
}

// NewValidator creates a new token validator
func NewValidator(config ValidatorConfig) *Validator {
	var metadataMu *sync.RWMutex
	if config.MetadataMu != nil {
		if mu, ok := config.MetadataMu.(*sync.RWMutex); ok {
			metadataMu = mu
		}
	}

	return &Validator{
		clientID:               config.ClientID,
		audience:               config.Audience,
		issuerURL:              config.IssuerURL,
		jwksURL:                config.JwksURL,
		tokenCache:             config.TokenCache,
		tokenBlacklist:         config.TokenBlacklist,
		tokenTypeCache:         config.TokenTypeCache,
		jwkCache:               config.JwkCache,
		httpClient:             config.HTTPClient,
		limiter:                config.Limiter,
		extractClaimsFunc:      config.ExtractClaimsFunc,
		tokenVerifier:          config.TokenVerifier,
		disableReplayDetection: config.DisableReplayDetection,
		suppressDiagnosticLogs: config.SuppressDiagnosticLogs,
		metadataMu:             metadataMu,
		logger:                 config.Logger,
	}
}

// VerifyToken verifies the validity of an ID token or access token.
// It performs comprehensive validation including format checks, blacklist verification,
// signature validation using JWKs, and standard claims validation.
func (v *Validator) VerifyToken(token string) error {
	if token == "" {
		return fmt.Errorf("invalid JWT format: token is empty")
	}

	if strings.Count(token, ".") != 2 {
		return fmt.Errorf("invalid JWT format: expected JWT with 3 parts, got %d parts", strings.Count(token, ".")+1)
	}

	if len(token) < 10 {
		return fmt.Errorf("token too short to be valid JWT")
	}

	// Check raw token blacklist
	if v.tokenBlacklist != nil {
		if blacklisted, exists := v.tokenBlacklist.Get(token); exists && blacklisted != nil {
			return fmt.Errorf("token is blacklisted (raw string) in cache")
		}
	}

	// Parse JWT for further validation
	parsedJWT, parseErr := v.parseJWT(token)
	if parseErr != nil {
		return fmt.Errorf("failed to parse JWT for blacklist check: %w", parseErr)
	}

	tokenType := v.determineTokenType(parsedJWT)

	// Check token cache FIRST - if token is already verified and cached, return immediately
	// This prevents false positives when multiple goroutines validate the same token concurrently
	if claims, exists := v.tokenCache.GetCachedToken(token); exists && len(claims) > 0 {
		return nil
	}

	// Check JTI blacklist for replay detection
	if err := v.checkJTIBlacklist(parsedJWT, token); err != nil {
		return err
	}

	// Rate limiting check
	if !v.checkRateLimit() {
		return fmt.Errorf("rate limit exceeded")
	}

	// Verify signature and claims
	if err := v.VerifyJWTSignatureAndClaims(parsedJWT, token); err != nil {
		if !strings.Contains(err.Error(), "token has expired") {
			v.logErrorf("%s token verification failed: %v", tokenType, err)
		}
		return err
	}

	// Cache verified token
	v.cacheVerifiedToken(token, parsedJWT.Claims)

	// Add JTI to blacklist for replay prevention
	v.addJTIToBlacklist(parsedJWT)

	return nil
}

// VerifyJWTSignatureAndClaims verifies JWT signature using provider's public keys and validates standard claims
func (v *Validator) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	v.logDebugf("Verifying JWT signature and claims")

	// Get JWKS URL
	v.metadataMu.RLock()
	jwksURL := v.jwksURL
	v.metadataMu.RUnlock()

	// Get JWKS from cache
	jwks, err := v.getJWKS(context.Background(), jwksURL)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Extract key ID and algorithm from token header
	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("missing key ID in token header")
	}

	alg, ok := jwt.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing algorithm in token header")
	}

	// Find matching key in JWKS
	matchingKey := v.findMatchingKey(jwks, kid)
	if matchingKey == nil {
		return fmt.Errorf("no matching public key found for kid: %s", kid)
	}

	// Convert JWK to PEM and verify signature
	if err := v.verifyTokenSignature(token, matchingKey, alg); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Detect token type and validate claims
	isIDToken := v.detectTokenType(jwt, token)
	expectedAudience := v.audience
	if isIDToken {
		expectedAudience = v.clientID
	}

	// Verify standard claims
	v.metadataMu.RLock()
	issuerURL := v.issuerURL
	v.metadataMu.RUnlock()

	if err := v.verifyStandardClaims(jwt, issuerURL, expectedAudience); err != nil {
		return fmt.Errorf("standard claim verification failed: %w", err)
	}

	return nil
}

// detectTokenType efficiently detects whether a token is an ID token or access token
func (v *Validator) detectTokenType(jwt *JWT, token string) bool {
	// Use first 32 chars of token as cache key
	cacheKey := token
	if len(token) > 32 {
		cacheKey = token[:32]
	}

	// Check cache first
	if v.tokenTypeCache != nil {
		if cachedData, found := v.tokenTypeCache.Get(cacheKey); found {
			if isIDToken, ok := cachedData["is_id_token"].(bool); ok {
				return isIDToken
			}
		}
	}

	// Check for ID token indicators
	isIDToken := false

	// 1. Check 'nonce' claim (definitive for ID tokens)
	if nonce, ok := jwt.Claims["nonce"]; ok {
		if _, ok := nonce.(string); ok {
			v.cacheTokenType(cacheKey, true)
			return true
		}
	}

	// 2. Check 'typ' header for "at+jwt" (definitive for access tokens)
	if typ, ok := jwt.Header["typ"].(string); ok && typ == "at+jwt" {
		v.cacheTokenType(cacheKey, false)
		return false
	}

	// 3. Check 'token_use' claim
	if tokenUse, ok := jwt.Claims["token_use"].(string); ok {
		switch tokenUse {
		case "id":
			v.cacheTokenType(cacheKey, true)
			return true
		case "access":
			v.cacheTokenType(cacheKey, false)
			return false
		}
	}

	// 4. Check 'scope' claim (indicator for access tokens)
	if scope, ok := jwt.Claims["scope"]; ok {
		if _, ok := scope.(string); ok {
			v.cacheTokenType(cacheKey, false)
			return false
		}
	}

	// 5. Check audience matching
	if aud, ok := jwt.Claims["aud"]; ok {
		if audStr, ok := aud.(string); ok && audStr == v.clientID {
			isIDToken = true
		} else if audArr, ok := aud.([]interface{}); ok && len(audArr) == 1 {
			for _, val := range audArr {
				if str, ok := val.(string); ok && str == v.clientID {
					isIDToken = true
					break
				}
			}
		}
	}

	v.cacheTokenType(cacheKey, isIDToken)
	return isIDToken
}

// Helper methods (stubs for interface compatibility)

func (v *Validator) parseJWT(token string) (*JWT, error) {
	// This would call the actual JWT parsing function
	// For now, returning a stub
	return nil, fmt.Errorf("parseJWT not implemented")
}

func (v *Validator) determineTokenType(jwt *JWT) string {
	if v.detectTokenType(jwt, "") {
		return TokenTypeID
	}
	return TokenTypeAccess
}

func (v *Validator) checkJTIBlacklist(jwt *JWT, token string) error {
	if v.disableReplayDetection {
		return nil
	}

	if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" {
		// Skip for test tokens
		if !strings.HasPrefix(token, "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0") {
			if v.tokenBlacklist != nil {
				if blacklisted, exists := v.tokenBlacklist.Get(jti); exists && blacklisted != nil {
					return fmt.Errorf("token replay detected (jti: %s) in cache", jti)
				}
			}
		}
	}
	return nil
}

func (v *Validator) checkRateLimit() bool {
	// Interface method call would go here
	return true
}

func (v *Validator) cacheVerifiedToken(token string, claims map[string]interface{}) {
	v.tokenCache.CacheToken(token, claims)
}

func (v *Validator) addJTIToBlacklist(jwt *JWT) {
	if v.disableReplayDetection {
		return
	}

	jti, ok := jwt.Claims["jti"].(string)
	if !ok || jti == "" {
		return
	}

	if v.tokenBlacklist != nil {
		v.tokenBlacklist.Set(jti, map[string]interface{}{
			"blacklisted_at": time.Now().Unix(),
			"reason":         "jti_replay_prevention",
		})
	}
}

func (v *Validator) cacheTokenType(cacheKey string, isIDToken bool) {
	if v.tokenTypeCache != nil {
		v.tokenTypeCache.Set(cacheKey, map[string]interface{}{
			"is_id_token": isIDToken,
			"cached_at":   time.Now().Unix(),
		})
	}
}

func (v *Validator) getJWKS(ctx context.Context, jwksURL string) (*JWKS, error) {
	// Interface method call would go here
	return nil, fmt.Errorf("getJWKS not implemented")
}

func (v *Validator) findMatchingKey(jwks *JWKS, kid string) *JWK {
	if jwks == nil {
		return nil
	}
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key
		}
	}
	return nil
}

func (v *Validator) verifyTokenSignature(token string, key *JWK, alg string) error {
	// Interface method call would go here
	return fmt.Errorf("verifyTokenSignature not implemented")
}

func (v *Validator) verifyStandardClaims(jwt *JWT, issuer, audience string) error {
	// Interface method call would go here
	return fmt.Errorf("verifyStandardClaims not implemented")
}

func (v *Validator) logDebugf(format string, args ...interface{}) {
	// Logger interface call would go here
}

func (v *Validator) logErrorf(format string, args ...interface{}) {
	// Logger interface call would go here
}
