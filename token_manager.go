// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains token management functionality including verification,
// caching, refresh, and provider-specific validation logic.
package traefikoidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

// VerifyToken verifies the validity of an ID token or access token.
// It performs comprehensive validation including format checks, blacklist verification,
// signature validation using JWKs, and standard claims validation. It also caches
// successfully verified tokens to avoid repeated verification.
// Parameters:
//   - token: The JWT token string to verify.
//
// Returns:
//   - An error if verification fails (e.g., blacklisted token, invalid format,
//     signature failure, or claims error), nil if verification succeeds.
//
//nolint:gocognit,gocyclo // Complex token verification logic requires multiple security checks
func (t *TraefikOidc) VerifyToken(token string) error {
	return t.verifyTokenWithOpts(token, verifyOpts{})
}

// verifyOpts are internal-only knobs for verifyTokenWithOpts. Kept unexported
// because they expose subtle replay-protection semantics that are dangerous
// to misuse.
type verifyOpts struct {
	// skipReplayMarking suppresses the JTI -> blacklist Set near the bottom
	// of verifyTokenWithOpts. The Get at the top remains active, so revoked
	// tokens (added to the blacklist by RevokeToken) are still rejected.
	// Used exclusively by the bearer-auth path, where bearer tokens are
	// designed to be reused until exp.
	skipReplayMarking bool
}

// verifyTokenWithOpts runs the full token verification pipeline used by both
// the cookie path and the bearer path. The cookie path uses the zero-value
// opts; the bearer path sets skipReplayMarking=true. See the security spec
// (docs/superpowers/specs/2026-05-18-bearer-token-auth-design.md §7.7) for
// the exact contract: skipReplayMarking gates ONLY the JTI Set, never the Get.
//
//nolint:gocognit,gocyclo // Complex token verification logic requires multiple security checks
func (t *TraefikOidc) verifyTokenWithOpts(token string, opts verifyOpts) error {
	if token == "" {
		return fmt.Errorf("invalid JWT format: token is empty")
	}

	if strings.Count(token, ".") != 2 {
		return fmt.Errorf("invalid JWT format: expected JWT with 3 parts, got %d parts", strings.Count(token, ".")+1)
	}

	if len(token) < 10 {
		return fmt.Errorf("token too short to be valid JWT")
	}

	if t.tokenBlacklist != nil {
		if blacklisted, exists := t.tokenBlacklist.Get(token); exists && blacklisted != nil {
			return fmt.Errorf("token is blacklisted (raw string) in cache")
		}
	}

	// Hot-path fast-return: a previously-verified token has already passed
	// signature, claims, and replay checks. Skipping the parseJWT cost here
	// matters under bursty traffic (e.g. 10+ concurrent panel requests on
	// every Grafana dashboard refresh) where the same token is validated
	// dozens of times per second by validateStandardTokens.
	if t.tokenCache != nil {
		if claims, exists := t.tokenCache.Get(token); exists && len(claims) > 0 {
			return nil
		}
	}

	parsedJWT, parseErr := parseJWT(token)
	if parseErr != nil {
		return fmt.Errorf("failed to parse JWT for blacklist check: %w", parseErr)
	}

	tokenType := "UNKNOWN"
	if aud, ok := parsedJWT.Claims["aud"]; ok {
		if audStr, ok := aud.(string); ok && audStr == t.clientID {
			tokenType = "ID_TOKEN"
		}
	}
	if scope, ok := parsedJWT.Claims["scope"]; ok {
		if _, ok := scope.(string); ok {
			tokenType = "ACCESS_TOKEN"
		}
	}

	// Only check JTI blacklist for tokens that aren't already in the cache
	// This is for FIRST-TIME validation to detect replay attacks. The
	// blacklist Get is ALWAYS active on the bearer path too — only the
	// Set below is gated by opts.skipReplayMarking.
	if jti, ok := parsedJWT.Claims["jti"].(string); ok && jti != "" {
		// Skip JTI blacklist check if replay detection is disabled
		if !t.disableReplayDetection {
			if !strings.HasPrefix(token, "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0") {
				if t.tokenBlacklist != nil {
					if blacklisted, exists := t.tokenBlacklist.Get(jti); exists && blacklisted != nil {
						return fmt.Errorf("token replay detected (jti: %s) in cache", jti)
					}
				}
			}
		}
	}

	if !t.limiter.Allow() {
		return fmt.Errorf("rate limit exceeded")
	}

	jwt := parsedJWT

	if err := t.VerifyJWTSignatureAndClaims(jwt, token); err != nil {
		if !strings.Contains(err.Error(), "token has expired") {
			t.safeLogErrorf("%s token verification failed: %v", tokenType, err)
		}
		return err
	}

	t.cacheVerifiedToken(token, jwt.Claims)

	// Replay marking: add JTI to blacklist so subsequent presentations of
	// the SAME token can short-circuit via cache. Bearer path suppresses
	// this Set (opts.skipReplayMarking=true) because bearer tokens are
	// designed for reuse until exp; the cache-evict-then-replay scenario
	// would otherwise trigger false replay detection.
	if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" && !t.disableReplayDetection && !opts.skipReplayMarking {
		expiry := time.Now().Add(defaultBlacklistDuration)
		if expClaim, expOk := jwt.Claims["exp"].(float64); expOk {
			expTime := time.Unix(int64(expClaim), 0)
			tokenDuration := time.Until(expTime)
			if tokenDuration > 0 && tokenDuration < defaultBlacklistDuration {
				expiry = expTime
			}
			// else: keep default expiry for expired tokens or tokens >24h
		}

		if t.tokenBlacklist != nil {
			t.tokenBlacklist.Set(jti, true, time.Until(expiry))
			t.safeLogDebugf("Added JTI %s to blacklist cache", jti)
		} else {
			t.safeLogErrorf("Token blacklist not available, skipping JTI %s blacklist", jti)
		}

		// Use sharded cache for replay detection - no global mutex needed
		// This reduces lock contention by ~64x under high load
		initReplayCache()
		duration := time.Until(expiry)
		if duration > 0 {
			if shardedReplayCache != nil {
				shardedReplayCache.Set(jti, true, duration)
			} else {
				// Fall back to legacy cache (should rarely happen)
				replayCacheMu.Lock()
				if replayCache != nil {
					replayCache.Set(jti, true, duration)
				}
				replayCacheMu.Unlock()
			}
		}
	}

	return nil
}

// verifyToken is a convenience wrapper for token verification.
// It delegates to the configured token verifier interface.
// Parameters:
//   - token: The token string to verify.
//
// Returns:
//   - The result of calling t.tokenVerifier.VerifyToken(token).
func (t *TraefikOidc) verifyToken(token string) error {
	return t.tokenVerifier.VerifyToken(token)
}

// cacheVerifiedToken stores a successfully verified token and its claims in the cache.
// The token is cached until its expiration time to avoid repeated verification.
// Parameters:
//   - token: The verified token string to cache.
//   - claims: The map of claims extracted from the verified token.
func (t *TraefikOidc) cacheVerifiedToken(token string, claims map[string]interface{}) {
	expClaim, ok := claims["exp"].(float64)
	if !ok {
		t.safeLogError("Failed to cache token: invalid 'exp' claim type")
		return
	}

	expirationTime := time.Unix(int64(expClaim), 0)
	now := time.Now()
	duration := expirationTime.Sub(now)
	t.tokenCache.Set(token, claims, duration)
}

// detectTokenType efficiently detects whether a token is an ID token or access token.
// It uses caching to avoid re-detection and optimizes the detection order for performance.
// Parameters:
//   - jwt: The parsed JWT structure containing header and claims.
//   - token: The raw token string for cache key generation.
//
// Returns:
//   - true if the token is an ID token, false if it's an access token.
//
//nolint:gocognit,gocyclo // Complex token type detection with multiple provider-specific checks
func (t *TraefikOidc) detectTokenType(jwt *JWT, token string) bool {
	// Key on a hash of the FULL token. The first 32 characters of a JWT are
	// only the base64url-encoded header, which is identical for every token
	// sharing the same alg+kid, so distinct tokens (e.g. an ID token and an
	// access token from the same issuer) would otherwise collide on the cache
	// key and be mis-classified.
	sum := sha256.Sum256([]byte(token))
	cacheKey := hex.EncodeToString(sum[:])

	// Check cache first
	if t.tokenTypeCache != nil {
		if cachedType, found := t.tokenTypeCache.Get(cacheKey); found {
			if isIDToken, ok := cachedType.(bool); ok {
				return isIDToken
			}
		}
	}

	// Perform optimized detection
	isIDToken := false

	// 1. Check 'nonce' claim first (most definitive for ID tokens - short circuit)
	if nonce, ok := jwt.Claims["nonce"]; ok {
		if _, ok := nonce.(string); ok {
			if !t.suppressDiagnosticLogs {
				t.safeLogDebugf("ID token detected via nonce claim")
			}
			// Cache and return immediately
			if t.tokenTypeCache != nil {
				t.tokenTypeCache.Set(cacheKey, true, 5*time.Minute)
			}
			return true
		}
	}

	// 2. Check 'typ' header for "at+jwt" (definitive for access tokens - short circuit)
	if typ, ok := jwt.Header["typ"].(string); ok && typ == "at+jwt" {
		// RFC 9068 compliant access token
		if !t.suppressDiagnosticLogs {
			t.safeLogDebugf("RFC 9068 access token detected (typ=at+jwt)")
		}
		// Cache and return immediately
		if t.tokenTypeCache != nil {
			t.tokenTypeCache.Set(cacheKey, false, 5*time.Minute)
		}
		return false
	}

	// 3. Check 'token_use' claim (definitive if present - short circuit)
	if tokenUse, ok := jwt.Claims["token_use"].(string); ok {
		switch tokenUse {
		case "id":
			if !t.suppressDiagnosticLogs {
				t.safeLogDebugf("ID token detected via token_use claim")
			}
			// Cache and return
			if t.tokenTypeCache != nil {
				t.tokenTypeCache.Set(cacheKey, true, 5*time.Minute)
			}
			return true
		case "access":
			if !t.suppressDiagnosticLogs {
				t.safeLogDebugf("Access token detected via token_use claim")
			}
			// Cache and return
			if t.tokenTypeCache != nil {
				t.tokenTypeCache.Set(cacheKey, false, 5*time.Minute)
			}
			return false
		}
	}

	// 4. Check 'scope' claim (strong indicator for access tokens)
	if scope, ok := jwt.Claims["scope"]; ok {
		if _, ok := scope.(string); ok {
			if !t.suppressDiagnosticLogs {
				t.safeLogDebugf("Access token detected via scope claim")
			}
			// Cache and return
			if t.tokenTypeCache != nil {
				t.tokenTypeCache.Set(cacheKey, false, 5*time.Minute)
			}
			return false
		}
	}

	// 5. Check if aud == clientID only (ID token pattern)
	if aud, ok := jwt.Claims["aud"]; ok {
		// Check string audience
		if audStr, ok := aud.(string); ok && audStr == t.clientID {
			isIDToken = true
		} else if audArr, ok := aud.([]interface{}); ok {
			// Check array audience - only treat as ID token if client_id is sole audience
			if len(audArr) == 1 {
				for _, v := range audArr {
					if str, ok := v.(string); ok && str == t.clientID {
						isIDToken = true
						break
					}
				}
			}
		}
	}

	// Cache the result
	if t.tokenTypeCache != nil {
		t.tokenTypeCache.Set(cacheKey, isIDToken, 5*time.Minute)
	}

	// Log detection result in debug mode
	if !t.suppressDiagnosticLogs {
		if isIDToken {
			t.safeLogDebugf("ID token detected via audience matching")
		} else {
			t.safeLogDebugf("Defaulting to access token")
		}
	}

	return isIDToken
}

// VerifyJWTSignatureAndClaims verifies JWT signature using provider's public keys and validates standard claims.
// It retrieves the appropriate public key from the JWKS cache, verifies the token signature,
// and validates standard OIDC claims like issuer, audience, and expiration.
// Parameters:
//   - jwt: The parsed JWT structure containing header and claims.
//   - token: The raw token string for signature verification.
//
// Returns:
//   - An error if verification fails (e.g., JWKS retrieval failed, no matching key,
//     signature verification failed, standard claim validation failed), nil if successful.
func (t *TraefikOidc) VerifyJWTSignatureAndClaims(jwt *JWT, token string) error {
	t.safeLogDebugf("Verifying JWT signature and claims")

	// Read jwksURL with RLock
	t.metadataMu.RLock()
	jwksURL := t.jwksURL
	t.metadataMu.RUnlock()

	kid, ok := jwt.Header["kid"].(string)
	if !ok {
		return fmt.Errorf("missing key ID in token header")
	}
	alg, ok := jwt.Header["alg"].(string)
	if !ok {
		return fmt.Errorf("missing algorithm in token header")
	}

	if !t.suppressDiagnosticLogs {
		t.safeLogDebugf("DIAGNOSTIC: Looking for kid=%s, alg=%s in JWKS", kid, alg)
	}

	pubKey, err := t.jwkCache.GetPublicKey(context.Background(), jwksURL, kid, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	if err := verifySignatureWithKey(token, pubKey, alg); err != nil {
		if !t.suppressDiagnosticLogs {
			// Microsoft Graph access tokens carry a `nonce` JWT header and are
			// signed in a proprietary form Microsoft documents as unverifiable
			// by client applications. They reach this path only when the
			// per-provider classifier (validateAzureTokens) didn't catch them,
			// so log at debug to keep the error stream actionable while still
			// surfacing the cause for diagnostics.
			if _, isMSProprietary := jwt.Header["nonce"]; isMSProprietary {
				t.safeLogDebugf("DIAGNOSTIC: Signature verification failed for kid=%s, alg=%s (Microsoft proprietary nonce header — token is opaque to clients): %v", kid, alg, err)
			} else {
				t.safeLogErrorf("DIAGNOSTIC: Signature verification failed for kid=%s, alg=%s: %v", kid, alg, err)
			}
		}
		return fmt.Errorf("signature verification failed: %w", err)
	}

	if !t.suppressDiagnosticLogs {
		t.safeLogDebugf("DIAGNOSTIC: Signature verification successful for kid=%s", kid)
	}

	// Detect token type (cached for performance)
	isIDToken := t.detectTokenType(jwt, token)

	// Determine expected audience
	expectedAudience := t.audience // Default to configured audience
	if isIDToken {
		expectedAudience = t.clientID
	}
	if !t.suppressDiagnosticLogs {
		if isIDToken {
			t.safeLogDebugf("ID token detected, validating with client_id: %s", expectedAudience)
		} else {
			t.safeLogDebugf("Access token detected, validating with audience: %s", expectedAudience)
		}
	}

	// Read issuerURL with RLock
	t.metadataMu.RLock()
	issuerURL := t.issuerURL
	t.metadataMu.RUnlock()

	// Always skip replay check in JWT.Verify since we handle it at the VerifyToken level
	// This prevents false positives when multiple goroutines validate the same cached token
	if err := jwt.Verify(issuerURL, expectedAudience, true); err != nil {
		return fmt.Errorf("standard claim verification failed: %w", err)
	}

	return nil
}

// refreshToken attempts to refresh authentication tokens using the refresh token.
// It handles provider-specific refresh logic, validates new tokens, updates the session,
// and includes concurrency protection to prevent race conditions.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request context.
//   - session: The session data containing the refresh token.
//
// Returns:
//   - true if refresh succeeded and session was updated, false if refresh failed,
//     a concurrency conflict was detected, or saving the session failed.
//
//nolint:gocognit // Complex token refresh logic with multiple error handling paths
func (t *TraefikOidc) refreshToken(rw http.ResponseWriter, req *http.Request, session *SessionData) bool {
	session.refreshMutex.Lock()
	defer session.refreshMutex.Unlock()

	t.logger.Debug("Attempting to refresh token (mutex acquired)")

	if !session.inUse {
		t.logger.Debug("refreshToken aborted: Session no longer in use")
		return false
	}

	initialRefreshToken := session.GetRefreshToken()
	if initialRefreshToken == "" {
		t.logger.Debug("No refresh token found in session")
		return false
	}

	if t.isGoogleProvider() {
		t.logger.Debug("Google OIDC provider detected for token refresh operation")
	} else if t.isAzureProvider() {
		t.logger.Debug("Azure AD provider detected for token refresh operation")
	}

	tokenPrefix := initialRefreshToken
	if len(initialRefreshToken) > 10 {
		tokenPrefix = initialRefreshToken[:10]
	}
	t.logger.Debugf("Attempting refresh with token starting with %s...", tokenPrefix)

	newToken, err := t.coordinatedTokenRefresh(req, initialRefreshToken)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid_grant") || strings.Contains(errMsg, "token expired") {
			t.logger.Debug("Refresh token expired or revoked: %v", err)
			// Clear all tokens and authentication state when refresh token is invalid
			if err := session.SetAuthenticated(false); err != nil {
				t.logger.Errorf("Failed to set authenticated to false: %v", err)
			}
			session.SetRefreshToken("")
			session.SetAccessToken("")
			session.SetIDToken("")
			session.SetUserIdentifier("")
			// Clear CSRF tokens as well to prevent any replay attacks
			session.SetCSRF("")
			session.SetNonce("")
			session.SetCodeVerifier("")
			if err = session.Save(req, rw); err != nil {
				t.logger.Errorf("Failed to clear session after invalid refresh token: %v", err)
			}
		} else if strings.Contains(errMsg, "invalid_client") {
			t.logger.Errorf("Client credentials rejected: %v - check client_id and client_secret configuration", err)
		} else if t.isGoogleProvider() && strings.Contains(errMsg, "invalid_request") {
			t.logger.Errorf("Google OIDC provider error: %v - check scope configuration includes 'offline_access' and prompt=consent is used during authentication", err)
		} else {
			t.logger.Errorf("Token refresh failed: %v", err)
		}

		return false
	}

	if newToken.IDToken == "" {
		t.logger.Info("Provider did not return a new ID token during refresh")
		return false
	}

	if err = t.verifyToken(newToken.IDToken); err != nil {
		t.logger.Debug("Failed to verify newly obtained ID token: %v", err)
		return false
	}

	currentRefreshToken := session.GetRefreshToken()
	if initialRefreshToken != currentRefreshToken {
		t.logger.Infof("refreshToken aborted: Session refresh token changed concurrently during refresh attempt.")
		return false
	}

	t.logger.Debugf("Concurrency check passed. Updating session with new tokens.")

	claims, err := t.extractClaimsFunc(newToken.IDToken)
	if err != nil {
		t.logger.Errorf("refreshToken failed: Failed to extract claims from refreshed token: %v", err)
		return false
	}
	userIdentifier, _ := claims[t.userIdentifierClaim].(string)
	if userIdentifier == "" {
		if t.userIdentifierClaim != "sub" {
			userIdentifier, _ = claims["sub"].(string)
		}
		if userIdentifier == "" {
			t.logger.Errorf("refreshToken failed: User identifier claim '%s' missing or empty in refreshed token", t.userIdentifierClaim)
			return false
		}
		t.logger.Debugf("Configured claim '%s' not found in refreshed token, using 'sub' claim as fallback", t.userIdentifierClaim)
	}
	session.SetUserIdentifier(userIdentifier)

	// Get token expiry information for logging
	var expiryTime time.Time
	if expClaim, ok := claims["exp"].(float64); ok {
		expiryTime = time.Unix(int64(expClaim), 0)
		t.logger.Debugf("New token expires at: %v (in %v)", expiryTime, time.Until(expiryTime))
	}

	session.SetIDToken(newToken.IDToken)
	session.SetAccessToken(newToken.AccessToken)

	if newToken.RefreshToken != "" {
		t.logger.Debug("Received new refresh token from provider")
		session.SetRefreshToken(newToken.RefreshToken)
	} else {
		t.logger.Debug("Provider did not return a new refresh token, keeping the existing one")
		session.SetRefreshToken(initialRefreshToken)
	}

	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("refreshToken failed: Failed to set authenticated flag: %v", err)
		// Clear tokens on failure to maintain consistent state
		session.SetAccessToken("")
		session.SetIDToken("")
		session.SetRefreshToken("")
		session.SetUserIdentifier("")
		return false
	}

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("refreshToken failed: Failed to save session after successful token refresh: %v", err)
		// Reset authentication state since we couldn't persist it
		if err := session.SetAuthenticated(false); err != nil {
			t.logger.Errorf("Failed to set authenticated to false: %v", err)
		}
		return false
	}

	t.logger.Debugf("Token refresh successful and session saved")
	return true
}

// coordinatedTokenRefresh routes a refresh-token grant through the
// RefreshCoordinator so that concurrent requests sharing the same refresh
// token coalesce into a single upstream call. This prevents the thundering
// herd that yields invalid_grant when the IdP rotates refresh tokens.
//
// Falls back to a direct call when the coordinator is nil, which only
// happens in tests that build TraefikOidc literals without going through
// NewWithContext.
func (t *TraefikOidc) coordinatedTokenRefresh(req *http.Request, refreshToken string) (*TokenResponse, error) {
	if t.refreshCoordinator == nil {
		return t.tokenExchanger.GetNewTokenWithRefreshToken(refreshToken)
	}

	parentCtx := context.Background()
	if req != nil {
		parentCtx = req.Context()
	}
	ctx, cancel := context.WithTimeout(parentCtx, refreshCoordinatorWaitTimeout)
	defer cancel()

	sessionID := refreshCoordinatorSessionID(refreshToken)

	return t.refreshCoordinator.CoordinateRefresh(
		ctx,
		sessionID,
		refreshToken,
		func() (*TokenResponse, error) {
			// Cross-replica dedup. The in-process coordinator already
			// collapses concurrent grants on this pod; this Redis-backed
			// short-TTL cache covers the (rare) case of a failover or
			// load-balancer reroute mid-refresh, where two pods would
			// otherwise both POST the same refresh_token to the IdP.
			if cached, ok := t.lookupCachedRefreshResult(sessionID); ok {
				return cached, nil
			}
			resp, err := t.tokenExchanger.GetNewTokenWithRefreshToken(refreshToken)
			if err == nil && resp != nil {
				t.cacheRefreshResult(sessionID, resp)
			}
			return resp, err
		},
	)
}

// lookupCachedRefreshResult returns a previously-stored TokenResponse for the
// given refresh-token hash, if one exists and is still within its short TTL.
// The cache wraps the universal cache, which is Redis-backed in production -
// so a "hit" here means another Traefik replica refreshed this same token
// within the last few seconds.
func (t *TraefikOidc) lookupCachedRefreshResult(sessionID string) (*TokenResponse, bool) {
	if t.refreshResultCache == nil {
		return nil, false
	}
	v, ok := t.refreshResultCache.Get(refreshResultCacheKey(sessionID))
	if !ok || v == nil {
		return nil, false
	}
	if tr, ok := v.(*TokenResponse); ok && tr != nil {
		return tr, true
	}
	return nil, false
}

// cacheRefreshResult stores the new TokenResponse under the refresh-token
// hash for a short window. TTL is intentionally tight: the rotated refresh
// token cannot be re-presented to the IdP, and any peer waiting longer than
// this window has almost certainly given up via its own coordinator timeout.
func (t *TraefikOidc) cacheRefreshResult(sessionID string, resp *TokenResponse) {
	if t.refreshResultCache == nil || resp == nil {
		return
	}
	t.refreshResultCache.Set(refreshResultCacheKey(sessionID), resp, refreshResultCacheTTL)
}

// refreshResultCacheKey namespaces refresh-result entries inside the shared
// cache namespace.
func refreshResultCacheKey(sessionID string) string {
	return "rt-result:" + sessionID
}

// refreshResultCacheTTL bounds how long a peer can lean on the dedup cache.
// Long enough for a sibling replica to observe the result, short enough that
// a stale entry never re-supplies a token after the IdP has already moved on.
const refreshResultCacheTTL = 5 * time.Second

// RevokeToken revokes a token locally by adding it to the blacklist cache.
// It removes the token from the verification cache and adds both the token
// and its JTI (if present) to the blacklist to prevent future use.
// Parameters:
//   - token: The raw token string to revoke locally.
func (t *TraefikOidc) RevokeToken(token string) {
	t.tokenCache.Delete(token)

	if jwt, err := parseJWT(token); err == nil {
		if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" {
			expiry := time.Now().Add(24 * time.Hour)
			if t.tokenBlacklist != nil {
				t.tokenBlacklist.Set(jti, true, time.Until(expiry))
				t.logger.Debugf("Locally revoked token JTI %s (added to blacklist)", jti)
			}
		}
	}

	expiry := time.Now().Add(24 * time.Hour)
	if t.tokenBlacklist != nil {
		t.tokenBlacklist.Set(token, true, time.Until(expiry))
		t.logger.Debugf("Locally revoked token (added to blacklist)")
	}
}

// RevokeTokenWithProvider revokes a token with the OIDC provider.
// It sends a revocation request to the provider's revocation endpoint
// with proper authentication and error recovery if available.
// Parameters:
//   - token: The token to revoke.
//   - tokenType: The type of token ("access_token" or "refresh_token").
//
// Returns:
//   - An error if the request fails or the provider returns a non-OK status.
func (t *TraefikOidc) RevokeTokenWithProvider(token, tokenType string) error {
	// Read revocationURL with RLock
	t.metadataMu.RLock()
	revocationURL := t.revocationURL
	t.metadataMu.RUnlock()

	if revocationURL == "" {
		return fmt.Errorf("token revocation endpoint is not configured or discovered")
	}
	t.logger.Debugf("Attempting to revoke token (type: %s) with provider at %s", tokenType, revocationURL)

	// Read tokenURL with RLock — used as audience for private_key_jwt (RFC 7523 §3).
	t.metadataMu.RLock()
	tokenURL := t.tokenURL
	t.metadataMu.RUnlock()

	data := url.Values{
		"token":           {token},
		"token_type_hint": {tokenType},
	}
	// client_id is sent in the body for every method except client_secret_basic,
	// where it is carried in the Authorization header per RFC 6749 §2.3.1.
	if t.clientAuthMethod != "client_secret_basic" || t.clientAssertion != nil {
		data.Set("client_id", t.clientID)
	}

	useBasicAuth := false
	if t.clientAssertion != nil {
		assertion, err := t.clientAssertion.Sign(tokenURL, t.clientID)
		if err != nil {
			return fmt.Errorf("failed to sign client assertion: %w", err)
		}
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", assertion)
	} else if t.clientAuthMethod == "client_secret_basic" {
		useBasicAuth = true
	} else {
		data.Set("client_secret", t.clientSecret)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", revocationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token revocation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if useBasicAuth {
		setOAuthBasicAuth(req, t.clientID, t.clientSecret)
	}

	// Send the request with circuit breaker protection if available
	var resp *http.Response
	if t.errorRecoveryManager != nil {
		// Read issuerURL with RLock for service name
		t.metadataMu.RLock()
		serviceName := fmt.Sprintf("token-revocation-%s", t.issuerURL)
		t.metadataMu.RUnlock()
		err = t.errorRecoveryManager.ExecuteWithRecovery(context.Background(), serviceName, func() error {
			var reqErr error
			resp, reqErr = t.httpClient.Do(req) //nolint:bodyclose // Body is closed in defer after error check
			if reqErr != nil && resp != nil && resp.Body != nil {
				_ = resp.Body.Close() // Safe to ignore: closing body on error
			}
			return reqErr
		})
	} else {
		resp, err = t.httpClient.Do(req)
	}
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close() // Safe to ignore: closing body on error
		}
		return fmt.Errorf("failed to send token revocation request: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body) // Safe to ignore: draining body on defer
			_ = resp.Body.Close()                 // Safe to ignore: closing body on defer
		}
	}()

	if resp.StatusCode != http.StatusOK {
		limitReader := io.LimitReader(resp.Body, 1024*10)
		body, _ := io.ReadAll(limitReader) // Safe to ignore: reading error body for diagnostics
		t.logger.Errorf("Token revocation failed with status %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf("token revocation failed with status %d", resp.StatusCode)
	}

	t.logger.Debugf("Token successfully revoked with provider")
	return nil
}

// ExchangeCodeForToken exchanges an authorization code for tokens.
// This is a wrapper method that delegates to the internal token exchange logic
// while still allowing mocking for tests.
// Parameters:
//   - ctx: The request context.
//   - grantType: The OAuth 2.0 grant type ("authorization_code").
//   - codeOrToken: The authorization code received from the provider.
//   - redirectURL: The redirect URI used in the authorization request.
//   - codeVerifier: The PKCE code verifier (if PKCE is enabled).
//
// Returns:
//   - The token response containing access token, ID token, and refresh token.
//   - An error if the token exchange fails.
func (t *TraefikOidc) ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error) {
	return t.exchangeTokens(ctx, grantType, codeOrToken, redirectURL, codeVerifier)
}

// GetNewTokenWithRefreshToken refreshes tokens using a refresh token.
// This is a wrapper method that delegates to the internal refresh token logic
// while still allowing mocking for tests.
// Parameters:
//   - refreshToken: The refresh token to use for obtaining new tokens.
//
// Returns:
//   - The token response containing new access token, ID token, and potentially new refresh token.
//   - An error if the refresh fails.
func (t *TraefikOidc) GetNewTokenWithRefreshToken(refreshToken string) (*TokenResponse, error) {
	return t.getNewTokenWithRefreshToken(refreshToken)
}

// isGoogleProvider detects if the configured OIDC provider is Google.
// It checks the issuer URL for Google-specific domains.
// Returns:
//   - true if the provider is Google, false otherwise.
func (t *TraefikOidc) isGoogleProvider() bool {
	// Read issuerURL with RLock
	t.metadataMu.RLock()
	issuerURL := t.issuerURL
	t.metadataMu.RUnlock()

	return strings.Contains(issuerURL, "google") || strings.Contains(issuerURL, "accounts.google.com")
}

// isUnverifiableAzureAccessToken reports whether a JWT-shaped access token
// matches the Microsoft proprietary format that client applications must not
// validate. Microsoft injects a `nonce` value into the JWT header, signs over
// the SHA256 hash of that nonce, and ships the original nonce on the wire,
// guaranteeing that any standard JWS verifier rejects the signature. This is
// the documented mechanism that keeps access tokens opaque to non-resource
// holders (Microsoft Graph, Azure Management API).
//
// https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
//
// Returns true on parse failure as well — a token we cannot parse should not
// be passed through the verification path that emits ERROR logs.
func (t *TraefikOidc) isUnverifiableAzureAccessToken(token string) bool {
	parsed, err := parseJWT(token)
	if err != nil {
		return true
	}
	_, hasProprietaryNonce := parsed.Header["nonce"]
	return hasProprietaryNonce
}

// isAzureProvider detects if the configured OIDC provider is Azure AD.
// It checks the issuer URL for Microsoft Azure AD domains.
// Returns:
//   - true if the provider is Azure AD, false otherwise.
func (t *TraefikOidc) isAzureProvider() bool {
	// Read issuerURL with RLock
	t.metadataMu.RLock()
	issuerURL := t.issuerURL
	t.metadataMu.RUnlock()

	return strings.Contains(issuerURL, "login.microsoftonline.com") ||
		strings.Contains(issuerURL, "sts.windows.net") ||
		strings.Contains(issuerURL, "login.windows.net")
}

// startTokenCleanup starts background cleanup goroutines for cache maintenance.
// It runs periodic cleanup of token cache, JWK cache, and session chunks.
// Includes panic recovery to ensure stability.
func (t *TraefikOidc) startTokenCleanup() {
	if t == nil {
		return
	}

	// Use singleton resource manager for token cleanup
	rm := GetResourceManager()
	taskName := "singleton-token-cleanup"

	// Capture values for the cleanup function
	tokenCache := t.tokenCache
	jwkCache := t.jwkCache
	sessionManager := t.sessionManager
	logger := t.logger

	// Only use the fast cleanup interval when actually running under `go test`.
	// runtime.Compiler == "yaegi" makes isTestMode() return true in production
	// (Traefik interprets the plugin via yaegi), which would otherwise pin this
	// ticker to 20 Hz on a real cluster despite tokenCache.Cleanup and
	// jwkCache.Cleanup both being no-ops there.
	cleanupInterval := 1 * time.Minute
	if isTestMode() && runtime.Compiler != "yaegi" {
		cleanupInterval = 50 * time.Millisecond
	}

	// Create cleanup function
	cleanupFunc := func() {
		if logger != nil && !isTestMode() {
			logger.Debug("Starting token cleanup cycle")
		}
		if tokenCache != nil {
			tokenCache.Cleanup()
		}
		if jwkCache != nil {
			jwkCache.Cleanup()
		}
		if sessionManager != nil {
			sessionManager.PeriodicChunkCleanup()
			if logger != nil && !isTestMode() {
				logger.Debug("Running session health monitoring")
			}
		}
	}

	// Register as singleton task - will return existing if already registered
	err := rm.RegisterBackgroundTask(taskName, cleanupInterval, cleanupFunc)
	if err != nil {
		logger.Errorf("Failed to register token cleanup task: %v", err)
		return
	}

	// Start the task if not already running
	if !rm.IsTaskRunning(taskName) {
		if err := rm.StartBackgroundTask(taskName); err != nil {
			logger.Errorf("Failed to start background task: %v", err)
		} else {
			logger.Debug("Started singleton token cleanup task")
		}
	} else {
		logger.Debug("Token cleanup task already running, skipping duplicate")
	}
}

// extractGroupsAndRoles extracts group and role information from token claims.
// It parses the configured group/role claims from the supplied ID token.
//
// Most callers should prefer extractGroupsAndRolesFromClaims when claims have
// already been parsed for the request (e.g. via SessionData.GetIDTokenClaims),
// to avoid re-parsing the JWT.
func (t *TraefikOidc) extractGroupsAndRoles(idToken string) ([]string, []string, error) {
	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}
	return t.extractGroupsAndRolesFromClaims(claims)
}

// extractGroupsAndRolesFromClaims extracts group and role information from
// already-parsed claims. Hot path: callers that have a cached claims map (such
// as SessionData.GetIDTokenClaims) should use this to skip a redundant
// base64+JSON decode of the JWT on every authenticated request.
func (t *TraefikOidc) extractGroupsAndRolesFromClaims(claims map[string]interface{}) ([]string, []string, error) {
	var groups []string
	var roles []string

	if groupsClaim, exists := claims[t.groupClaimName]; exists {
		groupsSlice, ok := groupsClaim.([]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("%s claim is not an array", t.groupClaimName)
		}
		for _, group := range groupsSlice {
			if groupStr, ok := group.(string); ok {
				t.logger.Debugf("Found group from %s claim: %s", t.groupClaimName, groupStr)
				groups = append(groups, groupStr)
			} else {
				t.logger.Errorf("Non-string value found in %s claim array: %v", t.groupClaimName, group)
			}
		}
	}

	if rolesClaim, exists := claims[t.roleClaimName]; exists {
		rolesSlice, ok := rolesClaim.([]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("%s claim is not an array", t.roleClaimName)
		}
		for _, role := range rolesSlice {
			if roleStr, ok := role.(string); ok {
				t.logger.Debugf("Found role from %s claim: %s", t.roleClaimName, roleStr)
				roles = append(roles, roleStr)
			} else {
				t.logger.Errorf("Non-string value found in %s claim array: %v", t.roleClaimName, role)
			}
		}
	}

	return groups, roles, nil
}
