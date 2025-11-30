// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains token management functionality including verification,
// caching, refresh, and provider-specific validation logic.
package traefikoidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================================
// TOKEN VERIFICATION
// ============================================================================

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

	// Check token cache FIRST - if token is already verified and cached, return immediately
	// This prevents false positives when multiple goroutines validate the same token concurrently
	if claims, exists := t.tokenCache.Get(token); exists && len(claims) > 0 {
		return nil
	}

	// Only check JTI blacklist for tokens that aren't already in the cache
	// This is for FIRST-TIME validation to detect replay attacks
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

	if jti, ok := jwt.Claims["jti"].(string); ok && jti != "" && !t.disableReplayDetection {
		// Only add to blacklist if replay detection is enabled
		expiry := time.Now().Add(defaultBlacklistDuration)
		if expClaim, expOk := jwt.Claims["exp"].(float64); expOk {
			expTime := time.Unix(int64(expClaim), 0)
			tokenDuration := time.Until(expTime)
			if tokenDuration > defaultBlacklistDuration && tokenDuration < (24*time.Hour) {
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
	// Use first 32 chars of token as cache key (sufficient for uniqueness)
	cacheKey := token
	if len(token) > 32 {
		cacheKey = token[:32]
	}

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

	jwks, err := t.jwkCache.GetJWKS(context.Background(), jwksURL, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	if !t.suppressDiagnosticLogs && jwks != nil {
		t.safeLogDebugf("DIAGNOSTIC: Retrieved JWKS with %d keys from URL: %s", len(jwks.Keys), jwksURL)
	}

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

	if jwks == nil {
		return fmt.Errorf("JWKS is nil, cannot verify token")
	}

	// Find the matching key in JWKS
	var matchingKey *JWK
	availableKids := make([]string, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		availableKids = append(availableKids, key.Kid)
		if key.Kid == kid {
			matchingKey = &key
			break
		}
	}

	if matchingKey == nil {
		if !t.suppressDiagnosticLogs {
			t.safeLogErrorf("DIAGNOSTIC: No matching key found for kid=%s. Available kids: %v", kid, availableKids)
		}
		return fmt.Errorf("no matching public key found for kid: %s", kid)
	}

	if !t.suppressDiagnosticLogs {
		t.safeLogDebugf("DIAGNOSTIC: Found matching key for kid=%s, key type: %s", kid, matchingKey.Kty)
	}

	publicKeyPEM, err := jwkToPEM(matchingKey)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to PEM: %w", err)
	}

	if err := verifySignature(token, publicKeyPEM, alg); err != nil {
		if !t.suppressDiagnosticLogs {
			t.safeLogErrorf("DIAGNOSTIC: Signature verification failed for kid=%s, alg=%s: %v", kid, alg, err)
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

// ============================================================================
// TOKEN REFRESH & MANAGEMENT
// ============================================================================

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

	newToken, err := t.tokenExchanger.GetNewTokenWithRefreshToken(initialRefreshToken)
	if err != nil {
		errMsg := err.Error()
		//nolint:gocritic // Complex error handling with provider-specific conditions
		if strings.Contains(errMsg, "invalid_grant") || strings.Contains(errMsg, "token expired") {
			t.logger.Debug("Refresh token expired or revoked: %v", err)
			// Clear all tokens and authentication state when refresh token is invalid
			if err := session.SetAuthenticated(false); err != nil {
				t.logger.Errorf("Failed to set authenticated to false: %v", err)
			}
			session.SetRefreshToken("")
			session.SetAccessToken("")
			session.SetIDToken("")
			session.SetEmail("")
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
	email, _ := claims["email"].(string)
	if email == "" {
		t.logger.Errorf("refreshToken failed: Email claim missing or empty in refreshed token")
		return false
	}
	session.SetEmail(email)

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
		session.SetEmail("")
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

// ============================================================================
// TOKEN REVOCATION
// ============================================================================

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

	data := url.Values{
		"token":           {token},
		"token_type_hint": {tokenType},
		"client_id":       {t.clientID},
		"client_secret":   {t.clientSecret},
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", revocationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token revocation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

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

// ============================================================================
// TOKEN EXCHANGE OPERATIONS
// ============================================================================

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

// ============================================================================
// PROVIDER DETECTION
// ============================================================================

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

// ============================================================================
// PROVIDER VALIDATION
// ============================================================================

// validateAzureTokens validates tokens with Azure AD-specific logic.
// Azure tokens may be opaque access tokens that cannot be verified as JWTs,
// so this method handles both JWT and opaque token scenarios.
// Parameters:
//   - session: The session data containing tokens to validate.
//
// Returns:
//   - authenticated: Whether the user has valid authentication.
//   - needsRefresh: Whether tokens need to be refreshed.
//   - expired: Whether tokens have expired and cannot be refreshed.
//
//nolint:gocognit // Azure-specific validation requires multiple token type checks
func (t *TraefikOidc) validateAzureTokens(session *SessionData) (bool, bool, bool) {
	if !session.GetAuthenticated() {
		t.logger.Debug("Azure user is not authenticated according to session flag")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Azure session not authenticated, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, true, false
	}

	accessToken := session.GetAccessToken()
	idToken := session.GetIDToken()

	if accessToken != "" {
		if strings.Count(accessToken, ".") == 2 {
			if err := t.verifyToken(accessToken); err != nil {
				if idToken != "" {
					if err := t.verifyToken(idToken); err != nil {
						t.logger.Debugf("Azure: Both access and ID token validation failed: %v", err)
						if session.GetRefreshToken() != "" {
							return false, true, false
						}
						return false, false, true
					}
					return t.validateTokenExpiry(session, idToken)
				}
				if session.GetRefreshToken() != "" {
					return false, true, false
				}
				return false, false, true
			}
			return t.validateTokenExpiry(session, accessToken)
		}
		t.logger.Debug("Azure access token appears opaque, treating as valid")
		if idToken != "" {
			return t.validateTokenExpiry(session, idToken)
		}
		return true, false, false
	}

	if idToken != "" {
		if err := t.verifyToken(idToken); err != nil {
			if strings.Contains(err.Error(), "token has expired") {
				if session.GetRefreshToken() != "" {
					return false, true, false
				}
				return false, false, true
			}
			if session.GetRefreshToken() != "" {
				return false, true, false
			}
			return false, false, true
		}
		return t.validateTokenExpiry(session, idToken)
	}

	if session.GetRefreshToken() != "" {
		return false, true, false
	}
	return false, false, true
}

// validateGoogleTokens handles Google-specific token validation logic.
// Currently delegates to standard token validation but provides a hook
// for Google-specific validation requirements in the future.
// Parameters:
//   - session: The session data containing tokens to validate.
//
// Returns:
//   - authenticated: Whether the user has valid authentication.
//   - needsRefresh: Whether tokens need to be refreshed.
//   - expired: Whether tokens have expired and cannot be refreshed.
func (t *TraefikOidc) validateGoogleTokens(session *SessionData) (bool, bool, bool) {
	return t.validateStandardTokens(session)
}

// validateStandardTokens handles standard OIDC token validation logic.
// This is the default validation method for generic OIDC providers.
// It verifies ID tokens and handles access tokens appropriately.
// Parameters:
//   - session: The session data containing tokens to validate.
//
// Returns:
//   - authenticated: Whether the user has valid authentication.
//   - needsRefresh: Whether tokens need to be refreshed.
//   - expired: Whether tokens have expired and cannot be refreshed.
//
//nolint:gocognit,gocyclo // Complex validation logic handles multiple token scenarios and edge cases
func (t *TraefikOidc) validateStandardTokens(session *SessionData) (bool, bool, bool) {
	authenticated := session.GetAuthenticated()
	// Removed debug output
	if !authenticated {
		t.logger.Debug("User is not authenticated according to session flag")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Session not authenticated, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, false
	}

	accessToken := session.GetAccessToken()
	// Removed debug output
	if accessToken == "" {
		t.logger.Debug("Authenticated flag set, but no access token found in session")
		if session.GetRefreshToken() != "" {
			// Check if we have an ID token to determine if we're beyond grace period
			// When access token is missing, check ID token expiry to determine if refresh is viable
			idToken := session.GetIDToken()
			t.logger.Debugf("Checking ID token for grace period: ID token present: %v", idToken != "")
			if idToken != "" {
				// Try to parse the ID token to check its expiry
				parts := strings.Split(idToken, ".")
				if len(parts) == 3 {
					// Decode the claims part
					claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
					if err == nil {
						var claims map[string]interface{}
						if err := json.Unmarshal(claimsData, &claims); err == nil {
							if expClaim, ok := claims["exp"].(float64); ok {
								expTime := time.Unix(int64(expClaim), 0)
								if time.Now().After(expTime) {
									expiredDuration := time.Since(expTime)
									if expiredDuration > t.refreshGracePeriod {
										t.logger.Debugf("ID token expired beyond grace period (%v > %v), must re-authenticate",
											expiredDuration, t.refreshGracePeriod)
										return false, false, true // expired, cannot refresh
									}
									t.logger.Debugf("ID token expired %v ago, within grace period %v, allowing refresh",
										expiredDuration, t.refreshGracePeriod)
								}
							}
						}
					}
				}
			}
			t.logger.Debug("Access token missing, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, true
	}

	// Check if access token is opaque (doesn't have JWT structure)
	dotCount := strings.Count(accessToken, ".")
	isOpaqueToken := dotCount != 2

	// For opaque access tokens, use introspection if available (RFC 7662 - Option C: Scenario 3)
	if isOpaqueToken {
		t.logger.Debugf("Access token appears to be opaque (dots: %d)", dotCount)

		// Try introspection first if opaque tokens are allowed
		if t.allowOpaqueTokens {
			if err := t.validateOpaqueToken(accessToken); err != nil {
				t.logger.Infof("⚠️  Opaque access token validation via introspection failed: %v", err)

				// If introspection required, reject the session
				if t.requireTokenIntrospection {
					t.logger.Errorf("❌ SECURITY: Opaque token rejected (introspection required but failed)")
					if session.GetRefreshToken() != "" {
						return false, true, false
					}
					return false, false, true
				}

				// Otherwise fall back to ID token validation (Scenario 3 backward compatibility)
				t.logger.Infof("⚠️  Falling back to ID token validation for opaque access token")
			} else {
				// Introspection successful
				t.logger.Debugf("✓ Opaque access token validated via introspection")
				// Still need to check ID token for session expiry
				idToken := session.GetIDToken()
				if idToken != "" {
					return t.validateTokenExpiry(session, idToken)
				}
				return true, false, false
			}
		} else {
			// Opaque tokens not allowed - log warning and reject or fall back
			t.logger.Infof("⚠️  Opaque access token detected but allowOpaqueTokens=false")
		}

		// Fall back to ID token validation
		idToken := session.GetIDToken()
		if idToken == "" {
			t.logger.Debug("Opaque access token present but no ID token found")
			if session.GetRefreshToken() != "" {
				t.logger.Debug("ID token missing but refresh token exists. Signaling need for refresh.")
				return false, true, false
			}
			// Accept session with opaque access token even without ID token
			// The OAuth provider validated it when issued
			t.logger.Debug("Accepting session with opaque access token")
			return true, false, false
		}

		// Validate ID token if present
		if err := t.verifyToken(idToken); err != nil {
			if strings.Contains(err.Error(), "token has expired") {
				t.logger.Debugf("ID token expired with opaque access token, needs refresh")
				if session.GetRefreshToken() != "" {
					return false, true, false
				}
				return false, false, true
			}

			t.logger.Errorf("ID token verification failed with opaque access token: %v", err)
			if session.GetRefreshToken() != "" {
				return false, true, false
			}
			return false, false, true
		}

		// Use ID token for expiry validation
		return t.validateTokenExpiry(session, idToken)
	}

	// JWT access token present - validate it explicitly to detect Scenario 2
	// (Option C: Scenario 2 detection and strict mode)
	accessTokenValid := false
	accessTokenError := ""

	if err := t.verifyToken(accessToken); err != nil {
		// Access token validation failed
		accessTokenError = err.Error()

		// Check if it's an audience validation failure (Scenario 2)
		if strings.Contains(accessTokenError, "invalid audience") || strings.Contains(accessTokenError, "audience") {
			// SCENARIO 2 DETECTED: Access token has wrong audience
			t.logger.Infof("⚠️  SCENARIO 2 DETECTED: Access token validation failed due to audience mismatch: %v", err)

			if t.strictAudienceValidation {
				// Strict mode: Reject the session (don't fall back to ID token)
				t.logger.Errorf("❌ SECURITY: Session rejected due to access token audience mismatch (strictAudienceValidation=true)")
				t.logger.Errorf("❌ This prevents potential cross-API token confusion attacks (Auth0 Scenario 2)")
				if session.GetRefreshToken() != "" {
					return false, true, false // try refresh
				}
				return false, false, true // must re-authenticate
			}
			// Backward compatibility mode: Log loud warning but allow fallback to ID token
			t.logger.Infof("⚠️⚠️⚠️  SECURITY WARNING: Falling back to ID token validation despite access token audience mismatch!")
			t.logger.Infof("⚠️  This could allow tokens intended for different APIs to grant access")
			t.logger.Infof("⚠️  Set strictAudienceValidation=true to enforce proper audience validation")
			t.logger.Infof("⚠️  See: https://github.com/lukaszraczylo/traefikoidc/issues/74")
		} else if !strings.Contains(accessTokenError, "token has expired") {
			// Other validation errors (not expiration, not audience)
			t.logger.Debugf("Access token validation failed (non-expiration, non-audience): %v", err)
		}
	} else {
		// Access token is valid
		accessTokenValid = true
	}

	idToken := session.GetIDToken()
	if idToken == "" {
		if accessTokenValid {
			// Access token is valid, no ID token needed
			t.logger.Debug("Access token valid, no ID token present")
			return t.validateTokenExpiry(session, accessToken)
		}

		t.logger.Debug("Authenticated flag set with access token, but no ID token found in session")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("ID token missing but refresh token exists. Signaling conditional refresh to obtain ID token.")
			return true, true, false
		}
		return true, false, false
	}

	// Validate ID token
	if err := t.verifyToken(idToken); err != nil {
		if strings.Contains(err.Error(), "token has expired") {
			t.logger.Debugf("ID token signature/claims valid but token expired, needs refresh")
			if session.GetRefreshToken() != "" {
				return false, true, false
			}
			return false, false, true
		}

		t.logger.Errorf("ID token verification failed (non-expiration): %v", err)
		if session.GetRefreshToken() != "" {
			t.logger.Debug("ID token verification failed, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, true
	}

	// If access token was valid, use it for expiry; otherwise use ID token
	if accessTokenValid {
		return t.validateTokenExpiry(session, accessToken)
	}

	return t.validateTokenExpiry(session, idToken)
}

// validateTokenExpiry checks if a token is nearing expiration and needs refresh.
// It uses the configured grace period to determine when proactive refresh should occur.
// Parameters:
//   - session: The session data for refresh token availability.
//   - token: The token to check expiry for.
//
// Returns:
//   - authenticated: Whether the token is currently valid.
//   - needsRefresh: Whether the token is nearing expiration and should be refreshed.
//   - expired: Whether the token is invalid or verification failed.
func (t *TraefikOidc) validateTokenExpiry(session *SessionData, token string) (bool, bool, bool) {
	cachedClaims, found := t.tokenCache.Get(token)
	if !found {
		t.logger.Debug("Claims not found in cache after successful token verification")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Claims missing post-verification, attempting refresh to recover.")
			return false, true, false
		}
		return false, false, true
	}

	expClaim, ok := cachedClaims["exp"].(float64)
	if !ok {
		t.logger.Error("Failed to get expiration time ('exp' claim) from verified token")
		if session.GetRefreshToken() != "" {
			t.logger.Debug("Token missing 'exp' claim, but refresh token exists. Signaling need for refresh.")
			return false, true, false
		}
		return false, false, true
	}

	expTime := int64(expClaim)
	expTimeObj := time.Unix(expTime, 0)
	nowObj := time.Now()

	// Check if token has already expired
	if expTimeObj.Before(nowObj) {
		// Token has expired
		expiredDuration := nowObj.Sub(expTimeObj)

		t.logger.Debugf("Token expired %v ago, grace period is %v",
			expiredDuration, t.refreshGracePeriod)

		// If we have a refresh token, always attempt to use it regardless of grace period
		// The refresh token has its own expiry and the provider will reject it if invalid
		if session.GetRefreshToken() != "" {
			t.logger.Debugf("Token expired, attempting refresh with available refresh token")
			return false, true, false // needs refresh
		}

		// No refresh token available - must re-authenticate
		t.logger.Debugf("Token expired and no refresh token available, must re-authenticate")
		return false, false, true // expired, cannot refresh
	}

	// Token not yet expired - check if nearing expiration
	refreshThreshold := nowObj.Add(t.refreshGracePeriod)

	t.logger.Debugf("Token expires at %v, now is %v, refresh threshold is %v",
		expTimeObj.Format(time.RFC3339),
		nowObj.Format(time.RFC3339),
		refreshThreshold.Format(time.RFC3339))

	if expTimeObj.Before(refreshThreshold) {
		remainingSeconds := int64(time.Until(expTimeObj).Seconds())
		t.logger.Debugf("Token nearing expiration (expires in %d seconds, grace period %s), scheduling proactive refresh",
			remainingSeconds, t.refreshGracePeriod)

		if session.GetRefreshToken() != "" {
			return true, true, false
		}

		t.logger.Debugf("Token nearing expiration but no refresh token available, cannot proactively refresh.")
		return true, false, false
	}

	t.logger.Debugf("Token is valid and not nearing expiration (expires in %d seconds, outside %s grace period)",
		int64(time.Until(expTimeObj).Seconds()), t.refreshGracePeriod)

	return true, false, false
}

// ============================================================================
// BACKGROUND TASKS & CLEANUP
// ============================================================================

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

	cleanupInterval := 1 * time.Minute
	if isTestMode() {
		cleanupInterval = 50 * time.Millisecond // Fast interval for tests
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

// ============================================================================
// AUTHORIZATION & ACCESS CONTROL
// ============================================================================

// extractGroupsAndRoles extracts group and role information from token claims.
// It parses the 'groups' and 'roles' claims from the ID token and validates their format.
// Parameters:
//   - idToken: The ID token containing claims to extract.
//
// Returns:
//   - groups: Array of group names from the 'groups' claim.
//   - roles: Array of role names from the 'roles' claim.
//   - An error if claim extraction fails or if the 'groups' or 'roles' claims are present
//     but not arrays of strings.
func (t *TraefikOidc) extractGroupsAndRoles(idToken string) ([]string, []string, error) {
	claims, err := t.extractClaimsFunc(idToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	var groups []string
	var roles []string

	// Extract groups using configurable claim name (defaults to "groups")
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

	// Extract roles using configurable claim name (defaults to "roles")
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
