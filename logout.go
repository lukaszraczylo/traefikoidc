// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file implements OIDC Backchannel Logout (OpenID Connect Back-Channel Logout 1.0)
// and Front-Channel Logout (OpenID Connect Front-Channel Logout 1.0) functionality.
package traefikoidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// logoutTokenType is the expected typ claim for logout tokens
	// #nosec G101 -- This is a JWT type claim value from OIDC spec, not a credential
	logoutTokenType = "logout+jwt"

	// sessionInvalidationTTL is how long to remember invalidated sessions
	// Should be at least as long as your session max age
	sessionInvalidationTTL = 25 * time.Hour
)

// LogoutTokenClaims represents the claims in an OIDC logout token
// as defined in OpenID Connect Back-Channel Logout 1.0
type LogoutTokenClaims struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub,omitempty"`
	Audience  interface{}            `json:"aud"` // Can be string or []string
	IssuedAt  int64                  `json:"iat"`
	JTI       string                 `json:"jti"`
	Events    map[string]interface{} `json:"events"`
	SessionID string                 `json:"sid,omitempty"`
	Nonce     string                 `json:"nonce,omitempty"` // Must NOT be present
}

// handleBackchannelLogout processes OIDC Backchannel Logout requests.
// It accepts POST requests with a logout_token parameter containing a JWT
// that identifies which session(s) to terminate.
//
// According to OpenID Connect Back-Channel Logout 1.0:
// - The logout_token is a JWT signed by the IdP
// - It contains either a 'sid' (session ID) or 'sub' (subject) claim to identify the session
// - The RP must validate the token and invalidate the matching session(s)
//
// Parameters:
//   - rw: The HTTP response writer
//   - req: The HTTP request containing the logout_token
func (t *TraefikOidc) handleBackchannelLogout(rw http.ResponseWriter, req *http.Request) {
	t.logger.Debug("Processing backchannel logout request")

	// Backchannel logout must be POST
	if req.Method != http.MethodPost {
		t.logger.Errorf("Backchannel logout: invalid method %s, expected POST", req.Method)
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data to get logout_token
	if err := req.ParseForm(); err != nil {
		t.logger.Errorf("Backchannel logout: failed to parse form: %v", err)
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return
	}

	logoutToken := req.FormValue("logout_token")
	if logoutToken == "" {
		// Also try reading from request body as raw JWT
		body, err := io.ReadAll(io.LimitReader(req.Body, 64*1024)) // 64KB limit
		if err == nil && len(body) > 0 {
			logoutToken = string(body)
		}
	}

	if logoutToken == "" {
		t.logger.Error("Backchannel logout: missing logout_token")
		http.Error(rw, "logout_token required", http.StatusBadRequest)
		return
	}

	// Parse and validate the logout token
	claims, err := t.validateLogoutToken(logoutToken)
	if err != nil {
		t.logger.Errorf("Backchannel logout: token validation failed: %v", err)
		// Return 400 for invalid token per spec
		http.Error(rw, "Invalid logout token", http.StatusBadRequest)
		return
	}

	// Invalidate session(s) based on sid or sub
	if err := t.invalidateSession(claims.SessionID, claims.Subject); err != nil {
		t.logger.Errorf("Backchannel logout: failed to invalidate session: %v", err)
		http.Error(rw, "Failed to invalidate session", http.StatusInternalServerError)
		return
	}

	t.logger.Infof("Backchannel logout: successfully invalidated session (sid=%s, sub=%s)",
		claims.SessionID, claims.Subject)

	// Return 200 OK with empty body per spec
	rw.WriteHeader(http.StatusOK)
}

// handleFrontchannelLogout processes OIDC Front-Channel Logout requests.
// It accepts GET requests with 'iss' and 'sid' query parameters that identify
// which session to terminate. The IdP typically loads this URL in an iframe.
//
// According to OpenID Connect Front-Channel Logout 1.0:
// - The request contains 'iss' (issuer) and optionally 'sid' (session ID)
// - The RP should clear the session and return a response (typically empty or image)
// - The response must be cacheable to allow the IdP to load it in an iframe
//
// Parameters:
//   - rw: The HTTP response writer
//   - req: The HTTP request containing iss and sid parameters
func (t *TraefikOidc) handleFrontchannelLogout(rw http.ResponseWriter, req *http.Request) {
	t.logger.Debug("Processing front-channel logout request")

	// Front-channel logout should be GET
	if req.Method != http.MethodGet {
		t.logger.Errorf("Front-channel logout: invalid method %s, expected GET", req.Method)
		http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get iss and sid from query parameters
	iss := req.URL.Query().Get("iss")
	sid := req.URL.Query().Get("sid")

	// Validate issuer matches our expected issuer
	t.metadataMu.RLock()
	expectedIssuer := t.issuerURL
	t.metadataMu.RUnlock()

	if iss != "" && iss != expectedIssuer {
		t.logger.Errorf("Front-channel logout: issuer mismatch: got %s, expected %s", iss, expectedIssuer)
		http.Error(rw, "Invalid issuer", http.StatusBadRequest)
		return
	}

	// Must have at least sid for front-channel logout
	if sid == "" {
		t.logger.Error("Front-channel logout: missing sid parameter")
		http.Error(rw, "sid parameter required", http.StatusBadRequest)
		return
	}

	// Invalidate the session
	if err := t.invalidateSession(sid, ""); err != nil {
		t.logger.Errorf("Front-channel logout: failed to invalidate session: %v", err)
		http.Error(rw, "Failed to invalidate session", http.StatusInternalServerError)
		return
	}

	t.logger.Infof("Front-channel logout: successfully invalidated session (sid=%s)", sid)

	// Return a minimal HTML response that's suitable for iframe loading
	// Set headers to allow embedding and caching
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache, no-store")
	rw.Header().Set("Pragma", "no-cache")
	// Allow embedding in iframes from any origin (required for front-channel logout)
	rw.Header().Del("X-Frame-Options")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("<!DOCTYPE html><html><head><title>Logged Out</title></head><body></body></html>"))
}

// validateLogoutToken parses and validates a logout token JWT.
// It verifies the token signature, issuer, audience, and required claims.
//
// Parameters:
//   - tokenString: The raw JWT logout token
//
// Returns:
//   - The parsed logout token claims
//   - An error if validation fails
func (t *TraefikOidc) validateLogoutToken(tokenString string) (*LogoutTokenClaims, error) {
	// Parse the JWT
	jwt, err := parseJWT(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse logout token: %w", err)
	}

	// Check token type if present
	if typ, ok := jwt.Header["typ"].(string); ok {
		// The typ should be "logout+jwt" or omitted
		if typ != "" && typ != logoutTokenType && typ != "JWT" {
			return nil, fmt.Errorf("invalid token type: %s", typ)
		}
	}

	// Verify signature only (not standard claims - logout tokens don't have 'exp')
	if err := t.verifyLogoutTokenSignature(jwt, tokenString); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Extract claims
	claims := &LogoutTokenClaims{}
	claimsJSON, err := json.Marshal(jwt.Claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}
	if err := json.Unmarshal(claimsJSON, claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Validate required claims
	t.metadataMu.RLock()
	expectedIssuer := t.issuerURL
	t.metadataMu.RUnlock()

	// Validate issuer
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("issuer mismatch: got %s, expected %s", claims.Issuer, expectedIssuer)
	}

	// Validate audience (must contain our client_id)
	if !t.validateLogoutTokenAudience(claims.Audience) {
		return nil, fmt.Errorf("audience validation failed")
	}

	// Validate iat (issued at) - must be present and not too old
	if claims.IssuedAt == 0 {
		return nil, fmt.Errorf("missing iat claim")
	}
	iatTime := time.Unix(claims.IssuedAt, 0)
	// Allow up to 5 minutes clock skew and 10 minutes token age
	if time.Since(iatTime) > 15*time.Minute {
		return nil, fmt.Errorf("logout token too old: issued at %v", iatTime)
	}
	// Token should not be from the future (with 5 min clock skew tolerance)
	if iatTime.After(time.Now().Add(5 * time.Minute)) {
		return nil, fmt.Errorf("logout token issued in the future: %v", iatTime)
	}

	// Validate events claim - must contain the logout event
	if claims.Events == nil {
		return nil, fmt.Errorf("missing events claim")
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return nil, fmt.Errorf("missing backchannel-logout event in events claim")
	}

	// Validate that nonce is NOT present (per spec)
	if claims.Nonce != "" {
		return nil, fmt.Errorf("nonce claim must not be present in logout token")
	}

	// Must have either sid or sub (or both)
	if claims.SessionID == "" && claims.Subject == "" {
		return nil, fmt.Errorf("logout token must contain either sid or sub claim")
	}

	return claims, nil
}

// validateLogoutTokenAudience checks if the logout token audience contains our client_id
func (t *TraefikOidc) validateLogoutTokenAudience(aud interface{}) bool {
	switch v := aud.(type) {
	case string:
		return v == t.clientID
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == t.clientID {
				return true
			}
		}
	case []string:
		for _, a := range v {
			if a == t.clientID {
				return true
			}
		}
	}
	return false
}

// verifyLogoutTokenSignature verifies only the signature of a logout token.
// Unlike VerifyJWTSignatureAndClaims, this does NOT validate standard claims like 'exp'
// because logout tokens don't have an expiration claim per OIDC Back-Channel Logout spec.
//
// Parameters:
//   - jwt: The parsed JWT structure
//   - tokenString: The raw token string for signature verification
//
// Returns:
//   - An error if signature verification fails
func (t *TraefikOidc) verifyLogoutTokenSignature(jwt *JWT, tokenString string) error {
	t.logger.Debug("Verifying logout token signature")

	// Read jwksURL with RLock
	t.metadataMu.RLock()
	jwksURL := t.jwksURL
	t.metadataMu.RUnlock()

	jwks, err := t.jwkCache.GetJWKS(context.Background(), jwksURL, t.httpClient)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	if jwks == nil {
		return fmt.Errorf("JWKS is nil, cannot verify token")
	}

	kid, ok := jwt.Header["kid"].(string)
	if !ok || kid == "" {
		return fmt.Errorf("missing key ID in token header")
	}

	alg, ok := jwt.Header["alg"].(string)
	if !ok || alg == "" {
		return fmt.Errorf("missing algorithm in token header")
	}

	// Find the matching key in JWKS
	var matchingKey *JWK
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			matchingKey = &key
			break
		}
	}

	if matchingKey == nil {
		return fmt.Errorf("no matching public key found for kid: %s", kid)
	}

	publicKeyPEM, err := jwkToPEM(matchingKey)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to PEM: %w", err)
	}

	if err := verifySignature(tokenString, publicKeyPEM, alg); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	t.logger.Debug("Logout token signature verified successfully")
	return nil
}

// invalidateSession marks a session as invalidated in the session invalidation cache.
// It stores entries by both sid and sub if available.
//
// Parameters:
//   - sid: The session ID to invalidate (from the 'sid' claim)
//   - sub: The subject to invalidate (from the 'sub' claim)
//
// Returns:
//   - An error if the invalidation fails
func (t *TraefikOidc) invalidateSession(sid, sub string) error {
	if t.sessionInvalidationCache == nil {
		return fmt.Errorf("session invalidation cache not initialized")
	}

	now := time.Now().Unix()

	// Store by session ID
	if sid != "" {
		key := t.buildSessionInvalidationKey("sid", sid)
		t.sessionInvalidationCache.Set(key, now, sessionInvalidationTTL)
		t.logger.Debugf("Invalidated session by sid: %s", sid)
	}

	// Store by subject (invalidates all sessions for this user)
	if sub != "" {
		key := t.buildSessionInvalidationKey("sub", sub)
		t.sessionInvalidationCache.Set(key, now, sessionInvalidationTTL)
		t.logger.Debugf("Invalidated session by sub: %s", sub)
	}

	return nil
}

// isSessionInvalidated checks if a session has been invalidated via backchannel
// or front-channel logout.
//
// Parameters:
//   - sid: The session ID to check
//   - sub: The subject to check
//   - sessionCreatedAt: When the session was created (to compare against invalidation time)
//
// Returns:
//   - true if the session has been invalidated, false otherwise
func (t *TraefikOidc) isSessionInvalidated(sid, sub string, sessionCreatedAt time.Time) bool {
	if t.sessionInvalidationCache == nil {
		return false
	}

	// Truncate session creation time to seconds for fair comparison with Unix timestamps
	sessionCreatedAtSec := sessionCreatedAt.Truncate(time.Second)

	// Check by session ID first (more specific)
	if sid != "" {
		key := t.buildSessionInvalidationKey("sid", sid)
		if val, found := t.sessionInvalidationCache.Get(key); found {
			if invalidatedAt, ok := val.(int64); ok {
				// Session was invalidated at or after it was created
				invalidationTime := time.Unix(invalidatedAt, 0)
				if !invalidationTime.Before(sessionCreatedAtSec) {
					t.logger.Debugf("Session invalidated by sid: %s", sid)
					return true
				}
			}
		}
	}

	// Check by subject (all sessions for this user)
	if sub != "" {
		key := t.buildSessionInvalidationKey("sub", sub)
		if val, found := t.sessionInvalidationCache.Get(key); found {
			if invalidatedAt, ok := val.(int64); ok {
				// Sessions for this subject created at or before invalidation are invalid
				invalidationTime := time.Unix(invalidatedAt, 0)
				if !invalidationTime.Before(sessionCreatedAtSec) {
					t.logger.Debugf("Session invalidated by sub: %s", sub)
					return true
				}
			}
		}
	}

	return false
}

// buildSessionInvalidationKey creates a cache key for session invalidation
func (t *TraefikOidc) buildSessionInvalidationKey(keyType, value string) string {
	return fmt.Sprintf("session_invalidation:%s:%s", keyType, value)
}

// extractSessionInfo extracts sid and sub from an ID token for session tracking
func (t *TraefikOidc) extractSessionInfo(idToken string) (sid, sub string, createdAt time.Time) {
	if idToken == "" {
		return "", "", time.Time{}
	}

	jwt, err := parseJWT(idToken)
	if err != nil {
		return "", "", time.Time{}
	}

	// Extract sid (session ID)
	if sidVal, ok := jwt.Claims["sid"].(string); ok {
		sid = sidVal
	}

	// Extract sub (subject)
	if subVal, ok := jwt.Claims["sub"].(string); ok {
		sub = subVal
	}

	// Extract iat for session creation time
	if iatVal, ok := jwt.Claims["iat"].(float64); ok {
		createdAt = time.Unix(int64(iatVal), 0)
	} else {
		// Default to now if iat not present
		createdAt = time.Now()
	}

	return sid, sub, createdAt
}

// determineLogoutPath checks if the given path matches any logout URL
func (t *TraefikOidc) determineLogoutPath(path string) string {
	// Check backchannel logout path
	if t.backchannelLogoutPath != "" && path == t.backchannelLogoutPath {
		return "backchannel"
	}

	// Check front-channel logout path
	if t.frontchannelLogoutPath != "" && path == t.frontchannelLogoutPath {
		return "frontchannel"
	}

	// Check regular logout path (for RP-initiated logout)
	if path == t.logoutURLPath {
		return "rp"
	}

	return ""
}

// normalizeLogoutPath ensures logout paths start with /
func normalizeLogoutPath(path string) string {
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}
