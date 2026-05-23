// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains the core HTTP middleware functionality for request processing
// and authentication flow management.
package traefikoidc

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/utils"
)

// bypassReason describes why a request is being forwarded without OIDC auth.
// It is only used for logging and to decide whether extra side-effects
// (propagating the user header from an existing session) should run.
const (
	bypassReasonExcluded  = "excluded-url"
	bypassReasonSSE       = "sse"
	bypassReasonWebSocket = "websocket"
)

// isWebSocketUpgrade reports whether req is a WebSocket upgrade handshake
// (RFC 6455). The middleware can only see the handshake; once Traefik
// completes the upgrade it forwards frames directly, so we never re-process
// per-frame traffic. We bypass auth on the handshake the same way we do for
// SSE, because browser WebSocket clients cannot follow an OIDC redirect.
func isWebSocketUpgrade(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, token := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

// shouldBypassAuth decides whether a request must skip OIDC authentication
// entirely. It returns (true, reason) when either the request path matches a
// configured excluded URL, the Accept header asks for a text/event-stream
// response (SSE), or the request is a WebSocket upgrade handshake. The
// reason lets ServeHTTP apply any side-effects that are unique to the bypass
// kind (e.g. propagating user headers).
//
// This must be called BEFORE waiting on t.initComplete so excluded, SSE and
// WebSocket traffic is never blocked by a slow/broken provider.
func (t *TraefikOidc) shouldBypassAuth(req *http.Request) (bool, string) {
	if t.determineExcludedURL(req.URL.Path) {
		return true, bypassReasonExcluded
	}
	if strings.Contains(req.Header.Get("Accept"), "text/event-stream") {
		return true, bypassReasonSSE
	}
	if isWebSocketUpgrade(req) {
		return true, bypassReasonWebSocket
	}
	return false, ""
}

// applyBypassUserHeaders enforces authentication on SSE / WebSocket bypass
// requests and, on success, copies the authenticated user's identity onto
// the outgoing request so downstream services can see who the user is.
//
// Returns true when the request carries a valid authenticated session and
// the bypass should proceed. Returns false when no usable session is
// present; callers must then reject the request (typically with 401) to
// prevent unauthenticated traffic from reaching the backend just by setting
// `Accept: text/event-stream` or sending a WebSocket upgrade.
//
// The check is cookie-only: the session cookie is sealed by our encryption
// key, so the authenticated flag cannot be forged. We do NOT run full token
// signature verification here so that SSE/WS keeps working when the OIDC
// provider is briefly unavailable for JWK fetches.
func (t *TraefikOidc) applyBypassUserHeaders(req *http.Request, reason string) bool {
	if t.sessionManager == nil {
		return false
	}

	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Debugf("%s bypass: unable to load session: %v", reason, err)
		return false
	}
	defer session.returnToPoolSafely()

	if !session.GetAuthenticated() {
		t.logger.Debugf("%s bypass: rejecting request without authenticated session", reason)
		return false
	}

	userIdentifier := session.GetUserIdentifier()
	if userIdentifier == "" {
		t.logger.Debugf("%s bypass: rejecting request, session has no user identifier", reason)
		return false
	}

	req.Header.Set("X-Forwarded-User", userIdentifier)
	if !t.minimalHeaders {
		req.Header.Set("X-Auth-Request-User", userIdentifier)
	}
	t.logger.Debugf("%s bypass: forwarded user %s from session", reason, userIdentifier)
	return true
}

// ServeHTTP implements the main middleware logic for processing HTTP requests.
// It handles the complete OIDC authentication flow including:
//   - Excluded URL bypass
//   - Session validation and management
//   - Authentication callback processing
//   - Logout handling
//   - Token verification and refresh
//   - Header injection for authenticated requests
//
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The incoming HTTP request.
func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Log request entry for debugging routing issues
	t.logger.Debugf("Incoming request: %s %s", req.Method, req.URL.Path)

	// Handle logout requests early - before waiting for OIDC initialization
	// This allows users to logout even if the OIDC provider is unavailable
	if req.URL.Path == t.logoutURLPath {
		t.logger.Debugf("Logout path matched early: %s", req.URL.Path)
		t.handleLogout(rw, req)
		return
	}

	// Handle backchannel logout (IdP-initiated POST with logout_token)
	if t.enableBackchannelLogout && t.backchannelLogoutPath != "" && req.URL.Path == t.backchannelLogoutPath {
		t.logger.Debug("Backchannel logout path matched")
		t.handleBackchannelLogout(rw, req)
		return
	}

	// Handle front-channel logout (IdP-initiated GET with sid/iss in iframe)
	if t.enableFrontchannelLogout && t.frontchannelLogoutPath != "" && req.URL.Path == t.frontchannelLogoutPath {
		t.logger.Debug("Front-channel logout path matched")
		t.handleFrontchannelLogout(rw, req)
		return
	}

	if !strings.HasPrefix(req.URL.Path, "/health") {
		// Lock-free one-shot bootstrap. The previous firstRequestMutex.Lock()
		// fired on EVERY non-health request forever (even after the boolean
		// flipped true), which under Yaegi added a per-request serialization
		// point. CAS gives single-firing semantics with zero steady-state cost.
		if atomic.CompareAndSwapInt32(&t.firstRequestStarted, 0, 1) {
			t.logger.Debug("Starting background tasks on first request")
			t.startTokenCleanup()

			if t.providerURL != "" &&
				atomic.CompareAndSwapInt32(&t.metadataRefreshStartedAtomic, 0, 1) {
				// Metadata refresh is handled by singleton resource manager
				t.startMetadataRefresh(t.providerURL)
			}
		}
	}

	// Evaluate auth-bypass once, before waiting for initialization. Excluded
	// URLs, SSE and WebSocket upgrade requests must not block on provider
	// init. For SSE/WebSocket we ALSO require an authenticated session
	// (cookie-only check, no JWK fetch) and otherwise return 401 — clients
	// of in-flight streams can't follow an OIDC redirect, so forwarding
	// unauthenticated traffic would silently expose the backend.
	if bypass, reason := t.shouldBypassAuth(req); bypass {
		t.logger.Debugf("Bypassing OIDC for %s (%s)", req.URL.Path, reason)
		// When bearer auth is enabled, strip the Authorization header on
		// bypassed paths so a bearer token can't leak into health/metrics/
		// public endpoint logs via downstream services that don't expect it.
		// Excluded URLs are explicitly public; bearer is an artifact of the
		// API auth flow that doesn't belong on them.
		if t.enableBearerAuth {
			req.Header.Del("Authorization")
		}
		switch reason {
		case bypassReasonExcluded:
			// Operator-declared excluded URLs forward unconditionally.
			t.next.ServeHTTP(rw, req)
		case bypassReasonSSE, bypassReasonWebSocket:
			// Skip the OIDC redirect dance (clients can't follow it
			// mid-stream) but still require an authenticated session.
			// Otherwise an unauthenticated client could hit the backend
			// just by setting Accept: text/event-stream or sending a
			// WebSocket upgrade.
			if !t.applyBypassUserHeaders(req, reason) {
				t.sendErrorResponse(rw, req, "Authentication required", http.StatusUnauthorized)
				return
			}
			t.next.ServeHTTP(rw, req)
		default:
			t.next.ServeHTTP(rw, req)
		}
		return
	}

	// Log waiting for initialization to help diagnose hanging requests
	t.logger.Debug("Waiting for OIDC provider initialization...")

	// time.NewTimer + Stop avoids leaking a goroutine+channel for 30s on every
	// request when initComplete fires quickly (would happen with time.After).
	initTimer := time.NewTimer(30 * time.Second)
	defer initTimer.Stop()

	select {
	case <-t.initComplete:
		// Read issuerURL via atomic snapshot when available — replaces the
		// metadataMu.RLock that previously fired on every non-bypass request.
		// Under Yaegi each RLock acquisition costs 1-5ms of interpreter
		// dispatch; the snapshot is a single atomic.Value.Load. Falls back
		// to the legacy field+RLock for paths that haven't published a
		// snapshot yet (notably some test setups that initialize the struct
		// fields directly).
		var issuerURL string
		if snap := t.metadataSnap(); snap != nil {
			issuerURL = snap.IssuerURL
		} else {
			t.metadataMu.RLock()
			issuerURL = t.issuerURL
			t.metadataMu.RUnlock()
		}

		if issuerURL == "" {
			// Provider metadata initialization failed - try to recover.
			// Retry every 30 seconds to allow automatic recovery. Lock-free
			// throttle via CAS on lastMetadataRetryNano: one goroutine wins
			// the window, others see shouldRetry=false.
			nowNano := time.Now().UnixNano()
			last := atomic.LoadInt64(&t.lastMetadataRetryNano)
			shouldRetry := time.Duration(nowNano-last) >= 30*time.Second &&
				atomic.CompareAndSwapInt64(&t.lastMetadataRetryNano, last, nowNano)

			if shouldRetry && t.providerURL != "" {
				t.logger.Info("Attempting to recover OIDC provider metadata...")
				go t.attemptMetadataRecovery()
			}

			t.logger.Error("OIDC provider metadata initialization failed or incomplete")
			t.sendErrorResponse(rw, req, "OIDC provider metadata initialization failed - please check provider availability and configuration", http.StatusServiceUnavailable)
			return
		}
	case <-req.Context().Done():
		t.logger.Debug("Request canceled while waiting for OIDC initialization")
		t.sendErrorResponse(rw, req, "Request canceled", http.StatusRequestTimeout)
		return
	case <-initTimer.C:
		t.logger.Error("Timeout waiting for OIDC initialization")
		t.sendErrorResponse(rw, req, "Timeout waiting for OIDC provider initialization - please try again later", http.StatusServiceUnavailable)
		return
	}

	// Bypass checks already ran before the init wait; no need to repeat them.
	t.sessionManager.CleanupOldCookies(rw, req)

	// Bearer-token auth (opt-in). Runs after init (we need issuer+JWKs+aud
	// available) and after bypass (excluded URLs always win). Cookie-vs-
	// bearer precedence is configurable; the safe default is cookie-wins.
	// See bearer_auth.go for the full pipeline.
	if t.enableBearerAuth {
		if _, hasBearer := detectBearerToken(req); hasBearer {
			cookiePresent := t.hasSessionCookie(req)
			if !cookiePresent || t.bearerOverridesCookie {
				if cookiePresent {
					t.logger.Infof("Both Authorization: Bearer and session cookie present on %s; bearer-wins per BearerOverridesCookie=true", req.URL.Path)
				}
				t.handleBearerRequest(rw, req)
				return
			}
			t.logger.Infof("Both Authorization: Bearer and session cookie present on %s; cookie-wins (default); bearer ignored", req.URL.Path)
		}
	}

	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Error getting session: %v. Initiating authentication.", err)
		cleanReq := req.Clone(req.Context())
		session, _ = t.sessionManager.GetSession(cleanReq) // Safe to ignore: error already logged, proceeding with new session
		if session != nil {
			defer session.returnToPoolSafely()
			if clearErr := session.Clear(cleanReq, rw); clearErr != nil {
				t.logger.Errorf("Error clearing potentially corrupted session: %v", clearErr)
			}
		} else {
			t.logger.Error("Critical session error: Failed to get even a new session.")
			t.sendErrorResponse(rw, req, "Critical session error", http.StatusInternalServerError)
			return
		}
		// Sub-resource requests (script/image/fetch/serviceWorker) must not
		// trigger an OIDC redirect from this path either: they would overwrite
		// any in-flight CSRF/nonce in the session. Let the next HTML navigation
		// initiate the flow. See issue #129.
		if t.isAjaxRequest(req) || t.isNonNavigationRequest(req) {
			t.sendErrorResponse(rw, req, "Authentication required", http.StatusUnauthorized)
			return
		}
		scheme := utils.DetermineScheme(req, t.forceHTTPS)
		host := utils.DetermineHost(req)
		redirectURL := buildFullURL(scheme, host, t.redirURLPath)
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	defer session.returnToPoolSafely()

	scheme := utils.DetermineScheme(req, t.forceHTTPS)
	host := utils.DetermineHost(req)
	redirectURL := buildFullURL(scheme, host, t.redirURLPath)

	// Check if the current request is the OIDC callback
	t.logger.Debugf("Checking callback URL match: request_path=%q, configured_callback=%q", req.URL.Path, t.redirURLPath)
	if req.URL.Path == t.redirURLPath {
		t.logger.Debugf("Callback URL matched, processing OIDC callback (redirect_url=%s)", redirectURL)
		t.handleCallback(rw, req, redirectURL)
		return
	}
	t.logger.Debugf("Callback URL did not match (request_path=%q != configured=%q), continuing auth flow", req.URL.Path, t.redirURLPath)

	authenticated, needsRefresh, expired := t.isUserAuthenticated(session)

	if expired {
		t.logger.Debug("Session token is definitively expired or invalid, initiating re-auth")
		t.handleExpiredToken(rw, req, session, redirectURL)
		return
	}

	userIdentifier := session.GetUserIdentifier()
	// User authorization check
	if authenticated && userIdentifier != "" {
		if !t.isAllowedUser(userIdentifier) {
			t.logger.Infof("User %s is not authorized", userIdentifier)
			errorMsg := fmt.Sprintf("Access denied: You are not authorized to access this resource. To log out, visit: %s", t.logoutURLPath)
			t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	if authenticated && !needsRefresh {
		t.logger.Debug("User authenticated and token valid, proceeding to process authorized request")
		// Access token validation is already performed by provider-specific validation
		// methods (validateAzureTokens/validateStandardTokens) before reaching this point.
		// Redundant validation here was causing issues with Azure AD tokens that have
		// JWT format but unverifiable signatures. See issue #89.
		t.processAuthorizedRequest(rw, req, session, redirectURL)
		return
	}

	refreshTokenPresent := session.GetRefreshToken() != ""

	// Decide whether to answer with 401 instead of a redirect. AJAX requests
	// cannot follow a 302 into an IdP, and sub-resource loads (script/image/
	// fetch/serviceWorker) must not trigger a fresh OIDC flow because parallel
	// loads would each overwrite the session CSRF/nonce (issue #129). Only
	// top-level HTML navigations should redirect.
	isAjaxRequest := t.isAjaxRequest(req) || t.isNonNavigationRequest(req)

	// Check if refresh token is likely expired (older than 6 hours)
	refreshTokenExpired := refreshTokenPresent && t.isRefreshTokenExpired(session)

	shouldAttemptRefresh := needsRefresh && refreshTokenPresent && !refreshTokenExpired

	// If AJAX request and refresh token expired, return 401 immediately
	if isAjaxRequest && refreshTokenExpired {
		t.logger.Debug("AJAX request with expired refresh token, returning 401")
		t.sendErrorResponse(rw, req, "Session expired", http.StatusUnauthorized)
		return
	}

	if shouldAttemptRefresh {
		idToken := session.GetIDToken()
		if idToken != "" {
			jwt, err := parseJWT(idToken)
			if err == nil {
				claims := jwt.Claims
				if expClaim, ok := claims["exp"].(float64); ok {
					expTime := int64(expClaim)
					expTimeObj := time.Unix(expTime, 0)
					refreshThreshold := time.Now().Add(t.refreshGracePeriod)

					if !expTimeObj.Before(refreshThreshold) {
						t.logger.Debug("Token is valid and outside grace period, skipping refresh")
						t.processAuthorizedRequest(rw, req, session, redirectURL)
						return
					}
				} else {
					t.logger.Debug("Could not extract 'exp' claim for grace period check, proceeding with refresh")
				}
			}
		}

		if needsRefresh && authenticated {
			t.logger.Debug("Session token needs proactive refresh, attempting refresh")
		} else if needsRefresh && !authenticated {
			t.logger.Debug("ID token invalid/expired, but refresh token found. Attempting refresh.")
		}

		refreshed := t.refreshToken(rw, req, session)
		if refreshed {
			userIdentifier = session.GetUserIdentifier()
			if userIdentifier != "" && !t.isAllowedUser(userIdentifier) {
				t.logger.Infof("User with refreshed token %s is not authorized", userIdentifier)
				errorMsg := fmt.Sprintf("Access denied: You are not authorized to access this resource. To log out, visit: %s", t.logoutURLPath)
				t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
				return
			}

			t.logger.Debug("Token refresh successful, proceeding to process authorized request")
			t.processAuthorizedRequest(rw, req, session, redirectURL)
			return
		}

		t.logger.Debug("Token refresh failed, requiring re-authentication")
		if isAjaxRequest {
			t.logger.Debug("AJAX request with failed token refresh, sending 401 Unauthorized")
			t.sendErrorResponse(rw, req, "Token refresh failed", http.StatusUnauthorized)
		} else {
			t.logger.Debug("Browser request with failed token refresh, initiating re-auth")
			// Reset redirect count when starting fresh auth after failed refresh to prevent redirect loops
			session.ResetRedirectCount()
			t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		}
		return
	}

	t.logger.Debugf("Initiating full OIDC authentication flow (authenticated=%v, needsRefresh=%v, refreshTokenPresent=%v)", authenticated, needsRefresh, refreshTokenPresent)

	// If AJAX request without valid authentication, return 401
	if isAjaxRequest {
		t.logger.Debug("AJAX request requires authentication, sending 401 Unauthorized")
		t.sendErrorResponse(rw, req, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Reset redirect count when starting fresh authentication flow
	session.ResetRedirectCount()
	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// processAuthorizedRequest processes requests for authenticated cookie/session
// users. It performs session-specific checks (identifier presence, backchannel-
// logout invalidation, claims extraction with potential re-auth), persists
// dirty session state, then delegates the post-auth pipeline (roles/groups,
// header injection, security headers, cookie strip, forward) to
// forwardAuthorized.
//
// The bearer-token path uses the same forwardAuthorized helper but takes a
// different route to it (see bearer_auth.go). Keeping forwardAuthorized
// session-agnostic is what lets the two auth methods share one pipeline.
//
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request to process.
//   - session: The user's session data containing tokens and claims.
//   - redirectURL: The callback URL for re-authentication if needed.
func (t *TraefikOidc) processAuthorizedRequest(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	userIdentifier := session.GetUserIdentifier()
	if userIdentifier == "" {
		t.logger.Info("No user identifier found in session during final processing, initiating re-auth")
		// Reset redirect count to prevent loops when session is invalid
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	// Check if session has been invalidated via backchannel or front-channel logout
	if t.enableBackchannelLogout || t.enableFrontchannelLogout {
		idToken := session.GetIDToken()
		if idToken != "" {
			sid, sub, createdAt := t.extractSessionInfo(idToken)
			if t.isSessionInvalidated(sid, sub, createdAt) {
				t.logger.Infof("Session for user %s has been invalidated via IdP-initiated logout", userIdentifier)
				// Clear the session and redirect to login
				if err := session.Clear(req, rw); err != nil {
					t.logger.Errorf("Error clearing invalidated session: %v", err)
				}
				session.ResetRedirectCount()
				t.defaultInitiateAuthentication(rw, req, session, redirectURL)
				return
			}
		}
	}

	// Resolve ID-token claims at most once per request. SessionData caches
	// the parsed claims keyed on the raw ID token, so concurrent dashboard
	// panel requests on the same session don't repeatedly base64-decode and
	// JSON-unmarshal the same JWT (a real cost under the yaegi interpreter
	// that hosts Traefik plugins).
	idToken := session.GetIDToken()
	var (
		idClaims    map[string]interface{}
		idClaimsErr error
	)
	if idToken != "" {
		idClaims, idClaimsErr = session.GetIDTokenClaims(t.extractClaimsFunc)
	}

	// Choose which claims drive groups/roles extraction. Prefer the ID
	// token (cached) and fall back to the access token if there is no ID
	// token in the session — matching the prior behavior for opaque
	// ID-token providers.
	var (
		groupClaims    map[string]interface{}
		groupClaimsErr error
	)
	if idToken != "" {
		groupClaims, groupClaimsErr = idClaims, idClaimsErr
	} else if accessToken := session.GetAccessToken(); accessToken != "" {
		groupClaims, groupClaimsErr = t.extractClaimsFunc(accessToken)
	} else if len(t.allowedRolesAndGroups) > 0 {
		t.logger.Error("No token available but roles/groups checks are required")
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	if groupClaimsErr != nil && len(t.allowedRolesAndGroups) > 0 {
		// Claims couldn't be extracted but roles checks are required:
		// re-authenticate rather than 403 (session may be salvageable on
		// re-issue). Bearer path uses 401 for the equivalent failure.
		t.logger.Errorf("Failed to extract claims for roles/groups check: %v", groupClaimsErr)
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	// Persist any dirty session state BEFORE forwardAuthorized writes the
	// response. Once next.ServeHTTP fires, Set-Cookie can no longer reach
	// the client. The forwardAuthorized pipeline does not mutate session
	// state, so saving here is safe.
	if session.IsDirty() {
		if err := session.Save(req, rw); err != nil {
			t.logger.Errorf("Failed to save session after processing headers: %v", err)
		}
	} else {
		t.logger.Debug("Session not dirty, skipping save in processAuthorizedRequest")
	}

	// Build the source-agnostic principal. ID-token claims drive header
	// templates and roles when present; otherwise fall back to access-token
	// claims (matches prior behavior for opaque-ID-token providers).
	p := &principal{
		Source:       sourceSession,
		Identifier:   userIdentifier,
		AccessToken:  session.GetAccessToken(),
		IDToken:      idToken,
		RefreshToken: session.GetRefreshToken(),
		Claims:       groupClaims,
	}

	t.forwardAuthorized(rw, req, p)
}

// forwardAuthorized completes the post-authentication pipeline shared by the
// cookie/session path and the bearer-token path. It performs:
//
//  1. Roles/groups extraction from p.Claims (idempotent; existing
//     extractGroupsAndRolesFromClaims helper).
//  2. allowedRolesAndGroups gate — writes a 403 and returns if denied.
//  3. Identity-header injection (X-Forwarded-User, X-User-Groups, X-User-Roles,
//     plus X-Auth-Request-* when !minimalHeaders).
//  4. Operator-defined header templates.
//  5. Security headers (delegated to t.securityHeadersApplier or fallback).
//  6. OIDC session-cookie strip (stripAuthCookies).
//  7. Authorization header strip on bearer source when stripAuthorizationHeader.
//  8. next.ServeHTTP.
//
// Session persistence is the CALLER's responsibility — it must happen before
// this function so Set-Cookie reaches the response.
func (t *TraefikOidc) forwardAuthorized(rw http.ResponseWriter, req *http.Request, p *principal) {
	var (
		groups, roles []string
		extractErr    error
	)
	if p.Claims != nil {
		groups, roles, extractErr = t.extractGroupsAndRolesFromClaims(p.Claims)
		if extractErr != nil && len(t.allowedRolesAndGroups) > 0 {
			// Bearer path: 403 (caller already verified the token; principal
			// claims are present but malformed for roles purposes).
			// Cookie path can't reach here because processAuthorizedRequest
			// catches groupClaimsErr earlier.
			t.logger.Errorf("Failed to extract groups and roles: %v", extractErr)
			t.sendErrorResponse(rw, req, "Access denied", http.StatusForbidden)
			return
		}
		if extractErr == nil {
			if len(groups) > 0 {
				req.Header.Set("X-User-Groups", strings.Join(groups, ","))
			}
			if len(roles) > 0 {
				req.Header.Set("X-User-Roles", strings.Join(roles, ","))
			}
		}
	}

	if len(t.allowedRolesAndGroups) > 0 {
		allowed := false
		for _, roleOrGroup := range append(groups, roles...) {
			if _, ok := t.allowedRolesAndGroups[roleOrGroup]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			t.logger.Infof("User %s does not have any allowed roles or groups", p.Identifier)
			errorMsg := fmt.Sprintf("Access denied: You do not have any of the allowed roles or groups. To log out, visit: %s", t.logoutURLPath)
			t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
			return
		}
	}

	req.Header.Set("X-Forwarded-User", p.Identifier)

	// When minimalHeaders is enabled, skip extra headers to prevent 431 errors
	if !t.minimalHeaders {
		req.Header.Set("X-Auth-Request-Redirect", req.URL.RequestURI())
		req.Header.Set("X-Auth-Request-User", p.Identifier)
		if p.IDToken != "" {
			req.Header.Set("X-Auth-Request-Token", p.IDToken)
		}
	}

	if len(t.headerTemplates) > 0 {
		// p.Claims may be nil (e.g. session without an ID token). Templates
		// referencing .Claims.* will simply produce empty values — matches
		// the prior behavior. Bearer-source principals always carry access-
		// token claims (post-verifyToken).
		templateData := map[string]interface{}{
			"AccessToken":  p.AccessToken,
			"IDToken":      p.IDToken,
			"RefreshToken": p.RefreshToken,
			"Claims":       p.Claims,
		}

		for headerName, tmpl := range t.headerTemplates {
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, templateData); err != nil {
				t.logger.Errorf("Failed to execute template for header %s: %v", headerName, err)
				continue
			}
			headerValue := buf.String()
			req.Header.Set(headerName, headerValue)
			t.logger.Debugf("Set templated header %s = %s", headerName, headerValue)
		}
	}

	// Apply security headers if configured
	if t.securityHeadersApplier != nil {
		t.securityHeadersApplier(rw, req)
	} else {
		// Fallback to basic security headers
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-XSS-Protection", "1; mode=block")
		rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}

	// Strip OIDC session cookies before forwarding to the backend to prevent
	// HTTP 431 "Request Header Fields Too Large" errors (GitHub issue #122).
	if t.stripAuthCookies && t.sessionManager != nil {
		prefix := t.sessionManager.GetCookiePrefix()
		filtered := make([]*http.Cookie, 0, len(req.Cookies()))
		for _, c := range req.Cookies() {
			if !strings.HasPrefix(c.Name, prefix) {
				filtered = append(filtered, c)
			}
		}
		req.Header.Del("Cookie")
		for _, c := range filtered {
			req.AddCookie(c)
		}
	}

	// Bearer source: strip the Authorization header to keep the raw token
	// out of downstream service logs. Off-by-config for operators who chain
	// services that each re-verify the bearer.
	if p.Source == sourceBearer && t.stripAuthorizationHeader {
		req.Header.Del("Authorization")
	}

	t.logger.Debugf("Request authorized for user %s (source=%d), forwarding to next handler", p.Identifier, p.Source)

	t.next.ServeHTTP(rw, req)
}
