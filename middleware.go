// Package traefikoidc provides OIDC authentication middleware for Traefik.
// This file contains the core HTTP middleware functionality for request processing
// and authentication flow management.
package traefikoidc

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/traefikoidc/internal/utils"
)

// trackingWriter wraps an http.ResponseWriter so the deferred panic handler
// can tell whether a response was already committed. WriteHeader is
// idempotent so calling it again after commit is a no-op, but a later
// Write appends to the committed body - so writing "Internal Server
// Error" after a handler has already produced a valid 200 (or a 302
// redirect) corrupts the response. Flush/Hijack are forwarded so
// downstream SSE and WebSocket handlers keep working through the wrapper.
type trackingWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *trackingWriter) WriteHeader(code int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *trackingWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

func (w *trackingWriter) Flush() {
	w.wroteHeader = true
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.wroteHeader = true
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *trackingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// bypassReason describes why a request is being forwarded without OIDC auth.
// It is only used for logging and to decide whether extra side-effects
// (propagating the user header from an existing session) should run.
const (
	bypassReasonExcluded  = "excluded-url"
	bypassReasonSSE       = "sse"
	bypassReasonWebSocket = "websocket"
	bypassReasonOptions   = "options"
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
	// CORS preflights carry no session cookie and must reach the backend so
	// it can answer with Access-Control-Allow-*. Otherwise the 401 here
	// (with no ACAO headers, since the security applier only runs on the
	// authenticated path) makes the browser block the cross-origin
	// request entirely and the real request never proceeds (R124).
	if req.Method == http.MethodOptions {
		return true, bypassReasonOptions
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
// The second return value (0 when forwarding) is the HTTP status to send
// when the request is rejected, letting the caller distinguish a 401
// (unauthenticated) from a 403 (authenticated but not permitted).
// identityHeaders are the headers this middleware owns upstream. It
// unconditionally strips any inbound values with these names before
// forwarding — both on authenticated and bypassed requests — so forged
// values (e.g. X-Forwarded-User: admin on a public path) can never
// reach the backend and be trusted for downstream authorization.
var identityHeaders = []string{
	"X-Forwarded-User",
	"X-User-Groups",
	"X-User-Roles",
	"X-Auth-Request-User",
	"X-Auth-Request-Redirect",
	"X-Auth-Request-Token",
}

// stripIdentityHeaders removes any inbound identity headers from req. The
// middleware re-injects its own authoritative values afterwards where
// appropriate. See identityHeaders.
func stripIdentityHeaders(req *http.Request) {
	for _, h := range identityHeaders {
		req.Header.Del(h)
	}
}

func (t *TraefikOidc) applyBypassUserHeaders(req *http.Request, reason string) (bool, int) {
	if t.sessionManager == nil {
		return false, http.StatusUnauthorized
	}

	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Debugf("%s bypass: unable to load session: %v", reason, err)
		return false, http.StatusUnauthorized
	}
	defer session.returnToPoolSafely()

	if !session.GetAuthenticated() {
		t.logger.Debugf("%s bypass: rejecting request without authenticated session", reason)
		return false, http.StatusUnauthorized
	}

	userIdentifier := session.GetUserIdentifier()
	if userIdentifier == "" {
		t.logger.Debugf("%s bypass: rejecting request, session has no user identifier", reason)
		return false, http.StatusUnauthorized
	}

	// Enforce the user allowlist, mirroring the normal path's authorization
	// check (isAllowedUser). Without this, an authenticated user not in
	// allowedUsers (or whose domain is not in allowedUserDomains) could
	// reach the backend just by using the SSE/WebSocket bypass.
	if !t.isAllowedUser(userIdentifier) {
		t.logger.Infof("User %s is not authorized (bypass)", userIdentifier)
		return false, http.StatusForbidden
	}

	// Enforce the allowedRolesAndGroups gate, mirroring forwardAuthorized:
	// an authenticated user without any permitted role/group must not reach
	// the SSE/WebSocket backend just by using the streaming bypass. Claims
	// come from the session's ID token by preference, falling back to the
	// access token when there is no ID token — the same source selection the
	// main authorization path (processAuthorizedRequest) uses. Without the
	// fallback, opaque-ID-token providers (groups only in the access token)
	// were granted on normal requests but 403'd on the streaming bypass
	// (R118).
	if len(t.allowedRolesAndGroups) > 0 {
		var groupClaims map[string]interface{}
		var claimsErr error
		if idToken := session.GetIDToken(); idToken != "" {
			groupClaims, claimsErr = session.GetIDTokenClaims(t.extractClaimsFunc)
		} else if accessToken := session.GetAccessToken(); accessToken != "" {
			groupClaims, claimsErr = t.extractClaimsFunc(accessToken)
		}
		if claimsErr != nil || groupClaims == nil {
			t.logger.Debugf("%s bypass: cannot read claims for role check (err=%v): %s", reason, claimsErr, userIdentifier)
			return false, http.StatusForbidden
		}
		groups, roles, extErr := t.extractGroupsAndRolesFromClaims(groupClaims)
		if extErr != nil {
			t.logger.Debugf("%s bypass: role extraction failed for %s: %v", reason, userIdentifier, extErr)
			return false, http.StatusForbidden
		}
		allowed := false
		for _, roleOrGroup := range append(groups, roles...) {
			if _, ok := t.allowedRolesAndGroups[roleOrGroup]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			t.logger.Infof("User %s does not have any allowed roles or groups (bypass)", userIdentifier)
			return false, http.StatusForbidden
		}
	}

	// This middleware fully owns the identity headers it injects upstream, even
	// on the SSE/WebSocket bypass path. Unconditionally remove inbound values
	// for the same names first: a client can forge X-User-Groups /
	// X-Auth-Request-User etc. on a bypassed request, and since this path
	// only sets X-Forwarded-User / X-Auth-Request-User (never groups/roles),
	// forged group/role headers would otherwise survive to the backend,
	// which commonly trusts them for downstream authorization. Must precede
	// the sanitize gate so even the drop-on-unsafe early return has already
	// cleared forged values (R100).
	stripIdentityHeaders(req)

	// Sanitize the claim-derived identifier before it is injected as a
	// header, matching forwardAuthorized (which uses safeIdentifier). The
	// value originates from an IdP-controlled claim and can contain CRLF
	// or delimiter characters that would otherwise inject or confuse
	// downstream header parsing. On failure, drop the header but still
	// honor the bypass (the identity headers are decoration here).
	safeIdentifier, ok := sanitizeHeaderClaimValue(userIdentifier, t.headerClaimMaxLen())
	if !ok {
		t.logger.Debugf("%s bypass: dropping unsafe user-identifier header: %s", reason, headerClaimValueReason(userIdentifier, t.headerClaimMaxLen()))
		return true, 0
	}

	req.Header.Set("X-Forwarded-User", safeIdentifier)
	if !t.minimalHeaders {
		req.Header.Set("X-Auth-Request-User", safeIdentifier)
	}
	t.logger.Debugf("%s bypass: forwarded user %s from session", reason, safeIdentifier)
	return true, 0
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
//
// shouldSkipGraceRefresh reports whether a proactive refresh can be skipped for
// this request. The token forwarded downstream (forwardAuthorized) is the
// ACCESS token, and needsRefresh (validateStandardTokensRS -> validateTokenExpiryRS)
// is derived from the ACCESS token's expiry whenever it is a verifiable JWT.
// Basing the skip decision on the (possibly longer-lived) ID token's exp would
// forward a stale access token whenever the ID token is still fresh. Base it on
// the access token's expiry, falling back to the ID token only when the access
// token is opaque and unparseable (worst case: refresh when a skip might have
// been possible — the safe direction).
func (t *TraefikOidc) shouldSkipGraceRefresh(session *SessionData) bool {
	return skipRefreshForTokens(session.GetAccessToken(), session.GetIDToken(), t.refreshGracePeriod)
}

// skipRefreshForTokens reports whether a proactive refresh can be skipped given
// the session's access and ID tokens.
func skipRefreshForTokens(accessToken, idToken string, grace time.Duration) bool {
	graceToken := accessToken
	graceJWT, graceErr := parseJWT(graceToken)
	if graceErr != nil || graceJWT == nil {
		graceToken = idToken
		graceJWT, graceErr = parseJWT(graceToken)
	}
	if graceJWT == nil || graceErr != nil {
		return false
	}
	expClaim, ok := graceJWT.Claims["exp"].(float64)
	if !ok {
		return false
	}
	expTimeObj := time.Unix(int64(expClaim), 0)
	return !expTimeObj.Before(time.Now().Add(grace))
}

func (t *TraefikOidc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Track whether a response has been committed so the panic handler can
	// avoid appending an error body to an already-emitted valid response.
	tw := &trackingWriter{ResponseWriter: rw}
	rw = tw
	// Recover from any panic in the handler chain (session decode, token
	// validation, header injection, authorize-url build) so a bug answers a
	// single clean 500 (and logs a stack) instead of escaping to net/http,
	// which closes/truncates the connection. If the response was already
	// committed by a handler (200 + body or a redirect), WriteHeader is an
	// idempotent no-op and appending the body would corrupt a valid
	// response, so only write when nothing has been sent yet.
	defer func() {
		if r := recover(); r != nil {
			t.logger.Errorf("OIDC handler panic recovered: %v\n%s", r, debug.Stack())
			if !tw.wroteHeader {
				// A panic-induced 500 must not be cached (consistent with
				// every other auth-failure response, R101/R172).
				rw.Header().Set("Cache-Control", "no-store")
				rw.WriteHeader(http.StatusInternalServerError)
				_, _ = rw.Write([]byte("Internal Server Error"))
			}
		}
	}()

	// Apply security headers to EVERY response this middleware authors
	// (redirects, error pages, bypass forwards, and authenticated
	// forwards), not just the forwardAuthorized tail. Previously they only
	// reached successfully-authenticated forwarding, so the initial
	// 302-to-IdP, /health, /metrics, error pages and SSE/WS responses
	// carried no Strict-Transport-Security / framing / MIME sniffing
	// protections (R132).
	if t.securityHeadersApplier != nil {
		t.securityHeadersApplier(rw, req)
	} else {
		// Fallback to basic security headers
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("X-XSS-Protection", "1; mode=block")
		rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}

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
		// Also honor stripAuthorizationHeader (default true) so a raw
		// client-supplied Authorization header is not forwarded verbatim on
		// the SSE/WebSocket/excluded bypass — the same leak R144 closed for
		// the normal path was left open on the streaming bypass (R151).
		if t.enableBearerAuth || t.stripAuthorizationHeader {
			req.Header.Del("Authorization")
		}
		switch reason {
		case bypassReasonExcluded:
			// Operator-declared excluded URLs forward unconditionally.
			// These are public paths; still strip any client-forged
			// identity headers so X-Forwarded-User / X-User-Groups etc.
			// on a public endpoint can't be trusted downstream (R102).
			stripIdentityHeaders(req)
			t.next.ServeHTTP(rw, req)
		case bypassReasonSSE, bypassReasonWebSocket:
			// Skip the OIDC redirect dance (clients can't follow it
			// mid-stream) but still require an authenticated session.
			// Otherwise an unauthenticated client could hit the backend
			// just by setting Accept: text/event-stream or sending a
			// WebSocket upgrade.
			if ok, status := t.applyBypassUserHeaders(req, reason); !ok {
				msg := "Authentication required"
				if status == http.StatusForbidden {
					msg = "Access denied"
				}
				t.sendErrorResponse(rw, req, msg, status)
				return
			}
			t.next.ServeHTTP(rw, req)
		case bypassReasonOptions:
			// CORS preflight: forward unconditionally (no session needed)
			// so the backend can answer with CORS headers.
			stripIdentityHeaders(req)
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
			if clearErr := session.Clear(cleanReq, rw); clearErr != nil {
				t.logger.Errorf("Error clearing potentially corrupted session: %v", clearErr)
			}
			// Clear() returns the session to the object pool, so discard the
			// pointer — reusing it would be a use-after-return, since a
			// concurrent GetSession may already own the pooled object
			// (cross-request session bleed / data race). Obtain a fresh
			// owned session in the shared block below. (R108)
			session = nil
		}
		if session == nil {
			// Session cookie is expired (past sessionMaxAge): a fresh
			// GetSession still re-reads the same expired cookie and returns
			// nil, so obtain a clean session and let the shared block below
			// re-initiate authentication rather than returning 500 —
			// otherwise every request past the session max age is a 500
			// with no way to recover (R97).
			session = t.sessionManager.newSession(cleanReq)
			if session == nil {
				t.logger.Error("Critical session error: Failed to get even a new session.")
				t.sendErrorResponse(rw, req, "Critical session error", http.StatusInternalServerError)
				return
			}
			defer session.returnToPoolSafely()
			t.logger.Infof("Session expired or unreadable; re-initiating authentication")
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

	// Capture per-request state: one RLock on sd.sessionMutex covers all the
	// getter values the handler chain needs (instead of 5-7 separate
	// session.GetX() calls each acquiring their own RLock under Yaegi).
	// metadataSnap is also stored once so downstream handlers don't repeat
	// the atomic.Value.Load.
	rs := (&requestState{
		scheme:      scheme,
		host:        host,
		redirectURL: redirectURL,
		next:        t.next,
		metadata:    t.metadataSnap(),
	}).captureSession(session)

	// Check if the current request is the OIDC callback
	t.logger.Debugf("Checking callback URL match: request_path=%q, configured_callback=%q", req.URL.Path, t.redirURLPath)
	if req.URL.Path == t.redirURLPath {
		t.logger.Debugf("Callback URL matched, processing OIDC callback (redirect_url=%s)", redirectURL)
		// The authorization-code response is delivered to the redirect
		// endpoint via HTTP GET (RFC 6749 §3.1.2): handleCallback reads
		// code/state/error only from the query string (form_post is not
		// supported - a POST would see an empty query and fail with "No
		// authorization code" anyway). Reject other methods with 405 so a
		// HEAD/non-GET probe doesn't consume the one-time state and code
		// and emit a 302 (R181).
		if req.Method != http.MethodGet {
			t.logger.Debugf("Callback requested with method %s (want GET); returning 405", req.Method)
			rw.Header().Set("Cache-Control", "no-store")
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.handleCallback(rw, req, redirectURL)
		return
	}
	t.logger.Debugf("Callback URL did not match (request_path=%q != configured=%q), continuing auth flow", req.URL.Path, t.redirURLPath)

	// Token validation reads session via the captured snapshot — saves ~21
	// sd.sessionMutex.RLock acquisitions (Yaegi-dispatched, ~1-5ms each)
	// across the validation path.
	authenticated, needsRefresh, expired := t.isUserAuthenticatedRS(rs)

	if expired {
		// AJAX / sub-resource requests must not follow a 302 into the IdP:
		// parallel loads would each overwrite the shared session's CSRF/nonce
		// mid-navigation (issue #129), the same reason the sibling branches
		// below return 401 instead of redirecting.
		if t.isAjaxRequest(req) || t.isNonNavigationRequest(req) {
			t.logger.Debug("Session token expired on AJAX/sub-resource request, sending 401")
			t.sendErrorResponse(rw, req, "Authentication required", http.StatusUnauthorized)
			return
		}
		t.logger.Debug("Session token is definitively expired or invalid, initiating re-auth")
		t.handleExpiredToken(rw, req, session, redirectURL)
		return
	}

	userIdentifier := rs.userIdentifier
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
		t.processAuthorizedRequestRS(rw, req, rs)
		return
	}

	refreshTokenPresent := rs.refreshToken != ""

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
		// Only skip the proactive refresh when the session is genuinely
		// authenticated. skipRefreshForTokens only parseJWT's the access
		// token and reads the raw exp claim — it does not verify the
		// signature or identity, so gating on the authenticated flag keeps
		// an unauthenticated session (or one that failed verification for a
		// non-expiry reason) from being bare-forwarded past the allowlist
		// gate (R142).
		if authenticated && t.shouldSkipGraceRefresh(session) {
			t.logger.Debug("Token is valid and outside grace period, skipping refresh")
			t.processAuthorizedRequest(rw, req, session, redirectURL)
			return
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
//
// processAuthorizedRequestRS is the requestState-aware variant of
// processAuthorizedRequest. It reads SessionData fields from the captured
// snapshot in rs instead of calling session.GetX() (each of which acquires
// sd.sessionMutex.RLock — under Yaegi every RLock pays ~1-5ms of interpreter
// dispatch). Only session-mutating operations (Save, ResetRedirectCount,
// Clear, IsDirty) still go through the session pointer because those write
// state and have no snapshot.
func (t *TraefikOidc) processAuthorizedRequestRS(rw http.ResponseWriter, req *http.Request, rs *requestState) {
	session := rs.session
	redirectURL := rs.redirectURL
	userIdentifier := rs.userIdentifier
	if userIdentifier == "" {
		t.logger.Info("No user identifier found in session during final processing, initiating re-auth")
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	// Check if session has been invalidated via backchannel or front-channel logout
	idToken := rs.idToken
	if t.enableBackchannelLogout || t.enableFrontchannelLogout {
		if idToken != "" {
			sid, sub, _ := t.extractSessionInfo(idToken)
			createdAt := t.sessionCreatedAtForInvalidation(idToken, session)
			if t.isSessionInvalidated(sid, sub, createdAt) {
				t.logger.Infof("Session for user %s has been invalidated via IdP-initiated logout", userIdentifier)
				if err := session.Clear(req, rw); err != nil {
					t.logger.Errorf("Error clearing invalidated session: %v", err)
				}
				// Clear already returned `session` to the shared pool via
				// returnToPoolSafely; re-acquire an owned session so a
				// concurrent GetSession can't pop the pooled object while we
				// write the re-auth challenge into it.
				ns, gerr := t.sessionManager.GetSession(req)
				if gerr != nil {
					t.logger.Errorf("Error creating session for re-authentication: %v", gerr)
					t.sendErrorResponse(rw, req, "Failed to start re-authentication", http.StatusInternalServerError)
					return
				}
				ns.ResetRedirectCount()
				t.defaultInitiateAuthentication(rw, req, ns, redirectURL)
				ns.returnToPoolSafely()
				return
			}
		}
	}

	// Resolve ID-token claims at most once per request. SessionData caches
	// the parsed claims keyed on the raw ID token.
	var (
		idClaims    map[string]interface{}
		idClaimsErr error
	)
	if idToken != "" {
		idClaims, idClaimsErr = session.GetIDTokenClaims(t.extractClaimsFunc)
	}

	var (
		groupClaims    map[string]interface{}
		groupClaimsErr error
	)
	if idToken != "" {
		groupClaims, groupClaimsErr = idClaims, idClaimsErr
	} else if rs.accessToken != "" {
		groupClaims, groupClaimsErr = t.extractClaimsFunc(rs.accessToken)
	} else if len(t.allowedRolesAndGroups) > 0 {
		t.logger.Error("No token available but roles/groups checks are required")
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	if groupClaimsErr != nil && len(t.allowedRolesAndGroups) > 0 {
		t.logger.Errorf("Failed to extract claims for roles/groups check: %v", groupClaimsErr)
		session.ResetRedirectCount()
		t.defaultInitiateAuthentication(rw, req, session, redirectURL)
		return
	}

	// Persist any dirty session state BEFORE forwardAuthorized writes the
	// response.
	if session.IsDirty() {
		if err := session.Save(req, rw); err != nil {
			t.logger.Errorf("Failed to save session after processing headers: %v", err)
		}
	} else {
		t.logger.Debug("Session not dirty, skipping save in processAuthorizedRequest")
	}

	p := &principal{
		Source:       sourceSession,
		Identifier:   userIdentifier,
		AccessToken:  rs.accessToken,
		IDToken:      idToken,
		RefreshToken: rs.refreshToken,
		Claims:       groupClaims,
	}

	t.forwardAuthorized(rw, req, p)
}

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
			sid, sub, _ := t.extractSessionInfo(idToken)
			createdAt := t.sessionCreatedAtForInvalidation(idToken, session)
			if t.isSessionInvalidated(sid, sub, createdAt) {
				t.logger.Infof("Session for user %s has been invalidated via IdP-initiated logout", userIdentifier)
				// Clear the session and redirect to login
				if err := session.Clear(req, rw); err != nil {
					t.logger.Errorf("Error clearing invalidated session: %v", err)
				}
				// Clear already returned `session` to the shared pool via
				// returnToPoolSafely; re-acquire an owned session so a
				// concurrent GetSession can't pop the pooled object while we
				// write the re-auth challenge into it.
				ns, gerr := t.sessionManager.GetSession(req)
				if gerr != nil {
					t.logger.Errorf("Error creating session for re-authentication: %v", gerr)
					t.sendErrorResponse(rw, req, "Failed to start re-authentication", http.StatusInternalServerError)
					return
				}
				ns.ResetRedirectCount()
				t.defaultInitiateAuthentication(rw, req, ns, redirectURL)
				ns.returnToPoolSafely()
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
// headerTemplateMaxLen bounds the length of a rendered operator-defined header
// template before it is forwarded downstream. Generous enough for an
// "Authorization: Bearer <jwt>" value but small enough to reject obviously
// abusive output. Matches the input-validation default header cap (8KB).
const headerTemplateMaxLen = 8192

// noValueSentinel is Go's text/template placeholder for a missing key in an
// interface-valued map. It is stripped from rendered header values so an
// optional claim the provider does not emit does not leak "<no value>".
const noValueSentinel = "<no value>"

// noValueTokenRe matches "<no value>" only as a whole token (bounded by
// non-alphanumerics or string end), so a legitimate claim value that
// happens to contain the substring survives the strip instead of being
// corrupted (R103).
var noValueTokenRe = regexp.MustCompile(`(^|[^0-9A-Za-z])` + regexp.QuoteMeta(noValueSentinel) + `([^0-9A-Za-z]|$)`)

// stripNoValueSentinels removes text/template's missing-key placeholder
// only when it appears as a whole token.
func stripNoValueSentinels(s string) string {
	return noValueTokenRe.ReplaceAllString(s, "${1}${2}")
}

// headerClaimMaxLen returns the maximum accepted length for a claim-derived
// header value (principal identifier, group, role). Reuses the operator-
// configured identifier cap (default 256) so a single setting governs both
// auth paths; falls back to 256 when unset.
func (t *TraefikOidc) headerClaimMaxLen() int {
	if t.maxIdentifierLength > 0 {
		return t.maxIdentifierLength
	}
	return 256
}

// sanitizeHeaderClaimList drops any group/role value that fails claim
// sanitization (control chars, bidi-override runes, the , ; = delimiters, or an
// over-long value) and returns the surviving values. Failing closed on a bad
// entry prevents header injection and stops an embedded comma from injecting
// extra entries into the comma-joined header. headerName is used only for
// debug logging — the value is never logged.
func (t *TraefikOidc) sanitizeHeaderClaimList(values []string, headerName string) []string {
	if len(values) == 0 {
		return nil
	}
	safe := make([]string, 0, len(values))
	for _, v := range values {
		if clean, ok := sanitizeHeaderClaimValue(v, t.headerClaimMaxLen()); ok {
			safe = append(safe, clean)
		} else {
			t.logger.Debugf("Dropping %s entry: value failed claim sanitization", headerName)
		}
	}
	return safe
}

// joinBoundedClaimHeader joins sanitized claim values with commas, bounding
// the TOTAL length to headerTemplateMaxLen. A provider can return an
// unbounded number of groups/roles; joining them all into a single header
// would let an oversized value reach a downstream proxy that rejects or
// truncates over-long headers (431), even though each value already passed
// the per-value cap. Accumulates as many leading values as fit, so a
// well-formed list is unaffected; an empty result means nothing fit and the
// caller should drop the header (fail-closed).
func joinBoundedClaimHeader(values []string) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	for _, v := range values {
		sep := 0
		if b.Len() > 0 {
			sep = 1 // leading comma
		}
		if b.Len()+sep+len(v) > headerTemplateMaxLen {
			break
		}
		if sep > 0 {
			b.WriteByte(',')
		}
		b.WriteString(v)
	}
	return b.String()
}

func (t *TraefikOidc) forwardAuthorized(rw http.ResponseWriter, req *http.Request, p *principal) {
	// This middleware fully owns the identity headers it injects upstream.
	// Unconditionally remove any inbound values with the same names first:
	// a request could carry a forged X-User-Groups / X-Auth-Request-User
	// etc. that, if the middleware computes no value for one of them
	// (e.g. an authenticated user with no groups, an absent ID token, a
	// a header-template skip), would otherwise survive through to the
	// backend and be trusted for downstream authorization. Clearing here —
	// before any conditional Set — makes the values we emit authoritative.
	stripIdentityHeaders(req)

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
			// Sanitize each group/role before it is joined into a comma-
			// delimited header. The cookie/session path does not otherwise
			// sanitize claim-derived values (the bearer path sanitizes its
			// identifier at construction), so a control char would enable
			// header injection and an embedded comma would inject extra
			// entries into the comma-joined header. Fail closed: drop any
			// value that does not pass.
			// X-User-Groups / X-User-Roles are the largest variably-sized
			// forward headers; gate them behind minimalHeaders like the
			// X-Auth-Request-* family so group-heavy users don't still trip
			// HTTP 431 on the backend (the failure minimalHeaders exists to
			// prevent, #64). Identity (X-Forwarded-User) stays
			// unconditional; the allowedRolesAndGroups gate below still
			// evaluates groups regardless of emission.
			if !t.minimalHeaders {
				if safeGroups := t.sanitizeHeaderClaimList(groups, "X-User-Groups"); len(safeGroups) > 0 {
					if gh := joinBoundedClaimHeader(safeGroups); gh != "" {
						req.Header.Set("X-User-Groups", gh)
					}
				}
				if safeRoles := t.sanitizeHeaderClaimList(roles, "X-User-Roles"); len(safeRoles) > 0 {
					if rh := joinBoundedClaimHeader(safeRoles); rh != "" {
						req.Header.Set("X-User-Roles", rh)
					}
				}
			}
		}
	}

	// Bearer (M2M) path: enforce allowedUsers / allowedUserDomains the same
	// way every cookie-path entry point does. The bearer path reaches here
	// via buildPrincipalFromBearerToken with no earlier isAllowedUser check;
	// without this, a valid bearer whose subject is absent from the
	// allowlist would still be forwarded, making the restriction a no-op.
	if p.Source == sourceBearer && !t.isAllowedUser(p.Identifier) {
		t.logger.Infof("Bearer user %s is not in allowed users or domains", p.Identifier)
		errorMsg := fmt.Sprintf("Access denied: User not allowed. To log out, visit: %s", t.logoutURLPath)
		t.sendErrorResponse(rw, req, errorMsg, http.StatusForbidden)
		return
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

	// Sanitize the principal identifier before injecting it into headers. The
	// bearer path already sanitizes its identifier at construction; the
	// cookie/session path does not, so a claim carrying control chars, bidi-
	// override runes, or , ; = could inject or spoof header content. Fail
	// closed: drop the identifier header(s) rather than forward a tainted value.
	safeIdentifier, identifierOK := sanitizeHeaderClaimValue(p.Identifier, t.headerClaimMaxLen())
	if identifierOK {
		req.Header.Set("X-Forwarded-User", safeIdentifier)
	} else {
		t.logger.Debugf("Dropping X-Forwarded-User header: identifier failed claim sanitization")
	}

	// When minimalHeaders is enabled, skip extra headers to prevent 431 errors
	if !t.minimalHeaders {
		req.Header.Set("X-Auth-Request-Redirect", req.URL.RequestURI())
		if identifierOK {
			req.Header.Set("X-Auth-Request-User", safeIdentifier)
		} else {
			t.logger.Debugf("Dropping X-Auth-Request-User header: identifier failed claim sanitization")
		}
		if p.IDToken != "" {
			// Bound the raw ID token to the same header budget as rendered
			// template values so a large token can't push this (and every
			// other header on the request) past nginx/traefik 431 limits.
			idTokenHeader := p.IDToken
			if len(idTokenHeader) > headerTemplateMaxLen {
				idTokenHeader = idTokenHeader[:headerTemplateMaxLen]
			}
			req.Header.Set("X-Auth-Request-Token", idTokenHeader)
		}
	}

	// Strip the raw inbound Authorization header for BOTH auth paths when
	// configured. The bearer path already stripped it; the cookie/session
	// path forwarded a client-supplied Authorization verbatim, letting a
	// session user present an arbitrary (and possibly more privileged)
	// bearer that a downstream verifier might trust over X-Forwarded-User,
	// or leaking a raw token into downstream logs. Kept out of downstream
	// logs and make X-Forwarded-User / X-Auth-Request-Token the
	// authoritative identity signal. Stripped here, before header-template
	// application, so an operator-supplied Authorization template (e.g.
	// "Authorization: Bearer {{.AccessToken}}") can re-supply the
	// downstream value rather than being immediately deleted.
	if t.stripAuthorizationHeader {
		req.Header.Del("Authorization")
	}

	if len(t.headerTemplates) > 0 {
		// p.Claims may be nil (e.g. session without an ID token). Templates
		// referencing .Claims.* will simply produce empty values — matches
		// the prior behavior. Bearer-source principals always carry access-
		// token claims (post-verifyToken).
		templateData := map[string]interface{}{
			"AccessToken":  p.AccessToken,
			"IDToken":      p.IDToken,
			"IdToken":      p.IDToken, // documented spelling (README/CONFIGURATION); alias so {{.IdToken}} renders (issue #149 review)
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
			// Go's text/template renders a missing key in an interface-valued
			// map as the literal "<no value>" even with missingkey=zero
			// (zero only applies to typed keys). Replace that sentinel so an
			// optional claim the provider did not emit (e.g. email) does not
			// leak "<no value>" into the downstream header.
			if strings.Contains(headerValue, noValueSentinel) {
				headerValue = stripNoValueSentinels(headerValue)
			}
			// Skip an empty render: Setting "" would clobber an identity
			// header (X-Forwarded-User / X-Auth-Request-*) already injected
			// earlier in this function with the authenticated value, silently
			// dropping the user identity at the backend.
			if headerValue == "" {
				t.logger.Debugf("Skipping templated header %s: rendered value is empty", headerName)
				continue
			}
			// Sanitize the rendered output: template inputs are claim-derived
			// and attacker-influenceable, so reject control chars (header
			// injection), bidi-override runes, the , ; = delimiters, and an
			// over-long value. Fail closed by dropping the header rather than
			// forwarding a tainted value. Do not log the value (it commonly
			// carries the access token); log only name + reason.
			if reason := headerValueReason(headerValue, headerTemplateMaxLen); reason != "" {
				t.logger.Debugf("Dropping templated header %s: value failed sanitization (%s)", headerName, reason)
				continue
			}
			req.Header.Set(headerName, headerValue)
			// Do not log the value: templated headers commonly carry the access
			// token (e.g. "Authorization: Bearer {{.AccessToken}}"), and logging
			// it — even at debug — leaks credentials into logs.
			t.logger.Debugf("Set templated header %s (%d bytes)", headerName, len(headerValue))
		}
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

	t.logger.Debugf("Request authorized for user %s (source=%d), forwarding to next handler", p.Identifier, p.Source)

	t.next.ServeHTTP(rw, req)
}
