package traefikoidc

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// validateRedirectCount checks if redirect limit is exceeded and handles the error
func (t *TraefikOidc) validateRedirectCount(session *SessionData, rw http.ResponseWriter, req *http.Request) error {
	const maxRedirects = 5
	redirectCount := session.GetRedirectCount()
	if redirectCount >= maxRedirects {
		t.logger.Errorf("Maximum redirect limit (%d) exceeded, possible redirect loop detected", maxRedirects)
		session.ResetRedirectCount()
		// Persist the reset so the NEXT request starts at 0 and can
		// attempt auth again. Without Save, the reset only touched the
		// in-memory session value (dirty flag set but never flushed): the
		// cookie still carried the old count, so every subsequent
		// request re-observed redirect_count==max and the user was
		// hard-locked on 508 for the whole session with no recovery
		// (R123).
		if err := session.Save(req, rw); err != nil {
			t.logger.Errorf("Failed to save session after redirect reset: %v", err)
		}
		t.sendErrorResponse(rw, req, "Authentication failed: Too many redirects", http.StatusLoopDetected)
		return fmt.Errorf("redirect limit exceeded")
	}

	session.IncrementRedirectCount()
	return nil
}

// generatePKCEParameters generates PKCE code verifier and challenge if PKCE is enabled
func (t *TraefikOidc) generatePKCEParameters() (string, string, error) {
	if !t.enablePKCE {
		return "", "", nil
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := deriveCodeChallenge(codeVerifier)
	t.logger.Debugf("PKCE enabled, generated code challenge")

	return codeVerifier, codeChallenge, nil
}

// prepareSessionForAuthentication clears existing session data and sets new authentication state
func (t *TraefikOidc) prepareSessionForAuthentication(session *SessionData, csrfToken, nonce, codeVerifier, incomingPath string) {
	// Clear all existing session data
	_ = session.SetAuthenticated(false) // Safe to ignore: clearing authentication state on new flow
	session.SetUserIdentifier("")
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetIDToken("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	// Set new authentication state
	session.SetCSRF(csrfToken)
	session.SetNonce(nonce)
	if t.enablePKCE && codeVerifier != "" {
		session.SetCodeVerifier(codeVerifier)
	}
	session.SetIncomingPath(incomingPath)
	t.logger.Debugf("Storing incoming path: %s", incomingPath)
}

// defaultInitiateAuthentication initiates the OIDC authentication flow.
// It generates CSRF tokens, nonce, PKCE parameters (if enabled), clears the session,
// stores authentication state, and redirects the user to the OIDC provider.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request initiating authentication.
//   - session: The session data to prepare for authentication.
//   - redirectURL: The pre-calculated callback URL (redirect_uri) for this middleware instance.
//
// rateLimitPerSourceAuth applies the (optional) per-external-source auth
// throttle at an OIDC gate. Returns true if the request was already
// answered with 429 and the caller must return. No-op when the limiter is
// disabled (PerSourceLoginRateLimit <= 0) or the source is internal.
func (t *TraefikOidc) rateLimitPerSourceAuth(rw http.ResponseWriter, req *http.Request) bool {
	if t.perSourceLimiter == nil {
		return false
	}
	if t.perSourceLimiter.allow(req) {
		return false
	}
	rw.Header().Set("Retry-After", "1")
	t.sendErrorResponse(rw, req, "Too many authentication attempts, please try again shortly", http.StatusTooManyRequests)
	return true
}

func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debugf("Initiating new OIDC authentication flow for request: %s", req.URL.RequestURI())

	// Per-external-source throttle on login initiation: a single host
	// flooding the route with auth starts shouldn't be able to spin up an
	// unbounded number of IdP round-trips or wear the shared token-origin
	// bucket down for everyone (R185).
	if t.rateLimitPerSourceAuth(rw, req) {
		return
	}

	// Check and handle redirect limits
	if err := t.validateRedirectCount(session, rw, req); err != nil {
		return
	}

	csrfToken, err := newUUIDv4()
	if err != nil {
		t.logger.Errorf("Failed to generate CSRF token: %v", err)
		http.Error(rw, "Failed to generate CSRF token", http.StatusInternalServerError)
		return
	}
	nonce, err := generateNonce()
	if err != nil {
		t.logger.Errorf("Failed to generate nonce: %v", err)
		http.Error(rw, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Generate PKCE parameters if enabled
	codeVerifier, codeChallenge, err := t.generatePKCEParameters()
	if err != nil {
		t.logger.Errorf("Failed to generate PKCE parameters: %v", err)
		http.Error(rw, "Failed to generate PKCE parameters", http.StatusInternalServerError)
		return
	}

	// Build the provider authorize URL BEFORE mutating the session. A URL-
	// build failure must not clear a valid existing session, and must not
	// emit an empty-Location redirect (browsers reload the current page,
	// re-entering this flow and bumping the redirect count until the hard
	// 508). Fail closed with an explicit status instead (R142).
	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)
	if authURL == "" {
		t.logger.Errorf("Failed to build provider authorize URL; aborting login flow")
		http.Error(rw, "Failed to build provider authorize URL", http.StatusInternalServerError)
		return
	}

	// When dynamic client registration is enabled but has not yet produced a
	// client_id (registration pending or failed), forging an authorize URL
	// with client_id="" would send the user to the provider on a broken
	// flow. Fail with a clear status instead of redirecting. This guard
	// must run BEFORE prepareSessionForAuthentication re-seeds the session:
	// re-seeding (and the save that follows) would otherwise mutate and
	// persist the session even though we are about to answer 503 with no
	// redirect — discarding any existing session state for no reason (R163).
	// Snapshot clientID under metadataMu: DCR rewrites it at runtime (R137).
	clientID, _, _, _, _ := t.clientCredentials()
	if t.dcrConfig != nil && t.dcrConfig.Enabled && clientID == "" {
		t.logger.Errorf("OIDC dynamic client registration has not produced a client_id; refusing to redirect to provider")
		http.Error(rw, "Identity provider registration pending", http.StatusServiceUnavailable)
		return
	}

	// Clear existing session data and set new authentication state
	t.prepareSessionForAuthentication(session, csrfToken, nonce, codeVerifier, req.URL.RequestURI())

	// Persist the redirect_uri so the callback reuses the exact value sent
	// to the IdP, instead of rebuilding it from the (client-affectable)
	// callback request's X-Forwarded-Host (R136).
	session.SetRedirectURL(redirectURL)

	session.MarkDirty()

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session before redirecting to provider: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Session saved before redirect. CSRF: %s, Nonce: %s",
		csrfToken, nonce)

	t.logger.Debugf("Redirecting user to OIDC provider: %s", authURL)

	// 302s into the IdP must not be heuristically cacheable (RFC 7234):
	// a stale, cached redirect could replay the pre-re-authentication URL.
	// Every other auth response sets no-store; these redirects were missed
	// (R147).
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, authURL, http.StatusFound)
}

// handleCallback processes the OIDC callback after user authentication.
// It validates state/CSRF tokens, exchanges authorization code for tokens,
// verifies the received tokens, extracts claims, and establishes the session.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The callback request containing authorization code and state.
//   - redirectURL: The fully qualified callback URL (used in the token exchange request).
//
// clearOneTimeAuthState clears the one-time CSRF/nonce/PKCE-verifier after a
// callback that consumed the authorization code but then failed, and persists
// the cleared state. Without it the failed session stays in a pending-auth
// state and a retried callback would re-exchange a fresh code before failing
// again. Mirrors the cleanup on the exchange-failure / empty-access-token
// paths (R134).
func (t *TraefikOidc) clearOneTimeAuthState(session *SessionData, req *http.Request, rw http.ResponseWriter) {
	session.SetCSRF("")
	session.SetNonce("")
	session.SetCodeVerifier("")
	if saveErr := session.Save(req, rw); saveErr != nil {
		t.logger.Errorf("Failed to save session after callback failure: %v", saveErr)
	}
}

func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	// Per-external-source throttle on the authorization-code callback: this
	// is where the one-time code exchange (server round-trip + token
	// cache write) happens, so a single source can't brute-force
	// repeated code exchanges or drown the shared limiter (R185).
	if t.rateLimitPerSourceAuth(rw, req) {
		return
	}

	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error during callback: %v", err)
		t.sendErrorResponse(rw, req, "Session error during callback", http.StatusInternalServerError)
		return
	}
	defer session.returnToPoolSafely()

	t.logger.Debugf("Handling callback, URL: %s", redactCallbackURL(req.URL.String()))

	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		if errorDescription == "" {
			errorDescription = req.URL.Query().Get("error")
		}
		// error / error_description are attacker-controlled query params.
		// Sanitize before logging and before echoing back to the client:
		// an embedded newline would inject a forged line into (especially
		// structured) logs, and unbounded length would bloat the log and
		// the error response (R145).
		sanitizeErr := func(s string) string {
			s = strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
			const maxErrLen = 512
			if len(s) > maxErrLen {
				s = s[:maxErrLen]
			}
			return s
		}
		t.logger.Errorf("Authentication error from provider during callback: %s - %s", sanitizeErr(req.URL.Query().Get("error")), sanitizeErr(errorDescription))
		t.sendErrorResponse(rw, req, fmt.Sprintf("Authentication error from provider: %s", sanitizeErr(errorDescription)), http.StatusBadRequest)
		return
	}

	state := req.URL.Query().Get("state")
	if state == "" {
		t.logger.Error("No state in callback")
		t.sendErrorResponse(rw, req, "State parameter missing in callback", http.StatusBadRequest)
		return
	}

	csrfToken := session.GetCSRF()
	if csrfToken == "" {
		t.logger.Errorf("CSRF token missing in session during callback. Authenticated: %v, Request URL: %s",
			session.GetAuthenticated(), redactCallbackURL(req.URL.String()))

		cookie, err := req.Cookie("_oidc_raczylo_m")
		if err != nil {
			t.logger.Errorf("Main session cookie not found in request: %v", err)
		} else {
			t.logger.Errorf("Main session cookie exists but CSRF token is empty. Cookie value length: %d", len(cookie.Value))
		}

		t.sendErrorResponse(rw, req, "CSRF token missing in session", http.StatusBadRequest)
		return
	}

	if !constantTimeStringCompare(state, csrfToken) {
		t.logger.Error("State parameter does not match CSRF token in session during callback")
		t.sendErrorResponse(rw, req, "Invalid state parameter (CSRF mismatch)", http.StatusBadRequest)
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		t.logger.Error("No code in callback")
		t.sendErrorResponse(rw, req, "No authorization code received in callback", http.StatusBadRequest)
		return
	}

	codeVerifier := session.GetCodeVerifier()
	if t.enablePKCE && codeVerifier == "" {
		t.logger.Error("PKCE is enabled but code verifier is missing from session during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: PKCE verifier missing", http.StatusBadRequest)
		return
	}

	// Use the redirect_uri persisted at initiate time (must match what was
	// sent to the IdP's authorize endpoint). Fall back to the rebuilt one
	// only for pre-existing sessions that predate R136 (R136).
	if stored := session.GetRedirectURL(); stored != "" {
		redirectURL = stored
	}

	tokenResponse, err := t.tokenExchanger.ExchangeCodeForToken(req.Context(), "authorization_code", code, redirectURL, codeVerifier)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token during callback: %v", err)
		// Invalidate the one-time auth state and persist it so a
		// partially-failed flow cannot be continued: the authorization code
		// may still be unconsumed at the provider, so a replayed callback
		// must re-authenticate rather than revalidate a stale
		// state/nonce/code_verifier. Mirrors the cleanup on success.
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not exchange code for token", http.StatusInternalServerError)
		return
	}

	if tokenResponse.AccessToken == "" {
		t.logger.Errorf("Token endpoint returned no access token during callback")
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Token endpoint returned no access token", http.StatusInternalServerError)
		return
	}

	if err = t.verifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token during callback: %v", err)
		t.clearOneTimeAuthState(session, req, rw)
		if errors.Is(err, ErrRateLimitExceeded) {
			// Rate-limit exhaustion must be a 429 + Retry-After, not a
			// generic 500: a single source's burst currently degrades
			// every user's callback to "server error" (R179).
			rw.Header().Set("Retry-After", "1")
			t.sendErrorResponse(rw, req, "Authentication failed: Too many requests, please retry", http.StatusTooManyRequests)
			return
		}
		t.sendErrorResponse(rw, req, "Authentication failed: Could not verify ID token", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims during callback: %v", err)
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not extract claims from token", http.StatusInternalServerError)
		return
	}

	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token during callback")
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in token", http.StatusBadRequest)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session during callback")
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in session", http.StatusBadRequest)
		return
	}

	if !constantTimeStringCompare(nonceClaim, sessionNonce) {
		t.logger.Error("Nonce claim does not match session nonce during callback")
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce mismatch", http.StatusBadRequest)
		return
	}

	// Extract user identifier from the configured claim (defaults to "email" for backward compatibility)
	userIdentifier, _ := claimScalarString(claims[t.userIdentifierClaim])
	if userIdentifier == "" {
		// Try "sub" as fallback since it's required by OIDC spec
		if t.userIdentifierClaim != "sub" {
			userIdentifier, _ = claimScalarString(claims["sub"])
		}
		if userIdentifier == "" {
			t.logger.Errorf("User identifier claim '%s' missing or empty in token during callback", t.userIdentifierClaim)
			t.clearOneTimeAuthState(session, req, rw)
			t.sendErrorResponse(rw, req, "Authentication failed: User identifier missing in token", http.StatusInternalServerError)
			return
		}
		t.logger.Debugf("Configured claim '%s' not found, using 'sub' claim as fallback", t.userIdentifierClaim)
	}

	// Validate user authorization. When the identity is an email, require the
	// IdP not to have explicitly flagged it as unverified — an unverified
	// address must not satisfy an email/domain allowlist (see
	// emailIdentityPermitted).
	if !emailIdentityPermitted(userIdentifier, claims) {
		t.logger.Errorf("User email not verified during callback, rejecting email-based authorization: %s", userIdentifier)
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: Email not verified", http.StatusForbidden)
		return
	}

	// Validate user authorization
	if !t.isAllowedUser(userIdentifier) {
		t.logger.Errorf("User not authorized during callback: %s", userIdentifier)
		t.clearOneTimeAuthState(session, req, rw)
		t.sendErrorResponse(rw, req, "Authentication failed: User not authorized", http.StatusForbidden)
		return
	}

	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("Failed to set authenticated state and regenerate session ID: %v", err)
		t.sendErrorResponse(rw, req, "Failed to update session", http.StatusInternalServerError)
		return
	}
	session.SetUserIdentifier(userIdentifier)
	session.SetIDToken(tokenResponse.IDToken)
	session.SetAccessToken(tokenResponse.AccessToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	session.SetCSRF("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	session.ResetRedirectCount()

	redirectPath := "/"
	if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != t.redirURLPath {
		// Neutralize open-redirect payloads (e.g. //evil.com, /\evil.com) stored
		// from the original request target before using it as the post-login
		// redirect target. normalizeLogoutPath forces a host-relative path.
		redirectPath = normalizeLogoutPath(incomingPath)
	}
	session.SetIncomingPath("")

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session after callback: %v", err)
		t.sendErrorResponse(rw, req, "Failed to save session after callback", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Callback successful, redirecting to %s", redirectPath)
	// no-store so the post-auth redirect isn't cached and replayed (R147).
	rw.Header().Set("Cache-Control", "no-store")
	http.Redirect(rw, req, redirectPath, http.StatusFound)
}

// handleExpiredToken handles requests with expired or invalid tokens.
// It clears the session data and initiates a new authentication flow.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The HTTP request with expired token.
//   - session: The session data to clear.
//   - redirectURL: The callback URL to be used in the new authentication flow.
func (t *TraefikOidc) handleExpiredToken(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debug("Handling expired token: Clearing session and initiating re-authentication.")
	_ = session.SetAuthenticated(false) // Safe to ignore: clearing authentication on expired token
	session.SetIDToken("")
	session.SetAccessToken("")
	session.SetRefreshToken("")
	session.SetUserIdentifier("")
	// Clear CSRF tokens to prevent replay attacks
	session.SetCSRF("")
	session.SetNonce("")
	session.SetCodeVerifier("")
	// Reset redirect count to prevent loops when handling expired tokens
	session.ResetRedirectCount()

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save cleared session during expired token handling: %v", err)
	}

	t.defaultInitiateAuthentication(rw, req, session, redirectURL)
}

// isAjaxRequest determines if this is an AJAX request that should receive 401 instead of redirect
func (t *TraefikOidc) isAjaxRequest(req *http.Request) bool {
	xhr := req.Header.Get("X-Requested-With")
	contentType := req.Header.Get("Content-Type")
	accept := req.Header.Get("Accept")

	return xhr == "XMLHttpRequest" ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(accept, "application/json")
}

// isNonNavigationRequest reports whether the request is a browser
// sub-resource (script, image, stylesheet, fetch, serviceWorker) rather than
// a top-level HTML navigation. Non-navigation requests MUST NOT trigger an
// OIDC redirect flow: several sub-resource loads happening in parallel would
// each call defaultInitiateAuthentication, each overwriting the session's
// CSRF/nonce, breaking the eventual callback (issue #129).
//
// Detection prefers Sec-Fetch-Mode, which all modern browsers send
// (Chrome/Edge/Firefox/Safari). For older or non-browser clients we fall
// back to Accept: if Accept is present and does not list text/html, treat
// it as a sub-resource. An empty/missing Accept is assumed to be navigation
// (safer to redirect than 401 on an ambiguous request).
func (t *TraefikOidc) isNonNavigationRequest(req *http.Request) bool {
	if mode := req.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode != "navigate"
	}
	accept := req.Header.Get("Accept")
	if accept == "" || accept == "*/*" {
		return false
	}
	return !strings.Contains(accept, "text/html")
}

// isRefreshTokenExpired checks whether the stored refresh token is likely
// past its useful lifetime, using the cookie-side issued_at timestamp set by
// SetRefreshToken. IdPs do not expose RT TTL on the wire, so this is a
// conservative heuristic gated by t.maxRefreshTokenAge (default 6h, set via
// MaxRefreshTokenAgeSeconds; 0 disables the check).
//
// The point of this check is to short-circuit the refresh path BEFORE the
// thundering herd hits the IdP for a token the provider has almost certainly
// revoked. Together with the RefreshCoordinator wireup, it keeps Grafana-
// style polling clients from looping on invalid_grant after a long pause.
func (t *TraefikOidc) isRefreshTokenExpired(session *SessionData) bool {
	if t == nil || session == nil {
		return false
	}
	if t.maxRefreshTokenAge <= 0 {
		return false
	}

	issuedAt := session.GetRefreshTokenIssuedAt()
	if issuedAt.IsZero() {
		// No timestamp recorded (legacy session pre-dating the issued_at
		// field). Don't force a re-auth - attempt refresh once and let the
		// IdP be the source of truth.
		return false
	}

	return time.Since(issuedAt) > t.maxRefreshTokenAge
}
