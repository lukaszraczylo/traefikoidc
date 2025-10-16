package traefikoidc

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// ============================================================================
// AUTHENTICATION FLOW
// ============================================================================

// validateRedirectCount checks if redirect limit is exceeded and handles the error
func (t *TraefikOidc) validateRedirectCount(session *SessionData, rw http.ResponseWriter, req *http.Request) error {
	const maxRedirects = 5
	redirectCount := session.GetRedirectCount()
	if redirectCount >= maxRedirects {
		t.logger.Errorf("Maximum redirect limit (%d) exceeded, possible redirect loop detected", maxRedirects)
		session.ResetRedirectCount()
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
	session.SetEmail("")
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
func (t *TraefikOidc) defaultInitiateAuthentication(rw http.ResponseWriter, req *http.Request, session *SessionData, redirectURL string) {
	t.logger.Debugf("Initiating new OIDC authentication flow for request: %s", req.URL.RequestURI())

	// Check and handle redirect limits
	if err := t.validateRedirectCount(session, rw, req); err != nil {
		return
	}

	csrfToken := uuid.NewString()
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

	// Clear existing session data and set new authentication state
	t.prepareSessionForAuthentication(session, csrfToken, nonce, codeVerifier, req.URL.RequestURI())

	session.MarkDirty()

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session before redirecting to provider: %v", err)
		http.Error(rw, "Failed to save session", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Session saved before redirect. CSRF: %s, Nonce: %s",
		csrfToken, nonce)

	authURL := t.buildAuthURL(redirectURL, csrfToken, nonce, codeChallenge)
	t.logger.Debugf("Redirecting user to OIDC provider: %s", authURL)

	http.Redirect(rw, req, authURL, http.StatusFound)
}

// handleCallback processes the OIDC callback after user authentication.
// It validates state/CSRF tokens, exchanges authorization code for tokens,
// verifies the received tokens, extracts claims, and establishes the session.
// Parameters:
//   - rw: The HTTP response writer.
//   - req: The callback request containing authorization code and state.
//   - redirectURL: The fully qualified callback URL (used in the token exchange request).
func (t *TraefikOidc) handleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := t.sessionManager.GetSession(req)
	if err != nil {
		t.logger.Errorf("Session error during callback: %v", err)
		t.sendErrorResponse(rw, req, "Session error during callback", http.StatusInternalServerError)
		return
	}
	defer session.returnToPoolSafely()

	t.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		if errorDescription == "" {
			errorDescription = req.URL.Query().Get("error")
		}
		t.logger.Errorf("Authentication error from provider during callback: %s - %s", req.URL.Query().Get("error"), errorDescription)
		t.sendErrorResponse(rw, req, fmt.Sprintf("Authentication error from provider: %s", errorDescription), http.StatusBadRequest)
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
			session.GetAuthenticated(), req.URL.String())

		cookie, err := req.Cookie("_oidc_raczylo_m")
		if err != nil {
			t.logger.Errorf("Main session cookie not found in request: %v", err)
		} else {
			t.logger.Errorf("Main session cookie exists but CSRF token is empty. Cookie value length: %d", len(cookie.Value))
		}

		t.sendErrorResponse(rw, req, "CSRF token missing in session", http.StatusBadRequest)
		return
	}

	if state != csrfToken {
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

	tokenResponse, err := t.tokenExchanger.ExchangeCodeForToken(req.Context(), "authorization_code", code, redirectURL, codeVerifier)
	if err != nil {
		t.logger.Errorf("Failed to exchange code for token during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not exchange code for token", http.StatusInternalServerError)
		return
	}

	if err = t.verifyToken(tokenResponse.IDToken); err != nil {
		t.logger.Errorf("Failed to verify id_token during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not verify ID token", http.StatusInternalServerError)
		return
	}

	claims, err := t.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		t.logger.Errorf("Failed to extract claims during callback: %v", err)
		t.sendErrorResponse(rw, req, "Authentication failed: Could not extract claims from token", http.StatusInternalServerError)
		return
	}

	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		t.logger.Error("Nonce claim missing in id_token during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in token", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		t.logger.Error("Nonce not found in session during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce missing in session", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		t.logger.Error("Nonce claim does not match session nonce during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Nonce mismatch", http.StatusInternalServerError)
		return
	}

	email, _ := claims["email"].(string)
	if email == "" {
		t.logger.Errorf("Email claim missing or empty in token during callback")
		t.sendErrorResponse(rw, req, "Authentication failed: Email missing in token", http.StatusInternalServerError)
		return
	}
	if !t.isAllowedDomain(email) {
		t.logger.Errorf("Disallowed email domain during callback: %s", email)
		t.sendErrorResponse(rw, req, "Authentication failed: Email domain not allowed", http.StatusForbidden)
		return
	}

	if err := session.SetAuthenticated(true); err != nil {
		t.logger.Errorf("Failed to set authenticated state and regenerate session ID: %v", err)
		t.sendErrorResponse(rw, req, "Failed to update session", http.StatusInternalServerError)
		return
	}
	session.SetEmail(email)
	session.SetIDToken(tokenResponse.IDToken)
	session.SetAccessToken(tokenResponse.AccessToken)
	session.SetRefreshToken(tokenResponse.RefreshToken)

	session.SetCSRF("")
	session.SetNonce("")
	session.SetCodeVerifier("")

	session.ResetRedirectCount()

	redirectPath := "/"
	if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != t.redirURLPath {
		redirectPath = incomingPath
	}
	session.SetIncomingPath("")

	if err := session.Save(req, rw); err != nil {
		t.logger.Errorf("Failed to save session after callback: %v", err)
		t.sendErrorResponse(rw, req, "Failed to save session after callback", http.StatusInternalServerError)
		return
	}

	t.logger.Debugf("Callback successful, redirecting to %s", redirectPath)
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
	session.SetEmail("")
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

// isUserAuthenticated determines the authentication status and refresh requirements.
// It delegates to provider-specific validation methods that handle different token types
// and expiration behaviors.
// Parameters:
//   - session: The session data containing authentication tokens.
//
// Returns:
//   - authenticated (bool): True if the user has valid tokens.
//   - needsRefresh (bool): True if tokens are valid but nearing expiration.
//   - expired (bool): True if the session is unauthenticated, the token is missing,
//     or the token verification failed for reasons other than nearing/actual expiration.
func (t *TraefikOidc) isUserAuthenticated(session *SessionData) (bool, bool, bool) {
	if t.isAzureProvider() {
		return t.validateAzureTokens(session)
	} else if t.isGoogleProvider() {
		return t.validateGoogleTokens(session)
	}
	// Auth0 and other providers can now use standard validation
	// which handles opaque tokens generically
	return t.validateStandardTokens(session)
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

// isRefreshTokenExpired checks if refresh token is likely expired (older than 6 hours)
func (t *TraefikOidc) isRefreshTokenExpired(session *SessionData) bool {
	// This is a heuristic check - actual implementation would depend on
	// the specific provider and token metadata
	return false // Placeholder implementation
}
