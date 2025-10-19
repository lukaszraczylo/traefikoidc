// Package handlers provides HTTP request handlers for the OIDC middleware.
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// OAuthHandler handles OAuth callback requests
type OAuthHandler struct {
	logger                Logger
	sessionManager        SessionManager
	tokenExchanger        TokenExchanger
	tokenVerifier         TokenVerifier
	extractClaimsFunc     func(tokenString string) (map[string]interface{}, error)
	isAllowedDomainFunc   func(email string) bool
	redirURLPath          string
	sendErrorResponseFunc func(rw http.ResponseWriter, req *http.Request, message string, code int)
}

// Logger interface for dependency injection
type Logger interface {
	Debugf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Error(msg string)
}

// SessionManager interface for session operations
type SessionManager interface {
	GetSession(req *http.Request) (SessionData, error)
}

// SessionData interface for session data operations
type SessionData interface {
	GetCSRF() string
	GetNonce() string
	GetCodeVerifier() string
	GetIncomingPath() string
	GetAuthenticated() bool
	GetAccessToken() string
	GetRefreshToken() string
	GetIDToken() string
	GetEmail() string
	SetAuthenticated(bool) error
	SetEmail(string)
	SetIDToken(string)
	SetAccessToken(string)
	SetRefreshToken(string)
	SetCSRF(string)
	SetNonce(string)
	SetCodeVerifier(string)
	SetIncomingPath(string)
	ResetRedirectCount()
	Save(req *http.Request, rw http.ResponseWriter) error
	returnToPoolSafely()
}

// TokenExchanger interface for token operations
type TokenExchanger interface {
	ExchangeCodeForToken(ctx context.Context, grantType string, codeOrToken string, redirectURL string, codeVerifier string) (*TokenResponse, error)
}

// TokenVerifier interface for token verification
type TokenVerifier interface {
	VerifyToken(token string) error
}

// TokenResponse represents the response from token exchange
type TokenResponse struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(logger Logger, sessionManager SessionManager, tokenExchanger TokenExchanger,
	tokenVerifier TokenVerifier, extractClaimsFunc func(string) (map[string]interface{}, error),
	isAllowedDomainFunc func(string) bool, redirURLPath string,
	sendErrorResponseFunc func(http.ResponseWriter, *http.Request, string, int)) *OAuthHandler {

	return &OAuthHandler{
		logger:                logger,
		sessionManager:        sessionManager,
		tokenExchanger:        tokenExchanger,
		tokenVerifier:         tokenVerifier,
		extractClaimsFunc:     extractClaimsFunc,
		isAllowedDomainFunc:   isAllowedDomainFunc,
		redirURLPath:          redirURLPath,
		sendErrorResponseFunc: sendErrorResponseFunc,
	}
}

// HandleCallback handles OAuth callback requests
func (h *OAuthHandler) HandleCallback(rw http.ResponseWriter, req *http.Request, redirectURL string) {
	session, err := h.sessionManager.GetSession(req)
	if err != nil {
		h.logger.Errorf("Session error during callback: %v", err)
		h.sendErrorResponseFunc(rw, req, "Session error during callback", http.StatusInternalServerError)
		return
	}
	defer session.returnToPoolSafely()

	h.logger.Debugf("Handling callback, URL: %s", req.URL.String())

	// Debug logging for cookie configuration
	h.logger.Debugf("Callback request headers - Host: %s, X-Forwarded-Host: %s, X-Forwarded-Proto: %s",
		req.Host, req.Header.Get("X-Forwarded-Host"), req.Header.Get("X-Forwarded-Proto"))

	// Log all cookies in the request for debugging
	cookies := req.Cookies()
	h.logger.Debugf("Total cookies in callback request: %d", len(cookies))
	for _, cookie := range cookies {
		if strings.HasPrefix(cookie.Name, "_oidc_") {
			h.logger.Debugf("Cookie found - Name: %s, Domain: %s, Path: %s, SameSite: %v, Secure: %v, HttpOnly: %v, Value length: %d",
				cookie.Name, cookie.Domain, cookie.Path, cookie.SameSite, cookie.Secure, cookie.HttpOnly, len(cookie.Value))
		}
	}

	if req.URL.Query().Get("error") != "" {
		errorDescription := req.URL.Query().Get("error_description")
		if errorDescription == "" {
			errorDescription = req.URL.Query().Get("error")
		}
		h.logger.Errorf("Authentication error from provider during callback: %s - %s", req.URL.Query().Get("error"), errorDescription)
		h.sendErrorResponseFunc(rw, req, fmt.Sprintf("Authentication error from provider: %s", errorDescription), http.StatusBadRequest)
		return
	}

	state := req.URL.Query().Get("state")
	if state == "" {
		h.logger.Error("No state in callback")
		h.sendErrorResponseFunc(rw, req, "State parameter missing in callback", http.StatusBadRequest)
		return
	}

	// Debug log the state parameter received
	h.logger.Debugf("State parameter received in callback: %s (length: %d)", state, len(state))

	csrfToken := session.GetCSRF()
	if csrfToken == "" {
		h.logger.Errorf("CSRF token missing in session during callback. Authenticated: %v, Request URL: %s",
			session.GetAuthenticated(), req.URL.String())

		// Enhanced debugging for missing CSRF token
		cookie, err := req.Cookie("_oidc_raczylo_m")
		if err != nil {
			h.logger.Errorf("Main session cookie not found in request: %v", err)
			// Log cookie names only, not values (avoid logging sensitive session data)
			cookieNames := make([]string, 0, len(req.Cookies()))
			for _, c := range req.Cookies() {
				cookieNames = append(cookieNames, c.Name)
			}
			h.logger.Debugf("Available cookies (names only): %v", cookieNames)
		} else {
			h.logger.Errorf("Main session cookie exists but CSRF token is empty. Cookie value length: %d", len(cookie.Value))
			h.logger.Debugf("Cookie details - Domain: %s, Path: %s, Secure: %v, HttpOnly: %v, SameSite: %v",
				cookie.Domain, cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.SameSite)
		}

		// Log session state for debugging
		h.logger.Debugf("Session state during CSRF check - Authenticated: %v, Has AccessToken: %v",
			session.GetAuthenticated(), session.GetAccessToken() != "")

		h.sendErrorResponseFunc(rw, req, "CSRF token missing in session", http.StatusBadRequest)
		return
	}

	// Debug log successful CSRF token retrieval
	h.logger.Debugf("CSRF token retrieved from session: %s (length: %d)", csrfToken, len(csrfToken))

	if state != csrfToken {
		h.logger.Error("State parameter does not match CSRF token in session during callback")
		h.sendErrorResponseFunc(rw, req, "Invalid state parameter (CSRF mismatch)", http.StatusBadRequest)
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		h.logger.Error("No code in callback")
		h.sendErrorResponseFunc(rw, req, "No authorization code received in callback", http.StatusBadRequest)
		return
	}

	codeVerifier := session.GetCodeVerifier()

	tokenResponse, err := h.tokenExchanger.ExchangeCodeForToken(req.Context(), "authorization_code", code, redirectURL, codeVerifier)
	if err != nil {
		h.logger.Errorf("Failed to exchange code for token during callback: %v", err)
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Could not exchange code for token", http.StatusInternalServerError)
		return
	}

	if err = h.tokenVerifier.VerifyToken(tokenResponse.IDToken); err != nil {
		h.logger.Errorf("Failed to verify id_token during callback: %v", err)
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Could not verify ID token", http.StatusInternalServerError)
		return
	}

	claims, err := h.extractClaimsFunc(tokenResponse.IDToken)
	if err != nil {
		h.logger.Errorf("Failed to extract claims during callback: %v", err)
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Could not extract claims from token", http.StatusInternalServerError)
		return
	}

	nonceClaim, ok := claims["nonce"].(string)
	if !ok || nonceClaim == "" {
		h.logger.Error("Nonce claim missing in id_token during callback")
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Nonce missing in token", http.StatusInternalServerError)
		return
	}

	sessionNonce := session.GetNonce()
	if sessionNonce == "" {
		h.logger.Error("Nonce not found in session during callback")
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Nonce missing in session", http.StatusInternalServerError)
		return
	}

	if nonceClaim != sessionNonce {
		h.logger.Error("Nonce claim does not match session nonce during callback")
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Nonce mismatch", http.StatusInternalServerError)
		return
	}

	email, _ := claims["email"].(string)
	if email == "" {
		h.logger.Errorf("Email claim missing or empty in token during callback")
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Email missing in token", http.StatusInternalServerError)
		return
	}
	if !h.isAllowedDomainFunc(email) {
		h.logger.Errorf("Disallowed email domain during callback: %s", email)
		h.sendErrorResponseFunc(rw, req, "Authentication failed: Email domain not allowed", http.StatusForbidden)
		return
	}

	if err := session.SetAuthenticated(true); err != nil {
		h.logger.Errorf("Failed to set authenticated state and regenerate session ID: %v", err)
		h.sendErrorResponseFunc(rw, req, "Failed to update session", http.StatusInternalServerError)
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
	if incomingPath := session.GetIncomingPath(); incomingPath != "" && incomingPath != h.redirURLPath {
		redirectPath = incomingPath
	}
	session.SetIncomingPath("")

	if err := session.Save(req, rw); err != nil {
		h.logger.Errorf("Failed to save session after callback: %v", err)
		h.sendErrorResponseFunc(rw, req, "Failed to save session after callback", http.StatusInternalServerError)
		return
	}

	h.logger.Debugf("Callback successful, redirecting to %s", redirectPath)
	http.Redirect(rw, req, redirectPath, http.StatusFound)
}

// URLHelper provides utility methods for URL operations
type URLHelper struct {
	logger Logger
}

// NewURLHelper creates a new URL helper
func NewURLHelper(logger Logger) *URLHelper {
	return &URLHelper{logger: logger}
}

// DetermineExcludedURL checks if a URL path should bypass OIDC authentication.
// It compares the request path against configured excluded URL prefixes.
func (h *URLHelper) DetermineExcludedURL(currentRequest string, excludedURLs map[string]struct{}) bool {
	for excludedURL := range excludedURLs {
		if strings.HasPrefix(currentRequest, excludedURL) {
			h.logger.Debugf("URL is excluded - got %s / excluded hit: %s", currentRequest, excludedURL)
			return true
		}
	}
	return false
}

// DetermineScheme determines the URL scheme for building redirect URLs.
// It checks X-Forwarded-Proto header first, then TLS presence.
func (h *URLHelper) DetermineScheme(req *http.Request) string {
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

// DetermineHost determines the host for building redirect URLs.
// It checks X-Forwarded-Host header first, then falls back to req.Host.
func (h *URLHelper) DetermineHost(req *http.Request) string {
	if host := req.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return req.Host
}
