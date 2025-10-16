// Package handlers provides authentication flow management
package handlers

import (
	"net/http"
	"time"
)

// AuthFlowHandler manages the complete OIDC authentication flow
type AuthFlowHandler struct {
	sessionHandler *SessionHandler
	tokenHandler   TokenHandler
	logger         Logger
	excludedURLs   map[string]struct{}
	initComplete   chan struct{}
	issuerURL      string
}

// TokenHandler interface for token operations
type TokenHandler interface {
	VerifyToken(token string) error
	RefreshToken(refreshToken string) (*TokenResponse, error)
}

// TokenResponse represents token exchange response
type TokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// AuthFlowResult represents the result of authentication flow processing
type AuthFlowResult struct {
	Authenticated   bool
	RequiresAuth    bool
	RequiresRefresh bool
	Error           error
	RedirectURL     string
	StatusCode      int
}

// NewAuthFlowHandler creates a new authentication flow handler
func NewAuthFlowHandler(sessionHandler *SessionHandler, tokenHandler TokenHandler, logger Logger, excludedURLs map[string]struct{}, initComplete chan struct{}, issuerURL string) *AuthFlowHandler {
	return &AuthFlowHandler{
		sessionHandler: sessionHandler,
		tokenHandler:   tokenHandler,
		logger:         logger,
		excludedURLs:   excludedURLs,
		initComplete:   initComplete,
		issuerURL:      issuerURL,
	}
}

// ProcessRequest handles the main authentication flow
func (h *AuthFlowHandler) ProcessRequest(rw http.ResponseWriter, req *http.Request) AuthFlowResult {
	// Check if URL should be excluded
	if h.shouldExcludeURL(req.URL.Path) {
		h.logger.Debugf("Request path %s excluded by configuration, bypassing OIDC", req.URL.Path)
		return AuthFlowResult{Authenticated: true}
	}

	// Check for streaming requests
	if h.isStreamingRequest(req) {
		h.logger.Debugf("Streaming request detected, bypassing OIDC")
		return AuthFlowResult{Authenticated: true}
	}

	// Wait for initialization
	if !h.waitForInitialization(req) {
		return AuthFlowResult{
			Error:      ErrInitializationTimeout,
			StatusCode: http.StatusServiceUnavailable,
		}
	}

	// Get and validate session
	session, err := h.sessionHandler.sessionManager.GetSession(req)
	if err != nil {
		h.logger.Errorf("Error getting session: %v", err)
		return AuthFlowResult{
			RequiresAuth: true,
			Error:        err,
		}
	}
	defer session.ReturnToPoolSafely()

	// Clean up old cookies
	h.sessionHandler.sessionManager.CleanupOldCookies(rw, req)

	// Validate session
	validationResult := h.sessionHandler.ValidateSession(session)
	if !validationResult.Valid {
		if validationResult.NeedsAuth {
			return AuthFlowResult{RequiresAuth: true}
		}
		return AuthFlowResult{
			Error:      ErrSessionInvalid,
			StatusCode: http.StatusUnauthorized,
		}
	}

	// Check token validity and refresh if needed
	return h.validateAndRefreshTokens(session, req, rw)
}

// shouldExcludeURL checks if a URL should bypass authentication
func (h *AuthFlowHandler) shouldExcludeURL(path string) bool {
	for excludedURL := range h.excludedURLs {
		if len(path) >= len(excludedURL) && path[:len(excludedURL)] == excludedURL {
			return true
		}
	}
	return false
}

// isStreamingRequest checks if request is a streaming request that should bypass auth
func (h *AuthFlowHandler) isStreamingRequest(req *http.Request) bool {
	acceptHeader := req.Header.Get("Accept")
	return acceptHeader == "text/event-stream"
}

// waitForInitialization waits for OIDC provider initialization
func (h *AuthFlowHandler) waitForInitialization(req *http.Request) bool {
	select {
	case <-h.initComplete:
		if h.issuerURL == "" {
			h.logger.Error("OIDC provider metadata initialization failed")
			return false
		}
		return true
	case <-req.Context().Done():
		h.logger.Debug("Request canceled while waiting for OIDC initialization")
		return false
	case <-time.After(30 * time.Second):
		h.logger.Error("Timeout waiting for OIDC initialization")
		return false
	}
}

// validateAndRefreshTokens handles token validation and refresh logic
func (h *AuthFlowHandler) validateAndRefreshTokens(session Session, req *http.Request, rw http.ResponseWriter) AuthFlowResult {
	// Check access token if present
	if accessToken := session.GetAccessToken(); accessToken != "" {
		if err := h.tokenHandler.VerifyToken(accessToken); err != nil {
			h.logger.Errorf("Access token validation failed: %v", err)

			// Try refresh if refresh token is available
			if refreshToken := session.GetRefreshToken(); refreshToken != "" {
				return h.attemptTokenRefresh(session, req, rw)
			}

			return AuthFlowResult{RequiresAuth: true}
		}
	}

	// Check ID token
	if idToken := session.GetIDToken(); idToken != "" {
		if err := h.tokenHandler.VerifyToken(idToken); err != nil {
			h.logger.Errorf("ID token validation failed: %v", err)

			// Try refresh if refresh token is available
			if refreshToken := session.GetRefreshToken(); refreshToken != "" {
				return h.attemptTokenRefresh(session, req, rw)
			}

			return AuthFlowResult{RequiresAuth: true}
		}
	}

	return AuthFlowResult{Authenticated: true}
}

// attemptTokenRefresh tries to refresh tokens
func (h *AuthFlowHandler) attemptTokenRefresh(session Session, req *http.Request, rw http.ResponseWriter) AuthFlowResult {
	refreshToken := session.GetRefreshToken()
	if refreshToken == "" {
		return AuthFlowResult{RequiresAuth: true}
	}

	// Check if this is an AJAX request
	if h.sessionHandler.IsAjaxRequest(req) {
		return AuthFlowResult{
			Error:      ErrSessionExpiredAjax,
			StatusCode: http.StatusUnauthorized,
		}
	}

	_, err := h.tokenHandler.RefreshToken(refreshToken)
	if err != nil {
		h.logger.Errorf("Token refresh failed: %v", err)
		return AuthFlowResult{RequiresAuth: true}
	}

	// Update session with new tokens would be handled here
	// Implementation depends on the actual session interface

	if err := session.Save(req, rw); err != nil {
		h.logger.Errorf("Failed to save refreshed session: %v", err)
		return AuthFlowResult{
			Error:      err,
			StatusCode: http.StatusInternalServerError,
		}
	}

	return AuthFlowResult{Authenticated: true}
}

// Common errors
var (
	ErrInitializationTimeout = &AuthFlowError{Code: "INIT_TIMEOUT", Message: "OIDC initialization timeout"}
	ErrSessionInvalid        = &AuthFlowError{Code: "SESSION_INVALID", Message: "Invalid session"}
	ErrSessionExpiredAjax    = &AuthFlowError{Code: "SESSION_EXPIRED_AJAX", Message: "Session expired for AJAX request"}
)

// AuthFlowError represents authentication flow errors
type AuthFlowError struct {
	Code    string
	Message string
}

func (e *AuthFlowError) Error() string {
	return e.Message
}
