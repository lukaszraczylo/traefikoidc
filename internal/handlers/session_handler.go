// Package handlers provides HTTP request handlers for OIDC operations
package handlers

import (
	"fmt"
	"net/http"
	"strings"
)

// SessionHandler manages session-related HTTP operations
type SessionHandler struct {
	sessionManager        SessionManager
	logger                Logger
	logoutURLPath         string
	postLogoutRedirectURI string
	endSessionURL         string
	clientID              string
}

// SessionManager interface for session operations
type SessionManager interface {
	GetSession(req *http.Request) (Session, error)
	CleanupOldCookies(rw http.ResponseWriter, req *http.Request)
}

// Session interface for session data
type Session interface {
	GetAuthenticated() bool
	SetAuthenticated(bool) error
	GetEmail() string
	SetEmail(string)
	GetIDToken() string
	GetAccessToken() string
	GetRefreshToken() string
	SetRefreshToken(string)
	Clear(req *http.Request, rw http.ResponseWriter) error
	Save(req *http.Request, rw http.ResponseWriter) error
	ReturnToPoolSafely()
}

// Logger interface for logging operations
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Info(msg string)
	Infof(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

// NewSessionHandler creates a new session handler
func NewSessionHandler(sessionManager SessionManager, logger Logger, logoutURLPath, postLogoutRedirectURI, endSessionURL, clientID string) *SessionHandler {
	return &SessionHandler{
		sessionManager:        sessionManager,
		logger:                logger,
		logoutURLPath:         logoutURLPath,
		postLogoutRedirectURI: postLogoutRedirectURI,
		endSessionURL:         endSessionURL,
		clientID:              clientID,
	}
}

// HandleLogout processes logout requests
func (h *SessionHandler) HandleLogout(rw http.ResponseWriter, req *http.Request) {
	h.logger.Debug("Processing logout request")

	session, err := h.sessionManager.GetSession(req)
	if err != nil {
		h.logger.Errorf("Error getting session during logout: %v", err)
		// Continue with logout even if session retrieval fails
	}

	var idToken string
	if session != nil {
		defer session.ReturnToPoolSafely()
		idToken = session.GetIDToken()

		// Clear the session
		if err := session.Clear(req, rw); err != nil {
			h.logger.Errorf("Error clearing session during logout: %v", err)
		}
	}

	// Build logout URL
	logoutURL := h.buildLogoutURL(idToken)

	h.logger.Debugf("Redirecting to logout URL: %s", logoutURL)
	http.Redirect(rw, req, logoutURL, http.StatusFound)
}

// buildLogoutURL constructs the provider logout URL
func (h *SessionHandler) buildLogoutURL(idToken string) string {
	if h.endSessionURL == "" {
		// If no end session URL, redirect to post-logout redirect URI
		return h.postLogoutRedirectURI
	}

	logoutURL := h.endSessionURL

	// Add query parameters
	params := make([]string, 0, 3)

	if idToken != "" {
		params = append(params, fmt.Sprintf("id_token_hint=%s", idToken))
	}

	if h.postLogoutRedirectURI != "" {
		params = append(params, fmt.Sprintf("post_logout_redirect_uri=%s", h.postLogoutRedirectURI))
	}

	if h.clientID != "" {
		params = append(params, fmt.Sprintf("client_id=%s", h.clientID))
	}

	if len(params) > 0 {
		separator := "?"
		if strings.Contains(logoutURL, "?") {
			separator = "&"
		}
		logoutURL += separator + strings.Join(params, "&")
	}

	return logoutURL
}

// ValidateSession checks if a session is valid and authenticated
func (h *SessionHandler) ValidateSession(session Session) SessionValidationResult {
	if session == nil {
		return SessionValidationResult{
			Valid:        false,
			NeedsAuth:    true,
			ErrorMessage: "session is nil",
		}
	}

	if !session.GetAuthenticated() {
		return SessionValidationResult{
			Valid:        false,
			NeedsAuth:    true,
			ErrorMessage: "session not authenticated",
		}
	}

	email := session.GetEmail()
	if email == "" {
		return SessionValidationResult{
			Valid:        false,
			NeedsAuth:    true,
			ErrorMessage: "no email in session",
		}
	}

	return SessionValidationResult{
		Valid:     true,
		NeedsAuth: false,
	}
}

// SessionValidationResult represents the result of session validation
type SessionValidationResult struct {
	Valid        bool
	NeedsAuth    bool
	ErrorMessage string
}

// CleanupExpiredSession clears an expired session
func (h *SessionHandler) CleanupExpiredSession(rw http.ResponseWriter, req *http.Request, session Session) error {
	h.logger.Debug("Cleaning up expired session")

	if session == nil {
		return nil
	}

	// Clear all session data
	if err := session.SetAuthenticated(false); err != nil {
		h.logger.Errorf("Failed to set authenticated to false: %v", err)
	}

	session.SetEmail("")
	session.SetRefreshToken("")

	// Save the cleared session
	if err := session.Save(req, rw); err != nil {
		h.logger.Errorf("Failed to save cleared session: %v", err)
		return err
	}

	return nil
}

// IsAjaxRequest determines if the request is an AJAX/XHR request
func (h *SessionHandler) IsAjaxRequest(req *http.Request) bool {
	// Check X-Requested-With header (commonly used by jQuery and other libraries)
	if req.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}

	// Check Accept header for JSON preference
	accept := req.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return true
	}

	// Check for fetch API indication
	if req.Header.Get("Sec-Fetch-Mode") == "cors" {
		return true
	}

	return false
}

// SendErrorResponse sends an appropriate error response based on request type
func (h *SessionHandler) SendErrorResponse(rw http.ResponseWriter, req *http.Request, message string, statusCode int) {
	if h.IsAjaxRequest(req) {
		// For AJAX requests, send JSON response
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(statusCode)
		_, _ = fmt.Fprintf(rw, `{"error": "%s"}`, message) // Safe to ignore: writing error response
	} else {
		// For browser requests, send HTML response
		rw.Header().Set("Content-Type", "text/html")
		rw.WriteHeader(statusCode)
		_, _ = fmt.Fprintf(rw, `<html><body><h1>Error %d</h1><p>%s</p></body></html>`, statusCode, message) // Safe to ignore: writing error response
	}
}

// SetSecurityHeaders sets standard security headers
func (h *SessionHandler) SetSecurityHeaders(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-XSS-Protection", "1; mode=block")
	rw.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Handle CORS for AJAX requests
	origin := req.Header.Get("Origin")
	if origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		rw.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		rw.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if req.Method == "OPTIONS" {
			rw.WriteHeader(http.StatusOK)
			return
		}
	}
}
