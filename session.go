package traefikoidc

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

const (
	mainCookieName     = "_raczylo_oidc"         // Main session cookie
	accessTokenCookie  = "_raczylo_oidc_access"  // Access token cookie
	refreshTokenCookie = "_raczylo_oidc_refresh" // Refresh token cookie
)

// SessionManager handles multiple session cookies
type SessionManager struct {
	store      sessions.Store
	forceHTTPS bool
	logger     *Logger
}

// NewSessionManager creates a new session manager
func NewSessionManager(encryptionKey string, forceHTTPS bool, logger *Logger) *SessionManager {
	return &SessionManager{
		store:      sessions.NewCookieStore([]byte(encryptionKey)),
		forceHTTPS: forceHTTPS,
		logger:     logger,
	}
}

// getSessionOptions returns session options based on scheme
func (sm *SessionManager) getSessionOptions(isSecure bool) *sessions.Options {
	return &sessions.Options{
		HttpOnly: true,
		Secure:   isSecure || sm.forceHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   ConstSessionTimeout,
		Path:     "/",
	}
}

// GetSession retrieves all session data
func (sm *SessionManager) GetSession(r *http.Request) (*SessionData, error) {
	mainSession, err := sm.store.Get(r, mainCookieName)
	if err != nil {
		return nil, fmt.Errorf("failed to get main session: %w", err)
	}

	accessSession, err := sm.store.Get(r, accessTokenCookie)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token session: %w", err)
	}

	refreshSession, err := sm.store.Get(r, refreshTokenCookie)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token session: %w", err)
	}

	sessionData := &SessionData{
		manager:        sm,
		mainSession:    mainSession,
		accessSession:  accessSession,
		refreshSession: refreshSession,
	}

	return sessionData, nil
}

// SessionData holds all session information
type SessionData struct {
	manager        *SessionManager
	mainSession    *sessions.Session
	accessSession  *sessions.Session
	refreshSession *sessions.Session
}

// Save saves all session data
func (sd *SessionData) Save(r *http.Request, w http.ResponseWriter) error {
	isSecure := strings.HasPrefix(r.URL.Scheme, "https") || sd.manager.forceHTTPS

	// Set options for all sessions
	sd.mainSession.Options = sd.manager.getSessionOptions(isSecure)
	sd.accessSession.Options = sd.manager.getSessionOptions(isSecure)
	sd.refreshSession.Options = sd.manager.getSessionOptions(isSecure)

	if err := sd.mainSession.Save(r, w); err != nil {
		return fmt.Errorf("failed to save main session: %w", err)
	}
	if err := sd.accessSession.Save(r, w); err != nil {
		return fmt.Errorf("failed to save access token session: %w", err)
	}
	if err := sd.refreshSession.Save(r, w); err != nil {
		return fmt.Errorf("failed to save refresh token session: %w", err)
	}

	return nil
}

// Clear clears all session data
func (sd *SessionData) Clear(r *http.Request, w http.ResponseWriter) error {
	// Clear and expire all sessions
	sd.mainSession.Options.MaxAge = -1
	sd.accessSession.Options.MaxAge = -1
	sd.refreshSession.Options.MaxAge = -1

	for k := range sd.mainSession.Values {
		delete(sd.mainSession.Values, k)
	}
	for k := range sd.accessSession.Values {
		delete(sd.accessSession.Values, k)
	}
	for k := range sd.refreshSession.Values {
		delete(sd.refreshSession.Values, k)
	}

	return sd.Save(r, w)
}

// GetAuthenticated returns authentication status
func (sd *SessionData) GetAuthenticated() bool {
	auth, _ := sd.mainSession.Values["authenticated"].(bool)
	return auth
}

// SetAuthenticated sets authentication status
func (sd *SessionData) SetAuthenticated(value bool) {
	sd.mainSession.Values["authenticated"] = value
}

// GetAccessToken returns the access token
func (sd *SessionData) GetAccessToken() string {
	token, _ := sd.accessSession.Values["token"].(string)
	return token
}

// SetAccessToken sets the access token
func (sd *SessionData) SetAccessToken(token string) {
	sd.accessSession.Values["token"] = token
}

// GetRefreshToken returns the refresh token
func (sd *SessionData) GetRefreshToken() string {
	token, _ := sd.refreshSession.Values["token"].(string)
	return token
}

// SetRefreshToken sets the refresh token
func (sd *SessionData) SetRefreshToken(token string) {
	sd.refreshSession.Values["token"] = token
}

// GetCSRF returns the CSRF token
func (sd *SessionData) GetCSRF() string {
	csrf, _ := sd.mainSession.Values["csrf"].(string)
	return csrf
}

// SetCSRF sets the CSRF token
func (sd *SessionData) SetCSRF(token string) {
	sd.mainSession.Values["csrf"] = token
}

// GetNonce returns the nonce
func (sd *SessionData) GetNonce() string {
	nonce, _ := sd.mainSession.Values["nonce"].(string)
	return nonce
}

// SetNonce sets the nonce
func (sd *SessionData) SetNonce(nonce string) {
	sd.mainSession.Values["nonce"] = nonce
}

// GetEmail returns the user's email
func (sd *SessionData) GetEmail() string {
	email, _ := sd.mainSession.Values["email"].(string)
	return email
}

// SetEmail sets the user's email
func (sd *SessionData) SetEmail(email string) {
	sd.mainSession.Values["email"] = email
}

// GetIncomingPath returns the original incoming path
func (sd *SessionData) GetIncomingPath() string {
	path, _ := sd.mainSession.Values["incoming_path"].(string)
	return path
}

// SetIncomingPath sets the original incoming path
func (sd *SessionData) SetIncomingPath(path string) {
	sd.mainSession.Values["incoming_path"] = path
}
