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
	maxCookieSize      = 2000                    // Max size for each chunk to stay within 4096-byte cookie limit

	// REASON:
	// Let x be the maximum size of the chunk (maxCookieSize).
	// Encrypted size = x + 28 bytes
	// Base64-encoded size = ((x + 28) * 4) / 3 bytes
	// ((x + 28) * 4) / 3 <= 4096
	// Multiply both sides by 3:
	// 4 * (x + 28) <= 4096 * 3
	// 4 * (x + 28) <= 12288
	// Divide both sides by 4:
	// x + 28 <= 3072
	// Subtract 28 from both sides:
	// x <= 3044
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
		request:        r,
		mainSession:    mainSession,
		accessSession:  accessSession,
		refreshSession: refreshSession,
	}

	// Retrieve chunked access token sessions
	sessionData.accessTokenChunks = sm.getTokenChunkSessions(r, accessTokenCookie)
	// Retrieve chunked refresh token sessions
	sessionData.refreshTokenChunks = sm.getTokenChunkSessions(r, refreshTokenCookie)

	return sessionData, nil
}

// getTokenChunkSessions retrieves sessions for token chunks
func (sm *SessionManager) getTokenChunkSessions(r *http.Request, baseName string) map[int]*sessions.Session {
	chunks := make(map[int]*sessions.Session)
	for i := 0; ; i++ {
		sessionName := fmt.Sprintf("%s_%d", baseName, i)
		session, err := sm.store.Get(r, sessionName)
		if err != nil || session.IsNew {
			// No more sessions
			break
		}
		chunks[i] = session
	}
	return chunks
}

// SessionData holds all session information
type SessionData struct {
	manager            *SessionManager
	request            *http.Request
	mainSession        *sessions.Session
	accessSession      *sessions.Session
	refreshSession     *sessions.Session
	accessTokenChunks  map[int]*sessions.Session
	refreshTokenChunks map[int]*sessions.Session
}

// Save saves all session data
func (sd *SessionData) Save(r *http.Request, w http.ResponseWriter) error {
	isSecure := strings.HasPrefix(r.URL.Scheme, "https") || sd.manager.forceHTTPS

	// Set options for all sessions
	options := sd.manager.getSessionOptions(isSecure)
	sd.mainSession.Options = options
	sd.accessSession.Options = options
	sd.refreshSession.Options = options

	// Save main session
	if err := sd.mainSession.Save(r, w); err != nil {
		return fmt.Errorf("failed to save main session: %w", err)
	}

	// Save access token session
	if err := sd.accessSession.Save(r, w); err != nil {
		return fmt.Errorf("failed to save access token session: %w", err)
	}

	// Save refresh token session
	if err := sd.refreshSession.Save(r, w); err != nil {
		return fmt.Errorf("failed to save refresh token session: %w", err)
	}

	// Save access token chunks
	for _, session := range sd.accessTokenChunks {
		session.Options = options
		if err := session.Save(r, w); err != nil {
			return fmt.Errorf("failed to save access token chunk session: %w", err)
		}
	}

	// Save refresh token chunks
	for _, session := range sd.refreshTokenChunks {
		session.Options = options
		if err := session.Save(r, w); err != nil {
			return fmt.Errorf("failed to save refresh token chunk session: %w", err)
		}
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

	// Clear chunk sessions
	sd.clearTokenChunks(r, sd.accessTokenChunks)
	sd.clearTokenChunks(r, sd.refreshTokenChunks)

	return sd.Save(r, w)
}

// clearTokenChunks clears chunked token sessions
func (sd *SessionData) clearTokenChunks(r *http.Request, chunks map[int]*sessions.Session) {
	for _, session := range chunks {
		session.Options.MaxAge = -1
		for k := range session.Values {
			delete(session.Values, k)
		}
	}
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
	if token != "" {
		return token
	}

	// Reassemble token from chunks
	if len(sd.accessTokenChunks) == 0 {
		return ""
	}

	var chunks []string
	for i := 0; ; i++ {
		session, ok := sd.accessTokenChunks[i]
		if !ok {
			break
		}
		chunk, _ := session.Values["token_chunk"].(string)
		chunks = append(chunks, chunk)
	}

	return strings.Join(chunks, "")
}

// SetAccessToken sets the access token
func (sd *SessionData) SetAccessToken(token string) {
	// Clear existing chunks
	sd.clearTokenChunks(sd.request, sd.accessTokenChunks)
	sd.accessTokenChunks = make(map[int]*sessions.Session)

	if len(token) <= maxCookieSize {
		sd.accessSession.Values["token"] = token
	} else {
		// Split token into chunks
		sd.accessSession.Values["token"] = ""
		chunks := splitIntoChunks(token, maxCookieSize)
		for i, chunk := range chunks {
			sessionName := fmt.Sprintf("%s_%d", accessTokenCookie, i)
			session, _ := sd.manager.store.Get(sd.request, sessionName)
			session.Values["token_chunk"] = chunk
			sd.accessTokenChunks[i] = session
		}
	}
}

// GetRefreshToken returns the refresh token
func (sd *SessionData) GetRefreshToken() string {
	token, _ := sd.refreshSession.Values["token"].(string)
	if token != "" {
		return token
	}

	// Reassemble token from chunks
	if len(sd.refreshTokenChunks) == 0 {
		return ""
	}

	var chunks []string
	for i := 0; ; i++ {
		session, ok := sd.refreshTokenChunks[i]
		if !ok {
			break
		}
		chunk, _ := session.Values["token_chunk"].(string)
		chunks = append(chunks, chunk)
	}

	return strings.Join(chunks, "")
}

// SetRefreshToken sets the refresh token
func (sd *SessionData) SetRefreshToken(token string) {
	// Clear existing chunks
	sd.clearTokenChunks(sd.request, sd.refreshTokenChunks)
	sd.refreshTokenChunks = make(map[int]*sessions.Session)

	if len(token) <= maxCookieSize {
		sd.refreshSession.Values["token"] = token
	} else {
		// Split token into chunks
		sd.refreshSession.Values["token"] = ""
		chunks := splitIntoChunks(token, maxCookieSize)
		for i, chunk := range chunks {
			sessionName := fmt.Sprintf("%s_%d", refreshTokenCookie, i)
			session, _ := sd.manager.store.Get(sd.request, sessionName)
			session.Values["token_chunk"] = chunk
			sd.refreshTokenChunks[i] = session
		}
	}
}

// splitIntoChunks splits a string into chunks of specified size
func splitIntoChunks(s string, chunkSize int) []string {
	var chunks []string
	for len(s) > 0 {
		if len(s) > chunkSize {
			chunks = append(chunks, s[:chunkSize])
			s = s[chunkSize:]
		} else {
			chunks = append(chunks, s)
			break
		}
	}
	return chunks
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
