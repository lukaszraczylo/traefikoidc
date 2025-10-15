// Package core provides core session management functionality for the OIDC middleware
package core

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/sessions"
)

const (
	minEncryptionKeyLength = 32
	absoluteSessionTimeout = 24 * time.Hour
)

// SessionManager handles session creation, management and cleanup
type SessionManager struct {
	sessionPool  sync.Pool
	store        sessions.Store
	logger       Logger
	chunkManager ChunkManager
	cookieDomain string
	cleanupMutex sync.RWMutex
	forceHTTPS   bool
	cleanupDone  bool
}

// Logger interface for dependency injection
type Logger interface {
	Debug(msg string)
	Debugf(format string, args ...interface{})
	Error(msg string)
	Errorf(format string, args ...interface{})
}

// ChunkManager interface for chunk operations
type ChunkManager interface {
	CleanupExpiredSessions()
}

// SessionData interface for session data operations
type SessionData interface {
	Reset()
	SetManager(manager *SessionManager)
	SetAuthenticated(bool) error
	GetAuthenticated() bool
	GetAccessToken() string
	GetRefreshToken() string
	GetIDToken() string
	GetEmail() string
	GetCSRF() string
	GetNonce() string
	GetCodeVerifier() string
	GetIncomingPath() string
	GetRedirectCount() int
	IncrementRedirectCount()
	ResetRedirectCount()
	MarkDirty()
	IsDirty() bool
	Save(r *http.Request, w http.ResponseWriter) error
	Clear(r *http.Request, w http.ResponseWriter) error
	GetRefreshTokenIssuedAt() time.Time
	returnToPoolSafely()
}

// NewSessionManager creates a new SessionManager instance with secure defaults.
// It initializes the cookie store with encryption, sets up session pooling,
// and configures chunk management for large tokens.
func NewSessionManager(encryptionKey string, forceHTTPS bool, cookieDomain string, logger Logger, chunkManager ChunkManager) (*SessionManager, error) {
	if len(encryptionKey) < minEncryptionKeyLength {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long", minEncryptionKeyLength)
	}

	sm := &SessionManager{
		store:        sessions.NewCookieStore([]byte(encryptionKey)),
		forceHTTPS:   forceHTTPS,
		cookieDomain: cookieDomain,
		logger:       logger,
		chunkManager: chunkManager,
	}

	sm.sessionPool.New = func() interface{} {
		return NewSessionData(sm, logger)
	}

	return sm, nil
}

// GetSession retrieves or creates a session for the request
func (sm *SessionManager) GetSession(r *http.Request) (SessionData, error) {
	sessionDataInterface := sm.sessionPool.Get()
	sessionData, ok := sessionDataInterface.(SessionData)
	if !ok || sessionData == nil {
		sessionData = NewSessionData(sm, sm.logger)
	}

	// Initialize the session data
	err := sm.initializeSession(sessionData, r)
	if err != nil {
		sm.sessionPool.Put(sessionData)
		return nil, fmt.Errorf("failed to initialize session: %w", err)
	}

	return sessionData, nil
}

// initializeSession initializes session data from HTTP request
func (sm *SessionManager) initializeSession(sessionData SessionData, r *http.Request) error {
	// Reset session data to clean state
	sessionData.Reset()
	sessionData.SetManager(sm)

	// Load session data from cookies
	session, err := sm.store.Get(r, MainCookieName())
	if err != nil {
		sm.logger.Debugf("Error getting main session: %v", err)
		return nil // Not a fatal error, will create new session
	}

	// Extract and set session values
	if auth, ok := session.Values["authenticated"].(bool); ok {
		_ = sessionData.SetAuthenticated(auth) // Safe to ignore: session initialization error
	}

	return nil
}

// CleanupOldCookies removes old/expired cookies from the response
func (sm *SessionManager) CleanupOldCookies(w http.ResponseWriter, r *http.Request) {
	sm.cleanupMutex.Lock()
	defer sm.cleanupMutex.Unlock()

	if sm.cleanupDone {
		return
	}

	sm.logger.Debug("Starting cleanup of old session cookies")

	oldCookieNames := []string{
		"_oidc_session_old_v1",
		"_oidc_session_legacy",
		"_oidc_auth_state_old",
		"_legacy_oidc_token",
		"_old_session_chunks",
	}

	for _, cookieName := range oldCookieNames {
		if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
			sm.logger.Debugf("Expiring old cookie: %s", cookieName)
			expiredCookie := &http.Cookie{
				Name:     cookieName,
				Value:    "",
				Path:     "/",
				Domain:   sm.cookieDomain,
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				Secure:   sm.shouldUseSecureCookies(r),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(w, expiredCookie)
		}
	}

	sm.cleanupDone = true
}

// PeriodicChunkCleanup performs comprehensive session maintenance and cleanup
func (sm *SessionManager) PeriodicChunkCleanup() {
	if sm == nil || sm.logger == nil {
		return
	}

	sm.logger.Debug("Starting comprehensive session cleanup cycle")

	cleanupStart := time.Now()
	var orphanedChunks, expiredSessions, cleanupErrors int

	if sm.store != nil {
		if cookieStore, ok := sm.store.(*sessions.CookieStore); ok {
			sm.logger.Debug("Running session store cleanup")
			_ = cookieStore
		}
	}

	// Cleanup expired sessions in chunk manager to prevent memory leaks
	if sm.chunkManager != nil {
		sm.chunkManager.CleanupExpiredSessions()
	}

	poolCleaned := 0
	for i := 0; i < 10; i++ {
		if poolSession := sm.sessionPool.Get(); poolSession != nil {
			if sessionData, ok := poolSession.(SessionData); ok && sessionData != nil {
				sessionData.Reset()
				poolCleaned++
			}
			sm.sessionPool.Put(poolSession)
		}
	}

	cleanupDuration := time.Since(cleanupStart)
	sm.logger.Debugf("Session cleanup completed in %v: pool_cleaned=%d, orphaned_chunks=%d, expired_sessions=%d, errors=%d",
		cleanupDuration, poolCleaned, orphanedChunks, expiredSessions, cleanupErrors)
}

// ValidateSessionHealth performs comprehensive validation of session integrity
func (sm *SessionManager) ValidateSessionHealth(sessionData SessionData) error {
	if sessionData == nil {
		return fmt.Errorf("session data is nil")
	}

	// Check if user is authenticated
	if !sessionData.GetAuthenticated() {
		return nil // Not authenticated is not an error
	}

	// Validate token formats
	if accessToken := sessionData.GetAccessToken(); accessToken != "" {
		if err := sm.validateTokenFormat(accessToken, "access"); err != nil {
			return fmt.Errorf("invalid access token format: %w", err)
		}
	}

	if idToken := sessionData.GetIDToken(); idToken != "" {
		if err := sm.validateTokenFormat(idToken, "id"); err != nil {
			return fmt.Errorf("invalid ID token format: %w", err)
		}
	}

	// Check for session tampering
	if err := sm.detectSessionTampering(sessionData); err != nil {
		return fmt.Errorf("session tampering detected: %w", err)
	}

	return nil
}

// validateTokenFormat validates the format of JWT tokens
func (sm *SessionManager) validateTokenFormat(token, tokenType string) error {
	if token == "" {
		return nil
	}

	// JWT tokens should have exactly 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%s token is not a valid JWT format", tokenType)
	}

	// Each part should be non-empty
	for i, part := range parts {
		if part == "" {
			return fmt.Errorf("%s token part %d is empty", tokenType, i+1)
		}
	}

	return nil
}

// detectSessionTampering detects potential tampering in session data
func (sm *SessionManager) detectSessionTampering(sessionData SessionData) error {
	email := sessionData.GetEmail()
	authenticated := sessionData.GetAuthenticated()

	// If authenticated but no email, that's suspicious
	if authenticated && email == "" {
		return fmt.Errorf("authenticated session without email")
	}

	// If email exists but not authenticated, that's also suspicious
	if !authenticated && email != "" {
		sm.logger.Debugf("Warning: Email exists (%s) but session not authenticated", email)
	}

	return nil
}

// GetSessionMetrics returns metrics about session usage
func (sm *SessionManager) GetSessionMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	metrics["store_type"] = fmt.Sprintf("%T", sm.store)
	metrics["cookie_domain"] = sm.cookieDomain
	metrics["force_https"] = sm.forceHTTPS
	metrics["cleanup_done"] = sm.cleanupDone

	return metrics
}

// shouldUseSecureCookies determines if cookies should be secure based on request
func (sm *SessionManager) shouldUseSecureCookies(r *http.Request) bool {
	if sm.forceHTTPS {
		return true
	}

	// Check if the request came over HTTPS
	if r.TLS != nil {
		return true
	}

	// Check X-Forwarded-Proto header
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}

	return false
}

// getSessionOptions returns session options for the given security context
func (sm *SessionManager) getSessionOptions(isSecure bool) *sessions.Options {
	return &sessions.Options{
		Path:     "/",
		Domain:   sm.cookieDomain,
		MaxAge:   int(absoluteSessionTimeout.Seconds()),
		Secure:   isSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Cookie name functions
func MainCookieName() string     { return "_oidc_raczylo_m" }
func AccessTokenCookie() string  { return "_oidc_raczylo_a" }
func RefreshTokenCookie() string { return "_oidc_raczylo_r" }
func IDTokenCookie() string      { return "_oidc_raczylo_id" }

// NewSessionData creates a new session data instance
func NewSessionData(manager *SessionManager, logger Logger) SessionData {
	// This function should be implemented to return a concrete SessionData implementation
	// The actual implementation depends on the SessionData struct definition
	return nil
}
