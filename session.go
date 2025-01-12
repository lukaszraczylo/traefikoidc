package traefikoidc

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/sessions"
)

// Cookie names and configuration constants used for session management
const (
	// mainCookieName is the name of the main session cookie that stores authentication state
	// and basic user information like email and CSRF tokens
	mainCookieName = "_raczylo_oidc"

	// accessTokenCookie is the name of the cookie that stores the OIDC access token
	// This may be split into multiple cookies if the token is large
	accessTokenCookie = "_raczylo_oidc_access"

	// refreshTokenCookie is the name of the cookie that stores the OIDC refresh token
	// This may be split into multiple cookies if the token is large
	refreshTokenCookie = "_raczylo_oidc_refresh"

	// maxCookieSize is the maximum size for each cookie chunk.
	// This value is calculated to ensure the final cookie size stays within browser limits:
	// 1. Browser cookie size limit is typically 4096 bytes
	// 2. Cookie content undergoes encryption (adds 28 bytes) and base64 encoding (4/3 ratio)
	// 3. Calculation:
	//    - Let x be the chunk size
	//    - After encryption: x + 28 bytes
	//    - After base64: ((x + 28) * 4/3) bytes
	//    - Must satisfy: ((x + 28) * 4/3) ≤ 4096
	//    - Solving for x: x ≤ 3044
	// 4. We use 2000 as a conservative limit to account for cookie metadata
	maxCookieSize = 2000
)

// compressToken compresses a token using gzip and base64 encodes it
func compressToken(token string) string {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(token)); err != nil {
		return token // fallback to uncompressed on error
	}
	if err := gz.Close(); err != nil {
		return token
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

// decompressToken decompresses a base64 encoded gzipped token
func decompressToken(compressed string) string {
	data, err := base64.StdEncoding.DecodeString(compressed)
	if err != nil {
		return compressed // return as-is if not base64
	}
	
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return compressed
	}
	defer gz.Close()
	
	decompressed, err := io.ReadAll(gz)
	if err != nil {
		return compressed
	}
	
	return string(decompressed)
}

// SessionManager handles the management of multiple session cookies for OIDC authentication.
// It provides functionality for storing and retrieving authentication state, tokens,
// and other session-related data across multiple cookies to handle large tokens.
type SessionManager struct {
	// store is the underlying session store for cookie management
	store sessions.Store

	// forceHTTPS enforces secure cookie attributes regardless of request scheme
	forceHTTPS bool

	// logger provides structured logging capabilities
	logger *Logger

	// sessionPool is a sync.Pool for reusing SessionData objects
	sessionPool sync.Pool
}

// NewSessionManager creates a new session manager with the specified configuration.
// Parameters:
//   - encryptionKey: Key used to encrypt session data (must be at least 32 bytes)
//   - forceHTTPS: When true, forces secure cookie attributes regardless of request scheme
//   - logger: Logger instance for recording session-related events
// The manager handles session creation, storage, and cookie security settings.
func NewSessionManager(encryptionKey string, forceHTTPS bool, logger *Logger) *SessionManager {
	sm := &SessionManager{
		store:      sessions.NewCookieStore([]byte(encryptionKey)),
		forceHTTPS: forceHTTPS,
		logger:     logger,
	}

	// Initialize session pool
	sm.sessionPool.New = func() interface{} {
		return &SessionData{
			manager:           sm,
			accessTokenChunks: make(map[int]*sessions.Session),
			refreshTokenChunks: make(map[int]*sessions.Session),
		}
	}

	return sm
}

// getSessionOptions returns secure session options configured for the current request.
// Parameters:
//   - isSecure: Whether the current request is using HTTPS
// The options ensure cookies are:
//   - HTTP-only (not accessible via JavaScript)
//   - Secure when using HTTPS or when forceHTTPS is enabled
//   - Using SameSite=Lax for CSRF protection
//   - Set with appropriate timeout and path settings
func (sm *SessionManager) getSessionOptions(isSecure bool) *sessions.Options {
	return &sessions.Options{
		HttpOnly: true,
		Secure:   isSecure || sm.forceHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   ConstSessionTimeout,
		Path:     "/",
	}
}

// GetSession retrieves all session data for the current request.
// It loads the main session and token sessions, including any chunked token data,
// and combines them into a single SessionData structure for easy access.
// Returns an error if any session component cannot be loaded.
func (sm *SessionManager) GetSession(r *http.Request) (*SessionData, error) {
	// Get session from pool
	sessionData := sm.sessionPool.Get().(*SessionData)
	sessionData.request = r

	var err error
	sessionData.mainSession, err = sm.store.Get(r, mainCookieName)
	if err != nil {
		sm.sessionPool.Put(sessionData)
		return nil, fmt.Errorf("failed to get main session: %w", err)
	}

	sessionData.accessSession, err = sm.store.Get(r, accessTokenCookie)
	if err != nil {
		sm.sessionPool.Put(sessionData)
		return nil, fmt.Errorf("failed to get access token session: %w", err)
	}

	sessionData.refreshSession, err = sm.store.Get(r, refreshTokenCookie)
	if err != nil {
		sm.sessionPool.Put(sessionData)
		return nil, fmt.Errorf("failed to get refresh token session: %w", err)
	}

	// Clear and reuse chunk maps
	for k := range sessionData.accessTokenChunks {
		delete(sessionData.accessTokenChunks, k)
	}
	for k := range sessionData.refreshTokenChunks {
		delete(sessionData.refreshTokenChunks, k)
	}

	// Retrieve chunked token sessions
	sm.getTokenChunkSessions(r, accessTokenCookie, sessionData.accessTokenChunks)
	sm.getTokenChunkSessions(r, refreshTokenCookie, sessionData.refreshTokenChunks)

	return sessionData, nil
}

// getTokenChunkSessions retrieves all session chunks for a given token type.
// Parameters:
//   - r: The HTTP request
//   - baseName: The base name for the token's session cookies
//   - chunks: Map to store the chunks in
func (sm *SessionManager) getTokenChunkSessions(r *http.Request, baseName string, chunks map[int]*sessions.Session) {
	for i := 0; ; i++ {
		sessionName := fmt.Sprintf("%s_%d", baseName, i)
		session, err := sm.store.Get(r, sessionName)
		if err != nil || session.IsNew {
			// No more sessions
			break
		}
		chunks[i] = session
	}
}

// SessionData holds all session information for an authenticated user.
// It manages multiple session cookies to handle the main session state
// and potentially large access and refresh tokens that may need to be
// split across multiple cookies due to browser size limitations.
type SessionData struct {
	// manager is the SessionManager that created this SessionData
	manager *SessionManager

	// request is the current HTTP request associated with this session
	request *http.Request

	// mainSession stores authentication state and basic user info
	mainSession *sessions.Session

	// accessSession stores the primary access token cookie
	accessSession *sessions.Session

	// refreshSession stores the primary refresh token cookie
	refreshSession *sessions.Session

	// accessTokenChunks stores additional chunks of the access token
	// when it exceeds the maximum cookie size
	accessTokenChunks map[int]*sessions.Session

	// refreshTokenChunks stores additional chunks of the refresh token
	// when it exceeds the maximum cookie size
	refreshTokenChunks map[int]*sessions.Session
}

// Save persists all session data to cookies in the HTTP response.
// It saves the main session, token sessions, and any token chunks,
// applying appropriate security options to each cookie. All cookies
// are saved with consistent security settings based on the request scheme.
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

// Clear removes all session data by expiring all cookies and clearing their values.
// This is typically used during logout to ensure all session data is properly cleaned up.
// It handles both main session data and any token chunks that may exist.
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

	err := sd.Save(r, w)
	
	// Return session to pool
	sd.manager.sessionPool.Put(sd)
	
	return err
}

// clearTokenChunks removes all session chunks for a given token type.
// It expires the cookies and removes all stored values to ensure
// no token data remains after logout or token invalidation.
func (sd *SessionData) clearTokenChunks(r *http.Request, chunks map[int]*sessions.Session) {
	for _, session := range chunks {
		session.Options.MaxAge = -1
		for k := range session.Values {
			delete(session.Values, k)
		}
	}
}

// GetAuthenticated returns whether the current session is authenticated.
// Returns true if the user has successfully completed OIDC authentication,
// false otherwise or if the authentication status cannot be determined.
func (sd *SessionData) GetAuthenticated() bool {
	auth, _ := sd.mainSession.Values["authenticated"].(bool)
	return auth
}

// SetAuthenticated updates the session's authentication status.
// This should be called after successful OIDC authentication or during logout.
func (sd *SessionData) SetAuthenticated(value bool) {
	sd.mainSession.Values["authenticated"] = value
}

// GetAccessToken retrieves the complete access token from the session.
// If the token was split into chunks due to size limitations, it will
// automatically reassemble the complete token from all chunks.
// Returns an empty string if no token is found.
func (sd *SessionData) GetAccessToken() string {
	token, _ := sd.accessSession.Values["token"].(string)
	if token != "" {
		compressed, _ := sd.accessSession.Values["compressed"].(bool)
		if compressed {
			return decompressToken(token)
		}
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

	token = strings.Join(chunks, "")
	compressed, _ := sd.accessSession.Values["compressed"].(bool)
	if compressed {
		return decompressToken(token)
	}
	return token
}

// SetAccessToken stores the access token in the session.
// If the token exceeds maxCookieSize, it is automatically compressed and split into
// multiple cookie chunks to handle large tokens while staying within
// browser cookie size limits. Any existing token or chunks are cleared
// before setting the new token.
func (sd *SessionData) SetAccessToken(token string) {
	// Clear existing chunks
	sd.clearTokenChunks(sd.request, sd.accessTokenChunks)
	sd.accessTokenChunks = make(map[int]*sessions.Session)

	// Compress token
	compressed := compressToken(token)

	if len(compressed) <= maxCookieSize {
		sd.accessSession.Values["token"] = compressed
		sd.accessSession.Values["compressed"] = true
	} else {
		// Split compressed token into chunks
		sd.accessSession.Values["token"] = ""
		sd.accessSession.Values["compressed"] = true
		chunks := splitIntoChunks(compressed, maxCookieSize)
		for i, chunk := range chunks {
			sessionName := fmt.Sprintf("%s_%d", accessTokenCookie, i)
			session, _ := sd.manager.store.Get(sd.request, sessionName)
			session.Values["token_chunk"] = chunk
			sd.accessTokenChunks[i] = session
		}
	}
}

// GetRefreshToken retrieves the complete refresh token from the session.
// If the token was split into chunks due to size limitations, it will
// automatically reassemble the complete token from all chunks.
// Returns an empty string if no token is found.
func (sd *SessionData) GetRefreshToken() string {
	token, _ := sd.refreshSession.Values["token"].(string)
	if token != "" {
		compressed, _ := sd.refreshSession.Values["compressed"].(bool)
		if compressed {
			return decompressToken(token)
		}
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

	token = strings.Join(chunks, "")
	compressed, _ := sd.refreshSession.Values["compressed"].(bool)
	if compressed {
		return decompressToken(token)
	}
	return token
}

// SetRefreshToken stores the refresh token in the session.
// If the token exceeds maxCookieSize, it is automatically compressed and split into
// multiple cookie chunks to handle large tokens while staying within
// browser cookie size limits. Any existing token or chunks are cleared
// before setting the new token.
func (sd *SessionData) SetRefreshToken(token string) {
	// Clear existing chunks
	sd.clearTokenChunks(sd.request, sd.refreshTokenChunks)
	sd.refreshTokenChunks = make(map[int]*sessions.Session)

	// Compress token
	compressed := compressToken(token)

	if len(compressed) <= maxCookieSize {
		sd.refreshSession.Values["token"] = compressed
		sd.refreshSession.Values["compressed"] = true
	} else {
		// Split compressed token into chunks
		sd.refreshSession.Values["token"] = ""
		sd.refreshSession.Values["compressed"] = true
		chunks := splitIntoChunks(compressed, maxCookieSize)
		for i, chunk := range chunks {
			sessionName := fmt.Sprintf("%s_%d", refreshTokenCookie, i)
			session, _ := sd.manager.store.Get(sd.request, sessionName)
			session.Values["token_chunk"] = chunk
			sd.refreshTokenChunks[i] = session
		}
	}
}

// splitIntoChunks splits a string into chunks of specified size.
// This is used internally to handle large tokens that exceed cookie size limits.
// Parameters:
//   - s: The string to split
//   - chunkSize: Maximum size of each chunk
// Returns an array of string chunks, each no larger than chunkSize.
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

// GetCSRF retrieves the CSRF token from the session.
// This token is used to prevent cross-site request forgery attacks
// by ensuring requests originate from the authenticated user.
// Returns an empty string if no CSRF token is found.
func (sd *SessionData) GetCSRF() string {
	csrf, _ := sd.mainSession.Values["csrf"].(string)
	return csrf
}

// SetCSRF stores a new CSRF token in the session.
// This should be called when initiating authentication to generate
// a new token for the authentication flow.
func (sd *SessionData) SetCSRF(token string) {
	sd.mainSession.Values["csrf"] = token
}

// GetNonce retrieves the nonce value from the session.
// The nonce is used to prevent replay attacks in the OIDC flow
// by ensuring the token received matches the authentication request.
// Returns an empty string if no nonce is found.
func (sd *SessionData) GetNonce() string {
	nonce, _ := sd.mainSession.Values["nonce"].(string)
	return nonce
}

// SetNonce stores a new nonce value in the session.
// This should be called when initiating authentication to generate
// a new nonce for the OIDC authentication flow.
func (sd *SessionData) SetNonce(nonce string) {
	sd.mainSession.Values["nonce"] = nonce
}

// GetEmail retrieves the authenticated user's email address from the session.
// The email is typically extracted from the OIDC ID token claims.
// Returns an empty string if no email is found.
func (sd *SessionData) GetEmail() string {
	email, _ := sd.mainSession.Values["email"].(string)
	return email
}

// SetEmail stores the user's email address in the session.
// This should be called after successful authentication when
// processing the OIDC ID token claims.
func (sd *SessionData) SetEmail(email string) {
	sd.mainSession.Values["email"] = email
}

// GetIncomingPath retrieves the original request path that triggered
// the authentication flow. This is used to redirect the user back
// to their intended destination after successful authentication.
// Returns an empty string if no path was stored.
func (sd *SessionData) GetIncomingPath() string {
	path, _ := sd.mainSession.Values["incoming_path"].(string)
	return path
}

// SetIncomingPath stores the original request path that triggered
// the authentication flow. This should be called before redirecting
// to the OIDC provider to remember where to send the user afterward.
func (sd *SessionData) SetIncomingPath(path string) {
	sd.mainSession.Values["incoming_path"] = path
}
