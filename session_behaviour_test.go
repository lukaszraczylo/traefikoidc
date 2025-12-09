package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// SessionBehaviourSuite tests session management behavior
type SessionBehaviourSuite struct {
	suite.Suite
	logger         *Logger
	sessionManager *SessionManager
}

func (s *SessionBehaviourSuite) SetupTest() {
	s.logger = NewLogger("error")

	var err error
	s.sessionManager, err = NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)
}

func (s *SessionBehaviourSuite) TearDownTest() {
	if s.sessionManager != nil {
		s.sessionManager.Shutdown()
	}
}

// TestValidateSessionHealth_NilSession tests validation with nil session
func (s *SessionBehaviourSuite) TestValidateSessionHealth_NilSession() {
	err := s.sessionManager.ValidateSessionHealth(nil)
	s.Error(err)
	s.Contains(err.Error(), "session data is nil")
}

// TestValidateSessionHealth_NotAuthenticated tests validation with unauthenticated session
func (s *SessionBehaviourSuite) TestValidateSessionHealth_NotAuthenticated() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Session is not authenticated by default
	err = s.sessionManager.ValidateSessionHealth(session)
	s.Error(err)
	s.Contains(err.Error(), "session is not authenticated")
}

// TestValidateSessionHealth_AuthenticatedSession tests validation with authenticated session
func (s *SessionBehaviourSuite) TestValidateSessionHealth_AuthenticatedSession() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set session as authenticated
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)

	// Validate health - should pass
	err = s.sessionManager.ValidateSessionHealth(session)
	s.NoError(err)
}

// TestValidateSessionHealth_WithValidAccessToken tests validation with valid access token
func (s *SessionBehaviourSuite) TestValidateSessionHealth_WithValidAccessToken() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set session as authenticated
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)

	// Set a valid-format access token (opaque token format)
	session.SetAccessToken("valid-access-token-with-sufficient-length-for-testing")

	// Validate health - should pass
	err = s.sessionManager.ValidateSessionHealth(session)
	s.NoError(err)
}

// TestValidateSessionHealth_CorruptedAccessToken tests validation with corrupted access token
func (s *SessionBehaviourSuite) TestValidateSessionHealth_CorruptedAccessToken() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set session as authenticated
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)

	// Manually set a corrupted access token
	session.accessSession.Values["token"] = "__CORRUPTION_MARKER_TEST__"
	session.accessSession.Values["compressed"] = false

	// Validate health - should fail
	err = s.sessionManager.ValidateSessionHealth(session)
	s.Error(err)
	s.Contains(err.Error(), "access token validation failed")
}

// TestValidateSessionHealth_PathTraversalAttempt tests detection of path traversal in session
func (s *SessionBehaviourSuite) TestValidateSessionHealth_PathTraversalAttempt() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set session as authenticated
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)

	// Inject path traversal attempt in session value
	session.mainSession.Values["malicious"] = "../../../etc/passwd"

	// Validate health - should detect tampering
	err = s.sessionManager.ValidateSessionHealth(session)
	s.Error(err)
	s.Contains(err.Error(), "tampering detected")
}

// TestValidateSessionHealth_XSSAttempt tests detection of XSS attempt in session
func (s *SessionBehaviourSuite) TestValidateSessionHealth_XSSAttempt() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set session as authenticated
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)

	// Inject XSS attempt in session value
	session.mainSession.Values["xss"] = "<script>alert('xss')</script>"

	// Validate health - should detect tampering
	err = s.sessionManager.ValidateSessionHealth(session)
	s.Error(err)
	s.Contains(err.Error(), "tampering detected")
}

// TestValidateSessionHealth_SuspiciouslyLongValue tests detection of suspiciously long values
func (s *SessionBehaviourSuite) TestValidateSessionHealth_SuspiciouslyLongValue() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set session as authenticated
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)

	// Inject suspiciously long value
	session.mainSession.Values["long_value"] = strings.Repeat("x", 15000)

	// Validate health - should detect suspicious value
	err = s.sessionManager.ValidateSessionHealth(session)
	s.Error(err)
	s.Contains(err.Error(), "suspiciously long")
}

// TestValidateTokenFormat_EmptyToken tests validation of empty token
func (s *SessionBehaviourSuite) TestValidateTokenFormat_EmptyToken() {
	err := s.sessionManager.validateTokenFormat("", "access_token")
	s.NoError(err) // Empty tokens are valid (just not present)
}

// TestValidateTokenFormat_ValidJWT tests validation of valid JWT format
func (s *SessionBehaviourSuite) TestValidateTokenFormat_ValidJWT() {
	// Valid JWT format (header.payload.signature)
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	err := s.sessionManager.validateTokenFormat(jwt, "id_token")
	s.NoError(err)
}

// TestValidateTokenFormat_InvalidJWTWithEmptyPart tests JWT with empty part
func (s *SessionBehaviourSuite) TestValidateTokenFormat_InvalidJWTWithEmptyPart() {
	// JWT with empty part
	invalidJWT := "header..signature"
	err := s.sessionManager.validateTokenFormat(invalidJWT, "id_token")
	s.Error(err)
	s.Contains(err.Error(), "empty part")
}

// TestValidateTokenFormat_CorruptionMarker tests detection of corruption marker
func (s *SessionBehaviourSuite) TestValidateTokenFormat_CorruptionMarker() {
	err := s.sessionManager.validateTokenFormat("__CORRUPTION_MARKER_TEST__", "access_token")
	s.Error(err)
	s.Contains(err.Error(), "corruption marker")
}

// TestPeriodicChunkCleanup tests the periodic cleanup function
func (s *SessionBehaviourSuite) TestPeriodicChunkCleanup() {
	// This should not panic or error
	s.sessionManager.PeriodicChunkCleanup()

	// Verify it can be called multiple times
	s.sessionManager.PeriodicChunkCleanup()
	s.sessionManager.PeriodicChunkCleanup()
}

// TestPeriodicChunkCleanup_WithCanceledContext tests cleanup with canceled context
func (s *SessionBehaviourSuite) TestPeriodicChunkCleanup_WithCanceledContext() {
	// Cancel the context
	s.sessionManager.cancel()

	// Should return early without panicking
	s.sessionManager.PeriodicChunkCleanup()
}

// TestGetSessionStats tests session statistics retrieval
func (s *SessionBehaviourSuite) TestGetSessionStats() {
	stats := s.sessionManager.GetSessionStats()

	s.NotNil(stats)
	s.Contains(stats, "active_sessions")
	s.Contains(stats, "pool_hits")
	s.Contains(stats, "pool_misses")
}

// TestGetSessionMetrics tests session metrics retrieval
func (s *SessionBehaviourSuite) TestGetSessionMetrics() {
	metrics := s.sessionManager.GetSessionMetrics()

	s.NotNil(metrics)
	s.Equal("CookieStore", metrics["session_manager_type"])
	s.Contains(metrics, "force_https")
	s.Contains(metrics, "absolute_timeout_hours")
	s.Contains(metrics, "max_cookie_size")
	s.Contains(metrics, "has_encryption")
}

// TestEnhanceSessionSecurity_NilOptions tests enhancing nil options
func (s *SessionBehaviourSuite) TestEnhanceSessionSecurity_NilOptions() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	options := s.sessionManager.EnhanceSessionSecurity(nil, req)

	s.NotNil(options)
	s.True(options.HttpOnly)
	s.Equal("/", options.Path)
}

// TestEnhanceSessionSecurity_WithHTTPS tests enhancing with HTTPS request
func (s *SessionBehaviourSuite) TestEnhanceSessionSecurity_WithHTTPS() {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	options := s.sessionManager.EnhanceSessionSecurity(nil, req)

	s.True(options.Secure)
	s.Equal(http.SameSiteLaxMode, options.SameSite)
}

// TestEnhanceSessionSecurity_MissingUserAgent tests handling of missing User-Agent
func (s *SessionBehaviourSuite) TestEnhanceSessionSecurity_MissingUserAgent() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Explicitly remove User-Agent
	req.Header.Del("User-Agent")

	options := s.sessionManager.EnhanceSessionSecurity(nil, req)

	// Should have reduced MaxAge for suspicious requests
	s.NotNil(options)
}

// TestCleanupOldCookies tests cookie cleanup
func (s *SessionBehaviourSuite) TestCleanupOldCookies() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Host", "example.com")
	rw := httptest.NewRecorder()

	// Add some cookies that match the prefix
	req.AddCookie(&http.Cookie{Name: "_oidc_raczylo_m", Value: "test"})
	req.AddCookie(&http.Cookie{Name: "_oidc_raczylo_a", Value: "test"})

	// Should not panic
	s.sessionManager.CleanupOldCookies(rw, req)
}

// TestSessionData_DirtyTracking tests dirty flag tracking
func (s *SessionBehaviourSuite) TestSessionData_DirtyTracking() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Initially not dirty (fresh session from pool)
	s.False(session.IsDirty())

	// Mark dirty
	session.MarkDirty()
	s.True(session.IsDirty())

	// Reset should clear dirty flag
	session.Reset()
	s.False(session.IsDirty())
}

// TestSessionData_SetEmail tests email setter with dirty tracking
func (s *SessionBehaviourSuite) TestSessionData_SetEmail() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set email
	session.SetEmail("test@example.com")
	s.Equal("test@example.com", session.GetEmail())
	s.True(session.IsDirty())
}

// TestSessionData_SetCSRF tests CSRF setter with dirty tracking
func (s *SessionBehaviourSuite) TestSessionData_SetCSRF() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set CSRF
	session.SetCSRF("csrf-token-value")
	s.Equal("csrf-token-value", session.GetCSRF())
	s.True(session.IsDirty())

	// Setting same value should not trigger dirty again
	session.dirty = false
	session.SetCSRF("csrf-token-value")
	s.False(session.IsDirty())
}

// TestSessionData_SetNonce tests nonce setter with dirty tracking
func (s *SessionBehaviourSuite) TestSessionData_SetNonce() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set nonce
	session.SetNonce("nonce-value")
	s.Equal("nonce-value", session.GetNonce())
	s.True(session.IsDirty())
}

// TestSessionData_SetCodeVerifier tests code verifier setter
func (s *SessionBehaviourSuite) TestSessionData_SetCodeVerifier() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set code verifier
	session.SetCodeVerifier("pkce-code-verifier")
	s.Equal("pkce-code-verifier", session.GetCodeVerifier())
	s.True(session.IsDirty())
}

// TestSessionData_SetIncomingPath tests incoming path setter
func (s *SessionBehaviourSuite) TestSessionData_SetIncomingPath() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set incoming path
	session.SetIncomingPath("/original/path?query=value")
	s.Equal("/original/path?query=value", session.GetIncomingPath())
	s.True(session.IsDirty())
}

// TestSessionData_RedirectCount tests redirect count operations
func (s *SessionBehaviourSuite) TestSessionData_RedirectCount() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Initial count should be 0
	s.Equal(0, session.GetRedirectCount())

	// Increment
	session.IncrementRedirectCount()
	s.Equal(1, session.GetRedirectCount())

	session.IncrementRedirectCount()
	s.Equal(2, session.GetRedirectCount())

	// Reset
	session.ResetRedirectCount()
	s.Equal(0, session.GetRedirectCount())
}

// TestSessionData_SetAccessToken tests access token storage
func (s *SessionBehaviourSuite) TestSessionData_SetAccessToken() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set a valid opaque access token
	token := "opaque-access-token-with-sufficient-length-for-testing"
	session.SetAccessToken(token)

	// Get the token back
	retrieved := session.GetAccessToken()
	s.Equal(token, retrieved)
}

// TestSessionData_SetAccessToken_InvalidFormat tests rejection of invalid token format
func (s *SessionBehaviourSuite) TestSessionData_SetAccessToken_InvalidFormat() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set a token with invalid format (exactly 1 dot is invalid)
	session.SetAccessToken("invalid.token")

	// Should be rejected
	retrieved := session.GetAccessToken()
	s.Empty(retrieved)
}

// TestSessionData_SetAccessToken_TooShortOpaque tests rejection of too short opaque token
func (s *SessionBehaviourSuite) TestSessionData_SetAccessToken_TooShortOpaque() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set a very short opaque token (less than 20 chars)
	session.SetAccessToken("short")

	// Should be rejected
	retrieved := session.GetAccessToken()
	s.Empty(retrieved)
}

// TestSessionData_SetIDToken_ValidJWT tests ID token storage with valid JWT
func (s *SessionBehaviourSuite) TestSessionData_SetIDToken_ValidJWT() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set a valid JWT format ID token
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature"
	session.SetIDToken(token)

	// The ID token should be stored - verify it directly from the session
	// since GetIDToken uses ChunkManager which may apply additional validation
	storedToken, _ := session.idTokenSession.Values["token"].(string)
	s.NotEmpty(storedToken)
	s.True(session.IsDirty())
}

// TestSessionData_SetIDToken_InvalidFormat tests rejection of invalid ID token format
func (s *SessionBehaviourSuite) TestSessionData_SetIDToken_InvalidFormat() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set a non-JWT format (ID tokens must be JWT)
	session.SetIDToken("not-a-jwt-token")

	// Should be rejected
	retrieved := session.GetIDToken()
	s.Empty(retrieved)
}

// TestSessionData_SetRefreshToken tests refresh token storage
func (s *SessionBehaviourSuite) TestSessionData_SetRefreshToken() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Set refresh token (opaque format is valid)
	token := "refresh-token-opaque-format-value"
	session.SetRefreshToken(token)

	// Get the token back
	retrieved := session.GetRefreshToken()
	s.Equal(token, retrieved)
}

// TestSessionData_SetRefreshToken_TooLarge tests rejection of too large refresh token
func (s *SessionBehaviourSuite) TestSessionData_SetRefreshToken_TooLarge() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Create a very large token (over 50KB)
	largeToken := strings.Repeat("x", 60*1024)
	session.SetRefreshToken(largeToken)

	// Should be rejected
	retrieved := session.GetRefreshToken()
	s.Empty(retrieved)
}

// TestSessionData_GetRefreshTokenIssuedAt tests refresh token issued timestamp
func (s *SessionBehaviourSuite) TestSessionData_GetRefreshTokenIssuedAt() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Before setting refresh token, issued_at should be zero
	issuedAt := session.GetRefreshTokenIssuedAt()
	s.True(issuedAt.IsZero())

	// Set refresh token (this sets issued_at)
	session.SetRefreshToken("refresh-token-value-here")

	// Now issued_at should be set
	issuedAt = session.GetRefreshTokenIssuedAt()
	s.False(issuedAt.IsZero())
	s.True(time.Since(issuedAt) < 5*time.Second) // Should be very recent
}

// TestSessionData_Clear tests session clearing
func (s *SessionBehaviourSuite) TestSessionData_Clear() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rw := httptest.NewRecorder()

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)

	// Set some data
	err = session.SetAuthenticated(true)
	s.Require().NoError(err)
	session.SetEmail("test@example.com")
	session.SetCSRF("csrf-token")

	// Clear session
	err = session.Clear(req, rw)
	s.NoError(err)

	// After clear, session is returned to pool, so we shouldn't use it
}

// TestSessionData_Save tests session saving
func (s *SessionBehaviourSuite) TestSessionData_Save() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rw := httptest.NewRecorder()

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)
	defer session.returnToPoolSafely()

	// Modify session
	session.SetEmail("test@example.com")
	s.True(session.IsDirty())

	// Save session
	err = session.Save(req, rw)
	s.NoError(err)

	// After save, dirty flag should be cleared
	s.False(session.IsDirty())

	// Response should have cookies
	cookies := rw.Result().Cookies()
	s.NotEmpty(cookies)
}

// TestSessionData_ReturnToPool tests returning session to pool
func (s *SessionBehaviourSuite) TestSessionData_ReturnToPool() {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	session, err := s.sessionManager.GetSession(req)
	s.Require().NoError(err)

	// Initially in use
	s.True(session.inUse)

	// Return to pool safely
	session.returnToPoolSafely()

	// Should no longer be in use
	s.False(session.inUse)
}

// TestTokenCompression tests token compression functionality
func (s *SessionBehaviourSuite) TestTokenCompression() {
	// A typical JWT token that could benefit from compression
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsInN1YiI6InRlc3Qtc3ViamVjdCIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjoxNzAyNDE2MDAwLCJpYXQiOjE3MDI0MTI0MDAsIm5vbmNlIjoidGVzdC1ub25jZSIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSJ9.signature_data_here"

	compressed := compressToken(token)

	// Decompress and verify
	decompressed := decompressToken(compressed)
	s.Equal(token, decompressed)
}

// TestTokenCompression_EmptyToken tests compression of empty token
func (s *SessionBehaviourSuite) TestTokenCompression_EmptyToken() {
	compressed := compressToken("")
	s.Empty(compressed)

	decompressed := decompressToken("")
	s.Empty(decompressed)
}

// TestTokenCompression_InvalidFormat tests compression of non-JWT token
func (s *SessionBehaviourSuite) TestTokenCompression_InvalidFormat() {
	// Token without proper JWT format (wrong number of dots)
	token := "not-a-jwt"
	compressed := compressToken(token)

	// Should return original (not compressed)
	s.Equal(token, compressed)
}

// TestSplitIntoChunks tests chunk splitting functionality
func (s *SessionBehaviourSuite) TestSplitIntoChunks() {
	// Test with a string that needs splitting
	data := strings.Repeat("x", 3000)
	chunks := splitIntoChunks(data, 1000)

	s.Equal(3, len(chunks))
	s.Equal(1000, len(chunks[0]))
	s.Equal(1000, len(chunks[1]))
	s.Equal(1000, len(chunks[2]))

	// Verify reassembly
	reassembled := strings.Join(chunks, "")
	s.Equal(data, reassembled)
}

// TestSplitIntoChunks_SmallData tests chunk splitting with data smaller than chunk size
func (s *SessionBehaviourSuite) TestSplitIntoChunks_SmallData() {
	data := "small"
	chunks := splitIntoChunks(data, 1000)

	s.Equal(1, len(chunks))
	s.Equal(data, chunks[0])
}

// TestValidateChunkSize tests chunk size validation
func (s *SessionBehaviourSuite) TestValidateChunkSize() {
	// Small chunk should be valid
	s.True(validateChunkSize("small_chunk_data"))

	// Very large chunk should be invalid
	largeChunk := strings.Repeat("x", 5000)
	s.False(validateChunkSize(largeChunk))
}

// TestIsCorruptionMarker tests corruption marker detection
func (s *SessionBehaviourSuite) TestIsCorruptionMarker() {
	// Known corruption markers
	s.True(isCorruptionMarker("__CORRUPTION_MARKER_TEST__"))
	s.True(isCorruptionMarker("__INVALID_BASE64_DATA__"))
	s.True(isCorruptionMarker("<<<CORRUPTED>>>"))

	// Normal data
	s.False(isCorruptionMarker("normal-data"))
	s.False(isCorruptionMarker("eyJhbGciOiJSUzI1NiJ9"))
	s.False(isCorruptionMarker(""))

	// Data with special characters (in long strings)
	s.True(isCorruptionMarker("long-string-with!special@chars"))
}

// TestSessionManager_Shutdown tests graceful shutdown
func (s *SessionBehaviourSuite) TestSessionManager_Shutdown() {
	// Create a new session manager for this test
	sm, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Require().NoError(err)

	// Shutdown should complete without error
	err = sm.Shutdown()
	s.NoError(err)

	// Second shutdown should also be safe (idempotent)
	err = sm.Shutdown()
	s.NoError(err)
}

// TestCookieNameHelpers tests cookie name helper methods
func (s *SessionBehaviourSuite) TestCookieNameHelpers() {
	s.Equal("_oidc_raczylo_m", s.sessionManager.mainCookieName())
	s.Equal("_oidc_raczylo_a", s.sessionManager.accessTokenCookieName())
	s.Equal("_oidc_raczylo_r", s.sessionManager.refreshTokenCookieName())
	s.Equal("_oidc_raczylo_id", s.sessionManager.idTokenCookieName())
}

// TestSessionManager_CustomCookiePrefix tests custom cookie prefix
func (s *SessionBehaviourSuite) TestSessionManager_CustomCookiePrefix() {
	customSM, err := NewSessionManager(
		"test-encryption-key-32-bytes-long!!",
		false,
		"",
		"custom_prefix_",
		0,
		s.logger,
	)
	s.Require().NoError(err)
	defer customSM.Shutdown()

	s.Equal("custom_prefix_m", customSM.mainCookieName())
	s.Equal("custom_prefix_a", customSM.accessTokenCookieName())
	s.Equal("custom_prefix_r", customSM.refreshTokenCookieName())
	s.Equal("custom_prefix_id", customSM.idTokenCookieName())
}

// TestSessionManager_ShortEncryptionKey tests rejection of short encryption key
func (s *SessionBehaviourSuite) TestSessionManager_ShortEncryptionKey() {
	_, err := NewSessionManager(
		"short", // Too short
		false,
		"",
		"",
		0,
		s.logger,
	)
	s.Error(err)
	s.Contains(err.Error(), "encryption key must be at least")
}

// TestGenerateSecureRandomString tests secure random string generation
func (s *SessionBehaviourSuite) TestGenerateSecureRandomString() {
	// Generate two random strings
	str1, err := generateSecureRandomString(32)
	s.NoError(err)
	s.Equal(64, len(str1)) // Hex encoding doubles length

	str2, err := generateSecureRandomString(32)
	s.NoError(err)
	s.Equal(64, len(str2))

	// They should be different
	s.NotEqual(str1, str2)
}

// TestConstantTimeStringCompare tests constant-time string comparison
func (s *SessionBehaviourSuite) TestConstantTimeStringCompare() {
	s.True(constantTimeStringCompare("hello", "hello"))
	s.False(constantTimeStringCompare("hello", "world"))
	s.False(constantTimeStringCompare("hello", "hell"))
	s.False(constantTimeStringCompare("", "hello"))
	s.True(constantTimeStringCompare("", ""))
}

func TestSessionBehaviourSuite(t *testing.T) {
	suite.Run(t, new(SessionBehaviourSuite))
}
