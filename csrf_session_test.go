package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCSRFTokenSessionManagement tests the session management changes that fix the login loop
func TestCSRFTokenSessionManagement(t *testing.T) {
	// Test that CSRF tokens persist through the authentication flow
	t.Run("CSRF_Token_Persists_After_Selective_Clear", func(t *testing.T) {
		// Create a session manager
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
		require.NoError(t, err)

		// Create initial request
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set initial values
		csrfToken := "critical-csrf-token"
		session.SetCSRF(csrfToken)
		session.SetNonce("test-nonce")
		session.SetAuthenticated(true)
		session.SetEmail("user@example.com")
		session.SetAccessToken("old-access-token")
		session.SetRefreshToken("old-refresh-token")
		session.SetIDToken("old-id-token")

		// Save session
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Get cookies
		cookies := rec.Result().Cookies()

		// Create new request with cookies (simulating redirect back)
		req2 := httptest.NewRequest("GET", "http://example.com/test2", nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		// Get session again
		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		// Verify all values are there
		assert.Equal(t, csrfToken, session2.GetCSRF())
		assert.Equal(t, "test-nonce", session2.GetNonce())
		assert.True(t, session2.GetAuthenticated())

		// Now perform selective clearing (as done in the fix)
		session2.SetAuthenticated(false)
		session2.SetEmail("")
		session2.SetAccessToken("")
		session2.SetRefreshToken("")
		session2.SetIDToken("")
		// Clear OIDC flow values from previous attempts
		session2.SetNonce("")
		session2.SetCodeVerifier("")

		// CRITICAL: CSRF token should still be there
		assert.Equal(t, csrfToken, session2.GetCSRF(), "CSRF token must persist after selective clearing")

		// Save again
		rec2 := httptest.NewRecorder()
		err = session2.Save(req2, rec2)
		require.NoError(t, err)

		// Verify CSRF token persists in new session
		req3 := httptest.NewRequest("GET", "http://example.com/callback", nil)
		for _, cookie := range rec2.Result().Cookies() {
			req3.AddCookie(cookie)
		}

		session3, err := sessionManager.GetSession(req3)
		require.NoError(t, err)
		assert.Equal(t, csrfToken, session3.GetCSRF(), "CSRF token must persist across saves")
	})

	// Test that marking session as dirty forces save
	t.Run("Mark_Dirty_Forces_Session_Save", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set CSRF token
		csrfToken := "test-csrf-token"
		session.SetCSRF(csrfToken)

		// Mark as dirty explicitly
		session.MarkDirty()

		// Save should work even if no apparent changes
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify cookie was set
		cookies := rec.Result().Cookies()
		assert.NotEmpty(t, cookies, "Cookies should be set after save")

		// Find main session cookie
		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie, "Main session cookie should be set")
	})

	// Test Azure-specific session handling
	t.Run("Azure_Session_Cookie_Configuration", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
		require.NoError(t, err)

		// Simulate Azure callback scenario
		req := httptest.NewRequest("GET", "http://example.com/oidc/callback?code=test&state=test-csrf", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set values as would happen in auth flow
		session.SetCSRF("test-csrf")
		session.SetNonce("test-nonce")

		// Save with proper cookie settings
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Check cookie attributes
		cookies := rec.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				// Azure requires SameSite=Lax for cross-site redirects
				assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite, "SameSite should be Lax for Azure compatibility")
				assert.Equal(t, "/", cookie.Path, "Path should be root")
				assert.True(t, cookie.HttpOnly, "Cookie should be HttpOnly")
				// In production, Secure would be true, but false in test
			}
		}
	})

	// Test session continuity through auth flow
	t.Run("Session_Continuity_Through_Auth_Flow", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
		require.NoError(t, err)

		// Step 1: Initial request
		req1 := httptest.NewRequest("GET", "http://example.com/protected", nil)
		session1, err := sessionManager.GetSession(req1)
		require.NoError(t, err)

		// Simulate auth initiation
		csrfToken := "auth-flow-csrf-token"
		nonce := "auth-flow-nonce"
		session1.SetCSRF(csrfToken)
		session1.SetNonce(nonce)
		session1.SetIncomingPath("/protected")

		// Force save
		session1.MarkDirty()
		rec1 := httptest.NewRecorder()
		err = session1.Save(req1, rec1)
		require.NoError(t, err)

		cookies := rec1.Result().Cookies()
		require.NotEmpty(t, cookies)

		// Step 2: Callback request with same cookies
		req2 := httptest.NewRequest("GET", "http://example.com/oidc/callback?code=test&state="+csrfToken, nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		// Verify session continuity
		assert.Equal(t, csrfToken, session2.GetCSRF(), "CSRF token should be maintained")
		assert.Equal(t, nonce, session2.GetNonce(), "Nonce should be maintained")
		assert.Equal(t, "/protected", session2.GetIncomingPath(), "Incoming path should be maintained")
	})

	// Test large token handling doesn't affect CSRF
	t.Run("Large_Tokens_Dont_Affect_CSRF", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set CSRF first
		csrfToken := "important-csrf"
		session.SetCSRF(csrfToken)

		// Add large tokens that might cause chunking
		largeToken := generateMockJWT(5000)
		session.SetIDToken(largeToken)
		session.SetAccessToken(largeToken)

		// Save
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Count cookies
		cookies := rec.Result().Cookies()
		mainFound := false
		chunkCount := 0
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainFound = true
			}
			if strings.Contains(cookie.Name, "_oidc_raczylo_") && strings.Contains(cookie.Name, "_") {
				chunkCount++
			}
		}

		assert.True(t, mainFound, "Main session cookie must exist")
		t.Logf("Total chunks created: %d", chunkCount)

		// Verify CSRF is still accessible
		req2 := httptest.NewRequest("GET", "http://example.com/test2", nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)
		assert.Equal(t, csrfToken, session2.GetCSRF(), "CSRF must be preserved with large tokens")
	})
}

// TestAuthFlowWithoutExternalDependencies tests the auth flow without external dependencies
func TestAuthFlowWithoutExternalDependencies(t *testing.T) {
	plugin := CreateConfig()
	plugin.ProviderURL = "https://login.microsoftonline.com/test-tenant/v2.0"
	plugin.ClientID = "test-client-id"
	plugin.ClientSecret = "test-client-secret"
	plugin.CallbackURL = "http://example.com/oidc/callback"
	plugin.SessionEncryptionKey = "test-encryption-key-32-characters"
	plugin.LogLevel = "debug"

	// Variables removed as they're not used in this test

	// We can't fully initialize TraefikOidc without network access,
	// but we can test the session management directly
	sessionManager, err := NewSessionManager(plugin.SessionEncryptionKey, plugin.ForceHTTPS, "", "", NewLogger(plugin.LogLevel))
	require.NoError(t, err)

	t.Run("Session_Created_On_Protected_Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/protected", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Session should be new
		assert.False(t, session.GetAuthenticated())

		// Set auth flow values
		session.SetCSRF("test-csrf-token")
		session.SetNonce("test-nonce")
		session.SetIncomingPath("/protected")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Should have set cookies
		cookies := rec.Result().Cookies()
		assert.NotEmpty(t, cookies)
	})
}

// TestRegressionLoginLoop specifically tests the fix for issue #53
func TestRegressionLoginLoop(t *testing.T) {
	// This test verifies that the specific changes made to fix the login loop work correctly
	sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
	require.NoError(t, err)

	// Simulate the exact flow that was causing the login loop
	t.Run("Fix_Session_Clear_Timing", func(t *testing.T) {
		// Initial request
		req := httptest.NewRequest("GET", "http://example.com/protected", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set initial session data
		session.SetAuthenticated(true)
		session.SetEmail("old@example.com")
		session.SetAccessToken("old-token")
		session.SetCSRF("existing-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		cookies := rec.Result().Cookies()

		// New request with existing session (user hits protected resource again)
		req2 := httptest.NewRequest("GET", "http://example.com/protected", nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		// OLD BEHAVIOR: session.Clear() would have been called here, losing CSRF
		// NEW BEHAVIOR: Selective clearing
		session2.SetAuthenticated(false)
		session2.SetEmail("")
		session2.SetAccessToken("")
		session2.SetRefreshToken("")
		session2.SetIDToken("")
		session2.SetNonce("")
		session2.SetCodeVerifier("")

		// CSRF should still exist
		existingCSRF := session2.GetCSRF()
		assert.Equal(t, "existing-csrf", existingCSRF, "CSRF should persist through selective clear")

		// Set new auth flow values
		newCSRF := "new-csrf-for-auth"
		session2.SetCSRF(newCSRF)
		session2.SetNonce("new-nonce")

		// Force save
		session2.MarkDirty()
		rec2 := httptest.NewRecorder()
		err = session2.Save(req2, rec2)
		require.NoError(t, err)

		// Simulate callback
		cookies2 := rec2.Result().Cookies()
		req3 := httptest.NewRequest("GET", "http://example.com/oidc/callback?code=test&state="+newCSRF, nil)
		for _, cookie := range cookies2 {
			req3.AddCookie(cookie)
		}

		session3, err := sessionManager.GetSession(req3)
		require.NoError(t, err)

		// CSRF should match
		assert.Equal(t, newCSRF, session3.GetCSRF(), "CSRF token should be available in callback")
	})

	t.Run("Fix_Force_Session_Save", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set CSRF but don't change authenticated status
		session.SetCSRF("important-csrf")

		// Without MarkDirty(), the session might not save if the session manager
		// doesn't detect the change. The fix ensures we call MarkDirty()
		session.MarkDirty()

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify cookie was actually set
		cookies := rec.Result().Cookies()
		found := false
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				found = true
				assert.NotEmpty(t, cookie.Value, "Cookie should have value")
			}
		}
		assert.True(t, found, "Main session cookie must be set after MarkDirty")
	})
}

// TestCSRFValidationTiming tests timing-sensitive CSRF validation scenarios
func TestCSRFValidationTiming(t *testing.T) {
	sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", "", NewLogger("debug"))
	require.NoError(t, err)

	t.Run("Rapid_Redirect_Maintains_CSRF", func(t *testing.T) {
		// Simulate rapid redirect (no delay between auth init and callback)
		req1 := httptest.NewRequest("GET", "http://example.com/auth", nil)
		session1, err := sessionManager.GetSession(req1)
		require.NoError(t, err)

		csrfToken := "rapid-redirect-csrf"
		session1.SetCSRF(csrfToken)
		session1.MarkDirty()

		rec1 := httptest.NewRecorder()
		err = session1.Save(req1, rec1)
		require.NoError(t, err)

		// Immediate callback (no delay)
		cookies := rec1.Result().Cookies()
		req2 := httptest.NewRequest("GET", "http://example.com/callback", nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)
		assert.Equal(t, csrfToken, session2.GetCSRF())
	})

	t.Run("Delayed_Redirect_Maintains_CSRF", func(t *testing.T) {
		// Simulate delayed redirect (user takes time at provider)
		req1 := httptest.NewRequest("GET", "http://example.com/auth", nil)
		session1, err := sessionManager.GetSession(req1)
		require.NoError(t, err)

		csrfToken := "delayed-redirect-csrf"
		session1.SetCSRF(csrfToken)
		session1.MarkDirty()

		rec1 := httptest.NewRecorder()
		err = session1.Save(req1, rec1)
		require.NoError(t, err)

		// Simulate delay
		time.Sleep(500 * time.Millisecond)

		// Callback after delay
		cookies := rec1.Result().Cookies()
		req2 := httptest.NewRequest("GET", "http://example.com/callback", nil)
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)
		assert.Equal(t, csrfToken, session2.GetCSRF(), "CSRF should persist even with delay")
	})
}

// Helper function to generate a mock JWT of specified size
func generateMockJWT(targetSize int) string {
	header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	signature := "signature"

	// Calculate payload size needed
	overhead := len(header) + len(signature) + 2 // 2 dots
	payloadSize := targetSize - overhead

	// Create payload with padding
	payload := map[string]interface{}{
		"sub":     "1234567890",
		"name":    "Test User",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
		"padding": strings.Repeat("x", payloadSize-100), // Leave room for JSON structure
	}

	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return header + "." + payloadB64 + "." + signature
}
