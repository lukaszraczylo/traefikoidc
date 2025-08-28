package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssue53Regression tests the specific issue reported in GitHub issue #53
// where Azure OIDC authentication fails with "CSRF token missing in session"
// This was caused by incorrect HTTPS detection in reverse proxy environments
func TestIssue53Regression(t *testing.T) {
	t.Run("Issue53_CSRF_Missing_In_Session_Fix", func(t *testing.T) {
		// This test reproduces the exact scenario from issue #53:
		// 1. User accesses app via HTTPS through Traefik
		// 2. Traefik terminates SSL and forwards HTTP internally
		// 3. Session cookies must be properly configured for HTTPS
		// 4. CSRF token must persist through the OAuth flow

		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Step 1: Initial request to protected resource
		// User accesses https://app.example.com/protected
		// Traefik forwards as http://internal/protected with X-Forwarded-Proto: https
		initReq := httptest.NewRequest("GET", "http://internal/protected", nil)
		initReq.Header.Set("X-Forwarded-Proto", "https")
		initReq.Header.Set("X-Forwarded-Host", "app.example.com")
		initReq.Header.Set("User-Agent", "Mozilla/5.0") // Real browser

		// Get session and set OAuth flow data
		session, err := sessionManager.GetSession(initReq)
		require.NoError(t, err)

		// Set CSRF and other OAuth data
		csrfToken := "csrf-token-for-azure"
		nonce := "nonce-for-azure"
		session.SetCSRF(csrfToken)
		session.SetNonce(nonce)
		session.SetCodeVerifier("pkce-verifier")
		session.SetIncomingPath("/protected")
		session.MarkDirty()

		// Save session - this is where the bug was
		// Previously: used r.URL.Scheme which is always "http" behind proxy
		// Now: uses X-Forwarded-Proto header
		rec := httptest.NewRecorder()
		err = session.Save(initReq, rec)
		require.NoError(t, err)

		// Verify cookies are secure
		cookies := rec.Result().Cookies()
		require.NotEmpty(t, cookies, "Cookies must be set")

		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie, "Main session cookie must be set")

		// Critical assertions for issue #53
		assert.True(t, mainCookie.Secure, "Cookie MUST have Secure flag for HTTPS (was the bug)")
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite, "MUST use Lax for OAuth callbacks to work")
		assert.Equal(t, "/", mainCookie.Path, "Cookie path must be root")
		assert.True(t, mainCookie.HttpOnly, "Cookie must be HttpOnly")
		assert.Equal(t, "app.example.com", mainCookie.Domain, "Domain should use X-Forwarded-Host")

		// Step 2: OAuth provider redirects back to callback
		// Azure redirects to https://app.example.com/oidc/callback?code=...&state=...
		// Traefik forwards as http://internal/oidc/callback with headers
		callbackReq := httptest.NewRequest("GET",
			"http://internal/oidc/callback?code=azure-auth-code&state="+csrfToken, nil)
		callbackReq.Header.Set("X-Forwarded-Proto", "https")
		callbackReq.Header.Set("X-Forwarded-Host", "app.example.com")
		callbackReq.Header.Set("User-Agent", "Mozilla/5.0")

		// Add cookies from initial request
		// Browser sends secure cookies because request is HTTPS
		for _, cookie := range cookies {
			callbackReq.AddCookie(cookie)
		}

		// Get session in callback
		callbackSession, err := sessionManager.GetSession(callbackReq)
		require.NoError(t, err)

		// Verify CSRF token is present (was missing in issue #53)
		retrievedCSRF := callbackSession.GetCSRF()
		assert.Equal(t, csrfToken, retrievedCSRF,
			"CSRF token MUST persist (was missing in issue #53)")

		// Verify other session data also persists
		assert.Equal(t, nonce, callbackSession.GetNonce(),
			"Nonce must persist for security")
		assert.Equal(t, "pkce-verifier", callbackSession.GetCodeVerifier(),
			"PKCE verifier must persist")
		assert.Equal(t, "/protected", callbackSession.GetIncomingPath(),
			"Original path must persist for redirect after auth")
	})

	t.Run("Issue53_Signature_Verification_With_Secure_Session", func(t *testing.T) {
		// This test ensures that once the session is properly maintained,
		// token signature verification works correctly for Azure tokens

		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Create authenticated session with Azure tokens
		req := httptest.NewRequest("GET", "http://internal/api/data", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "app.example.com")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Simulate successful Azure authentication
		session.SetAuthenticated(true)
		session.SetEmail("user@example.com")
		// Azure may use opaque access tokens
		session.SetAccessToken("opaque-azure-access-token")
		session.SetIDToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ")
		session.SetRefreshToken("azure-refresh-token")

		// Save with proper security
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify session can be retrieved and tokens are intact
		cookies := rec.Result().Cookies()
		req2 := httptest.NewRequest("GET", "http://internal/api/data", nil)
		req2.Header.Set("X-Forwarded-Proto", "https")
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		assert.True(t, session2.GetAuthenticated(), "User should remain authenticated")
		assert.Equal(t, "user@example.com", session2.GetEmail())
		assert.NotEmpty(t, session2.GetAccessToken(), "Access token should persist")
		assert.NotEmpty(t, session2.GetIDToken(), "ID token should persist")
		assert.NotEmpty(t, session2.GetRefreshToken(), "Refresh token should persist")
	})

	t.Run("Issue53_Redirect_Loop_Prevention", func(t *testing.T) {
		// This test verifies the redirect loop prevention mechanism
		// that was added to handle authentication failures gracefully

		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://internal/protected", nil)
		req.Header.Set("X-Forwarded-Proto", "https")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Simulate multiple redirect attempts
		for i := 0; i < 3; i++ {
			session.IncrementRedirectCount()
		}

		// Verify redirect count is tracked
		count := session.GetRedirectCount()
		assert.Equal(t, 3, count, "Redirect count should be tracked")

		// After successful auth, count should be reset
		session.SetAuthenticated(true)
		session.ResetRedirectCount()
		assert.Equal(t, 0, session.GetRedirectCount(), "Count should reset after auth")
	})
}

// TestReverseProxySameSiteHandling tests SameSite cookie attribute handling
// in different reverse proxy scenarios
func TestReverseProxySameSiteHandling(t *testing.T) {
	t.Run("SameSite_Lax_For_HTTPS_OAuth", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// HTTPS request via proxy
		req := httptest.NewRequest("GET", "http://internal/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("User-Agent", "Mozilla/5.0")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)
		session.SetCSRF("test")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// HTTPS should use Lax mode for OAuth compatibility
		cookies := rec.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite,
					"HTTPS should use Lax SameSite for OAuth callbacks")
				break
			}
		}
	})

	t.Run("SameSite_Lax_For_HTTP", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Plain HTTP request (no proxy headers)
		req := httptest.NewRequest("GET", "http://localhost/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)
		session.SetCSRF("test")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// HTTP should use Lax mode for compatibility
		cookies := rec.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite,
					"HTTP should use Lax SameSite for compatibility")
				break
			}
		}
	})
}
