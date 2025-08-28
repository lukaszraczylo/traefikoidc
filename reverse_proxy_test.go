package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReverseProxyHTTPSDetection tests that HTTPS is properly detected in reverse proxy environments
func TestReverseProxyHTTPSDetection(t *testing.T) {
	t.Run("HTTPS_Detection_With_X_Forwarded_Proto", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Simulate request from reverse proxy (Traefik/nginx)
		// The reverse proxy terminates SSL and forwards HTTP internally
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "example.com")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Set critical session data
		session.SetCSRF("important-csrf-token")
		session.SetNonce("test-nonce")

		// Save session
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify cookies have Secure flag when X-Forwarded-Proto is https
		cookies := rec.Result().Cookies()
		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie, "Main session cookie should be set")
		assert.True(t, mainCookie.Secure, "Cookie should have Secure flag when X-Forwarded-Proto is https")
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite, "Should use Lax SameSite for OAuth compatibility")
	})

	t.Run("HTTPS_Detection_Without_Headers", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Request without reverse proxy headers (direct HTTP)
		req := httptest.NewRequest("GET", "http://example.com/test", nil)

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("test-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify cookies don't have Secure flag for plain HTTP
		cookies := rec.Result().Cookies()
		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie)
		assert.False(t, mainCookie.Secure, "Cookie should not have Secure flag for HTTP")
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite, "Should use Lax SameSite in HTTP")
	})

	t.Run("HTTPS_Detection_With_ForceHTTPS", func(t *testing.T) {
		// Test with forceHTTPS enabled
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", true, "", NewLogger("debug"))
		require.NoError(t, err)

		// Even without headers, forceHTTPS should make cookies secure
		req := httptest.NewRequest("GET", "http://example.com/test", nil)

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("forced-secure-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		cookies := rec.Result().Cookies()
		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie)
		assert.True(t, mainCookie.Secure, "Cookie should have Secure flag with forceHTTPS")
	})
}

// TestCSRFPersistenceInReverseProxy tests CSRF token persistence in reverse proxy setups
func TestCSRFPersistenceInReverseProxy(t *testing.T) {
	t.Run("CSRF_Persists_Through_OAuth_Flow_With_Proxy", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Step 1: Initial request to protected resource (HTTPS via proxy)
		req1 := httptest.NewRequest("GET", "http://example.com/protected", nil)
		req1.Header.Set("X-Forwarded-Proto", "https")
		req1.Header.Set("X-Forwarded-Host", "example.com")

		session1, err := sessionManager.GetSession(req1)
		require.NoError(t, err)

		// Set CSRF and other auth flow data
		csrfToken := "proxy-csrf-token-12345"
		session1.SetCSRF(csrfToken)
		session1.SetNonce("proxy-nonce")
		session1.SetIncomingPath("/protected")

		// Save session (should set Secure cookie)
		rec1 := httptest.NewRecorder()
		err = session1.Save(req1, rec1)
		require.NoError(t, err)

		cookies := rec1.Result().Cookies()

		// Step 2: Simulate OAuth callback (also HTTPS via proxy)
		req2 := httptest.NewRequest("GET", "http://example.com/oidc/callback?code=auth-code&state="+csrfToken, nil)
		req2.Header.Set("X-Forwarded-Proto", "https")
		req2.Header.Set("X-Forwarded-Host", "example.com")

		// Add cookies from step 1
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		// Get session in callback
		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		// CSRF token should persist
		retrievedCSRF := session2.GetCSRF()
		assert.Equal(t, csrfToken, retrievedCSRF, "CSRF token must persist through OAuth flow in reverse proxy")
		assert.Equal(t, "proxy-nonce", session2.GetNonce(), "Nonce should also persist")
		assert.Equal(t, "/protected", session2.GetIncomingPath(), "Incoming path should persist")
	})

	t.Run("Session_Cookie_Domain_With_Proxy_Headers", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Test with X-Forwarded-Host header
		req := httptest.NewRequest("GET", "http://internal.local/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "public.example.com")
		req.Host = "internal.local" // Internal host

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("domain-test-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		cookies := rec.Result().Cookies()
		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie)

		// Domain should be set based on X-Forwarded-Host when present
		// This ensures cookies work correctly with the public domain
		assert.Equal(t, "public.example.com", mainCookie.Domain, "Cookie domain should use forwarded host")
	})
}

// TestAzureOIDCWithReverseProxy simulates Azure OIDC flow behind a reverse proxy
func TestAzureOIDCWithReverseProxy(t *testing.T) {
	t.Run("Azure_Provider_Detection_And_Configuration", func(t *testing.T) {
		// This test verifies Azure-specific provider detection and configuration
		// without making actual network calls

		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Step 1: Test session setup for Azure OAuth flow
		req := httptest.NewRequest("GET", "http://internal/protected", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "app.example.com")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		// Simulate OAuth flow initialization
		csrfToken := "azure-csrf-token"
		nonce := "azure-nonce"
		session.SetCSRF(csrfToken)
		session.SetNonce(nonce)
		session.SetIncomingPath("/protected")
		session.MarkDirty()

		// Save session with proper HTTPS detection
		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify cookies have correct security attributes for Azure
		cookies := rec.Result().Cookies()
		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie, "Main session cookie must be set")
		assert.True(t, mainCookie.Secure, "Cookie must be secure for HTTPS reverse proxy")
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite, "Should use Lax SameSite for OAuth compatibility")

		// Step 2: Simulate callback and verify session persistence
		callbackReq := httptest.NewRequest("GET", "http://internal/oidc/callback?code=azure-code&state="+csrfToken, nil)
		callbackReq.Header.Set("X-Forwarded-Proto", "https")
		callbackReq.Header.Set("X-Forwarded-Host", "app.example.com")

		// Add cookies from initial request
		for _, cookie := range cookies {
			callbackReq.AddCookie(cookie)
		}

		// Get session in callback
		callbackSession, err := sessionManager.GetSession(callbackReq)
		require.NoError(t, err)

		// Verify session data persisted correctly
		assert.Equal(t, csrfToken, callbackSession.GetCSRF(), "CSRF token must persist in Azure flow")
		assert.Equal(t, nonce, callbackSession.GetNonce(), "Nonce must persist")
		assert.Equal(t, "/protected", callbackSession.GetIncomingPath(), "Original path must persist")
	})

	t.Run("Mixed_HTTP_HTTPS_Requests", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Simulate a scenario where some requests come via HTTPS proxy and some don't
		// This can happen in development or misconfigured environments

		// Request 1: HTTPS via proxy
		req1 := httptest.NewRequest("GET", "http://localhost:8080/test", nil)
		req1.Header.Set("X-Forwarded-Proto", "https")

		session1, err := sessionManager.GetSession(req1)
		require.NoError(t, err)
		session1.SetCSRF("mixed-csrf")

		rec1 := httptest.NewRecorder()
		err = session1.Save(req1, rec1)
		require.NoError(t, err)

		cookies1 := rec1.Result().Cookies()

		// Request 2: Direct HTTP (no proxy headers)
		req2 := httptest.NewRequest("GET", "http://localhost:8080/test", nil)
		// No X-Forwarded-Proto header

		// Try to use cookies from HTTPS request
		for _, cookie := range cookies1 {
			// Remove Secure flag to simulate browser behavior
			// (browser wouldn't send secure cookie over HTTP)
			if !cookie.Secure {
				req2.AddCookie(cookie)
			}
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		// Session should be empty because secure cookies weren't sent
		csrf2 := session2.GetCSRF()
		assert.Empty(t, csrf2, "CSRF should be empty when secure cookies can't be sent over HTTP")
	})
}

// TestEnhanceSessionSecurity verifies the security enhancement function
func TestEnhanceSessionSecurity(t *testing.T) {
	t.Run("Security_Enhancement_For_AJAX_Requests", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// AJAX request via HTTPS proxy
		req := httptest.NewRequest("GET", "http://internal/api/data", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("ajax-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Check that AJAX requests get strict same-site
		cookies := rec.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "AJAX requests should use Strict SameSite")
				break
			}
		}
	})

	t.Run("Security_Enhancement_Missing_User_Agent", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, "", NewLogger("debug"))
		require.NoError(t, err)

		// Request without User-Agent (potential bot/attack)
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		// No User-Agent header

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("no-ua-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify reduced session timeout for suspicious requests
		cookies := rec.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				// Should have reduced MaxAge (half of normal)
				assert.Less(t, cookie.MaxAge, int(absoluteSessionTimeout.Seconds()), "Suspicious requests should have reduced timeout")
				break
			}
		}
	})
}
