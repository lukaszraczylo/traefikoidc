package traefikoidc

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionCompatibilityAfterChanges ensures our session changes maintain backward compatibility
func TestSessionCompatibilityAfterChanges(t *testing.T) {
	t.Run("Plain_HTTP_Without_Proxy_Headers", func(t *testing.T) {
		// Test that plain HTTP requests without proxy headers still work
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://localhost:8080/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		// No X-Forwarded-Proto header

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("plain-http-csrf")
		session.SetAuthenticated(true)
		session.SetEmail("user@example.com")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		// Verify cookies work for plain HTTP
		cookies := rec.Result().Cookies()
		require.NotEmpty(t, cookies)

		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie)

		// Plain HTTP should NOT have Secure flag
		assert.False(t, mainCookie.Secure, "Plain HTTP should not have Secure flag")
		// Should use Lax for compatibility
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite, "Plain HTTP should use Lax SameSite")

		// Verify session can be retrieved
		req2 := httptest.NewRequest("GET", "http://localhost:8080/test2", nil)
		req2.Header.Set("User-Agent", "Mozilla/5.0")
		for _, cookie := range cookies {
			req2.AddCookie(cookie)
		}

		session2, err := sessionManager.GetSession(req2)
		require.NoError(t, err)

		assert.Equal(t, "plain-http-csrf", session2.GetCSRF())
		assert.True(t, session2.GetAuthenticated())
		assert.Equal(t, "user@example.com", session2.GetEmail())
	})

	t.Run("HTTPS_With_TLS_Field", func(t *testing.T) {
		// Test direct HTTPS connection (not proxied)
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "https://example.com/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		// Simulate TLS connection
		req.TLS = &tls.ConnectionState{}

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("direct-https-csrf")

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

		// Direct HTTPS should have Secure flag
		assert.True(t, mainCookie.Secure, "Direct HTTPS should have Secure flag")
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite, "HTTPS should use Lax for OAuth compatibility")
	})

	t.Run("ForceHTTPS_Setting", func(t *testing.T) {
		// Test forceHTTPS setting works regardless of request
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", true, NewLogger("debug"))
		require.NoError(t, err)

		// Plain HTTP request
		req := httptest.NewRequest("GET", "http://localhost/test", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("forced-https-csrf")

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

		// With forceHTTPS, even HTTP requests get Secure cookies
		assert.True(t, mainCookie.Secure, "ForceHTTPS should always set Secure flag")
	})

	t.Run("AJAX_Request_Gets_Strict_SameSite", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		// AJAX request
		req := httptest.NewRequest("GET", "http://example.com/api/data", nil)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("User-Agent", "Mozilla/5.0")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("ajax-csrf")

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

		// AJAX requests always get Strict SameSite
		assert.Equal(t, http.SameSiteStrictMode, mainCookie.SameSite, "AJAX requests should use Strict SameSite")
	})

	t.Run("Missing_UserAgent_Gets_Reduced_Timeout", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		// Request without User-Agent (suspicious)
		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		// No User-Agent

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)

		session.SetCSRF("no-ua-csrf")

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

		// Should have reduced MaxAge for suspicious requests
		expectedMaxAge := int((absoluteSessionTimeout / 2).Seconds())
		assert.Equal(t, expectedMaxAge, mainCookie.MaxAge, "Missing User-Agent should get reduced timeout")
	})
}
