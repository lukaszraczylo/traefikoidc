package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureOAuthCallbackScenario tests the exact scenario from issue #53
// This test ensures that cookies set during OAuth initiation are available
// during the callback from Azure AD
func TestAzureOAuthCallbackScenario(t *testing.T) {
	t.Run("Azure_OAuth_Complete_Flow", func(t *testing.T) {
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		// Step 1: User visits https://app.example.com/protected
		// Traefik receives this as http://internal/protected with headers
		initReq := httptest.NewRequest("GET", "http://internal/protected", nil)
		initReq.Header.Set("X-Forwarded-Proto", "https")
		initReq.Header.Set("X-Forwarded-Host", "app.example.com")
		initReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		initReq.Host = "internal" // The actual host Traefik sees

		// Get session and prepare for OAuth
		session, err := sessionManager.GetSession(initReq)
		require.NoError(t, err)

		// Set OAuth flow data
		csrfToken := "azure-csrf-state-token"
		nonce := "azure-nonce-value"
		codeVerifier := "pkce-code-verifier"

		session.SetCSRF(csrfToken)
		session.SetNonce(nonce)
		session.SetCodeVerifier(codeVerifier)
		session.SetIncomingPath("/protected")
		session.MarkDirty()

		// Save session
		rec := httptest.NewRecorder()
		err = session.Save(initReq, rec)
		require.NoError(t, err)

		// Examine the cookies that would be sent to the browser
		cookies := rec.Result().Cookies()
		require.NotEmpty(t, cookies, "Cookies must be set for OAuth flow")

		var mainCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				mainCookie = cookie
				break
			}
		}
		require.NotNil(t, mainCookie, "Main session cookie must be set")

		// Verify cookie attributes for Azure OAuth
		assert.True(t, mainCookie.Secure, "Cookie MUST be Secure for HTTPS")
		assert.Equal(t, http.SameSiteLaxMode, mainCookie.SameSite,
			"MUST be Lax to allow Azure callback from different domain")
		assert.Equal(t, "app.example.com", mainCookie.Domain,
			"Domain must match X-Forwarded-Host for browser to send it back")
		assert.Equal(t, "/", mainCookie.Path, "Path must be root")
		assert.True(t, mainCookie.HttpOnly, "HttpOnly for security")

		// Step 2: User is redirected to Azure AD login
		// Azure AD redirects back to https://app.example.com/oidc/callback?code=xxx&state=xxx
		// Traefik receives this as http://internal/oidc/callback with headers

		callbackReq := httptest.NewRequest("GET",
			"http://internal/oidc/callback?code=AzureAuthCode&state="+csrfToken, nil)
		callbackReq.Header.Set("X-Forwarded-Proto", "https")
		callbackReq.Header.Set("X-Forwarded-Host", "app.example.com")
		callbackReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		callbackReq.Host = "internal"

		// Browser sends cookies because:
		// 1. Request is to https://app.example.com (matches cookie domain)
		// 2. Cookie has Secure flag and request is HTTPS
		// 3. Cookie has SameSite=Lax which allows top-level navigation from Azure
		for _, cookie := range cookies {
			callbackReq.AddCookie(cookie)
		}

		// Get session in callback
		callbackSession, err := sessionManager.GetSession(callbackReq)
		require.NoError(t, err)

		// Verify session data is available - THIS WAS FAILING IN ISSUE #53
		retrievedCSRF := callbackSession.GetCSRF()
		assert.Equal(t, csrfToken, retrievedCSRF,
			"CSRF token MUST be available in callback (was missing in issue #53)")

		retrievedNonce := callbackSession.GetNonce()
		assert.Equal(t, nonce, retrievedNonce,
			"Nonce MUST be available for security validation")

		retrievedCodeVerifier := callbackSession.GetCodeVerifier()
		assert.Equal(t, codeVerifier, retrievedCodeVerifier,
			"PKCE verifier MUST be available for token exchange")

		retrievedPath := callbackSession.GetIncomingPath()
		assert.Equal(t, "/protected", retrievedPath,
			"Original path MUST be available for post-auth redirect")
	})

	t.Run("Cookie_Not_Sent_With_Wrong_Domain", func(t *testing.T) {
		// This test verifies that cookies with wrong domain won't be sent
		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		// Initial request sets cookie for app.example.com
		initReq := httptest.NewRequest("GET", "http://internal/protected", nil)
		initReq.Header.Set("X-Forwarded-Proto", "https")
		initReq.Header.Set("X-Forwarded-Host", "app.example.com")
		initReq.Header.Set("User-Agent", "Mozilla/5.0")

		session, err := sessionManager.GetSession(initReq)
		require.NoError(t, err)
		session.SetCSRF("test-csrf")

		rec := httptest.NewRecorder()
		err = session.Save(initReq, rec)
		require.NoError(t, err)

		// Callback comes to different domain
		callbackReq := httptest.NewRequest("GET", "http://internal/oidc/callback", nil)
		callbackReq.Header.Set("X-Forwarded-Proto", "https")
		callbackReq.Header.Set("X-Forwarded-Host", "different.example.com") // Different domain!
		callbackReq.Header.Set("User-Agent", "Mozilla/5.0")

		// Browser wouldn't send cookies because domain doesn't match
		// So we simulate that by not adding cookies

		callbackSession, err := sessionManager.GetSession(callbackReq)
		require.NoError(t, err)

		// Session should be empty
		assert.Empty(t, callbackSession.GetCSRF(),
			"CSRF should be empty when cookies aren't sent due to domain mismatch")
	})

	t.Run("SameSite_Strict_Would_Break_OAuth", func(t *testing.T) {
		// This test demonstrates why we can't use SameSite=Strict for OAuth
		// With Strict, cookies wouldn't be sent when redirecting from Azure to our app

		sessionManager, err := NewSessionManager("test-encryption-key-32-characters", false, NewLogger("debug"))
		require.NoError(t, err)

		// If we had SameSite=Strict (which we don't anymore), the browser would:
		// 1. Set cookie when user visits app.example.com
		// 2. NOT send cookie when Azure redirects back to app.example.com/callback
		// This is because the request originates from login.microsoftonline.com

		// Our fix ensures we use SameSite=Lax which allows top-level navigation
		req := httptest.NewRequest("GET", "http://internal/test", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "app.example.com")

		session, err := sessionManager.GetSession(req)
		require.NoError(t, err)
		session.SetCSRF("test")

		rec := httptest.NewRecorder()
		err = session.Save(req, rec)
		require.NoError(t, err)

		cookies := rec.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "_oidc_raczylo_m" {
				assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite,
					"Must use Lax, not Strict, for OAuth to work")
				break
			}
		}
	})
}
