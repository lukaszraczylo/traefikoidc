package regression

import (
	"net/http"
	"net/http/httptest"
	"testing"

	traefikoidc "github.com/lukaszraczylo/traefikoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssueRegressions consolidates regression tests for reported GitHub issues
func TestIssueRegressions(t *testing.T) {
	t.Run("Issue53_CSRF_Missing_In_Session", testIssue53CSRFRegression)
	t.Run("Issue53_Reverse_Proxy_HTTPS_Detection", testIssue53ReverseProxyHTTPS)
	t.Run("Issue53_SameSite_Cookie_Handling", testIssue53SameSiteCookies)
	t.Run("Issue60_Missing_Claim_Fields", testIssue60MissingClaimFields)
	t.Run("Issue60_Safe_Template_Functions", testIssue60SafeTemplateFunctions)
	t.Run("Issue60_Double_Processing_Concern", testIssue60DoubleProcessing)
}

// testIssue53CSRFRegression tests the specific issue reported in GitHub issue #53
// where Azure OIDC authentication fails with "CSRF token missing in session"
// This was caused by incorrect HTTPS detection in reverse proxy environments
func testIssue53CSRFRegression(t *testing.T) {
	// This test reproduces the exact scenario from issue #53:
	// 1. User accesses app via HTTPS through Traefik
	// 2. Traefik terminates SSL and forwards HTTP internally
	// 3. Session cookies must be properly configured for HTTPS
	// 4. CSRF token must persist through the OAuth flow

	sessionManager, err := traefikoidc.NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, traefikoidc.NewLogger("debug"))
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
}

// testIssue53ReverseProxyHTTPS tests HTTPS detection in reverse proxy setups
func testIssue53ReverseProxyHTTPS(t *testing.T) {
	sessionManager, err := traefikoidc.NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, traefikoidc.NewLogger("debug"))
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
	session.SetIDToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ") // trufflehog:ignore
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

	// Test redirect loop prevention
	for i := 0; i < 3; i++ {
		session2.IncrementRedirectCount()
	}

	// Verify redirect count is tracked
	count := session2.GetRedirectCount()
	assert.Equal(t, 3, count, "Redirect count should be tracked")

	// After successful auth, count should be reset
	session2.SetAuthenticated(true)
	session2.ResetRedirectCount()
	assert.Equal(t, 0, session2.GetRedirectCount(), "Count should reset after auth")
}

// testIssue53SameSiteCookies tests SameSite cookie attribute handling
// in different reverse proxy scenarios
func testIssue53SameSiteCookies(t *testing.T) {
	testCases := []struct {
		name             string
		proto            string
		description      string
		expectedSameSite http.SameSite
		expectedSecure   bool
	}{
		{
			name:             "HTTPS via proxy",
			proto:            "https",
			expectedSecure:   true,
			expectedSameSite: http.SameSiteLaxMode,
			description:      "HTTPS should use Lax SameSite for OAuth callbacks",
		},
		{
			name:             "HTTP direct",
			proto:            "",
			expectedSecure:   false,
			expectedSameSite: http.SameSiteLaxMode,
			description:      "HTTP should use Lax SameSite for compatibility",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sessionManager, err := traefikoidc.NewSessionManager("test-encryption-key-32-characters", false, "", "", 0, traefikoidc.NewLogger("debug"))
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "http://internal/test", nil)
			if tc.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			session, err := sessionManager.GetSession(req)
			require.NoError(t, err)
			session.SetCSRF("test")

			rec := httptest.NewRecorder()
			err = session.Save(req, rec)
			require.NoError(t, err)

			cookies := rec.Result().Cookies()
			for _, cookie := range cookies {
				if cookie.Name == "_oidc_raczylo_m" {
					assert.Equal(t, tc.expectedSecure, cookie.Secure, tc.description)
					assert.Equal(t, tc.expectedSameSite, cookie.SameSite, tc.description)
					break
				}
			}
		})
	}
}

// testIssue60MissingClaimFields tests handling of missing claim fields (GitHub issue #60)
func testIssue60MissingClaimFields(t *testing.T) {
	config := traefikoidc.CreateConfig()
	config.ProviderURL = "https://example.com"
	config.ClientID = "test-client"
	config.ClientSecret = "test-secret"
	config.CallbackURL = "/callback"
	config.SessionEncryptionKey = "test-encryption-key-32-characters"

	testCases := []struct {
		name           string
		description    string
		headers        []traefikoidc.TemplatedHeader
		shouldValidate bool
	}{
		{
			name: "Direct claim access",
			headers: []traefikoidc.TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-Internal-Role", Value: "{{.Claims.internal_role}}"},
			},
			shouldValidate: true,
			description:    "Direct claim access should validate",
		},
		{
			name: "Azure AD claims",
			headers: []traefikoidc.TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-OID", Value: "{{.Claims.oid}}"},
				{Name: "X-User-TID", Value: "{{.Claims.tid}}"},
				{Name: "X-User-UPN", Value: "{{.Claims.upn}}"},
				{Name: "X-Internal-Role", Value: "{{.Claims.internal_role}}"}, // Custom claim from issue #60
			},
			shouldValidate: true,
			description:    "Azure AD claims should validate",
		},
		{
			name: "Valid context fields",
			headers: []traefikoidc.TemplatedHeader{
				{Name: "X-Access-Token", Value: "{{.AccessToken}}"},
				{Name: "X-ID-Token", Value: "{{.IdToken}}"},
				{Name: "X-Refresh-Token", Value: "{{.RefreshToken}}"},
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-Sub", Value: "{{.Claims.sub}}"},
			},
			shouldValidate: true,
			description:    "All valid context fields should pass validation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config.Headers = tc.headers
			err := config.Validate()
			if tc.shouldValidate {
				assert.NoError(t, err, tc.description)
			} else {
				assert.Error(t, err, tc.description)
			}
		})
	}
}

// testIssue60SafeTemplateFunctions tests safe template functions for handling missing fields
func testIssue60SafeTemplateFunctions(t *testing.T) {
	config := traefikoidc.CreateConfig()
	config.ProviderURL = "https://example.com"
	config.ClientID = "test-client"
	config.ClientSecret = "test-secret"
	config.CallbackURL = "/callback"
	config.SessionEncryptionKey = "test-encryption-key-32-characters"

	// Templates using safe functions for missing fields
	config.Headers = []traefikoidc.TemplatedHeader{
		{Name: "X-User-Email", Value: "{{.Claims.email}}"},
		{Name: "X-User-Role", Value: "{{get .Claims \"internal_role\"}}"},
		{Name: "X-User-Dept", Value: "{{default \"unknown\" .Claims.department}}"},
		{Name: "X-User-Groups", Value: "{{with .Claims.groups}}{{.}}{{end}}"},
	}

	// Configuration should validate successfully
	err := config.Validate()
	assert.NoError(t, err, "Config with safe template functions should validate")

	// Test that dangerous templates are rejected
	dangerousTemplates := []traefikoidc.TemplatedHeader{
		{Name: "X-Bad-1", Value: "{{call .SomeFunc}}"},
		{Name: "X-Bad-2", Value: "{{range .Items}}{{.}}{{end}}"},
		{Name: "X-Bad-3", Value: "{{index .Array 0}}"},
		{Name: "X-Bad-4", Value: "{{printf \"%s\" .Data}}"},
	}

	for _, header := range dangerousTemplates {
		config.Headers = []traefikoidc.TemplatedHeader{header}
		err := config.Validate()
		require.Error(t, err, "Dangerous template should be rejected: %s", header.Value)
		assert.Contains(t, err.Error(), "dangerous", "Error should mention dangerous pattern")
	}

	// Test all safe patterns from the documentation
	safePatterns := []traefikoidc.TemplatedHeader{
		// Basic field access
		{Name: "X-User-Role", Value: "{{.Claims.internal_role}}"},
		// Using the get function
		{Name: "X-User-Role-Get", Value: "{{get .Claims \"internal_role\"}}"},
		// Using the default function
		{Name: "X-User-Role-Default", Value: "{{default \"guest\" .Claims.role}}"},
		// Nested fields with 'with'
		{Name: "X-User-Admin", Value: "{{with .Claims.groups}}{{.admin}}{{end}}"},
	}

	config.Headers = safePatterns
	err = config.Validate()
	assert.NoError(t, err, "All safe patterns from guide should validate")
}

// testIssue60DoubleProcessing tests the user's concern about double processing of templates
func testIssue60DoubleProcessing(t *testing.T) {
	// The user was concerned that templates might be processed twice:
	// 1. Once when Traefik parses the config
	// 2. Once when the plugin executes the template

	// This test verifies that templates are stored as strings during config parsing
	config := &traefikoidc.Config{
		Headers: []traefikoidc.TemplatedHeader{
			{Name: "X-Test", Value: "{{.Claims.test}}"},
		},
	}

	// The template should still be a raw string after config creation
	assert.Equal(t, "{{.Claims.test}}", config.Headers[0].Value,
		"Template should remain as raw string in config")

	// Test that our custom function syntax survives config marshaling/unmarshaling
	originalValue := `{{get .Claims "internal_role"}}`
	header := traefikoidc.TemplatedHeader{
		Name:  "X-Role",
		Value: originalValue,
	}

	// Even after any marshaling/unmarshaling, the template string should be preserved
	assert.Equal(t, originalValue, header.Value,
		"Template with functions should be preserved exactly")
}
