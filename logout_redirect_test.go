package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostLogoutRedirectURIConfiguration(t *testing.T) {
	tests := []struct {
		name                  string
		postLogoutRedirectURI string
		expectDefault         bool
		expectedValue         string
	}{
		{
			name:                  "custom post logout redirect URI",
			postLogoutRedirectURI: "/home",
			expectDefault:         false,
			expectedValue:         "/home",
		},
		{
			name:                  "empty uses default",
			postLogoutRedirectURI: "",
			expectDefault:         true,
			expectedValue:         "/",
		},
		{
			name:                  "external URL allowed",
			postLogoutRedirectURI: "https://example.com/goodbye",
			expectDefault:         false,
			expectedValue:         "https://example.com/goodbye",
		},
		{
			name:                  "relative path with query",
			postLogoutRedirectURI: "/logout-success?msg=goodbye",
			expectDefault:         false,
			expectedValue:         "/logout-success?msg=goodbye",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.PostLogoutRedirectURI = tt.postLogoutRedirectURI

			oidc, _ := setupTestOIDCMiddleware(t, config)

			// Check the configured value
			if tt.expectDefault {
				assert.Equal(t, tt.expectedValue, oidc.postLogoutRedirectURI)
			} else {
				assert.Equal(t, tt.postLogoutRedirectURI, oidc.postLogoutRedirectURI)
			}
		})
	}
}

func TestLogoutWithPostLogoutRedirect(t *testing.T) {
	tests := []struct {
		name                  string
		postLogoutRedirectURI string
		oidcEndSessionURL     string
		expectRedirectTo      string
		expectEndSession      bool
	}{
		{
			name:                  "redirect to custom URI without end session",
			postLogoutRedirectURI: "/goodbye",
			oidcEndSessionURL:     "",
			expectRedirectTo:      "http://example.com/goodbye",
			expectEndSession:      false,
		},
		{
			name:                  "redirect to default when not configured",
			postLogoutRedirectURI: "",
			oidcEndSessionURL:     "",
			expectRedirectTo:      "http://example.com/",
			expectEndSession:      false,
		},
		{
			name:                  "end session URL takes precedence",
			postLogoutRedirectURI: "/goodbye",
			oidcEndSessionURL:     "https://auth.example.com/logout",
			expectRedirectTo:      "https://auth.example.com/logout",
			expectEndSession:      true,
		},
		{
			name:                  "external post logout redirect",
			postLogoutRedirectURI: "https://app.example.com/logged-out",
			oidcEndSessionURL:     "",
			expectRedirectTo:      "https://app.example.com/logged-out",
			expectEndSession:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.PostLogoutRedirectURI = tt.postLogoutRedirectURI
			config.LogoutURL = "/logout"

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.endSessionURL = tt.oidcEndSessionURL

			// Create authenticated session
			session := createTestSession()
			session.SetIDToken(createMockJWT(t, "user123", "test@example.com"))
			session.SetAccessToken("test-access-token")

			// Create logout request
			req := httptest.NewRequest("GET", "/logout", nil)
			rec := httptest.NewRecorder()

			// Inject session into request
			injectSessionIntoRequest(t, req, session)

			// Handle logout
			oidc.ServeHTTP(rec, req)

			// Check redirect
			assert.Equal(t, http.StatusFound, rec.Code)
			location := rec.Header().Get("Location")

			if tt.expectEndSession {
				// When end session URL is present, it should redirect there
				assert.Contains(t, location, tt.oidcEndSessionURL)
				// Should include id_token_hint
				assert.Contains(t, location, "id_token_hint=")
				// Should include post_logout_redirect_uri
				if tt.postLogoutRedirectURI != "" {
					assert.Contains(t, location, "post_logout_redirect_uri=")
				}
			} else {
				// Otherwise, should redirect to post logout redirect URI
				assert.Equal(t, tt.expectRedirectTo, location)
			}

			// Session should be cleared
			cookies := rec.Result().Cookies()
			for _, cookie := range cookies {
				if cookie.Name == "oidc_session" {
					assert.Equal(t, -1, cookie.MaxAge, "Session cookie should be deleted")
				}
			}
		})
	}
}

func TestBuildLogoutURLWithPostLogoutRedirect(t *testing.T) {
	tests := []struct {
		name                  string
		oidcEndSessionURL     string
		postLogoutRedirectURI string
		idToken               string
		expectedParams        map[string]string
	}{
		{
			name:                  "includes all parameters",
			oidcEndSessionURL:     "https://auth.example.com/logout",
			postLogoutRedirectURI: "https://app.example.com/goodbye",
			idToken:               "test-id-token",
			expectedParams: map[string]string{
				"id_token_hint":            "test-id-token",
				"post_logout_redirect_uri": "https://app.example.com/goodbye",
			},
		},
		{
			name:                  "relative post logout URI",
			oidcEndSessionURL:     "https://auth.example.com/logout",
			postLogoutRedirectURI: "/logout-success",
			idToken:               "test-id-token",
			expectedParams: map[string]string{
				"id_token_hint":            "test-id-token",
				"post_logout_redirect_uri": "/logout-success",
			},
		},
		{
			name:                  "empty post logout URI omitted",
			oidcEndSessionURL:     "https://auth.example.com/logout",
			postLogoutRedirectURI: "",
			idToken:               "test-id-token",
			expectedParams: map[string]string{
				"id_token_hint": "test-id-token",
			},
		},
		{
			name:                  "special characters in URI",
			oidcEndSessionURL:     "https://auth.example.com/logout",
			postLogoutRedirectURI: "/logout?msg=Thank you!",
			idToken:               "test-id-token",
			expectedParams: map[string]string{
				"id_token_hint":            "test-id-token",
				"post_logout_redirect_uri": "/logout?msg=Thank you!",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the BuildLogoutURL function directly without middleware setup
			logoutURL, err := BuildLogoutURL(tt.oidcEndSessionURL, tt.idToken, tt.postLogoutRedirectURI)
			require.NoError(t, err)

			parsedURL, err := url.Parse(logoutURL)
			require.NoError(t, err)

			// Check base URL
			expectedBase := tt.oidcEndSessionURL
			actualBase := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
			assert.Equal(t, expectedBase, actualBase)

			// Check query parameters
			params := parsedURL.Query()
			for key, expectedValue := range tt.expectedParams {
				assert.Equal(t, expectedValue, params.Get(key), "Parameter %s mismatch", key)
			}

			// Ensure no extra parameters
			if tt.postLogoutRedirectURI == "" {
				assert.Empty(t, params.Get("post_logout_redirect_uri"))
			}
		})
	}
}

func TestLogoutFlowIntegration(t *testing.T) {
	// Mock provider's end session endpoint
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This won't be called in a unit test, but we keep it for completeness
		if r.URL.Path == "/endsession" {
			// Provider would handle logout and redirect to post_logout_redirect_uri
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer providerServer.Close()

	config := createTestConfig()
	config.LogoutURL = "/logout"
	config.PostLogoutRedirectURI = "/thank-you"
	config.OIDCEndSessionURL = providerServer.URL + "/endsession"

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.endSessionURL = config.OIDCEndSessionURL
	oidc.postLogoutRedirectURI = config.PostLogoutRedirectURI

	// Create authenticated session
	idToken := createMockJWT(t, "user123", "test@example.com")
	session := createTestSession()
	session.SetIDToken(idToken)
	session.SetAccessToken("test-access-token")

	// Initiate logout
	req := httptest.NewRequest("GET", "/logout", nil)
	rec := httptest.NewRecorder()

	// Inject session into request
	injectSessionIntoRequest(t, req, session)

	oidc.ServeHTTP(rec, req)

	// Verify redirect to provider's end session
	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")

	// Parse the redirect URL to check parameters
	parsedURL, err := url.Parse(location)
	assert.NoError(t, err)

	// Verify it's redirecting to the correct endpoint
	assert.Equal(t, providerServer.URL+"/endsession", parsedURL.Scheme+"://"+parsedURL.Host+parsedURL.Path)

	// Verify query parameters
	queryParams := parsedURL.Query()
	assert.Equal(t, idToken, queryParams.Get("id_token_hint"))
	assert.Equal(t, "http://example.com/thank-you", queryParams.Get("post_logout_redirect_uri"))

	// Note: The provider server won't actually be called in a unit test,
	// as the redirect response is returned to the test client
}

func TestLogoutWithoutSession(t *testing.T) {
	config := createTestConfig()
	config.LogoutURL = "/logout"
	config.PostLogoutRedirectURI = "/goodbye"

	oidc, _ := setupTestOIDCMiddleware(t, config)

	// Logout request without session
	req := httptest.NewRequest("GET", "/logout", nil)
	rec := httptest.NewRecorder()

	oidc.ServeHTTP(rec, req)

	// Should still redirect to post logout URI
	assert.Equal(t, http.StatusFound, rec.Code)
	// Relative URLs get converted to absolute URLs
	assert.Equal(t, "http://example.com/goodbye", rec.Header().Get("Location"))
}

func TestPostLogoutRedirectEdgeCases(t *testing.T) {
	tests := []struct {
		name                  string
		postLogoutRedirectURI string
		requestURL            string
		expectedBehavior      string
	}{
		{
			name:                  "preserves fragment in redirect",
			postLogoutRedirectURI: "/app#section",
			requestURL:            "/logout",
			expectedBehavior:      "Should preserve URL fragment",
		},
		{
			name:                  "handles encoded characters",
			postLogoutRedirectURI: "/message?text=Thank%20you%21",
			requestURL:            "/logout",
			expectedBehavior:      "Should handle URL encoding properly",
		},
		{
			name:                  "absolute URL with different domain",
			postLogoutRedirectURI: "https://other-app.com/logout-landing",
			requestURL:            "/logout",
			expectedBehavior:      "Should allow external redirects",
		},
		{
			name:                  "protocol-relative URL",
			postLogoutRedirectURI: "//example.com/logout",
			requestURL:            "/logout",
			expectedBehavior:      "Should handle protocol-relative URLs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.LogoutURL = "/logout"
			config.PostLogoutRedirectURI = tt.postLogoutRedirectURI

			oidc, _ := setupTestOIDCMiddleware(t, config)

			req := httptest.NewRequest("GET", tt.requestURL, nil)
			rec := httptest.NewRecorder()

			// Add minimal session
			session := createTestSession()
			session.SetIDToken("dummy-token")

			// Inject session into request
			injectSessionIntoRequest(t, req, session)

			oidc.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusFound, rec.Code)
			location := rec.Header().Get("Location")

			// Check based on the type of URL
			switch {
			case strings.HasPrefix(tt.postLogoutRedirectURI, "https://") || strings.HasPrefix(tt.postLogoutRedirectURI, "http://"):
				// Absolute URLs should be preserved
				assert.Equal(t, tt.postLogoutRedirectURI, location, tt.expectedBehavior)
			case strings.HasPrefix(tt.postLogoutRedirectURI, "//"):
				// Protocol-relative URLs get the scheme prepended
				assert.Equal(t, "http://example.com"+tt.postLogoutRedirectURI, location, tt.expectedBehavior)
			default:
				// Relative URLs get the full base URL prepended
				assert.Equal(t, "http://example.com"+tt.postLogoutRedirectURI, location, tt.expectedBehavior)
			}
		})
	}
}

func TestLogoutURLConfiguration(t *testing.T) {
	tests := []struct {
		name              string
		logoutURL         string
		callbackURL       string
		expectedLogoutURL string
	}{
		{
			name:              "custom logout URL",
			logoutURL:         "/auth/logout",
			callbackURL:       "/auth/callback",
			expectedLogoutURL: "/auth/logout",
		},
		{
			name:              "default logout URL from callback",
			logoutURL:         "",
			callbackURL:       "/oauth2/callback",
			expectedLogoutURL: "/oauth2/callback/logout",
		},
		{
			name:              "logout URL with trailing slash",
			logoutURL:         "/logout/",
			callbackURL:       "/callback",
			expectedLogoutURL: "/logout/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.LogoutURL = tt.logoutURL
			config.CallbackURL = tt.callbackURL

			oidc, _ := setupTestOIDCMiddleware(t, config)

			// The logout URL should be set correctly
			assert.Equal(t, tt.expectedLogoutURL, oidc.logoutURLPath)

			// Test that the logout URL is recognized
			req := httptest.NewRequest("GET", tt.expectedLogoutURL, nil)
			rec := httptest.NewRecorder()

			// Add session to trigger logout logic
			session := createTestSession()
			session.SetIDToken("test-token")

			// Inject session into request
			injectSessionIntoRequest(t, req, session)

			oidc.ServeHTTP(rec, req)

			// Should trigger logout (redirect)
			assert.Equal(t, http.StatusFound, rec.Code)
		})
	}
}
