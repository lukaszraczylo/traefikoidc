package traefikoidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExcludedURLsConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		excludedURLs  []string
		expectError   bool
		errorContains string
	}{
		{
			name:         "valid excluded URLs",
			excludedURLs: []string{"/health", "/metrics", "/public"},
			expectError:  false,
		},
		{
			name:         "empty excluded URLs list",
			excludedURLs: []string{},
			expectError:  false,
		},
		{
			name:          "URL without leading slash",
			excludedURLs:  []string{"health"},
			expectError:   true,
			errorContains: "excluded URL must start with /",
		},
		{
			name:          "URL with path traversal",
			excludedURLs:  []string{"/../../etc/passwd"},
			expectError:   true,
			errorContains: "must not contain path traversal",
		},
		{
			name:          "URL with wildcards",
			excludedURLs:  []string{"/api/*"},
			expectError:   true,
			errorContains: "must not contain wildcards",
		},
		{
			name:         "multiple valid URLs",
			excludedURLs: []string{"/login", "/logout", "/api/public", "/static/assets"},
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.ExcludedURLs = tt.excludedURLs

			err := config.Validate()
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExcludedURLsMatching(t *testing.T) {
	tests := []struct {
		name         string
		excludedURLs []string
		requestPath  string
		shouldMatch  bool
	}{
		{
			name:         "exact match",
			excludedURLs: []string{"/health"},
			requestPath:  "/health",
			shouldMatch:  true,
		},
		{
			name:         "prefix match",
			excludedURLs: []string{"/api/public"},
			requestPath:  "/api/public/users",
			shouldMatch:  true,
		},
		{
			name:         "no match",
			excludedURLs: []string{"/health"},
			requestPath:  "/api/private",
			shouldMatch:  false,
		},
		{
			name:         "multiple URLs with match",
			excludedURLs: []string{"/health", "/metrics", "/api/public"},
			requestPath:  "/api/public/data",
			shouldMatch:  true,
		},
		{
			name:         "case sensitive matching",
			excludedURLs: []string{"/Health"},
			requestPath:  "/health",
			shouldMatch:  false,
		},
		{
			name:         "trailing slash difference",
			excludedURLs: []string{"/api"},
			requestPath:  "/api/",
			shouldMatch:  true,
		},
		{
			name:         "nested path match",
			excludedURLs: []string{"/static"},
			requestPath:  "/static/css/main.css",
			shouldMatch:  true,
		},
		{
			name:         "partial path no match",
			excludedURLs: []string{"/api/public"},
			requestPath:  "/api",
			shouldMatch:  false,
		},
		{
			name:         "empty excluded URLs list",
			excludedURLs: []string{},
			requestPath:  "/anything",
			shouldMatch:  false,
		},
		{
			name:         "root path exclusion",
			excludedURLs: []string{"/"},
			requestPath:  "/anything",
			shouldMatch:  true, // Everything starts with /
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.ExcludedURLs = tt.excludedURLs

			oidc, _ := setupTestOIDCMiddleware(t, config)

			result := oidc.determineExcludedURL(tt.requestPath)
			assert.Equal(t, tt.shouldMatch, result)
		})
	}
}

func TestExcludedURLsBypassesAuthentication(t *testing.T) {
	// Track if next handler was called
	nextHandlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public content"))
	})

	tests := []struct {
		name               string
		excludedURLs       []string
		requestPath        string
		expectNextHandler  bool
		expectAuthRedirect bool
	}{
		{
			name:               "excluded URL bypasses auth",
			excludedURLs:       []string{"/public"},
			requestPath:        "/public/data",
			expectNextHandler:  true,
			expectAuthRedirect: false,
		},
		{
			name:               "non-excluded URL requires auth",
			excludedURLs:       []string{"/public"},
			requestPath:        "/private/data",
			expectNextHandler:  false,
			expectAuthRedirect: true,
		},
		{
			name:               "health check bypass",
			excludedURLs:       []string{"/health", "/readiness"},
			requestPath:        "/health",
			expectNextHandler:  true,
			expectAuthRedirect: false,
		},
		{
			name:               "metrics endpoint bypass",
			excludedURLs:       []string{"/metrics"},
			requestPath:        "/metrics",
			expectNextHandler:  true,
			expectAuthRedirect: false,
		},
		{
			name:               "login page bypass",
			excludedURLs:       []string{"/login"},
			requestPath:        "/login",
			expectNextHandler:  true,
			expectAuthRedirect: false,
		},
		{
			name:               "nested public path",
			excludedURLs:       []string{"/api/v1/public"},
			requestPath:        "/api/v1/public/docs",
			expectNextHandler:  true,
			expectAuthRedirect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset state
			nextHandlerCalled = false

			config := createTestConfig()
			config.ExcludedURLs = tt.excludedURLs

			oidc, server := setupTestOIDCMiddleware(t, config)
			defer server.Close()
			oidc.next = nextHandler

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			req.Host = "test.example.com" // Set a proper host header
			rec := httptest.NewRecorder()

			oidc.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectNextHandler, nextHandlerCalled)

			if tt.expectAuthRedirect {
				assert.Equal(t, http.StatusFound, rec.Code)
				location := rec.Header().Get("Location")
				// Check that it redirects to the test provider
				assert.Contains(t, location, "https://test-provider.example.com/auth")
			} else {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, "public content", rec.Body.String())
			}
		})
	}
}

func TestDefaultExcludedURLs(t *testing.T) {
	// Test that default excluded URLs (like /favicon) work correctly
	config := createTestConfig()
	// Don't set any ExcludedURLs to test defaults

	oidc, _ := setupTestOIDCMiddleware(t, config)

	// Check if /favicon is excluded by default
	assert.True(t, oidc.determineExcludedURL("/favicon"))
	assert.True(t, oidc.determineExcludedURL("/favicon.ico"))

	// Other paths should not be excluded
	assert.False(t, oidc.determineExcludedURL("/api"))
	assert.False(t, oidc.determineExcludedURL("/"))
}

func TestExcludedURLsWithAuthentication(t *testing.T) {
	// Test that excluded URLs work correctly when user is already authenticated
	nextHandlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	config := createTestConfig()
	config.ExcludedURLs = []string{"/public", "/health"}

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.next = nextHandler

	// Mock the token verifier to avoid JWKS lookup
	oidc.tokenVerifier = &mockTokenVerifier{
		verifyFunc: func(token string) error {
			// Always return success for test tokens
			claims, err := extractClaims(token)
			if err != nil {
				return err
			}
			// Cache the claims for the token
			oidc.tokenCache.Set(token, claims, time.Hour)
			return nil
		},
	}

	// Create authenticated session
	session := createTestSession()
	session.SetAuthenticated(true)
	session.SetAccessToken("valid-token-longer-than-20-chars")
	session.SetIDToken(createMockJWT(t, "test-user", "test@example.com"))
	session.SetEmail("test@example.com")

	tests := []struct {
		name              string
		requestPath       string
		expectNextHandler bool
	}{
		{
			name:              "excluded URL with auth session",
			requestPath:       "/public",
			expectNextHandler: true,
		},
		{
			name:              "non-excluded URL with auth session",
			requestPath:       "/private",
			expectNextHandler: true, // Should pass through because authenticated
		},
		{
			name:              "health check with auth session",
			requestPath:       "/health",
			expectNextHandler: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextHandlerCalled = false

			req := httptest.NewRequest("GET", tt.requestPath, nil)
			rec := httptest.NewRecorder()

			// Inject session into request
			injectSessionIntoRequest(t, req, session)

			oidc.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectNextHandler, nextHandlerCalled)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestExcludedURLsEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		excludedURLs []string
		requestPath  string
		description  string
		shouldMatch  bool
	}{
		{
			name:         "query parameters ignored",
			excludedURLs: []string{"/api/public"},
			requestPath:  "/api/public?secret=123",
			description:  "Query parameters should be ignored in matching",
			shouldMatch:  true,
		},
		{
			name:         "fragment ignored",
			excludedURLs: []string{"/docs"},
			requestPath:  "/docs#section1",
			description:  "URL fragments should be ignored in matching",
			shouldMatch:  true,
		},
		{
			name:         "double slashes normalized",
			excludedURLs: []string{"/api/public"},
			requestPath:  "//api/public",
			description:  "Double slashes should be handled",
			shouldMatch:  false, // Path normalization depends on implementation
		},
		{
			name:         "encoded URLs",
			excludedURLs: []string{"/api/public"},
			requestPath:  "/api%2Fpublic",
			description:  "URL encoding should be handled",
			shouldMatch:  false, // Encoded slash is different
		},
		{
			name:         "very long excluded path",
			excludedURLs: []string{"/this/is/a/very/long/path/that/should/still/work"},
			requestPath:  "/this/is/a/very/long/path/that/should/still/work/and/more",
			description:  "Long paths should work correctly",
			shouldMatch:  true,
		},
		{
			name:         "similar but different paths",
			excludedURLs: []string{"/api/v1"},
			requestPath:  "/api/v2",
			description:  "Similar paths should not match",
			shouldMatch:  false,
		},
		{
			name:         "empty path",
			excludedURLs: []string{"/api"},
			requestPath:  "",
			description:  "Empty path should not match",
			shouldMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.ExcludedURLs = tt.excludedURLs

			oidc, _ := setupTestOIDCMiddleware(t, config)

			result := oidc.determineExcludedURL(tt.requestPath)
			assert.Equal(t, tt.shouldMatch, result, tt.description)
		})
	}
}

func TestExcludedURLsPerformance(t *testing.T) {
	// Test performance with many excluded URLs
	excludedURLs := make([]string, 100)
	for i := 0; i < 100; i++ {
		excludedURLs[i] = fmt.Sprintf("/excluded/path/%d", i)
	}

	config := createTestConfig()
	config.ExcludedURLs = excludedURLs

	oidc, _ := setupTestOIDCMiddleware(t, config)

	// Suppress debug logs for performance test
	oldLogger := oidc.logger
	oidc.logger = newNoOpLogger()
	defer func() { oidc.logger = oldLogger }()

	// Test that matching is still fast with many URLs
	start := time.Now()
	for i := 0; i < 1000; i++ {
		oidc.determineExcludedURL("/excluded/path/50/subpath")
	}
	elapsed := time.Since(start)

	// Should complete 1000 checks in under 100ms (lenient for slower systems and CI)
	assert.Less(t, elapsed.Milliseconds(), int64(100), "URL matching should be fast")
}

func TestExcludedURLsIntegration(t *testing.T) {
	// Integration test simulating real-world usage
	publicContent := "This is public content"
	privateContent := "This is private content"

	publicHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/public") {
			w.Write([]byte(publicContent))
		} else {
			w.Write([]byte(privateContent))
		}
	})

	config := createTestConfig()
	config.ExcludedURLs = []string{
		"/health",
		"/api/public",
		"/login",
		"/static",
	}

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.next = publicHandler

	// Test various scenarios
	scenarios := []struct {
		path           string
		expectStatus   int
		expectContent  string
		expectRedirect bool
	}{
		{
			path:           "/health",
			expectStatus:   http.StatusOK,
			expectContent:  privateContent,
			expectRedirect: false,
		},
		{
			path:           "/api/public/users",
			expectStatus:   http.StatusOK,
			expectContent:  publicContent,
			expectRedirect: false,
		},
		{
			path:           "/api/private/admin",
			expectStatus:   http.StatusFound,
			expectContent:  "",
			expectRedirect: true,
		},
		{
			path:           "/static/css/main.css",
			expectStatus:   http.StatusOK,
			expectContent:  privateContent,
			expectRedirect: false,
		},
		{
			path:           "/login?redirect=/dashboard",
			expectStatus:   http.StatusOK,
			expectContent:  privateContent,
			expectRedirect: false,
		},
	}

	for _, scenario := range scenarios {
		t.Run("request to "+scenario.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", scenario.path, nil)
			rec := httptest.NewRecorder()

			oidc.ServeHTTP(rec, req)

			assert.Equal(t, scenario.expectStatus, rec.Code)

			if scenario.expectRedirect {
				assert.Contains(t, rec.Header().Get("Location"), "https://test-provider.example.com")
			} else {
				assert.Equal(t, scenario.expectContent, rec.Body.String())
			}
		})
	}
}
