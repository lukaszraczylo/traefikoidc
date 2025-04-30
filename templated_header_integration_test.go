package traefikoidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

// TestTemplatedHeadersIntegration tests that templated headers are correctly added to requests
// in the actual middleware flow
func TestTemplatedHeadersIntegration(t *testing.T) {
	// Create a TestSuite to use its helper methods and fields
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name               string
		headers            []TemplatedHeader
		sessionSetup       func(*SessionData)
		claims             map[string]interface{}
		expectedHeaders    map[string]string
		interceptedHeaders map[string]string
	}{
		{
			name: "Basic Email Header",
			headers: []TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
			},
			claims: map[string]interface{}{
				"email": "user@example.com",
			},
			expectedHeaders: map[string]string{
				"X-User-Email": "user@example.com",
			},
		},
		{
			name: "Multiple Headers",
			headers: []TemplatedHeader{
				{Name: "X-User-Email", Value: "{{.Claims.email}}"},
				{Name: "X-User-ID", Value: "{{.Claims.sub}}"},
				{Name: "X-User-Name", Value: "{{.Claims.given_name}} {{.Claims.family_name}}"},
			},
			claims: map[string]interface{}{
				"email":       "user@example.com",
				"sub":         "user123",
				"given_name":  "John",
				"family_name": "Doe",
			},
			expectedHeaders: map[string]string{
				"X-User-Email": "user@example.com",
				"X-User-ID":    "user123",
				"X-User-Name":  "John Doe",
			},
		},
		{
			name: "Authorization Header with Bearer Token",
			headers: []TemplatedHeader{
				{Name: "Authorization", Value: "Bearer {{.AccessToken}}"},
			},
			expectedHeaders: map[string]string{
				// We'll update this dynamically after generating the token
				"Authorization": "",
			},
		},
		{
			name: "Missing Claim",
			headers: []TemplatedHeader{
				{Name: "X-User-Role", Value: "{{.Claims.role}}"},
			},
			claims: map[string]interface{}{
				"email": "user@example.com",
				// role claim is missing
			},
			expectedHeaders: map[string]string{
				"X-User-Role": "<no value>", // Go templates provide <no value> for missing fields
			},
		},
		{
			name: "Conditional Header",
			headers: []TemplatedHeader{
				{Name: "X-User-Admin", Value: "{{if .Claims.is_admin}}true{{else}}false{{end}}"},
			},
			claims: map[string]interface{}{
				"email":    "admin@example.com",
				"is_admin": true,
			},
			expectedHeaders: map[string]string{
				"X-User-Admin": "true",
			},
		},
		{
			name: "Combined Token and Claim",
			headers: []TemplatedHeader{
				{Name: "X-Auth-Info", Value: "User={{.Claims.email}}, Token={{.AccessToken}}"},
			},
			claims: map[string]interface{}{
				"email": "user@example.com",
			},
			expectedHeaders: map[string]string{
				// We'll update this dynamically after generating the token
				"X-Auth-Info": "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create token with the test claims
			token := ts.token
			if len(tc.claims) > 0 {
				var err error
				claims := map[string]interface{}{
					"iss":   "https://test-issuer.com",
					"aud":   "test-client-id",
					"exp":   float64(3000000000), // Far future timestamp
					"iat":   float64(1000000000),
					"nbf":   float64(1000000000),
					"sub":   "test-subject",
					"nonce": "test-nonce",
					"jti":   generateRandomString(16),
				}

				// Add the test-specific claims
				for k, v := range tc.claims {
					claims[k] = v
				}

				token, err = createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
				if err != nil {
					t.Fatalf("Failed to create test JWT: %v", err)
				}
			}

			// Update expectedHeaders for the token-based tests after token generation
			if tc.name == "Authorization Header with Bearer Token" {
				tc.expectedHeaders["Authorization"] = "Bearer " + token
			}

			if tc.name == "Combined Token and Claim" {
				tc.expectedHeaders["X-Auth-Info"] = "User=user@example.com, Token=" + token
			}

			// Store intercepted headers for verification
			interceptedHeaders := make(map[string]string)

			// Create a test next handler that captures the headers
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Capture headers for verification
				for name := range tc.expectedHeaders {
					if value := r.Header.Get(name); value != "" {
						interceptedHeaders[name] = value
					}
				}
				w.WriteHeader(http.StatusOK)
			})

			// Instead of using New(), we'll directly create a TraefikOidc instance
			// similar to how it's done in TestSuite.Setup()
			tOidc := &TraefikOidc{
				next:               nextHandler,
				name:               "test",
				redirURLPath:       "/callback",
				logoutURLPath:      "/callback/logout",
				issuerURL:          "https://test-issuer.com",
				clientID:           "test-client-id",
				clientSecret:       "test-client-secret",
				jwkCache:           ts.mockJWKCache,
				jwksURL:            "https://test-jwks-url.com",
				tokenBlacklist:     NewCache(),
				tokenCache:         NewTokenCache(),
				limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
				logger:             NewLogger("debug"),
				allowedUserDomains: map[string]struct{}{"example.com": {}},
				excludedURLs:       map[string]struct{}{"/favicon": {}},
				includedURLs:       map[string]struct{}{"/private": {}},
				httpClient:         &http.Client{},
				initComplete:       make(chan struct{}),
				sessionManager:     ts.sessionManager,
				extractClaimsFunc:  extractClaims,
				headerTemplates:    make(map[string]*template.Template),
			}

			// Initialize and parse header templates
			for _, header := range tc.headers {
				tmpl, err := template.New(header.Name).Parse(header.Value)
				if err != nil {
					t.Fatalf("Failed to parse header template for %s: %v", header.Name, err)
				}
				tOidc.headerTemplates[header.Name] = tmpl
			}

			// Close the initComplete channel to bypass the waiting
			close(tOidc.initComplete)

			// Create a test request
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "example.com")
			rr := httptest.NewRecorder()

			// Create a session
			session, err := tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Setup the session with authentication data
			session.SetAuthenticated(true)
			session.SetEmail("user@example.com")
			session.SetAccessToken(token)
			session.SetRefreshToken("test-refresh-token")

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Add session cookies to the request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Reset the response recorder for the main test
			rr = httptest.NewRecorder()

			// Process the request
			tOidc.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != http.StatusOK {
				t.Errorf("Expected status code %d, got %d", http.StatusOK, rr.Code)
			}

			// Verify headers were set correctly
			for name, expectedValue := range tc.expectedHeaders {
				if value, exists := interceptedHeaders[name]; !exists {
					t.Errorf("Expected header %s was not set", name)
				} else if value != expectedValue {
					t.Errorf("Header %s expected value %q, got %q", name, expectedValue, value)
				}
			}
		})
	}
}

// TestEdgeCaseTemplatedHeaders tests edge cases for templated headers
func TestEdgeCaseTemplatedHeaders(t *testing.T) {
	// Create a TestSuite to use its helper methods and fields
	ts := &TestSuite{t: t}
	ts.Setup()

	tests := []struct {
		name               string
		headers            []TemplatedHeader
		claims             map[string]interface{}
		shouldExecuteCheck bool
	}{
		{
			name: "Very Large Template",
			headers: []TemplatedHeader{
				{
					Name:  "X-Large-Header",
					Value: createLargeTemplate(500), // Template with 500 variable references
				},
			},
			claims:             createLargeClaims(500), // Map with 500 claims
			shouldExecuteCheck: true,
		},
		{
			name: "Array Claim Access",
			headers: []TemplatedHeader{
				{Name: "X-Roles", Value: "{{range $i, $e := .Claims.roles}}{{if $i}},{{end}}{{$e}}{{end}}"},
			},
			claims: map[string]interface{}{
				"roles": []interface{}{"admin", "user", "manager"},
			},
			shouldExecuteCheck: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create token with the test claims
			claims := map[string]interface{}{
				"iss":   "https://test-issuer.com",
				"aud":   "test-client-id",
				"exp":   float64(3000000000), // Far future timestamp
				"iat":   float64(1000000000),
				"nbf":   float64(1000000000),
				"sub":   "test-subject",
				"nonce": "test-nonce",
				"jti":   generateRandomString(16),
			}

			// Add the test-specific claims
			for k, v := range tc.claims {
				claims[k] = v
			}

			token, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", claims)
			if err != nil {
				t.Fatalf("Failed to create test JWT: %v", err)
			}

			// Create a test next handler
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Instead of using New(), we'll directly create a TraefikOidc instance
			// similar to how it's done in TestSuite.Setup()
			tOidc := &TraefikOidc{
				next:               nextHandler,
				name:               "test",
				redirURLPath:       "/callback",
				logoutURLPath:      "/callback/logout",
				issuerURL:          "https://test-issuer.com",
				clientID:           "test-client-id",
				clientSecret:       "test-client-secret",
				jwkCache:           ts.mockJWKCache,
				jwksURL:            "https://test-jwks-url.com",
				tokenBlacklist:     NewCache(),
				tokenCache:         NewTokenCache(),
				limiter:            rate.NewLimiter(rate.Every(time.Second), 10),
				logger:             NewLogger("debug"),
				allowedUserDomains: map[string]struct{}{"example.com": {}},
				excludedURLs:       map[string]struct{}{"/favicon": {}},
				includedURLs:       map[string]struct{}{"/private": {}},
				httpClient:         &http.Client{},
				initComplete:       make(chan struct{}),
				sessionManager:     ts.sessionManager,
				extractClaimsFunc:  extractClaims,
				headerTemplates:    make(map[string]*template.Template),
			}

			// Initialize and parse header templates
			for _, header := range tc.headers {
				tmpl, err := template.New(header.Name).Parse(header.Value)
				if err != nil {
					t.Fatalf("Failed to parse header template for %s: %v", header.Name, err)
				}
				tOidc.headerTemplates[header.Name] = tmpl
			}

			// Close the initComplete channel to bypass the waiting
			close(tOidc.initComplete)

			// Create a test request
			req := httptest.NewRequest("GET", "/protected", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "example.com")
			rr := httptest.NewRecorder()

			// Create a session
			session, err := tOidc.sessionManager.GetSession(req)
			if err != nil {
				t.Fatalf("Failed to get session: %v", err)
			}

			// Setup the session with authentication data
			session.SetAuthenticated(true)
			session.SetEmail("user@example.com")
			session.SetAccessToken(token)
			session.SetRefreshToken("test-refresh-token")

			if err := session.Save(req, rr); err != nil {
				t.Fatalf("Failed to save session: %v", err)
			}

			// Add session cookies to the request
			for _, cookie := range rr.Result().Cookies() {
				req.AddCookie(cookie)
			}

			// Reset the response recorder for the main test
			rr = httptest.NewRecorder()

			// Process the request
			tOidc.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != http.StatusOK {
				t.Errorf("Expected status code %d, got %d", http.StatusOK, rr.Code)
			}

			// We are primarily checking that these edge cases don't cause panics or errors
			// For the array test, we can verify the content
			if tc.name == "Array Claim Access" {
				// Check if the header was set
				headerValue := req.Header.Get("X-Roles")
				expectedValue := "admin,user,manager"
				if headerValue != expectedValue {
					t.Errorf("Expected X-Roles header to be %q, got %q", expectedValue, headerValue)
				}
			}
		})
	}
}

// Helper functions for edge case tests

// createLargeTemplate creates a template with many variable references
func createLargeTemplate(size int) string {
	template := "{{with .Claims}}"
	for i := 0; i < size; i++ {
		if i > 0 {
			template += ","
		}
		template += "{{.field" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + "}}"
	}
	template += "{{end}}"
	return template
}

// createLargeClaims creates a map with many claims for testing large templates
func createLargeClaims(size int) map[string]interface{} {
	claims := make(map[string]interface{})
	for i := 0; i < size; i++ {
		key := "field" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		claims[key] = "value" + string(rune('a'+i%26)) + string(rune('0'+i%10))
	}
	return claims
}
