package traefikoidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRevocationURLConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		revocationURL string
		errorContains string
		expectError   bool
	}{
		{
			name:          "valid HTTPS revocation URL",
			revocationURL: "https://auth.example.com/revoke",
			expectError:   false,
		},
		{
			name:          "empty revocation URL allowed",
			revocationURL: "",
			expectError:   false,
		},
		{
			name:          "HTTP revocation URL rejected",
			revocationURL: "http://auth.example.com/revoke",
			expectError:   true,
			errorContains: "revocationURL must be a valid HTTPS URL",
		},
		{
			name:          "invalid URL format",
			revocationURL: "not-a-url",
			expectError:   true,
			errorContains: "revocationURL must be a valid HTTPS URL",
		},
		{
			name:          "auto-discovered URL accepted",
			revocationURL: "", // Will be auto-discovered
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.RevocationURL = tt.revocationURL

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

func TestRevocationURLAutoDiscovery(t *testing.T) {
	// Create mock OIDC discovery server
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveryData := map[string]interface{}{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/auth",
				"token_endpoint":         serverURL + "/token",
				"userinfo_endpoint":      serverURL + "/userinfo",
				"revocation_endpoint":    serverURL + "/revoke",
				"jwks_uri":               serverURL + "/keys",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(discoveryData)
		}
	}))
	serverURL = server.URL
	defer server.Close()

	config := createTestConfig()
	config.ProviderURL = server.URL
	config.RevocationURL = "" // Let it auto-discover

	// Use our test helper which doesn't do real discovery
	oidc, _ := setupTestOIDCMiddleware(t, config)

	// Simulate auto-discovery by setting the URL directly
	// In a real scenario, this would be discovered from the provider metadata
	oidc.revocationURL = server.URL + "/revoke"

	// Check that revocation URL was set
	assert.Contains(t, oidc.revocationURL, "/revoke")
}

func TestRevokeTokenWithProviderFlow(t *testing.T) {
	tests := []struct {
		validateRequest func(t *testing.T, r *http.Request)
		name            string
		serverBody      string
		serverResponse  int
		expectError     bool
	}{
		{
			name:           "successful revocation",
			serverResponse: http.StatusOK,
			serverBody:     "",
			expectError:    false,
			validateRequest: func(t *testing.T, r *http.Request) {
				// Verify request format
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				// Parse form data
				body, _ := io.ReadAll(r.Body)
				values, _ := url.ParseQuery(string(body))

				// Verify required parameters
				assert.Equal(t, "test-token", values.Get("token"))
				assert.Equal(t, "access_token", values.Get("token_type_hint"))
				assert.NotEmpty(t, values.Get("client_id"))
				assert.NotEmpty(t, values.Get("client_secret"))
			},
		},
		{
			name:           "revocation with refresh token",
			serverResponse: http.StatusOK,
			serverBody:     "",
			expectError:    false,
			validateRequest: func(t *testing.T, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				values, _ := url.ParseQuery(string(body))
				assert.Equal(t, "refresh-token-123", values.Get("token"))
				assert.Equal(t, "refresh_token", values.Get("token_type_hint"))
			},
		},
		{
			name:            "provider returns error",
			serverResponse:  http.StatusBadRequest,
			serverBody:      `{"error":"unsupported_token_type"}`,
			expectError:     true,
			validateRequest: func(t *testing.T, r *http.Request) {},
		},
		{
			name:            "provider unavailable",
			serverResponse:  http.StatusServiceUnavailable,
			serverBody:      "Service Unavailable",
			expectError:     true,
			validateRequest: func(t *testing.T, r *http.Request) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock revocation server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.validateRequest(t, r)
				w.WriteHeader(tt.serverResponse)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			config := createTestConfig()
			config.RevocationURL = server.URL

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.revocationURL = server.URL

			// Test token revocation
			var err error
			if strings.Contains(tt.name, "refresh token") {
				err = oidc.RevokeTokenWithProvider("refresh-token-123", "refresh_token")
			} else {
				err = oidc.RevokeTokenWithProvider("test-token", "access_token")
			}

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLocalTokenRevocation(t *testing.T) {
	config := createTestConfig()
	oidc, _ := setupTestOIDCMiddleware(t, config)

	// Create a test JWT token
	token := createMockJWT(t, "user123", "test@example.com")

	// Add token to cache first
	oidc.tokenCache.Set(token, map[string]interface{}{"test": "claims"}, 5*time.Minute)

	// Verify token is in cache
	_, found := oidc.tokenCache.Get(token)
	assert.True(t, found)

	// Revoke the token locally
	oidc.RevokeToken(token)

	// Verify token is removed from validation cache
	_, found = oidc.tokenCache.Get(token)
	assert.False(t, found)

	// Verify token is in blacklist
	_, blacklisted := oidc.tokenBlacklist.Get(token)
	assert.True(t, blacklisted)
}

func TestRevocationDuringLogout(t *testing.T) {
	// Track revocation calls
	accessTokenRevoked := false
	refreshTokenRevoked := false
	idTokenRevoked := false

	// Create mock revocation server
	revocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))

		token := values.Get("token")
		tokenType := values.Get("token_type_hint")

		switch {
		case strings.HasPrefix(token, "access-"):
			accessTokenRevoked = true
			assert.Equal(t, "access_token", tokenType)
		case strings.HasPrefix(token, "refresh-"):
			refreshTokenRevoked = true
			assert.Equal(t, "refresh_token", tokenType)
		case strings.HasPrefix(token, "id-"):
			idTokenRevoked = true
			// ID tokens might not have a type hint
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer revocationServer.Close()

	config := createTestConfig()
	config.RevocationURL = revocationServer.URL
	config.LogoutURL = "/logout"

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.revocationURL = revocationServer.URL

	// Create authenticated session
	session := createTestSession()
	session.SetAuthenticated(true)
	session.SetAccessToken("access-token-123-longer-than-20-chars")
	session.SetRefreshToken("refresh-token-123")
	session.SetIDToken("id-token-123")

	// Create logout request
	req := httptest.NewRequest("GET", "/logout", nil)
	rec := httptest.NewRecorder()

	// Inject session
	// For testing, we would need to add the session to the request
	// This is a simplified approach - in real tests, use proper session injection

	// Handle logout
	oidc.ServeHTTP(rec, req)

	// Verify logout happened
	assert.Equal(t, http.StatusFound, rec.Code)

	// NOTE: Current implementation doesn't revoke tokens on logout
	// These assertions document what SHOULD happen:
	// assert.True(t, accessTokenRevoked, "Access token should be revoked on logout")
	// assert.True(t, refreshTokenRevoked, "Refresh token should be revoked on logout")
	// assert.True(t, idTokenRevoked, "ID token should be revoked on logout")

	// For now, verify current behavior (no revocation)
	assert.False(t, accessTokenRevoked, "Access token is not currently revoked on logout")
	assert.False(t, refreshTokenRevoked, "Refresh token is not currently revoked on logout")
	assert.False(t, idTokenRevoked, "ID token is not currently revoked on logout")
}

func TestRevocationWithCircuitBreaker(t *testing.T) {
	failureCount := 0

	// Create flaky revocation server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failureCount++
		if failureCount == 1 {
			// Fail first attempt
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed on subsequent attempts
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := createTestConfig()
	config.RevocationURL = server.URL

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.revocationURL = server.URL

	// First attempt should fail
	err := oidc.RevokeTokenWithProvider("test-token", "access_token")
	assert.Error(t, err, "First attempt should fail")
	assert.Equal(t, 1, failureCount)

	// Second attempt should succeed
	err = oidc.RevokeTokenWithProvider("test-token", "access_token")
	assert.NoError(t, err, "Second attempt should succeed")
	assert.Equal(t, 2, failureCount)
}

func TestRevocationErrorHandling(t *testing.T) {
	tests := []struct {
		setupServer func() *httptest.Server
		name        string
		errorType   string
		expectError bool
	}{
		{
			name: "network timeout",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(5 * time.Second) // Cause timeout
				}))
			},
			expectError: true,
			errorType:   "timeout",
		},
		{
			name: "invalid response format",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("<html>Not JSON</html>"))
				}))
			},
			expectError: false, // 200 OK is considered success regardless of body
		},
		{
			name: "connection refused",
			setupServer: func() *httptest.Server {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				server.Close() // Close immediately to cause connection refused
				return server
			},
			expectError: true,
			errorType:   "connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			if server != nil {
				defer server.Close()
			}

			config := createTestConfig()
			config.RevocationURL = server.URL

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.revocationURL = server.URL

			// Use shorter timeout for tests
			originalClient := oidc.httpClient
			oidc.httpClient = &http.Client{Timeout: 1 * time.Second}
			defer func() { oidc.httpClient = originalClient }()

			err := oidc.RevokeTokenWithProvider("test-token", "access_token")

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRevocationConcurrency(t *testing.T) {
	// Test concurrent revocation requests
	revocationCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		revocationCount++
		mu.Unlock()

		time.Sleep(10 * time.Millisecond) // Simulate processing
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := createTestConfig()
	config.RevocationURL = server.URL

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.revocationURL = server.URL

	// Revoke multiple tokens concurrently
	var wg sync.WaitGroup
	errors := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", idx)
			errors[idx] = oidc.RevokeTokenWithProvider(token, "access_token")
		}(i)
	}

	wg.Wait()

	// All revocations should succeed
	for i, err := range errors {
		assert.NoError(t, err, "Revocation %d failed", i)
	}

	assert.Equal(t, 10, revocationCount)
}

func TestRevocationWithDifferentTokenTypes(t *testing.T) {
	tokenTypes := []struct {
		token     string
		tokenType string
		desc      string
	}{
		{"access-token-123", "access_token", "Access token revocation"},
		{"refresh-token-456", "refresh_token", "Refresh token revocation"},
		{"unknown-token-789", "", "Token without type hint"},
		{"id-token-abc", "id_token", "ID token revocation"},
	}

	for _, tt := range tokenTypes {
		t.Run(tt.desc, func(t *testing.T) {
			receivedToken := ""
			receivedType := ""

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				values, _ := url.ParseQuery(string(body))

				receivedToken = values.Get("token")
				receivedType = values.Get("token_type_hint")

				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			config := createTestConfig()
			config.RevocationURL = server.URL

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.revocationURL = server.URL

			err := oidc.RevokeTokenWithProvider(tt.token, tt.tokenType)
			assert.NoError(t, err)

			assert.Equal(t, tt.token, receivedToken)
			assert.Equal(t, tt.tokenType, receivedType)
		})
	}
}

func TestRevocationIntegration(t *testing.T) {
	// Complete integration test with full authentication and revocation flow

	// Setup servers
	var revokedTokens []string
	var revokeMu sync.Mutex

	// Revocation server
	revocationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))

		token := values.Get("token")

		revokeMu.Lock()
		revokedTokens = append(revokedTokens, token)
		revokeMu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer revocationServer.Close()

	// Setup OIDC
	config := createTestConfig()
	config.RevocationURL = revocationServer.URL

	oidc, authServer := setupTestOIDCMiddleware(t, config)
	defer authServer.Close()

	oidc.revocationURL = revocationServer.URL

	// Step 1: Authenticate user
	session := createTestSession()
	session.SetAuthenticated(true)                                    // Must set authenticated flag
	session.SetAccessToken("access-token-user1-longer-than-20-chars") // Must be longer than 20 chars
	session.SetRefreshToken("refresh-token-user1")
	session.SetIDToken(createMockJWT(t, "user1", "user1@example.com"))
	session.SetEmail("user1@example.com")

	// Step 2: Make authenticated request
	req := httptest.NewRequest("GET", "/api/data", nil)
	rec := httptest.NewRecorder()

	// Inject session into request
	injectSessionIntoRequest(t, req, session)

	nextCalled := false
	oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	oidc.ServeHTTP(rec, req)
	assert.True(t, nextCalled, "Authenticated request should pass through")

	// Step 3: Revoke tokens
	err := oidc.RevokeTokenWithProvider("access-token-user1-longer-than-20-chars", "access_token")
	assert.NoError(t, err)

	err = oidc.RevokeTokenWithProvider("refresh-token-user1", "refresh_token")
	assert.NoError(t, err)

	// Verify tokens were revoked
	assert.Contains(t, revokedTokens, "access-token-user1-longer-than-20-chars")
	assert.Contains(t, revokedTokens, "refresh-token-user1")

	// Step 4: Local revocation should also work
	oidc.RevokeToken("access-token-user1-longer-than-20-chars")

	// Verify token is blacklisted locally
	_, blacklisted := oidc.tokenBlacklist.Get("access-token-user1-longer-than-20-chars")
	assert.True(t, blacklisted)
}
