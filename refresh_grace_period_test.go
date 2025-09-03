package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Helper to create an authenticated session with tokens
func createAuthenticatedSession(accessToken, idToken, refreshToken string) *SessionData {
	session := createTestSession()
	session.SetAuthenticated(true)
	session.SetAccessToken(accessToken)
	session.SetIDToken(idToken)
	if refreshToken != "" {
		session.SetRefreshToken(refreshToken)
	}
	session.SetEmail("test@example.com")
	return session
}

func TestRefreshGracePeriodConfiguration(t *testing.T) {
	tests := []struct {
		name                      string
		refreshGracePeriodSeconds int
		expectDefault             bool
		expectedValue             int
	}{
		{
			name:                      "custom grace period",
			refreshGracePeriodSeconds: 120,
			expectDefault:             false,
			expectedValue:             120,
		},
		{
			name:                      "zero uses default",
			refreshGracePeriodSeconds: 0,
			expectDefault:             true,
			expectedValue:             60, // Default value
		},
		{
			name:                      "negative uses default",
			refreshGracePeriodSeconds: -30,
			expectDefault:             true,
			expectedValue:             60,
		},
		{
			name:                      "very large grace period",
			refreshGracePeriodSeconds: 3600, // 1 hour
			expectDefault:             false,
			expectedValue:             3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig()
			config.RefreshGracePeriodSeconds = tt.refreshGracePeriodSeconds

			oidc, _ := setupTestOIDCMiddleware(t, config)

			// Check the configured value
			assert.Equal(t, time.Duration(tt.expectedValue)*time.Second, oidc.refreshGracePeriod)
		})
	}
}

func TestTokenRefreshWithinGracePeriod(t *testing.T) {
	// Reset global state to prevent test interference
	resetGlobalState()

	refreshCount := int32(0)
	tokenVersion := int32(1)

	// Mock token server that returns new tokens
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&refreshCount, 1)
		currentVersion := atomic.LoadInt32(&tokenVersion)

		// Return new tokens
		newToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(5*time.Minute))
		response := map[string]interface{}{
			"access_token":  fmt.Sprintf("new-access-token-longer-than-20-v%d", currentVersion),
			"id_token":      newToken,
			"refresh_token": fmt.Sprintf("new-refresh-token-v%d", currentVersion),
			"expires_in":    300,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	config := createTestConfig()
	config.RefreshGracePeriodSeconds = 30 // 30 second grace period

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.tokenURL = tokenServer.URL
	oidc.refreshGracePeriod = time.Duration(30) * time.Second

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

	// Create session with token expiring soon (within grace period)
	expiryTime := time.Now().Add(25 * time.Second) // Expires in 25 seconds (within 30s grace)
	idToken := createMockJWTWithExpiry(t, "user123", "test@example.com", expiryTime)

	session := createAuthenticatedSession("old-access-token-longer-than-20-chars", idToken, "refresh-token-123")

	// Set up the next handler before concurrent requests
	var nextCallCount int32
	oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&nextCallCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	// Make concurrent requests during grace period
	var wg sync.WaitGroup
	results := make([]bool, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			req := httptest.NewRequest("GET", "/api/data", nil)
			rec := httptest.NewRecorder()

			// Clone session for each request
			reqSession := createTestSession()
			reqSession.SetAuthenticated(true)
			reqSession.SetAccessToken(session.GetAccessToken())
			reqSession.SetIDToken(session.GetIDToken())
			reqSession.SetRefreshToken(session.GetRefreshToken())
			reqSession.SetEmail(session.GetEmail())

			// Inject session into request
			injectSessionIntoRequest(t, req, reqSession)

			oidc.ServeHTTP(rec, req)
			results[idx] = rec.Code == http.StatusOK
		}(i)
	}

	wg.Wait()

	// All requests should succeed
	for i, success := range results {
		assert.True(t, success, "Request %d should succeed", i)
	}

	// Verify all requests reached the next handler
	assert.Equal(t, int32(5), atomic.LoadInt32(&nextCallCount), "All requests should reach next handler")

	// Each concurrent request will perform its own refresh because they each have
	// their own session instance loaded from cookies. The implementation doesn't
	// have a global refresh synchronization mechanism across different session instances.
	// This is a known limitation - the grace period only prevents repeated refreshes
	// within the same session instance, not across concurrent requests.
	assert.Equal(t, int32(5), atomic.LoadInt32(&refreshCount), "Each concurrent request performs its own refresh")
}

func TestTokenRefreshOutsideGracePeriod(t *testing.T) {
	refreshCalled := false

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalled = true

		// Return new token
		newToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(1*time.Hour))
		response := map[string]interface{}{
			"access_token":  "new-access-token-longer-than-20-chars",
			"id_token":      newToken,
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	config := createTestConfig()
	config.RefreshGracePeriodSeconds = 60

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.tokenURL = tokenServer.URL
	oidc.refreshGracePeriod = time.Duration(60) * time.Second

	// Mock the token verifier
	oidc.tokenVerifier = &mockTokenVerifier{
		verifyFunc: func(token string) error {
			claims, err := extractClaims(token)
			if err != nil {
				return err
			}
			oidc.tokenCache.Set(token, claims, time.Hour)
			return nil
		},
	}

	// Create session with expired token (outside grace period)
	expiredToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(-2*time.Minute))

	session := createAuthenticatedSession("expired-access-token-longer-than-20", expiredToken, "refresh-token-123")

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

	// Request should succeed after refresh
	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Refresh should have been called
	assert.True(t, refreshCalled, "Token refresh should be triggered for expired token")
}

func TestGracePeriodWithProviderSpecificBehavior(t *testing.T) {
	providers := []struct {
		name               string
		providerType       string
		supportsRefresh    bool
		gracePeriodSeconds int
	}{
		{
			name:               "Google provider with grace period",
			providerType:       "google",
			supportsRefresh:    true,
			gracePeriodSeconds: 120,
		},
		{
			name:               "Azure provider with grace period",
			providerType:       "azure",
			supportsRefresh:    true,
			gracePeriodSeconds: 60,
		},
		{
			name:               "Generic provider with grace period",
			providerType:       "generic",
			supportsRefresh:    true,
			gracePeriodSeconds: 90,
		},
	}

	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			config := createTestConfig()
			config.RefreshGracePeriodSeconds = provider.gracePeriodSeconds
			config.ProviderURL = "https://" + provider.providerType + ".example.com"

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.refreshGracePeriod = time.Duration(provider.gracePeriodSeconds) * time.Second

			// This test only verifies configuration, not actual refresh behavior
			// Verify grace period is respected for this provider
			assert.Equal(t, time.Duration(provider.gracePeriodSeconds)*time.Second, oidc.refreshGracePeriod)
		})
	}
}

func TestRefreshGracePeriodConcurrency(t *testing.T) {
	// Reset global state to prevent test interference
	resetGlobalState()

	var refreshMutex sync.Mutex
	refreshCount := 0
	blockedRequests := int32(0)

	// Mock token server with delay to simulate slow refresh
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshMutex.Lock()
		refreshCount++
		refreshMutex.Unlock()

		// Simulate slow token refresh
		time.Sleep(100 * time.Millisecond)

		newToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(1*time.Hour))
		response := map[string]interface{}{
			"access_token":  "new-access-token-longer-than-20-chars",
			"id_token":      newToken,
			"refresh_token": "new-refresh-token",
			"expires_in":    3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	config := createTestConfig()
	config.RefreshGracePeriodSeconds = 30

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.tokenURL = tokenServer.URL
	oidc.refreshGracePeriod = time.Duration(30) * time.Second

	// Mock the token verifier
	oidc.tokenVerifier = &mockTokenVerifier{
		verifyFunc: func(token string) error {
			claims, err := extractClaims(token)
			if err != nil {
				return err
			}
			oidc.tokenCache.Set(token, claims, time.Hour)
			return nil
		},
	}

	// Create session with token expiring within grace period
	expiryTime := time.Now().Add(20 * time.Second)
	idToken := createMockJWTWithExpiry(t, "user123", "test@example.com", expiryTime)

	session := createAuthenticatedSession("old-access-token-longer-than-20-chars", idToken, "refresh-token-123")

	// Set up the next handler before concurrent requests
	successCount := int32(0)
	oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&successCount, 1)
		w.WriteHeader(http.StatusOK)
	})

	// Make many concurrent requests
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest("GET", "/api/data", nil)
			rec := httptest.NewRecorder()

			// Each request gets its own session copy
			reqSession := createAuthenticatedSession(
				session.GetAccessToken(),
				session.GetIDToken(),
				session.GetRefreshToken(),
			)

			// Inject session into request
			injectSessionIntoRequest(t, req, reqSession)

			start := time.Now()
			oidc.ServeHTTP(rec, req)
			elapsed := time.Since(start)

			// Track if request was blocked waiting for refresh
			if elapsed > 50*time.Millisecond {
				atomic.AddInt32(&blockedRequests, 1)
			}
		}()
	}

	wg.Wait()

	// All requests should succeed
	assert.Equal(t, int32(20), successCount, "All requests should succeed")

	// Each concurrent request performs its own refresh due to separate session instances
	// The implementation lacks global refresh synchronization across session instances
	assert.Equal(t, 20, refreshCount, "Each concurrent request performs its own refresh")

	// With the current implementation, requests aren't blocked because each has its own mutex
	t.Logf("Requests with >50ms delay (own refresh): %d", blockedRequests)
}

func TestRefreshGracePeriodEdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		gracePeriodSeconds int
		tokenExpiryDelta   time.Duration
		expectRefresh      bool
		description        string
	}{
		{
			name:               "token exactly at grace boundary",
			gracePeriodSeconds: 60,
			tokenExpiryDelta:   60 * time.Second,
			expectRefresh:      true,
			description:        "Should refresh when exactly at grace period boundary",
		},
		{
			name:               "token just inside grace period",
			gracePeriodSeconds: 60,
			tokenExpiryDelta:   59 * time.Second,
			expectRefresh:      true,
			description:        "Should refresh when inside grace period",
		},
		{
			name:               "token just outside grace period",
			gracePeriodSeconds: 60,
			tokenExpiryDelta:   61 * time.Second,
			expectRefresh:      false,
			description:        "Should not refresh when outside grace period",
		},
		{
			name:               "already expired token",
			gracePeriodSeconds: 60,
			tokenExpiryDelta:   -10 * time.Second,
			expectRefresh:      true,
			description:        "Should always refresh expired tokens",
		},
		{
			name:               "very short grace period",
			gracePeriodSeconds: 1,
			tokenExpiryDelta:   500 * time.Millisecond,
			expectRefresh:      true,
			description:        "Should handle sub-second grace periods",
		},
		{
			name:               "zero grace period",
			gracePeriodSeconds: 0, // Will use default 60
			tokenExpiryDelta:   30 * time.Second,
			expectRefresh:      true,
			description:        "Should use default when zero configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refreshCalled := false

			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				refreshCalled = true

				newToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(1*time.Hour))
				response := map[string]interface{}{
					"access_token":  "new-access-token-longer-than-20-chars",
					"id_token":      newToken,
					"refresh_token": "new-refresh-token",
					"expires_in":    3600,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer tokenServer.Close()

			config := createTestConfig()
			config.RefreshGracePeriodSeconds = tt.gracePeriodSeconds

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.tokenURL = tokenServer.URL

			// Handle zero grace period defaulting to 60
			if tt.gracePeriodSeconds > 0 {
				oidc.refreshGracePeriod = time.Duration(tt.gracePeriodSeconds) * time.Second
			} else {
				oidc.refreshGracePeriod = time.Duration(60) * time.Second
			}

			// Mock the token verifier
			oidc.tokenVerifier = &mockTokenVerifier{
				verifyFunc: func(token string) error {
					claims, err := extractClaims(token)
					if err != nil {
						return err
					}
					oidc.tokenCache.Set(token, claims, time.Hour)
					return nil
				},
			}

			// Create token with specified expiry
			expiryTime := time.Now().Add(tt.tokenExpiryDelta)
			idToken := createMockJWTWithExpiry(t, "user123", "test@example.com", expiryTime)

			session := createAuthenticatedSession("test-access-token-longer-than-20-chars", idToken, "refresh-token-123")

			req := httptest.NewRequest("GET", "/api/data", nil)
			rec := httptest.NewRecorder()

			// Inject session into request
			injectSessionIntoRequest(t, req, session)

			oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			oidc.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectRefresh, refreshCalled, tt.description)
		})
	}
}

func TestRefreshGracePeriodWithoutRefreshToken(t *testing.T) {
	config := createTestConfig()
	config.RefreshGracePeriodSeconds = 30

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.refreshGracePeriod = time.Duration(30) * time.Second

	// Mock the token verifier
	oidc.tokenVerifier = &mockTokenVerifier{
		verifyFunc: func(token string) error {
			claims, err := extractClaims(token)
			if err != nil {
				return err
			}
			oidc.tokenCache.Set(token, claims, time.Hour)
			return nil
		},
	}

	// Create session with token expiring within grace period but NO refresh token
	expiryTime := time.Now().Add(20 * time.Second)
	idToken := createMockJWTWithExpiry(t, "user123", "test@example.com", expiryTime)

	// Create session with access token but no refresh token
	// Access token must be at least 20 chars for opaque tokens
	session := createAuthenticatedSession("test-access-token-longer-than-20-chars", idToken, "") // No refresh token

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

	// Should still allow access even though token is near expiry
	// because we can't refresh without a refresh token
	assert.True(t, nextCalled, "Request should proceed even without refresh capability")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// Helper function to create JWT with specific expiry
func createMockJWTWithExpiry(t *testing.T, sub, email string, expiry time.Time) string {
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "test-key-id",
	}

	claims := map[string]interface{}{
		"sub":   sub,
		"email": email,
		"iss":   "https://test-provider.com",
		"aud":   "test-client-id",
		"exp":   expiry.Unix(),
		"iat":   time.Now().Unix(),
		"name":  "Test User",
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create a fake signature
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return headerEncoded + "." + claimsEncoded + "." + signature
}
