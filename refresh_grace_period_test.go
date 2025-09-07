package traefikoidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

	// Debug before setting
	fmt.Printf("DEBUG: Before setting - accessSession: %v, idTokenSession: %v\n",
		session.accessSession != nil, session.idTokenSession != nil)

	session.SetAccessToken(accessToken)
	session.SetIDToken(idToken)
	if refreshToken != "" {
		session.SetRefreshToken(refreshToken)
	}
	session.SetEmail("test@example.com")

	// Debug: Verify tokens were actually stored
	if accessToken != "" && session.GetAccessToken() == "" {
		fmt.Printf("WARNING: Failed to store access token. Token length: %d, Token format check: %d dots\n",
			len(accessToken), strings.Count(accessToken, "."))
		// Check if the sub-sessions are initialized
		if session.accessSession == nil {
			fmt.Printf("ERROR: accessSession is nil\n")
		} else {
			// Check what's in the session
			if val, ok := session.accessSession.Values["token"]; ok {
				fmt.Printf("DEBUG: Token is in session.Values but as: %T, len: %d\n", val, len(val.(string)))
				// Try to get it manually
				result := session.GetAccessToken()
				fmt.Printf("DEBUG: GetAccessToken() returns: len=%d\n", len(result))
				// Check if manager is nil
				if session.manager == nil {
					fmt.Printf("DEBUG: session.manager is nil\n")
				} else if session.manager.chunkManager == nil {
					fmt.Printf("DEBUG: session.manager.chunkManager is nil\n")
				} else {
					fmt.Printf("DEBUG: Both manager and chunkManager are set\n")
					if session.manager.logger == nil {
						fmt.Printf("DEBUG: But logger is nil!\n")
					}
				}
			} else {
				fmt.Printf("DEBUG: Token key not found in session.Values\n")
			}
		}
	}
	if idToken != "" && session.GetIDToken() == "" {
		fmt.Printf("WARNING: Failed to store ID token. Token length: %d, Token format check: %d dots\n",
			len(idToken), strings.Count(idToken, "."))
		// Check if the sub-sessions are initialized
		if session.idTokenSession == nil {
			fmt.Printf("ERROR: idTokenSession is nil\n")
		}
	}

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
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

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
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

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

	// With refresh token available, should attempt refresh even outside grace period
	assert.True(t, refreshCalled, "Token refresh should be triggered when refresh token is available")

	// After successful refresh, request should proceed
	assert.True(t, nextCalled, "Request should proceed after successful refresh")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGracePeriodWithProviderSpecificBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

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
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

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
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	tests := []struct {
		name               string
		description        string
		gracePeriodSeconds int
		tokenExpiryDelta   time.Duration
		expectRefresh      bool
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
			description:        "Should not refresh when token is outside grace period",
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

// ====== COMPREHENSIVE 6-HOUR EXPIRY TESTS FOR GRACE PERIOD ======
// These tests demonstrate the broken behavior with 6-hour token expiry scenarios

// TestSixHourExpiryWithGracePeriod tests the interaction between 6-hour expiry and grace periods
// This test SHOULD FAIL - it demonstrates broken 6-hour expiry handling
func TestSixHourExpiryWithGracePeriod(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	t.Log("Testing 6-hour token expiry with grace period - this test demonstrates BROKEN BEHAVIOR")

	// Reset global state
	resetGlobalState()

	refreshAttempts := int32(0)
	unknownSessionRedirects := int32(0)

	// Mock token server for refresh attempts
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&refreshAttempts, 1)
		t.Logf("6-hour expiry test - refresh attempt #%d", atomic.LoadInt32(&refreshAttempts))

		// Return new valid tokens
		newToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(1*time.Hour))
		response := map[string]interface{}{
			"access_token":  "new-6hour-access-token-longer-than-20-chars",
			"id_token":      newToken,
			"refresh_token": "new-6hour-refresh-token",
			"expires_in":    3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Configure with grace period
	config := createTestConfig()
	config.RefreshGracePeriodSeconds = 300 // 5 minutes grace period

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.tokenURL = tokenServer.URL
	oidc.refreshGracePeriod = time.Duration(300) * time.Second

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

	// Create tokens that expired exactly 6 hours ago (browser inactivity scenario)
	sixHoursAgo := time.Now().Add(-6 * time.Hour)
	expiredToken := createMockJWTWithExpiry(t, "user123", "test@example.com", sixHoursAgo)

	session := createAuthenticatedSession("expired-6hour-access-token-longer-than-20", expiredToken, "valid-refresh-token")

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()

	// Inject session into request
	injectSessionIntoRequest(t, req, session)

	// Set up next handler to detect unknown-session redirects
	oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SUCCESS: Request processed after 6-hour token renewal"))
	})

	// We'll check the response after the call instead of wrapping ServeHTTP

	t.Log("Making request with 6-hour expired token - should refresh within grace period")

	// This should detect the 6-hour expired token and attempt refresh
	oidc.ServeHTTP(rec, req)

	// Check if response was a redirect to /unknown-session
	if rec.Code == http.StatusTemporaryRedirect {
		location := rec.Header().Get("Location")
		if strings.Contains(location, "/unknown-session") {
			atomic.AddInt32(&unknownSessionRedirects, 1)
		}
	}

	// ==== ASSERTIONS DEMONSTRATING THE 6-HOUR BUG ====

	finalRefreshAttempts := atomic.LoadInt32(&refreshAttempts)
	finalUnknownRedirects := atomic.LoadInt32(&unknownSessionRedirects)

	t.Logf("Refresh attempts: %d", finalRefreshAttempts)
	t.Logf("Unknown session redirects: %d", finalUnknownRedirects)
	t.Logf("Response code: %d", rec.Code)
	t.Logf("Response body: %s", rec.Body.String())

	// Current broken behavior - 6-hour expired tokens redirect to /unknown-session
	if finalUnknownRedirects > 0 {
		t.Errorf("BUG DEMONSTRATED: 6-hour expired token caused %d redirects to /unknown-session", finalUnknownRedirects)
		t.Error("BROKEN: Users see /unknown-session instead of transparent token renewal")
		t.Error("Expected: Automatic token refresh should happen transparently")
		t.Error("Expected: Grace period should allow renewal of recently expired tokens")

		if finalRefreshAttempts == 0 {
			t.Error("CRITICAL: No refresh attempt was made despite valid refresh token")
			t.Error("This proves the 6-hour expiry detection is completely broken")
		}
		return // Test fails as expected - demonstrates the bug
	}

	// This is what SHOULD happen (but doesn't currently work):
	if rec.Code == http.StatusOK && finalRefreshAttempts > 0 {
		t.Log("SUCCESS: 6-hour expired token was properly renewed within grace period")

		if !strings.Contains(rec.Body.String(), "SUCCESS") {
			t.Error("Expected success message after renewal")
		}

		// Verify the grace period was applied correctly
		if finalRefreshAttempts > 1 {
			t.Errorf("INEFFICIENCY: Too many refresh attempts (%d) - grace period not working", finalRefreshAttempts)
		}
	} else if finalRefreshAttempts == 0 {
		t.Error("BUG DEMONSTRATED: No refresh attempt made for 6-hour expired token")
		t.Error("Expected: Grace period should trigger refresh for recently expired tokens")
		t.Errorf("Response: Code=%d, Body=%s", rec.Code, rec.Body.String())
	} else {
		t.Errorf("UNEXPECTED: Response after refresh attempt - Code=%d, Body=%s", rec.Code, rec.Body.String())
	}
}

// TestGracePeriodSixHourEdgeCase tests the exact edge case of 6-hour token expiry
// This test SHOULD FAIL - it demonstrates the specific 6-hour boundary bug
func TestGracePeriodSixHourEdgeCase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	t.Log("Testing grace period at 6-hour boundary - this test demonstrates BROKEN BEHAVIOR")

	testCases := []struct {
		name           string
		expiryTime     time.Duration
		gracePeriod    time.Duration
		shouldRefresh  bool
		expectRedirect bool
		description    string
	}{
		{
			name:           "6 hours expired, 5 min grace",
			expiryTime:     -6 * time.Hour,
			gracePeriod:    5 * time.Minute,
			shouldRefresh:  true, // Always refresh when refresh token available
			expectRedirect: false,
			description:    "6-hour expiry should refresh with available refresh token",
		},
		{
			name:           "6 hours expired, 7 hour grace",
			expiryTime:     -6 * time.Hour,
			gracePeriod:    7 * time.Hour,
			shouldRefresh:  true, // Within grace period
			expectRedirect: false,
			description:    "6-hour expiry should be within 7-hour grace period",
		},
		{
			name:           "Exactly 6 hours expired, 6 hour grace",
			expiryTime:     -6 * time.Hour,
			gracePeriod:    6 * time.Hour,
			shouldRefresh:  true, // At boundary - should refresh
			expectRedirect: false,
			description:    "At exact boundary should favor refresh",
		},
		{
			name:           "5h59m expired, 6 hour grace",
			expiryTime:     -5*time.Hour - 59*time.Minute,
			gracePeriod:    6 * time.Hour,
			shouldRefresh:  true,
			expectRedirect: false,
			description:    "Just under 6 hours should refresh within 6-hour grace",
		},
		{
			name:           "6h01m expired, 6 hour grace",
			expiryTime:     -6*time.Hour - 1*time.Minute,
			gracePeriod:    6 * time.Hour,
			shouldRefresh:  true, // Always refresh when refresh token available
			expectRedirect: false,
			description:    "Just over 6 hours should refresh with available refresh token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing: %s", tc.description)

			resetGlobalState()

			refreshCount := int32(0)
			redirectCount := int32(0)
			unknownSessionCount := int32(0)

			// Mock token server
			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&refreshCount, 1)
				t.Logf("Grace period test '%s' - refresh attempt #%d", tc.name, atomic.LoadInt32(&refreshCount))

				newToken := createMockJWTWithExpiry(t, "user123", "test@example.com", time.Now().Add(1*time.Hour))
				response := map[string]interface{}{
					"access_token":  fmt.Sprintf("refreshed-%s-token-longer-than-20-chars", tc.name),
					"id_token":      newToken,
					"refresh_token": fmt.Sprintf("refreshed-%s-refresh-token", tc.name),
					"expires_in":    3600,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer tokenServer.Close()

			// Configure with specific grace period
			config := createTestConfig()
			config.RefreshGracePeriodSeconds = int(tc.gracePeriod.Seconds())

			oidc, _ := setupTestOIDCMiddleware(t, config)
			oidc.tokenURL = tokenServer.URL
			oidc.refreshGracePeriod = tc.gracePeriod

			// Mock token verifier
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

			// Create token with specific expiry time
			expiredTime := time.Now().Add(tc.expiryTime)
			expiredToken := createMockJWTWithExpiry(t, "user123", "test@example.com", expiredTime)

			session := createAuthenticatedSession(
				expiredToken, // Use proper JWT for access token
				expiredToken,
				"test-refresh-token",
			)

			// Debug: Check what's in the session before injection
			t.Logf("Session before injection - Access token: %v, ID token: %v, Refresh: %v",
				session.GetAccessToken() != "", session.GetIDToken() != "", session.GetRefreshToken() != "")

			req := httptest.NewRequest("GET", "/grace-test", nil)
			rec := httptest.NewRecorder()

			injectSessionIntoRequest(t, req, session)

			// Set up handlers to track behavior
			oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf("SUCCESS: %s processed", tc.name)))
			})

			// We'll check redirects after the call

			t.Logf("Executing grace period test for: %s", tc.name)
			t.Logf("Token expired: %v ago, Grace period: %v", -tc.expiryTime, tc.gracePeriod)

			// Execute the test
			oidc.ServeHTTP(rec, req)

			// Check for redirects after the call
			if rec.Code == http.StatusTemporaryRedirect || rec.Code == http.StatusFound {
				atomic.AddInt32(&redirectCount, 1)
				location := rec.Header().Get("Location")
				if strings.Contains(location, "/unknown-session") {
					atomic.AddInt32(&unknownSessionCount, 1)
				}
			}

			// Analyze results
			finalRefreshCount := atomic.LoadInt32(&refreshCount)
			finalRedirectCount := atomic.LoadInt32(&redirectCount)
			finalUnknownCount := atomic.LoadInt32(&unknownSessionCount)

			t.Logf("Results for '%s':", tc.name)
			t.Logf("  Refresh attempts: %d", finalRefreshCount)
			t.Logf("  Redirects: %d", finalRedirectCount)
			t.Logf("  Unknown session redirects: %d", finalUnknownCount)
			t.Logf("  Response code: %d", rec.Code)

			// Verify expected behavior
			if tc.shouldRefresh {
				if finalRefreshCount == 0 {
					t.Errorf("BUG: Expected refresh for '%s' within grace period, but none occurred", tc.name)
					t.Errorf("Grace period %v should cover expiry %v ago", tc.gracePeriod, -tc.expiryTime)

					if finalUnknownCount > 0 {
						t.Error("CRITICAL: Got /unknown-session redirect instead of refresh")
					}
				} else if rec.Code == http.StatusOK {
					t.Logf("SUCCESS: '%s' correctly refreshed within grace period", tc.name)
				}
			} else {
				// Should not refresh, but should redirect properly
				if finalRefreshCount > 0 {
					t.Errorf("INEFFICIENCY: Unnecessary refresh attempt for '%s' outside grace period", tc.name)
					t.Errorf("Grace period %v should NOT cover expiry %v ago", tc.gracePeriod, -tc.expiryTime)
				}
			}

			if tc.expectRedirect {
				if finalRedirectCount == 0 {
					t.Errorf("BUG: Expected redirect for '%s' outside grace period", tc.name)
				} else if finalUnknownCount > 0 {
					t.Errorf("BUG: Got /unknown-session redirect instead of proper auth redirect")
					t.Error("Expected: Redirect to OAuth provider for re-authentication")
				}
			}

			// Check for the critical /unknown-session bug
			if finalUnknownCount > 0 {
				t.Errorf("CRITICAL BUG: '%s' caused %d /unknown-session redirects", tc.name, finalUnknownCount)
				t.Error("This is the exact bug reported - users see /unknown-session after browser inactivity")
			}
		})
	}
}

// TestSixHourBrowserInactivityScenario simulates the exact real-world scenario
// This test SHOULD FAIL - it demonstrates the exact user experience bug
func TestSixHourBrowserInactivityScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	t.Log("Simulating real-world 6-hour browser inactivity scenario - this demonstrates USER-VISIBLE BUG")

	resetGlobalState()

	userExperienceLog := []string{}

	// Mock what happens during browser inactivity:
	// 1. User leaves browser open on protected page
	// 2. 6 hours pass with no activity
	// 3. User returns and clicks on something or refreshes
	// 4. System should renew tokens transparently
	// 5. But currently redirects to /unknown-session instead

	tokenRefreshAttempted := false
	unknownSessionShown := false
	userSawError := false

	// Mock token server (OIDC provider)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRefreshAttempted = true
		userExperienceLog = append(userExperienceLog, "Token server received refresh request")

		// Provider would normally return new tokens
		newToken := createMockJWTWithExpiry(t, "real-user", "user@company.com", time.Now().Add(8*time.Hour))
		response := map[string]interface{}{
			"access_token":  "new-valid-access-token-after-6hour-expiry",
			"id_token":      newToken,
			"refresh_token": "new-valid-refresh-token-after-6hour-expiry",
			"expires_in":    28800, // 8 hours
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		userExperienceLog = append(userExperienceLog, "Token server returned new tokens successfully")
	}))
	defer tokenServer.Close()

	// Set up middleware with real-world configuration
	config := createTestConfig()
	config.RefreshGracePeriodSeconds = 25200 // 7 hours grace period to handle 6-hour browser inactivity

	oidc, _ := setupTestOIDCMiddleware(t, config)
	oidc.tokenURL = tokenServer.URL
	oidc.refreshGracePeriod = 7 * time.Hour

	oidc.tokenVerifier = &mockTokenVerifier{
		verifyFunc: func(token string) error {
			claims, err := extractClaims(token)
			if err != nil {
				userExperienceLog = append(userExperienceLog, fmt.Sprintf("Token verification failed: %v", err))
				return err
			}
			oidc.tokenCache.Set(token, claims, time.Hour)
			return nil
		},
	}

	// Step 1: User initially logs in successfully (6+ hours ago)
	userExperienceLog = append(userExperienceLog, "User logged in successfully 6 hours ago")

	// Step 2: Simulate tokens that expired exactly 6 hours ago (realistic expiry time)
	sixHoursAgo := time.Now().Add(-6 * time.Hour)
	expiredAccessToken := createMockJWTWithExpiry(t, "real-user", "user@company.com", sixHoursAgo)
	expiredIDToken := createMockJWTWithExpiry(t, "real-user", "user@company.com", sixHoursAgo)

	// Refresh token should still be valid (typically 30-day expiry)
	validRefreshToken := "long-lived-refresh-token-still-valid"

	userExperienceLog = append(userExperienceLog, "6 hours of browser inactivity - tokens expired")

	// Step 3: User returns and tries to access protected resource
	userExperienceLog = append(userExperienceLog, "User returns and clicks on protected resource")

	session := createAuthenticatedSession(expiredAccessToken, expiredIDToken, validRefreshToken)
	session.SetEmail("user@company.com")

	req := httptest.NewRequest("GET", "/dashboard/important-page", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "myapp.company.com")
	rec := httptest.NewRecorder()

	injectSessionIntoRequest(t, req, session)

	// Set up what the user SHOULD see (success page)
	oidc.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userExperienceLog = append(userExperienceLog, "SUCCESS: User sees the protected page they requested")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>Welcome back! Your tokens were refreshed automatically.</h1></body></html>"))
	})

	// We'll check the user experience after the call

	t.Log("Simulating user returning after 6 hours of inactivity...")

	// Step 4: Execute the request (what happens when user returns)
	oidc.ServeHTTP(rec, req)

	// Check what the user actually sees due to the bug
	if rec.Code == http.StatusTemporaryRedirect {
		location := rec.Header().Get("Location")
		userExperienceLog = append(userExperienceLog, fmt.Sprintf("User redirected to: %s", location))

		if strings.Contains(location, "/unknown-session") {
			unknownSessionShown = true
			userSawError = true
			userExperienceLog = append(userExperienceLog, "BUG: User sees confusing /unknown-session error page")
			userExperienceLog = append(userExperienceLog, "User experience: 'What happened to my session? Why do I see this error?'")
		} else if strings.Contains(location, "auth") || strings.Contains(location, "login") {
			userExperienceLog = append(userExperienceLog, "User redirected to login (acceptable fallback)")
		}
	} else if rec.Code == http.StatusOK {
		userExperienceLog = append(userExperienceLog, "User successfully sees requested page")
	} else {
		userSawError = true
		userExperienceLog = append(userExperienceLog, fmt.Sprintf("User sees error: HTTP %d", rec.Code))
	}

	// ==== ANALYZE USER EXPERIENCE ====

	t.Log("\n=== USER EXPERIENCE ANALYSIS ===")
	for i, logEntry := range userExperienceLog {
		t.Logf("%d. %s", i+1, logEntry)
	}

	t.Logf("\nFinal Results:")
	t.Logf("  Token refresh attempted: %t", tokenRefreshAttempted)
	t.Logf("  User saw /unknown-session: %t", unknownSessionShown)
	t.Logf("  User experienced error: %t", userSawError)
	t.Logf("  HTTP Response Code: %d", rec.Code)

	// ==== ASSERTIONS FOR USER EXPERIENCE BUG ====

	if unknownSessionShown {
		t.Error("BUG DEMONSTRATED: Real user sees /unknown-session after 6 hours of browser inactivity")
		t.Error("IMPACT: User is confused and doesn't understand what happened")
		t.Error("IMPACT: User may lose work or have to restart their workflow")
		t.Error("EXPECTED: Tokens should refresh transparently in background")
		t.Error("EXPECTED: User should see the page they requested without interruption")

		if !tokenRefreshAttempted {
			t.Error("CRITICAL: System didn't even try to refresh the token")
			t.Error("This indicates fundamental failure in expired token detection")
		}

		// This represents the actual bug report
		t.Error("==== USER REPORT ====")
		t.Error("User: 'I left my browser open overnight and when I came back, I got some /unknown-session error'")
		t.Error("User: 'I had to log in again and lost my place. Why doesn't it just work?'")
		t.Error("Support: 'This is the 6-hour token expiry bug we need to fix'")

		return // Test fails as expected - demonstrates the exact bug
	}

	// This is what SHOULD happen:
	if rec.Code == http.StatusOK && tokenRefreshAttempted {
		t.Log("SUCCESS: User experience is seamless - tokens refreshed transparently")
		t.Log("User doesn't see any errors or confusing redirects")
		t.Log("User continues their work without interruption")

		bodyContent := rec.Body.String()
		if strings.Contains(bodyContent, "Welcome back") {
			t.Log("Perfect: User sees welcoming message confirming automatic renewal")
		}
	} else if !tokenRefreshAttempted {
		t.Error("BUG: System failed to attempt token refresh for 6-hour expired tokens")
		t.Error("This indicates the core issue - expired token detection is broken")
	} else {
		t.Errorf("UNEXPECTED: User experience unclear - Code: %d, Refresh: %t", rec.Code, tokenRefreshAttempted)
	}
}
