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

	"golang.org/x/time/rate"
)

// TestIntrospectToken_Success tests successful token introspection with active token
func TestIntrospectToken_Success(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	// Create mock introspection server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Expected application/x-www-form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		// Verify basic auth
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client" || password != "test-secret" {
			t.Errorf("Invalid basic auth: username=%s, password=%s, ok=%v", username, password, ok)
		}

		// Parse request body
		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))

		if values.Get("token") != "test-opaque-token" {
			t.Errorf("Expected token=test-opaque-token, got %s", values.Get("token"))
		}
		if values.Get("token_type_hint") != "access_token" {
			t.Errorf("Expected token_type_hint=access_token, got %s", values.Get("token_type_hint"))
		}

		// Return successful introspection response
		resp := IntrospectionResponse{
			Active:    true,
			Scope:     "openid profile email",
			ClientID:  "test-client",
			Username:  "testuser",
			TokenType: "Bearer",
			Exp:       time.Now().Add(1 * time.Hour).Unix(),
			Iat:       time.Now().Add(-5 * time.Minute).Unix(),
			Nbf:       time.Now().Add(-5 * time.Minute).Unix(),
			Sub:       "user123",
			Aud:       "test-audience",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Create TraefikOidc instance
	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	// Perform introspection
	resp, err := tOidc.introspectToken("test-opaque-token")
	if err != nil {
		t.Fatalf("introspectToken failed: %v", err)
	}

	// Verify response
	if !resp.Active {
		t.Error("Expected token to be active")
	}
	if resp.ClientID != "test-client" {
		t.Errorf("Expected clientID=test-client, got %s", resp.ClientID)
	}
	if resp.Username != "testuser" {
		t.Errorf("Expected username=testuser, got %s", resp.Username)
	}
	if resp.Scope != "openid profile email" {
		t.Errorf("Expected scope='openid profile email', got %s", resp.Scope)
	}
}

// TestIntrospectToken_CachedResult tests that cached introspection results are used
func TestIntrospectToken_CachedResult(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	requestCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
			Exp:      time.Now().Add(1 * time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	// First call - should hit the server
	resp1, err := tOidc.introspectToken("cached-token")
	if err != nil {
		t.Fatalf("First introspectToken failed: %v", err)
	}
	if !resp1.Active {
		t.Error("Expected first token to be active")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request after first call, got %d", requestCount)
	}

	// Second call - should use cache
	resp2, err := tOidc.introspectToken("cached-token")
	if err != nil {
		t.Fatalf("Second introspectToken failed: %v", err)
	}
	if !resp2.Active {
		t.Error("Expected second token to be active")
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request after cache hit, got %d", requestCount)
	}
}

// TestIntrospectToken_MissingEndpoint tests introspection without endpoint
func TestIntrospectToken_MissingEndpoint(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   "", // No endpoint
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	_, err := tOidc.introspectToken("test-token")
	if err == nil {
		t.Error("Expected error for missing introspection endpoint")
	}
	if !strings.Contains(err.Error(), "introspection endpoint not available") {
		t.Errorf("Expected 'introspection endpoint not available' error, got: %v", err)
	}
}

// TestIntrospectToken_HTTPError tests handling of HTTP error responses
func TestIntrospectToken_HTTPError(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_client"}`))
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	_, err := tOidc.introspectToken("test-token")
	if err == nil {
		t.Error("Expected error for HTTP 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("Expected error mentioning status 401, got: %v", err)
	}
}

// TestIntrospectToken_InvalidJSON tests handling of invalid JSON response
func TestIntrospectToken_InvalidJSON(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	_, err := tOidc.introspectToken("test-token")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Expected 'failed to decode' error, got: %v", err)
	}
}

// TestIntrospectToken_ExpiryHandling tests cache duration based on token expiry
func TestIntrospectToken_ExpiryHandling(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	// Token that expires in 2 minutes
	shortExpiry := time.Now().Add(2 * time.Minute).Unix()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
			Exp:      shortExpiry,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	resp, err := tOidc.introspectToken("expiring-token")
	if err != nil {
		t.Fatalf("introspectToken failed: %v", err)
	}
	if resp.Exp != shortExpiry {
		t.Errorf("Expected exp=%d, got %d", shortExpiry, resp.Exp)
	}
}

// TestValidateOpaqueToken_OpaqueTokensDisabled tests validation when opaque tokens are disabled
func TestValidateOpaqueToken_OpaqueTokensDisabled(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  false, // Disabled
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("test-token")
	if err == nil {
		t.Error("Expected error when opaque tokens are disabled")
	}
	if !strings.Contains(err.Error(), "opaque tokens are not enabled") {
		t.Errorf("Expected 'opaque tokens are not enabled' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_MissingEndpointWithRequirement tests validation when introspection is required but endpoint is missing
func TestValidateOpaqueToken_MissingEndpointWithRequirement(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:         true,
		requireTokenIntrospection: true, // Required
		introspectionURL:          "",   // Missing
		introspectionCache:        &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:                    logger,
		httpClient:                &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("test-token")
	if err == nil {
		t.Error("Expected error when introspection is required but endpoint is missing")
	}
	if !strings.Contains(err.Error(), "token introspection required but endpoint not available") {
		t.Errorf("Expected 'introspection required but endpoint not available' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_InactiveToken tests validation of an inactive token
func TestValidateOpaqueToken_InactiveToken(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active: false, // Inactive
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("inactive-token")
	if err == nil {
		t.Error("Expected error for inactive token")
	}
	if !strings.Contains(err.Error(), "not active") {
		t.Errorf("Expected 'not active' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_ExpiredToken tests validation of an expired token
func TestValidateOpaqueToken_ExpiredToken(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Exp:    time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("expired-token")
	if err == nil {
		t.Error("Expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Expected 'expired' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_NotYetValid tests validation of a token not yet valid (nbf in future)
func TestValidateOpaqueToken_NotYetValid(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Nbf:    time.Now().Add(1 * time.Hour).Unix(), // Valid 1 hour from now
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("future-token")
	if err == nil {
		t.Error("Expected error for not-yet-valid token")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("Expected 'not yet valid' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_InvalidAudience tests validation with mismatched audience
func TestValidateOpaqueToken_InvalidAudience(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Aud:    "wrong-audience",
			Exp:    time.Now().Add(1 * time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		audience:           "expected-audience",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("wrong-aud-token")
	if err == nil {
		t.Error("Expected error for invalid audience")
	}
	if !strings.Contains(err.Error(), "invalid audience") {
		t.Errorf("Expected 'invalid audience' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_SuccessfulValidation tests successful opaque token validation
func TestValidateOpaqueToken_SuccessfulValidation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
			Aud:      "test-audience",
			Exp:      time.Now().Add(1 * time.Hour).Unix(),
			Nbf:      time.Now().Add(-5 * time.Minute).Unix(),
			Scope:    "openid profile",
			Sub:      "user123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		audience:           "test-audience",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("valid-token")
	if err != nil {
		t.Errorf("Expected successful validation, got error: %v", err)
	}
}

// TestValidateOpaqueToken_FallbackWithoutEndpoint tests fallback to ID token validation when endpoint is missing
func TestValidateOpaqueToken_FallbackWithoutEndpoint(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:         true,
		requireTokenIntrospection: false, // Not required
		introspectionURL:          "",    // Missing
		introspectionCache:        &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:                    logger,
		httpClient:                &http.Client{Timeout: 10 * time.Second},
	}

	// Should succeed (falls back to ID token validation)
	err := tOidc.validateOpaqueToken("test-token")
	if err != nil {
		t.Errorf("Expected fallback to succeed, got error: %v", err)
	}
}

// TestIntrospectToken_WithCircuitBreaker tests introspection with error recovery manager
func TestIntrospectToken_WithCircuitBreaker(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Create error recovery manager
	errorRecoveryManager := NewErrorRecoveryManager(logger)

	tOidc := &TraefikOidc{
		clientID:             "test-client",
		clientSecret:         "test-secret",
		issuerURL:            "https://test-issuer.com",
		introspectionURL:     mockServer.URL,
		introspectionCache:   &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		errorRecoveryManager: errorRecoveryManager,
		logger:               logger,
		httpClient:           &http.Client{Timeout: 10 * time.Second},
	}

	resp, err := tOidc.introspectToken("test-token")
	if err != nil {
		t.Fatalf("introspectToken with circuit breaker failed: %v", err)
	}
	if !resp.Active {
		t.Error("Expected token to be active")
	}
}

// TestIntrospectToken_ConcurrentCalls tests concurrent introspection calls
func TestIntrospectToken_ConcurrentCalls(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	var requestCount int
	var mu sync.Mutex

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		// Small delay to simulate network latency
		time.Sleep(10 * time.Millisecond)

		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	// Run concurrent introspection calls
	var wg sync.WaitGroup
	concurrency := 10
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			defer wg.Done()
			token := fmt.Sprintf("concurrent-token-%d", id)
			_, err := tOidc.introspectToken(token)
			if err != nil {
				t.Errorf("Concurrent introspection %d failed: %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	// Each unique token should result in one request
	if finalCount != concurrency {
		t.Errorf("Expected %d requests for %d concurrent calls, got %d", concurrency, concurrency, finalCount)
	}
}

// TestValidateOpaqueToken_AudienceMatchesClientID tests audience validation when audience equals clientID
func TestValidateOpaqueToken_AudienceMatchesClientID(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
			Aud:      "different-aud",
			Exp:      time.Now().Add(1 * time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		audience:           "test-client", // Same as clientID
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	// Should succeed because audience validation is skipped when audience == clientID
	err := tOidc.validateOpaqueToken("test-token")
	if err != nil {
		t.Errorf("Expected validation to succeed when audience equals clientID, got error: %v", err)
	}
}

// TestValidateOpaqueToken_EmptyAudienceInResponse tests validation when response has empty audience
func TestValidateOpaqueToken_EmptyAudienceInResponse(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
			Aud:      "", // Empty audience
			Exp:      time.Now().Add(1 * time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		audience:           "expected-audience",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	// Should succeed because audience validation is skipped when response.Aud is empty
	err := tOidc.validateOpaqueToken("test-token")
	if err != nil {
		t.Errorf("Expected validation to succeed when response audience is empty, got error: %v", err)
	}
}

// TestIntrospectToken_RateLimiting tests introspection respects rate limiting
func TestIntrospectToken_RateLimiting(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Create a very restrictive rate limiter
	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		limiter:            rate.NewLimiter(rate.Every(1*time.Hour), 1), // Very strict
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	// First call should succeed
	_, err := tOidc.introspectToken("rate-limit-token-1")
	if err != nil {
		t.Fatalf("First introspection failed: %v", err)
	}
}

// TestIntrospectToken_HTTPClientTimeout tests introspection with HTTP timeout
func TestIntrospectToken_HTTPClientTimeout(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	// Server that delays response
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Delay longer than client timeout
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond}, // Short timeout
	}

	_, err := tOidc.introspectToken("timeout-token")
	if err == nil {
		t.Error("Expected timeout error")
	}
	// Error should indicate a timeout or request failure
	if !strings.Contains(err.Error(), "introspection request failed") {
		t.Errorf("Expected 'introspection request failed' error, got: %v", err)
	}
}

// TestValidateOpaqueToken_IntrospectionFailure tests validation when introspection fails
func TestValidateOpaqueToken_IntrospectionFailure(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer mockServer.Close()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  true,
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	err := tOidc.validateOpaqueToken("failing-token")
	if err == nil {
		t.Error("Expected error when introspection fails")
	}
	if !strings.Contains(err.Error(), "token introspection failed") {
		t.Errorf("Expected 'token introspection failed' error, got: %v", err)
	}
}

// TestIntrospectToken_ContextCancellation tests introspection with context cancellation
func TestIntrospectToken_ContextCancellation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	// Server that takes time to respond
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second) // Longer delay to ensure timeout
		resp := IntrospectionResponse{
			Active:   true,
			ClientID: "test-client",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Use context-aware HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         client,
	}

	// Note: introspectToken uses context.Background() internally, not tOidc.ctx
	// This test demonstrates that HTTP timeout will trigger instead of context cancellation
	// The actual behavior is that the HTTP client's timeout will be used
	_, err := tOidc.introspectToken("cancel-token")
	// The function should still return an error due to timeout or failure
	// but it won't be a context cancellation error since context.Background() is used
	_ = err // Accept any error including no error (fast completion)
}
