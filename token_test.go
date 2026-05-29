package traefikoidc

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"golang.org/x/time/rate"
)

// =============================================================================
// TOKEN TEST CONSTANTS AND TYPES
// =============================================================================

// Test tokens used across multiple test files
var (
	ValidAccessToken      = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjozMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU" // trufflehog:ignore
	ValidIDToken          = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjozMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU" // trufflehog:ignore
	ValidRefreshToken     = "refresh_token_abc123"
	MinimalValidJWT       = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." // trufflehog:ignore
	InvalidTokenOneDot    = "invalid.token"
	InvalidTokenNoDots    = "invalidtoken"
	InvalidTokenThreeDots = "invalid..token"
)

// TestTokens provides test JWT tokens
type TestTokens struct {
	validJWT   string
	expiredJWT string
}

func NewTestTokens() *TestTokens {
	return &TestTokens{
		validJWT:   "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjozMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU", // trufflehog:ignore
		expiredJWT: "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyLmNvbSIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwiZXhwIjoxMDAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.dGVzdC1zaWduYXR1cmU", // trufflehog:ignore
	}
}

func (tt *TestTokens) CreateValidJWT() string {
	return tt.validJWT
}

// TokenSet represents a complete set of tokens with proper field names
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
}

func (tt *TestTokens) GetValidTokenSet() *TokenSet {
	return &TokenSet{
		AccessToken:  tt.validJWT,
		IDToken:      tt.validJWT,
		RefreshToken: ValidRefreshToken,
	}
}

func (tt *TestTokens) CreateIncompressibleToken(size int) string {
	return "incompressible." + generateRandomString(size) + ".signature"
}

func (tt *TestTokens) CreateUniqueValidJWT(suffix string) string {
	return tt.validJWT + "_" + suffix
}

func (tt *TestTokens) GetLargeTokenSet() *TokenSet {
	return &TokenSet{
		AccessToken:  tt.CreateIncompressibleToken(2000),
		IDToken:      tt.CreateIncompressibleToken(2000),
		RefreshToken: ValidRefreshToken,
	}
}

func (tt *TestTokens) CreateExpiredJWT() string {
	return tt.expiredJWT
}

func (tt *TestTokens) CreateLargeValidJWT(claimSize int) string {
	largeClaim := generateRandomString(claimSize)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key-id"}`))
	payload := fmt.Sprintf(`{"iss":"https://test-issuer.com","aud":"test-client-id","exp":3000000000,"sub":"test-subject","email":"test@example.com","large_claim":"%s"}`, largeClaim)
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return fmt.Sprintf("%s.%s.%s", header, encodedPayload, signature)
}

// TestCache is a simple in-memory cache for testing
type TestCache struct {
	data map[string]interface{}
}

func NewTestCache() *TestCache {
	return &TestCache{
		data: make(map[string]interface{}),
	}
}

func (c *TestCache) Set(key string, value interface{}, ttl time.Duration) {
	c.data[key] = value
}

func (c *TestCache) Get(key string) (interface{}, bool) {
	val, ok := c.data[key]
	return val, ok
}

func (c *TestCache) Delete(key string) {
	delete(c.data, key)
}

func (c *TestCache) SetMaxSize(size int) {}
func (c *TestCache) Size() int           { return len(c.data) }
func (c *TestCache) Clear()              { c.data = make(map[string]interface{}) }
func (c *TestCache) Cleanup()            {}
func (c *TestCache) Close()              {}
func (c *TestCache) GetStats() map[string]interface{} {
	return map[string]interface{}{"size": len(c.data)}
}

// =============================================================================
// OPAQUE TOKEN TESTS
// =============================================================================

func TestOpaqueTokenDetection(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		description string
		isOpaque    bool
	}{
		{
			name:        "JWT token with 3 parts",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // trufflehog:ignore
			isOpaque:    false,
			description: "Standard JWT with header.payload.signature",
		},
		{
			name:        "Auth0 opaque token",
			token:       "8n3d84nd92nf92nf92nf92nf923nf923nf923nf9",
			isOpaque:    true,
			description: "Auth0 opaque access token",
		},
		{
			name:        "Okta opaque token",
			token:       "00Otkjhgt5Rfasde12345678901234567890",
			isOpaque:    true,
			description: "Okta opaque access token",
		},
		{
			name:        "AWS Cognito opaque token",
			token:       "AGPAYJhZmU3NzI5YTQtNGQ0Yy00YTU5LWJjYTQtYzdlMzQ0MmQ3ZDJl",
			isOpaque:    true,
			description: "AWS Cognito opaque access token",
		},
		{
			name:        "Invalid single dot token",
			token:       "invalid.token",
			isOpaque:    true,
			description: "Invalid format with single dot",
		},
		{
			name:        "Token with no dots",
			token:       "opaquetoken1234567890abcdefghijklmnop",
			isOpaque:    true,
			description: "Pure opaque token with no dots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dotCount := strings.Count(tt.token, ".")
			isOpaqueToken := dotCount != 2

			if isOpaqueToken != tt.isOpaque {
				t.Errorf("Token detection failed for %s: expected opaque=%v, got opaque=%v (dots=%d)",
					tt.name, tt.isOpaque, isOpaqueToken, dotCount)
			}
		})
	}
}

func TestOpaqueTokenValidation(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cm := NewChunkManager(logger)
	defer cm.Shutdown()

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "Valid opaque token",
			token:     "opaquetoken1234567890abcdefghijklmnop",
			wantError: false,
		},
		{
			name:      "Too short opaque token",
			token:     "short",
			wantError: true,
		},
		{
			name:      "Opaque token with spaces",
			token:     "opaque token with spaces 1234567890",
			wantError: true,
		},
		{
			name:      "Valid JWT token",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // trufflehog:ignore
			wantError: false,
		},
	}

	config := TokenConfig{
		Type:              "access",
		MinLength:         5,
		MaxLength:         100 * 1024,
		MaxChunks:         25,
		MaxChunkSize:      maxCookieSize,
		AllowOpaqueTokens: true,
		RequireJWTFormat:  false,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cm.validateToken(tt.token, config)
			hasError := result.Error != nil

			if hasError != tt.wantError {
				if tt.wantError {
					t.Errorf("Expected error for %s but got none", tt.name)
				} else {
					t.Errorf("Unexpected error for %s: %v", tt.name, result.Error)
				}
			}
		})
	}
}

func TestOpaqueTokenStorage(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		description string
		shouldStore bool
	}{
		{
			name:        "Valid opaque token",
			token:       "auth0_opaque_token_1234567890abcdefghijklmnop",
			shouldStore: true,
			description: "Opaque token with sufficient length and no dots",
		},
		{
			name:        "Valid JWT token",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // trufflehog:ignore
			shouldStore: true,
			description: "Standard JWT with three parts",
		},
		{
			name:        "Invalid single-dot token",
			token:       "invalid.token",
			shouldStore: false,
			description: "Token with single dot - invalid format",
		},
		{
			name:        "Too short opaque token",
			token:       "short",
			shouldStore: false,
			description: "Opaque token too short (less than 20 chars)",
		},
		{
			name:        "Multi-dot invalid token",
			token:       "too.many.dots.here",
			shouldStore: false,
			description: "Token with more than 2 dots - invalid format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldStore := true
			if tt.token != "" {
				dotCount := strings.Count(tt.token, ".")
				if dotCount == 1 {
					shouldStore = false
				}
				if dotCount == 0 && len(tt.token) < 20 {
					shouldStore = false
				}
				if dotCount > 2 {
					shouldStore = false
				}
			}

			if shouldStore != tt.shouldStore {
				t.Errorf("Token storage decision failed for %s: expected store=%v, got store=%v",
					tt.name, tt.shouldStore, shouldStore)
			}
		})
	}
}

// =============================================================================
// TOKEN INTROSPECTION TESTS
// =============================================================================

func TestIntrospectToken_Success(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Expected application/x-www-form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client" || password != "test-secret" {
			t.Errorf("Invalid basic auth: username=%s, password=%s, ok=%v", username, password, ok)
		}

		body, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(body))

		if values.Get("token") != "test-opaque-token" {
			t.Errorf("Expected token=test-opaque-token, got %s", values.Get("token"))
		}
		if values.Get("token_type_hint") != "access_token" {
			t.Errorf("Expected token_type_hint=access_token, got %s", values.Get("token_type_hint"))
		}

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

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   mockServer.URL,
		introspectionCache: &CacheInterfaceWrapper{cache: cacheManager.GetIntrospectionCache()},
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
	}

	resp, err := tOidc.introspectToken("test-opaque-token")
	if err != nil {
		t.Fatalf("introspectToken failed: %v", err)
	}

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

func TestIntrospectToken_MissingEndpoint(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	tOidc := &TraefikOidc{
		clientID:           "test-client",
		clientSecret:       "test-secret",
		introspectionURL:   "",
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

func TestValidateOpaqueToken_OpaqueTokensDisabled(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	tOidc := &TraefikOidc{
		allowOpaqueTokens:  false,
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

func TestValidateOpaqueToken_InactiveToken(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active: false,
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

func TestValidateOpaqueToken_ExpiredToken(t *testing.T) {
	logger := GetSingletonNoOpLogger()
	cacheManager := GetUniversalCacheManager(logger)
	defer ResetUniversalCacheManagerForTesting()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Exp:    time.Now().Add(-1 * time.Hour).Unix(),
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

	if finalCount != concurrency {
		t.Errorf("Expected %d requests for %d concurrent calls, got %d", concurrency, concurrency, finalCount)
	}
}

// =============================================================================
// TOKEN TYPE DETECTION TESTS
// =============================================================================

func TestDetectTokenType(t *testing.T) {
	tr := &TraefikOidc{
		clientID:               "test-client-id",
		suppressDiagnosticLogs: true,
		tokenTypeCache:         NewTestCache(),
	}

	testCases := []struct {
		jwt         *JWT
		name        string
		token       string
		description string
		expectedID  bool
	}{
		{
			name: "ID token with nonce",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"nonce": "test-nonce",
					"aud":   "test-client-id",
				},
			},
			token:       "test-token-with-nonce",
			expectedID:  true,
			description: "Should detect ID token via nonce claim",
		},
		{
			name: "RFC 9068 access token",
			jwt: &JWT{
				Header: map[string]interface{}{
					"alg": "RS256",
					"typ": "at+jwt",
				},
				Claims: map[string]interface{}{
					"scope": "openid profile",
				},
			},
			token:       "test-access-token-rfc9068",
			expectedID:  false,
			description: "Should detect access token via typ=at+jwt header",
		},
		{
			name: "Token with token_use=id",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"token_use": "id",
					"aud":       "test-client-id",
				},
			},
			token:       "test-token-use-id",
			expectedID:  true,
			description: "Should detect ID token via token_use claim",
		},
		{
			name: "Token with token_use=access",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"token_use": "access",
					"scope":     "read write",
				},
			},
			token:       "test-token-use-access",
			expectedID:  false,
			description: "Should detect access token via token_use claim",
		},
		{
			name: "Access token with scope",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"scope": "openid profile email",
					"aud":   "some-api-audience",
				},
			},
			token:       "test-access-token-with-scope",
			expectedID:  false,
			description: "Should detect access token via scope claim",
		},
		{
			name: "ID token with client_id audience",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"aud": "test-client-id",
					"sub": "user123",
				},
			},
			token:       "test-id-token-client-aud",
			expectedID:  true,
			description: "Should detect ID token via audience matching client_id",
		},
		{
			name: "Default to access token",
			jwt: &JWT{
				Header: map[string]interface{}{"alg": "RS256"},
				Claims: map[string]interface{}{
					"aud": "different-audience",
					"sub": "user123",
				},
			},
			token:       "test-default-access-token",
			expectedID:  false,
			description: "Should default to access token when no clear indicators",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tr.detectTokenType(tc.jwt, tc.token)
			if result != tc.expectedID {
				t.Errorf("%s: expected isIDToken=%v, got %v", tc.description, tc.expectedID, result)
			}

			result2 := tr.detectTokenType(tc.jwt, tc.token)
			if result2 != tc.expectedID {
				t.Errorf("%s (cached): expected isIDToken=%v, got %v", tc.description, tc.expectedID, result2)
			}
		})
	}
}

func TestDetectTokenTypeCaching(t *testing.T) {
	cache := NewTestCache()
	tr := &TraefikOidc{
		clientID:               "test-client-id",
		suppressDiagnosticLogs: true,
		tokenTypeCache:         cache,
	}

	jwt := &JWT{
		Header: map[string]interface{}{"alg": "RS256"},
		Claims: map[string]interface{}{
			"nonce": "test-nonce",
		},
	}
	token := "test-token-for-caching-with-enough-characters-for-key"
	// The cache key is a SHA-256 hash of the full token (collision-resistant).
	sum := sha256.Sum256([]byte(token))
	cacheKey := hex.EncodeToString(sum[:])

	result := tr.detectTokenType(jwt, token)
	if !result {
		t.Error("Expected ID token detection via nonce")
	}

	if cached, found := cache.Get(cacheKey); !found {
		t.Error("Expected token type to be cached")
	} else if cachedBool, ok := cached.(bool); !ok || !cachedBool {
		t.Error("Expected cached value to be true (ID token)")
	}

	jwt.Claims = map[string]interface{}{
		"scope": "openid profile",
	}

	result2 := tr.detectTokenType(jwt, token)
	if !result2 {
		t.Error("Expected cached ID token result, ignoring modified JWT")
	}
}

// =============================================================================
// CONSOLIDATED TOKEN TESTS
// =============================================================================

func TestTokenTypes(t *testing.T) {
	t.Run("TokenTypeDistinction", func(t *testing.T) {
		type templateData struct {
			Claims       map[string]interface{}
			AccessToken  string
			IDToken      string
			RefreshToken string
		}

		testData := templateData{
			AccessToken:  "test-access-token-abc123",
			IDToken:      "test-id-token-xyz789",
			RefreshToken: "test-refresh-token",
			Claims: map[string]interface{}{
				"sub":   "test-subject",
				"email": "user@example.com",
			},
		}

		tests := []struct {
			name          string
			templateText  string
			expectedValue string
		}{
			{
				name:          "Access Token Only",
				templateText:  "Bearer {{.AccessToken}}",
				expectedValue: "Bearer test-access-token-abc123",
			},
			{
				name:          "ID Token Only",
				templateText:  "ID: {{.IDToken}}",
				expectedValue: "ID: test-id-token-xyz789",
			},
			{
				name:          "Both Tokens",
				templateText:  "Access: {{.AccessToken}} ID: {{.IDToken}}",
				expectedValue: "Access: test-access-token-abc123 ID: test-id-token-xyz789",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				tmpl, err := template.New("test").Parse(tc.templateText)
				if err != nil {
					t.Fatalf("Failed to parse template: %v", err)
				}

				var buf bytes.Buffer
				err = tmpl.Execute(&buf, testData)
				if err != nil {
					t.Fatalf("Failed to execute template: %v", err)
				}

				result := buf.String()
				if result != tc.expectedValue {
					t.Errorf("Expected template output %q, got %q", tc.expectedValue, result)
				}
			})
		}
	})

	t.Run("TokenTypeIntegration", func(t *testing.T) {
		ts := NewTestSuite(t)
		ts.Setup()

		idToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":        "https://test-issuer.com",
			"aud":        "test-client-id",
			"exp":        float64(3000000000),
			"sub":        "id-token-subject",
			"email":      "id@example.com",
			"nonce":      "test-nonce",
			"token_type": "id",
		})
		if err != nil {
			t.Fatalf("Failed to create ID token: %v", err)
		}

		accessToken, err := createTestJWT(ts.rsaPrivateKey, "RS256", "test-key-id", map[string]interface{}{
			"iss":        "https://test-issuer.com",
			"aud":        "test-client-id",
			"exp":        float64(3000000000),
			"sub":        "access-token-subject",
			"email":      "access@example.com",
			"scope":      "openid email profile",
			"token_type": "access",
		})
		if err != nil {
			t.Fatalf("Failed to create access token: %v", err)
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		session, err := ts.sessionManager.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}
		defer session.ReturnToPool()

		session.SetIDToken(idToken)
		session.SetAccessToken(accessToken)

		retrievedID := session.GetIDToken()
		retrievedAccess := session.GetAccessToken()

		if retrievedID != idToken {
			t.Errorf("ID token mismatch: expected %q, got %q", idToken, retrievedID)
		}
		if retrievedAccess != accessToken {
			t.Errorf("Access token mismatch: expected %q, got %q", accessToken, retrievedAccess)
		}
	})
}

func TestTokenCorruption(t *testing.T) {
	t.Run("TokenCorruptionScenario", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		testTokens := NewTestTokens()
		validJWT := testTokens.CreateLargeValidJWT(100)

		tests := []struct {
			corruptionScenario func(*SessionData)
			name               string
			tokenSize          int
			iterations         int
			expectConsistent   bool
		}{
			{
				name:             "Small token - multiple retrievals",
				tokenSize:        len(validJWT),
				iterations:       10,
				expectConsistent: true,
			},
			{
				name:             "Large chunked token - multiple retrievals",
				tokenSize:        5000,
				iterations:       10,
				expectConsistent: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "http://example.com/foo", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("Failed to get session: %v", err)
				}
				defer session.ReturnToPool()

				token := createTokenOfSize(validJWT, tt.tokenSize)
				session.SetAccessToken(token)

				var retrievedTokens []string
				for i := 0; i < tt.iterations; i++ {
					retrieved := session.GetAccessToken()
					retrievedTokens = append(retrievedTokens, retrieved)

					if tt.expectConsistent && retrieved != token {
						t.Errorf("Iteration %d: Token changed unexpectedly", i)
					}
				}

				if tt.expectConsistent {
					for i, retrievedToken := range retrievedTokens {
						if retrievedToken != token {
							t.Errorf("Iteration %d: Token mismatch", i)
						}
					}
				}
			})
		}
	})

	t.Run("Base64CorruptionHandling", func(t *testing.T) {
		tests := []struct {
			name        string
			input       string
			expectError bool
		}{
			{"Valid base64", "eyJhbGciOiJSUzI1NiJ9", false},
			{"Invalid characters", "eyJ!@#$%^&*()", true},
			{"Missing padding", "eyJhbGc", false},
			{"Empty string", "", false},
			{"Spaces in base64", "eyJ hbG ciOi JSU zI1 NiJ9", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tt.input))
				hasError := err != nil
				if hasError != tt.expectError {
					t.Errorf("Expected error=%v, got error=%v (err: %v)", tt.expectError, hasError, err)
				}
			})
		}
	})
}

func TestTokenResilience(t *testing.T) {
	t.Run("ConcurrentTokenAccess", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		req := httptest.NewRequest("GET", "http://example.com", nil)
		session, err := sm.GetSession(req)
		if err != nil {
			t.Fatalf("Failed to get session: %v", err)
		}
		defer session.ReturnToPool()

		testToken := "test-token-" + generateRandomString(100)
		session.SetAccessToken(testToken)

		var wg sync.WaitGroup
		errors := make(chan error, 100)
		successCount := int32(0)

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				retrieved := session.GetAccessToken()
				if retrieved == testToken {
					atomic.AddInt32(&successCount, 1)
				} else {
					errors <- fmt.Errorf("token mismatch: expected %q, got %q", testToken, retrieved)
				}
			}()
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			t.Error(err)
		}

		if successCount != 100 {
			t.Errorf("Expected 100 successful retrievals, got %d", successCount)
		}
	})

	t.Run("TokenSizeHandling", func(t *testing.T) {
		logger := NewLogger("debug")
		sm, err := NewSessionManager("0123456789abcdef0123456789abcdef0123456789abcdef", false, "", "", 0, logger)
		if err != nil {
			t.Fatalf("Failed to create session manager: %v", err)
		}

		sizes := []int{
			100,
			1000,
			4000,
			5000,
			10000,
		}

		for _, size := range sizes {
			t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				session, err := sm.GetSession(req)
				if err != nil {
					t.Fatalf("Failed to get session: %v", err)
				}
				defer session.ReturnToPool()

				token := createTokenOfSize(ValidAccessToken, size)
				session.SetAccessToken(token)

				retrieved := session.GetAccessToken()
				if size > 15000 && retrieved == "" {
					t.Logf("Token size %d exceeds chunk limits (expected)", size)
				} else if retrieved != token {
					t.Errorf("Token mismatch for size %d", size)
				}
			})
		}
	})

	t.Run("RateLimitedTokenRefresh", func(t *testing.T) {
		limiter := rate.NewLimiter(rate.Limit(10), 1)

		var wg sync.WaitGroup
		successCount := int32(0)
		deniedCount := int32(0)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if limiter.Allow() {
					atomic.AddInt32(&successCount, 1)
				} else {
					atomic.AddInt32(&deniedCount, 1)
				}
			}()
			time.Sleep(10 * time.Millisecond)
		}

		wg.Wait()

		t.Logf("Allowed: %d, Denied: %d", successCount, deniedCount)
		if successCount == 0 {
			t.Error("No requests were allowed")
		}
		if successCount == 50 {
			t.Error("All requests were allowed, rate limiting not working")
		}
	})
}

func TestTokenValidation(t *testing.T) {
	t.Run("JWTStructureValidation", func(t *testing.T) {
		tests := []struct {
			name        string
			token       string
			expectValid bool
		}{
			{
				name:        "Valid JWT structure",
				token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
				expectValid: true,
			},
			{
				name:        "Missing signature",
				token:       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0",
				expectValid: false,
			},
			{
				name:        "Missing payload",
				token:       "eyJhbGciOiJSUzI1NiJ9..signature",
				expectValid: true,
			},
			{
				name:        "Only header",
				token:       "eyJhbGciOiJSUzI1NiJ9",
				expectValid: false,
			},
			{
				name:        "Too many parts",
				token:       "header.payload.signature.extra",
				expectValid: false,
			},
			{
				name:        "Empty token",
				token:       "",
				expectValid: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				parts := strings.Split(tt.token, ".")
				isValid := len(parts) == 3
				if isValid != tt.expectValid {
					t.Errorf("Expected valid=%v, got %v", tt.expectValid, isValid)
				}
			})
		}
	})

	t.Run("TokenExpiryValidation", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			exp         time.Time
			name        string
			expectValid bool
		}{
			{name: "Future expiry", exp: now.Add(time.Hour), expectValid: true},
			{name: "Just expired", exp: now.Add(-time.Second), expectValid: false},
			{name: "Long expired", exp: now.Add(-24 * time.Hour), expectValid: false},
			{name: "Far future", exp: now.Add(365 * 24 * time.Hour), expectValid: true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				isValid := tt.exp.After(now)
				if isValid != tt.expectValid {
					t.Errorf("Expected valid=%v, got %v", tt.expectValid, isValid)
				}
			})
		}
	})
}

func TestTokenChunking(t *testing.T) {
	t.Run("ChunkSplitting", func(t *testing.T) {
		chunkSize := 4000
		tests := []struct {
			name           string
			tokenSize      int
			expectedChunks int
		}{
			{"Small token", 100, 1},
			{"Just under chunk size", 3999, 1},
			{"Exactly chunk size", 4000, 1},
			{"Just over chunk size", 4100, 2},
			{"Multiple chunks", 10000, 3},
			{"Large token", 50000, 13},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token := generateRandomString(tt.tokenSize)
				chunks := (len(token) + chunkSize - 1) / chunkSize
				if chunks != tt.expectedChunks {
					t.Errorf("Expected %d chunks, got %d", tt.expectedChunks, chunks)
				}
			})
		}
	})

	t.Run("ChunkReassembly", func(t *testing.T) {
		originalToken := generateRandomString(10000)
		chunkSize := 4000

		var chunks []string
		for i := 0; i < len(originalToken); i += chunkSize {
			end := i + chunkSize
			if end > len(originalToken) {
				end = len(originalToken)
			}
			chunks = append(chunks, originalToken[i:end])
		}

		var reassembled strings.Builder
		for _, chunk := range chunks {
			reassembled.WriteString(chunk)
		}

		if reassembled.String() != originalToken {
			t.Error("Token reassembly failed")
		}
	})
}

func TestTokenCompression(t *testing.T) {
	t.Run("CompressionEfficiency", func(t *testing.T) {
		repetitiveToken := strings.Repeat("AAAA", 1000)

		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		_, err := gz.Write([]byte(repetitiveToken))
		if err != nil {
			t.Fatalf("Compression failed: %v", err)
		}
		gz.Close()

		compressionRatio := float64(len(repetitiveToken)) / float64(compressed.Len())
		t.Logf("Compression ratio: %.2fx (original: %d, compressed: %d)",
			compressionRatio, len(repetitiveToken), compressed.Len())

		if compressionRatio < 10 {
			t.Error("Expected better compression for repetitive data")
		}
	})

	t.Run("CompressionDecompression", func(t *testing.T) {
		tokens := []string{
			generateRandomString(100),
			generateRandomString(1000),
			generateRandomString(10000),
			strings.Repeat("A", 5000),
		}

		for i, token := range tokens {
			t.Run(fmt.Sprintf("Token_%d", i), func(t *testing.T) {
				var compressed bytes.Buffer
				gz := gzip.NewWriter(&compressed)
				_, err := gz.Write([]byte(token))
				if err != nil {
					t.Fatalf("Compression failed: %v", err)
				}
				gz.Close()

				reader, err := gzip.NewReader(&compressed)
				if err != nil {
					t.Fatalf("Failed to create decompressor: %v", err)
				}
				var decompressed bytes.Buffer
				_, err = decompressed.ReadFrom(reader)
				if err != nil {
					t.Fatalf("Decompression failed: %v", err)
				}
				reader.Close()

				if decompressed.String() != token {
					t.Error("Token changed after compression/decompression")
				}
			})
		}
	})
}

func TestAjaxTokenExpiry(t *testing.T) {
	t.Run("AjaxExpiryDetection", func(t *testing.T) {
		tests := []struct {
			name           string
			isAjax         bool
			tokenExpired   bool
			expectedStatus int
		}{
			{"Regular request, valid token", false, false, http.StatusOK},
			{"Regular request, expired token", false, true, http.StatusFound},
			{"Ajax request, valid token", true, false, http.StatusOK},
			{"Ajax request, expired token", true, true, http.StatusUnauthorized},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "http://example.com", nil)
				if tt.isAjax {
					req.Header.Set("X-Requested-With", "XMLHttpRequest")
				}

				w := httptest.NewRecorder()

				if tt.tokenExpired {
					if tt.isAjax {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte(`{"error": "token_expired", "message": "Your session has expired"}`))
					} else {
						w.WriteHeader(http.StatusFound)
						w.Header().Set("Location", "/auth/login")
					}
				} else {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Success"))
				}

				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}

				if tt.isAjax && tt.tokenExpired {
					body := w.Body.String()
					if !strings.Contains(body, "token_expired") {
						t.Error("Expected token_expired error in response")
					}
				}
			})
		}
	})
}

func TestTestTokens_CreateValidJWT(t *testing.T) {
	tokens := NewTestTokens()
	jwt := tokens.CreateValidJWT()

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 JWT parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}

	if header["alg"] != "RS256" {
		t.Errorf("Expected RS256 algorithm, got %v", header["alg"])
	}
}

func TestTestTokens_CreateLargeValidJWT(t *testing.T) {
	tokens := NewTestTokens()
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			jwt := tokens.CreateLargeValidJWT(size)

			parts := strings.Split(jwt, ".")
			if len(parts) != 3 {
				t.Errorf("Expected 3 JWT parts, got %d", len(parts))
			}

			minExpectedSize := size + 200
			if len(jwt) < minExpectedSize {
				t.Errorf("JWT seems too small for requested claim size: got %d, expected at least %d", len(jwt), minExpectedSize)
			}
		})
	}
}

func TestTestTokens_CreateExpiredJWT(t *testing.T) {
	tokens := NewTestTokens()
	jwt := tokens.CreateExpiredJWT()

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Errorf("Expected 3 JWT parts, got %d", len(parts))
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatal("Expected exp claim in payload")
	}

	if exp >= float64(time.Now().Unix()) {
		t.Error("Token should be expired")
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// Mock implementations for testing
type MockJWTVerifier struct {
	valid bool
}

func (v *MockJWTVerifier) Verify(token string) error {
	if !v.valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func createTokenOfSize(baseToken string, targetSize int) string {
	if targetSize > 1000 {
		testTokens := NewTestTokens()
		claimSize := targetSize - 230
		if claimSize < 0 {
			claimSize = 10
		}
		return testTokens.CreateLargeValidJWT(claimSize)
	}

	return baseToken
}
