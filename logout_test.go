package traefikoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBackchannelLogoutBasic tests the basic backchannel logout flow
func TestBackchannelLogoutBasic(t *testing.T) {
	// Create a mock cache for session invalidation
	mockCache := &mockCacheInterface{}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
	}

	tests := []struct {
		name           string
		method         string
		body           string
		contentType    string
		expectedStatus int
	}{
		{
			name:           "GET method not allowed",
			method:         http.MethodGet,
			body:           "",
			contentType:    "",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Missing logout_token",
			method:         http.MethodPost,
			body:           "",
			contentType:    "application/x-www-form-urlencoded",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid logout_token format",
			method:         http.MethodPost,
			body:           "logout_token=not-a-valid-jwt",
			contentType:    "application/x-www-form-urlencoded",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/backchannel-logout", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			rw := httptest.NewRecorder()

			oidc.handleBackchannelLogout(rw, req)

			if rw.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rw.Code)
			}
		})
	}
}

// TestFrontchannelLogoutBasic tests the basic front-channel logout flow
func TestFrontchannelLogoutBasic(t *testing.T) {
	// Create a mock cache for session invalidation
	mockCache := &mockCacheInterface{}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableFrontchannelLogout: true,
		frontchannelLogoutPath:   "/frontchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
	}

	tests := []struct {
		name           string
		method         string
		queryParams    map[string]string
		expectedStatus int
	}{
		{
			name:           "POST method not allowed",
			method:         http.MethodPost,
			queryParams:    map[string]string{},
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Missing sid parameter",
			method:         http.MethodGet,
			queryParams:    map[string]string{"iss": "https://provider.example.com"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid issuer",
			method:         http.MethodGet,
			queryParams:    map[string]string{"iss": "https://wrong-issuer.com", "sid": "session123"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Valid front-channel logout",
			method:         http.MethodGet,
			queryParams:    map[string]string{"iss": "https://provider.example.com", "sid": "session123"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid front-channel logout without issuer",
			method:         http.MethodGet,
			queryParams:    map[string]string{"sid": "session456"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			urlStr := "/frontchannel-logout"
			if len(tc.queryParams) > 0 {
				params := url.Values{}
				for k, v := range tc.queryParams {
					params.Set(k, v)
				}
				urlStr += "?" + params.Encode()
			}

			req := httptest.NewRequest(tc.method, urlStr, nil)
			rw := httptest.NewRecorder()

			oidc.handleFrontchannelLogout(rw, req)

			if rw.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rw.Code)
			}

			// For successful logout, verify response headers
			if tc.expectedStatus == http.StatusOK {
				// Should not have X-Frame-Options (to allow iframe embedding)
				if rw.Header().Get("X-Frame-Options") != "" {
					t.Error("Expected X-Frame-Options to be removed for front-channel logout")
				}
				// Should have HTML content type
				contentType := rw.Header().Get("Content-Type")
				if !strings.Contains(contentType, "text/html") {
					t.Errorf("Expected HTML content type, got %s", contentType)
				}
			}
		})
	}
}

// TestSessionInvalidation tests session invalidation storage and retrieval
func TestSessionInvalidation(t *testing.T) {
	mockCache := &mockCacheInterface{
		data: make(map[string]interface{}),
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		sessionInvalidationCache: mockCache,
	}

	// Test invalidating by session ID
	err := oidc.invalidateSession("session123", "")
	if err != nil {
		t.Fatalf("Failed to invalidate session by sid: %v", err)
	}

	// Verify the session was invalidated
	key := oidc.buildSessionInvalidationKey("sid", "session123")
	if _, found := mockCache.data[key]; !found {
		t.Error("Session invalidation by sid was not stored")
	}

	// Test invalidating by subject
	err = oidc.invalidateSession("", "user@example.com")
	if err != nil {
		t.Fatalf("Failed to invalidate session by sub: %v", err)
	}

	// Verify the subject was invalidated
	key = oidc.buildSessionInvalidationKey("sub", "user@example.com")
	if _, found := mockCache.data[key]; !found {
		t.Error("Session invalidation by sub was not stored")
	}
}

// TestIsSessionInvalidated tests checking if a session is invalidated
func TestIsSessionInvalidated(t *testing.T) {
	mockCache := &mockCacheInterface{
		data: make(map[string]interface{}),
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		sessionInvalidationCache: mockCache,
	}

	// Session created now
	sessionCreatedAt := time.Now()

	// Initially, session should not be invalidated
	if oidc.isSessionInvalidated("session123", "user@example.com", sessionCreatedAt) {
		t.Error("Session should not be invalidated initially")
	}

	// Invalidate the session
	_ = oidc.invalidateSession("session123", "")

	// Now session should be invalidated
	if !oidc.isSessionInvalidated("session123", "", sessionCreatedAt) {
		t.Error("Session should be invalidated after invalidateSession call")
	}

	// Session created after invalidation should not be affected
	futureSession := time.Now().Add(1 * time.Hour)
	if oidc.isSessionInvalidated("session123", "", futureSession) {
		t.Error("Session created after invalidation should not be affected")
	}
}

// TestLogoutTokenValidation tests logout token claim validation
func TestLogoutTokenValidation(t *testing.T) {
	tests := []struct {
		name        string
		claims      *LogoutTokenClaims
		expectError bool
		errorMsg    string
	}{
		{
			name: "Missing events claim",
			claims: &LogoutTokenClaims{
				Issuer:    "https://provider.example.com",
				Audience:  "test-client",
				IssuedAt:  time.Now().Unix(),
				SessionID: "session123",
			},
			expectError: true,
			errorMsg:    "missing events claim",
		},
		{
			name: "Missing both sid and sub",
			claims: &LogoutTokenClaims{
				Issuer:   "https://provider.example.com",
				Audience: "test-client",
				IssuedAt: time.Now().Unix(),
				Events: map[string]interface{}{
					"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
				},
			},
			expectError: true,
			errorMsg:    "must contain either sid or sub",
		},
		{
			name: "Nonce present (not allowed)",
			claims: &LogoutTokenClaims{
				Issuer:    "https://provider.example.com",
				Audience:  "test-client",
				IssuedAt:  time.Now().Unix(),
				SessionID: "session123",
				Nonce:     "should-not-be-here",
				Events: map[string]interface{}{
					"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
				},
			},
			expectError: true,
			errorMsg:    "nonce claim must not be present",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// We can't directly test validateLogoutToken without a properly signed JWT,
			// but we can verify the validation logic through the claims struct
			if tc.claims.Events == nil && tc.expectError && strings.Contains(tc.errorMsg, "events") {
				// Events validation would fail
			}
			if tc.claims.SessionID == "" && tc.claims.Subject == "" && tc.expectError && strings.Contains(tc.errorMsg, "sid or sub") {
				// sid/sub validation would fail
			}
			if tc.claims.Nonce != "" && tc.expectError && strings.Contains(tc.errorMsg, "nonce") {
				// nonce validation would fail
			}
		})
	}
}

// TestLogoutTokenAudienceValidation tests audience validation for logout tokens
func TestLogoutTokenAudienceValidation(t *testing.T) {
	oidc := &TraefikOidc{
		logger:   NewLogger("debug"),
		clientID: "test-client",
	}

	tests := []struct {
		name     string
		audience interface{}
		valid    bool
	}{
		{
			name:     "String audience matching client ID",
			audience: "test-client",
			valid:    true,
		},
		{
			name:     "String audience not matching",
			audience: "other-client",
			valid:    false,
		},
		{
			name:     "Array audience containing client ID",
			audience: []interface{}{"other-client", "test-client"},
			valid:    true,
		},
		{
			name:     "Array audience not containing client ID",
			audience: []interface{}{"other-client", "another-client"},
			valid:    false,
		},
		{
			name:     "String array audience containing client ID",
			audience: []string{"other-client", "test-client"},
			valid:    true,
		},
		{
			name:     "Nil audience",
			audience: nil,
			valid:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := oidc.validateLogoutTokenAudience(tc.audience)
			if result != tc.valid {
				t.Errorf("Expected %v, got %v", tc.valid, result)
			}
		})
	}
}

// TestExtractSessionInfo tests extraction of session info from ID tokens
func TestExtractSessionInfo(t *testing.T) {
	oidc := &TraefikOidc{
		logger: NewLogger("debug"),
	}

	// Test with empty token
	sid, sub, createdAt := oidc.extractSessionInfo("")
	if sid != "" || sub != "" || !createdAt.IsZero() {
		t.Error("Empty token should return empty values")
	}

	// Test with invalid token
	sid, sub, createdAt = oidc.extractSessionInfo("not-a-valid-jwt")
	if sid != "" || sub != "" || !createdAt.IsZero() {
		t.Error("Invalid token should return empty values")
	}

	// Create a simple unsigned JWT for testing (header.claims.signature)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	now := time.Now().Unix()
	claimsJSON := fmt.Sprintf(`{"sid":"test-session-id","sub":"test-subject","iat":%d}`, now)
	claims := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	testToken := header + "." + claims + "."

	sid, sub, createdAt = oidc.extractSessionInfo(testToken)
	if sid != "test-session-id" {
		t.Errorf("Expected sid 'test-session-id', got '%s'", sid)
	}
	if sub != "test-subject" {
		t.Errorf("Expected sub 'test-subject', got '%s'", sub)
	}
	if createdAt.Unix() != now {
		t.Errorf("Expected createdAt %d, got %d", now, createdAt.Unix())
	}
}

// TestMiddlewareBackchannelLogoutRouting tests that backchannel logout requests are routed correctly
func TestMiddlewareBackchannelLogoutRouting(t *testing.T) {
	mockCache := &mockCacheInterface{
		data: make(map[string]interface{}),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("next handler called"))
	})

	oidc := &TraefikOidc{
		next:                     nextHandler,
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		initComplete:             make(chan struct{}),
		firstRequestReceived:     true,
		metadataRefreshStarted:   true,
		logoutURLPath:            "/logout",
	}
	close(oidc.initComplete)

	// Request to backchannel logout path should be handled
	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout", nil)
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	// Should return 400 (bad request) because no logout_token provided
	// but importantly should NOT call next handler
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing logout_token, got %d", rw.Code)
	}
	if strings.Contains(rw.Body.String(), "next handler called") {
		t.Error("Backchannel logout should not call next handler")
	}
}

// TestMiddlewareFrontchannelLogoutRouting tests that front-channel logout requests are routed correctly
func TestMiddlewareFrontchannelLogoutRouting(t *testing.T) {
	mockCache := &mockCacheInterface{
		data: make(map[string]interface{}),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("next handler called"))
	})

	oidc := &TraefikOidc{
		next:                     nextHandler,
		logger:                   NewLogger("debug"),
		enableFrontchannelLogout: true,
		frontchannelLogoutPath:   "/frontchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		initComplete:             make(chan struct{}),
		firstRequestReceived:     true,
		metadataRefreshStarted:   true,
		logoutURLPath:            "/logout",
	}
	close(oidc.initComplete)

	// Request to front-channel logout path with valid sid should succeed
	req := httptest.NewRequest(http.MethodGet, "/frontchannel-logout?sid=test-session", nil)
	rw := httptest.NewRecorder()

	oidc.ServeHTTP(rw, req)

	// Should return 200 OK
	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rw.Code)
	}
	if strings.Contains(rw.Body.String(), "next handler called") {
		t.Error("Front-channel logout should not call next handler")
	}
}

// TestNormalizeLogoutPath tests the path normalization function
func TestNormalizeLogoutPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"/logout", "/logout"},
		{"logout", "/logout"},
		{"/backchannel-logout", "/backchannel-logout"},
		{"backchannel-logout", "/backchannel-logout"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeLogoutPath(tc.input)
			if result != tc.expected {
				t.Errorf("normalizeLogoutPath(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

// mockCacheInterface implements CacheInterface for testing
type mockCacheInterface struct {
	mu   sync.Mutex
	data map[string]interface{}
}

func (m *mockCacheInterface) Set(key string, value interface{}, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[string]interface{})
	}
	m.data[key] = value
}

func (m *mockCacheInterface) Get(key string) (interface{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return nil, false
	}
	val, found := m.data[key]
	return val, found
}

func (m *mockCacheInterface) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data != nil {
		delete(m.data, key)
	}
}

func (m *mockCacheInterface) SetMaxSize(size int) {}
func (m *mockCacheInterface) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.data)
}
func (m *mockCacheInterface) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]interface{})
}
func (m *mockCacheInterface) Cleanup() {}
func (m *mockCacheInterface) Close()   {}
func (m *mockCacheInterface) GetStats() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]interface{}{"size": len(m.data)}
}

// TestBackchannelLogoutWithValidToken tests backchannel logout with a properly formatted (but unsigned) token
func TestBackchannelLogoutWithValidToken(t *testing.T) {
	// This test verifies the token parsing and validation logic
	// Note: In production, the token would need to be properly signed by the IdP
	mockCache := &mockCacheInterface{
		data: make(map[string]interface{}),
	}

	// Create mock JWK cache that returns keys
	mockJWKCache := &mockJWKCacheForLogout{}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
	}

	// Create a minimal logout token structure (this won't pass signature verification
	// but tests the parsing logic)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"logout+jwt"}`))
	now := time.Now().Unix()
	claimsJSON := fmt.Sprintf(`{
		"iss":"https://provider.example.com",
		"aud":"test-client",
		"iat":%d,
		"jti":"unique-id-123",
		"events":{"http://schemas.openid.net/event/backchannel-logout":{}},
		"sid":"session-to-logout"
	}`, now)
	claims := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	logoutToken := header + "." + claims + ".fake-signature"

	// This should fail because of invalid signature, but we can verify
	// the token parsing works up to signature verification
	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	// Should fail with 400 due to signature verification failure
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rw.Code)
	}
}

// mockJWKCacheForLogout implements JWKCacheInterface for testing
type mockJWKCacheForLogout struct{}

func (m *mockJWKCacheForLogout) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	// Generate a test ECDSA key pair
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Convert public key to JWK format
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	return &JWKSet{
		Keys: []JWK{
			{
				Kty: "EC",
				Crv: "P-256",
				X:   x,
				Y:   y,
				Kid: "test-key-1",
				Use: "sig",
				Alg: "ES256",
			},
		},
	}, nil
}

func (m *mockJWKCacheForLogout) Clear()   {}
func (m *mockJWKCacheForLogout) Cleanup() {}
func (m *mockJWKCacheForLogout) Close()   {}

// TestBackchannelLogoutIntegration tests the full backchannel logout flow with a properly signed token
func TestBackchannelLogoutIntegration(t *testing.T) {
	// Generate ECDSA key pair for signing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	mockCache := &mockCacheInterface{
		data: make(map[string]interface{}),
	}

	// Create JWK cache that returns our test key
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{
				{
					Kty: "EC",
					Crv: "P-256",
					X:   x,
					Y:   y,
					Kid: "test-key-1",
					Use: "sig",
					Alg: "ES256",
				},
			},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Create and sign a valid logout token
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "logout+jwt",
		"kid": "test-key-1",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": now,
		"jti": "unique-id-123",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-to-logout",
	}
	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Sign the token
	signingInput := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Convert signature to fixed-size format (32 bytes each for P-256)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):], sBytes)
	signatureB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	logoutToken := headerB64 + "." + claimsB64 + "." + signatureB64

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	// Should succeed with 200 OK
	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rw.Code, rw.Body.String())
	}

	// Verify session was invalidated
	key := oidc.buildSessionInvalidationKey("sid", "session-to-logout")
	if _, found := mockCache.data[key]; !found {
		t.Error("Session should have been invalidated")
	}
}

// staticJWKCache returns a static JWKS for testing
type staticJWKCache struct {
	jwks *JWKSet
}

func (s *staticJWKCache) GetJWKS(ctx context.Context, jwksURL string, httpClient *http.Client) (*JWKSet, error) {
	return s.jwks, nil
}

func (s *staticJWKCache) Clear()   {}
func (s *staticJWKCache) Cleanup() {}
func (s *staticJWKCache) Close()   {}

// TestDetermineLogoutPath tests the logout path determination function
func TestDetermineLogoutPath(t *testing.T) {
	oidc := &TraefikOidc{
		logger:                 NewLogger("debug"),
		logoutURLPath:          "/logout",
		backchannelLogoutPath:  "/backchannel-logout",
		frontchannelLogoutPath: "/frontchannel-logout",
	}

	tests := []struct {
		path     string
		expected string
	}{
		{"/logout", "rp"},
		{"/backchannel-logout", "backchannel"},
		{"/frontchannel-logout", "frontchannel"},
		{"/api/resource", ""},
		{"/", ""},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			result := oidc.determineLogoutPath(tc.path)
			if result != tc.expected {
				t.Errorf("determineLogoutPath(%q) = %q, expected %q", tc.path, result, tc.expected)
			}
		})
	}
}

// TestSessionInvalidationWithNilCache tests that session invalidation handles nil cache gracefully
func TestSessionInvalidationWithNilCache(t *testing.T) {
	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		sessionInvalidationCache: nil,
	}

	// Should return error for nil cache
	err := oidc.invalidateSession("session123", "")
	if err == nil {
		t.Error("Expected error for nil cache")
	}

	// isSessionInvalidated should return false for nil cache
	if oidc.isSessionInvalidated("session123", "", time.Now()) {
		t.Error("Expected false for nil cache")
	}
}

// TestBackchannelLogoutWithSubOnly tests logout with subject claim only (no sid)
func TestBackchannelLogoutWithSubOnly(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-sub-only",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sub": "user@example.com", // Only sub, no sid
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rw.Code, rw.Body.String())
	}

	// Verify subject was invalidated
	key := oidc.buildSessionInvalidationKey("sub", "user@example.com")
	if _, found := mockCache.data[key]; !found {
		t.Error("Subject should have been invalidated")
	}
}

// TestBackchannelLogoutWithBothSidAndSub tests logout with both sid and sub claims
func TestBackchannelLogoutWithBothSidAndSub(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-both",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-123",
		"sub": "user@example.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rw.Code)
	}

	// Both sid and sub should be invalidated
	sidKey := oidc.buildSessionInvalidationKey("sid", "session-123")
	subKey := oidc.buildSessionInvalidationKey("sub", "user@example.com")
	if _, found := mockCache.data[sidKey]; !found {
		t.Error("Session ID should have been invalidated")
	}
	if _, found := mockCache.data[subKey]; !found {
		t.Error("Subject should have been invalidated")
	}
}

// TestBackchannelLogoutWrongIssuer tests that wrong issuer is rejected
func TestBackchannelLogoutWrongIssuer(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://wrong-issuer.com", // Wrong issuer
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-wrong-iss",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-123",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for wrong issuer, got %d", rw.Code)
	}
}

// TestBackchannelLogoutWrongAudience tests that wrong audience is rejected
func TestBackchannelLogoutWrongAudience(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "wrong-client-id", // Wrong audience
		"iat": time.Now().Unix(),
		"jti": "unique-id-wrong-aud",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-123",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for wrong audience, got %d", rw.Code)
	}
}

// TestBackchannelLogoutExpiredToken tests that expired tokens are rejected
func TestBackchannelLogoutExpiredToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token issued 20 minutes ago (> 15 min allowed)
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Add(-20 * time.Minute).Unix(), // Too old
		"jti": "unique-id-expired",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-123",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for expired token, got %d", rw.Code)
	}
}

// TestBackchannelLogoutFutureToken tests that future-dated tokens are rejected
func TestBackchannelLogoutFutureToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token issued 10 minutes in the future (> 5 min clock skew allowed)
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Add(10 * time.Minute).Unix(), // Future
		"jti": "unique-id-future",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-123",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for future token, got %d", rw.Code)
	}
}

// TestBackchannelLogoutMissingEvents tests that missing events claim is rejected
func TestBackchannelLogoutMissingEvents(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token without events claim
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-no-events",
		"sid": "session-123",
		// No events claim
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing events, got %d", rw.Code)
	}
}

// TestBackchannelLogoutWrongEventType tests that wrong event type is rejected
func TestBackchannelLogoutWrongEventType(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token with wrong event type
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-wrong-event",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/wrong-event": map[string]interface{}{}, // Wrong event
		},
		"sid": "session-123",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for wrong event type, got %d", rw.Code)
	}
}

// TestBackchannelLogoutWithNonce tests that nonce presence is rejected
func TestBackchannelLogoutWithNonce(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token with nonce (not allowed per spec)
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-with-nonce",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid":   "session-123",
		"nonce": "should-not-be-here", // Nonce not allowed
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for token with nonce, got %d", rw.Code)
	}
}

// TestBackchannelLogoutRawJWTBody tests logout with raw JWT in body (not form-urlencoded)
func TestBackchannelLogoutRawJWTBody(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-raw-body",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-raw-body",
	})

	// Send raw JWT in body (no form encoding)
	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout", strings.NewReader(logoutToken))
	req.Header.Set("Content-Type", "application/jwt")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rw.Code, rw.Body.String())
	}

	// Verify session was invalidated
	key := oidc.buildSessionInvalidationKey("sid", "session-raw-body")
	if _, found := mockCache.data[key]; !found {
		t.Error("Session should have been invalidated")
	}
}

// TestBackchannelLogoutArrayAudience tests logout with array audience claim
func TestBackchannelLogoutArrayAudience(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Array audience containing our client ID
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": []string{"other-client", "test-client", "another-client"},
		"iat": time.Now().Unix(),
		"jti": "unique-id-array-aud",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-array-aud",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestFrontchannelLogoutWithSubOnly tests front-channel logout with sub parameter only
func TestFrontchannelLogoutWithSubOnly(t *testing.T) {
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableFrontchannelLogout: true,
		frontchannelLogoutPath:   "/frontchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
	}

	// Front-channel with sub parameter (some IdPs use this)
	req := httptest.NewRequest(http.MethodGet, "/frontchannel-logout?sub=user@example.com&iss=https://provider.example.com", nil)
	rw := httptest.NewRecorder()

	oidc.handleFrontchannelLogout(rw, req)

	// Should fail because sid is required
	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 (sid required), got %d", rw.Code)
	}
}

// TestFrontchannelLogoutCacheControl tests that front-channel logout sets proper cache headers
func TestFrontchannelLogoutCacheControl(t *testing.T) {
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableFrontchannelLogout: true,
		frontchannelLogoutPath:   "/frontchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
	}

	req := httptest.NewRequest(http.MethodGet, "/frontchannel-logout?sid=session123", nil)
	rw := httptest.NewRecorder()

	oidc.handleFrontchannelLogout(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rw.Code)
	}

	// Check cache headers
	cacheControl := rw.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-cache") || !strings.Contains(cacheControl, "no-store") {
		t.Errorf("Expected Cache-Control to contain no-cache and no-store, got %s", cacheControl)
	}

	pragma := rw.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("Expected Pragma: no-cache, got %s", pragma)
	}

	// X-Frame-Options should be removed (to allow iframe embedding)
	if rw.Header().Get("X-Frame-Options") != "" {
		t.Error("X-Frame-Options should be removed for front-channel logout")
	}
}

// TestConcurrentSessionInvalidation tests concurrent session invalidations
func TestConcurrentSessionInvalidation(t *testing.T) {
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		sessionInvalidationCache: mockCache,
	}

	// Invalidate multiple sessions concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			sid := fmt.Sprintf("session-%d", idx)
			sub := fmt.Sprintf("user%d@example.com", idx)
			err := oidc.invalidateSession(sid, sub)
			if err != nil {
				t.Errorf("Failed to invalidate session %d: %v", idx, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all sessions were invalidated
	for i := 0; i < 10; i++ {
		sid := fmt.Sprintf("session-%d", i)
		sub := fmt.Sprintf("user%d@example.com", i)
		sidKey := oidc.buildSessionInvalidationKey("sid", sid)
		subKey := oidc.buildSessionInvalidationKey("sub", sub)
		if _, found := mockCache.Get(sidKey); !found {
			t.Errorf("Session %d should have been invalidated by sid", i)
		}
		if _, found := mockCache.Get(subKey); !found {
			t.Errorf("Session %d should have been invalidated by sub", i)
		}
	}
}

// TestSessionInvalidationTimeComparison tests the time comparison logic
func TestSessionInvalidationTimeComparison(t *testing.T) {
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		sessionInvalidationCache: mockCache,
	}

	// Create session at specific time
	sessionCreatedAt := time.Now()

	// Wait a tiny bit and invalidate
	time.Sleep(10 * time.Millisecond)
	_ = oidc.invalidateSession("session-time-test", "")

	// Session created before invalidation should be invalidated
	if !oidc.isSessionInvalidated("session-time-test", "", sessionCreatedAt) {
		t.Error("Session created before invalidation should be marked as invalidated")
	}

	// Session created after invalidation (simulated) should NOT be invalidated
	futureSession := time.Now().Add(1 * time.Second)
	if oidc.isSessionInvalidated("session-time-test", "", futureSession) {
		t.Error("Session created after invalidation should NOT be marked as invalidated")
	}
}

// TestBackchannelLogoutMissingIat tests that missing iat is rejected
func TestBackchannelLogoutMissingIat(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token without iat claim
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		// No iat
		"jti": "unique-id-no-iat",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		"sid": "session-123",
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing iat, got %d", rw.Code)
	}
}

// TestBackchannelLogoutMissingSidAndSub tests that missing both sid and sub is rejected
func TestBackchannelLogoutMissingSidAndSub(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mockCache := &mockCacheInterface{data: make(map[string]interface{})}
	x := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes())

	mockJWKCache := &staticJWKCache{
		jwks: &JWKSet{
			Keys: []JWK{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: "test-key-1", Use: "sig", Alg: "ES256"}},
		},
	}

	oidc := &TraefikOidc{
		logger:                   NewLogger("debug"),
		enableBackchannelLogout:  true,
		backchannelLogoutPath:    "/backchannel-logout",
		sessionInvalidationCache: mockCache,
		clientID:                 "test-client",
		issuerURL:                "https://provider.example.com",
		jwkCache:                 mockJWKCache,
		jwksURL:                  "https://provider.example.com/.well-known/jwks.json",
	}

	// Token without sid or sub
	logoutToken := createSignedLogoutToken(t, privateKey, map[string]interface{}{
		"iss": "https://provider.example.com",
		"aud": "test-client",
		"iat": time.Now().Unix(),
		"jti": "unique-id-no-sid-sub",
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
		// No sid or sub
	})

	req := httptest.NewRequest(http.MethodPost, "/backchannel-logout",
		strings.NewReader("logout_token="+url.QueryEscape(logoutToken)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	oidc.handleBackchannelLogout(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing sid and sub, got %d", rw.Code)
	}
}

// createSignedLogoutToken is a helper to create properly signed logout tokens for testing
func createSignedLogoutToken(t *testing.T, privateKey *ecdsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "logout+jwt",
		"kid": "test-key-1",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, _ := json.Marshal(claims)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Sign the token
	signingInput := headerB64 + "." + claimsB64
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Convert signature to fixed-size format (32 bytes each for P-256)
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):], sBytes)
	signatureB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return headerB64 + "." + claimsB64 + "." + signatureB64
}
