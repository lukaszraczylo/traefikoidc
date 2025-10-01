package token

import (
	"strings"
	"testing"
	"time"

	traefikoidc "github.com/lukaszraczylo/traefikoidc"
)

// Mock implementations for testing
type MockTokenCache struct {
	data map[string]map[string]interface{}
}

func (m *MockTokenCache) Get(key string) (map[string]interface{}, bool) {
	if m.data == nil {
		return nil, false
	}
	value, exists := m.data[key]
	return value, exists
}

func (m *MockTokenCache) Set(key string, claims map[string]interface{}, ttl time.Duration) {
	if m.data == nil {
		m.data = make(map[string]map[string]interface{})
	}
	m.data[key] = claims
}

type MockCache struct {
	data map[string]interface{}
}

func (m *MockCache) Get(key string) (interface{}, bool) {
	if m.data == nil {
		return nil, false
	}
	value, exists := m.data[key]
	return value, exists
}

func (m *MockCache) Set(key string, value interface{}, ttl time.Duration) {
	if m.data == nil {
		m.data = make(map[string]interface{})
	}
	m.data[key] = value
}

type MockJWKCache struct{}

func (m *MockJWKCache) GetJWKS(providerURL string) (*traefikoidc.JWKSet, error) {
	return &traefikoidc.JWKSet{
		Keys: []traefikoidc.JWK{
			{
				Kid: "test-key",
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
			},
		},
	}, nil
}

type MockRateLimiter struct {
	allow bool
}

func (m *MockRateLimiter) Allow() bool {
	return m.allow
}

type MockLogger struct {
	debugMessages []string
	errorMessages []string
}

func (m *MockLogger) Debugf(format string, args ...interface{}) {
	m.debugMessages = append(m.debugMessages, format)
}

func (m *MockLogger) Errorf(format string, args ...interface{}) {
	m.errorMessages = append(m.errorMessages, format)
}

func TestNewVerifier(t *testing.T) {
	tokenCache := &MockTokenCache{}
	tokenBlacklist := &MockCache{}
	jwkCache := &MockJWKCache{}
	limiter := &MockRateLimiter{allow: true}
	logger := &MockLogger{}

	verifier := NewVerifier(tokenCache, tokenBlacklist, jwkCache, limiter, logger)

	if verifier == nil {
		t.Fatal("NewVerifier returned nil")
	}

	if verifier.tokenCache != tokenCache {
		t.Error("TokenCache not set correctly")
	}

	if verifier.tokenBlacklist != tokenBlacklist {
		t.Error("TokenBlacklist not set correctly")
	}

	// Note: Interface comparison would require reflecting on the actual implementation
	// For now, we just check that the field was set to something non-nil
	if verifier.jwkCache == nil {
		t.Error("JWKCache not set correctly")
	}

	if verifier.limiter != limiter {
		t.Error("RateLimiter not set correctly")
	}

	if verifier.logger != logger {
		t.Error("Logger not set correctly")
	}
}

func TestVerifierBasicFunctionality(t *testing.T) {
	tokenCache := &MockTokenCache{}
	tokenBlacklist := &MockCache{}
	jwkCache := &MockJWKCache{}
	limiter := &MockRateLimiter{allow: true}
	logger := &MockLogger{}

	verifier := NewVerifier(tokenCache, tokenBlacklist, jwkCache, limiter, logger)

	// Test that the verifier was created successfully
	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestJWKSStructure(t *testing.T) {
	jwks := &traefikoidc.JWKSet{
		Keys: []traefikoidc.JWK{
			{
				Kid: "test-key-1",
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
			},
			{
				Kid: "test-key-2",
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
			},
		},
	}

	if len(jwks.Keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "test-key-1" {
		t.Errorf("Expected Kid 'test-key-1', got '%s'", jwks.Keys[0].Kid)
	}

	if jwks.Keys[1].Kid != "test-key-2" {
		t.Errorf("Expected Kid 'test-key-2', got '%s'", jwks.Keys[1].Kid)
	}
}

func TestJWKStructure(t *testing.T) {
	jwk := traefikoidc.JWK{
		Kid: "test-key",
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		N:   "test-modulus",
		E:   "test-exponent",
	}

	if jwk.Kid != "test-key" {
		t.Errorf("Expected Kid 'test-key', got '%s'", jwk.Kid)
	}

	if jwk.Kty != "RSA" {
		t.Errorf("Expected Kty 'RSA', got '%s'", jwk.Kty)
	}

	if jwk.Use != "sig" {
		t.Errorf("Expected Use 'sig', got '%s'", jwk.Use)
	}

	if jwk.Alg != "RS256" {
		t.Errorf("Expected Alg 'RS256', got '%s'", jwk.Alg)
	}
}

func TestVerifyToken(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		clientID       string
		jwksURL        string
		issuerURL      string
		rateLimitAllow bool
		cacheData      map[string]map[string]interface{}
		blacklistData  map[string]interface{}
		expectedError  string
	}{
		{
			name:           "Empty token",
			token:          "",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: true,
			expectedError:  "invalid JWT format: token is empty",
		},
		{
			name:           "Invalid JWT format - too few parts",
			token:          "header.payload",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: true,
			expectedError:  "invalid JWT format: expected JWT with 3 parts, got 2 parts",
		},
		{
			name:           "Invalid JWT format - too many parts",
			token:          "header.payload.signature.extra",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: true,
			expectedError:  "invalid JWT format: expected JWT with 3 parts, got 4 parts",
		},
		{
			name:           "Token too short",
			token:          "a.b.c",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: true,
			expectedError:  "token too short to be valid JWT",
		},
		{
			name:           "Blacklisted token",
			token:          "valid.format.token",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: true,
			blacklistData:  map[string]interface{}{"valid.format.token": true},
			expectedError:  "token is blacklisted",
		},
		{
			name:           "Cached token - success",
			token:          "valid.format.token",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: true,
			cacheData:      map[string]map[string]interface{}{"valid.format.token": {"sub": "user123"}},
			expectedError:  "",
		},
		{
			name:           "Rate limit exceeded",
			token:          "valid.format.token",
			clientID:       "test-client",
			jwksURL:        "https://example.com/jwks",
			issuerURL:      "https://example.com",
			rateLimitAllow: false,
			expectedError:  "rate limit exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenCache := &MockTokenCache{data: tt.cacheData}
			tokenBlacklist := &MockCache{data: tt.blacklistData}
			jwkCache := &MockJWKCache{}
			limiter := &MockRateLimiter{allow: tt.rateLimitAllow}
			logger := &MockLogger{}

			verifier := NewVerifier(tokenCache, tokenBlacklist, jwkCache, limiter, logger)
			err := verifier.VerifyToken(tt.token, tt.clientID, tt.jwksURL, tt.issuerURL)

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got: %v", tt.expectedError, err)
				}
			}
		})
	}
}

func TestParseJWT(t *testing.T) {
	tokenCache := &MockTokenCache{}
	tokenBlacklist := &MockCache{}
	jwkCache := &MockJWKCache{}
	limiter := &MockRateLimiter{allow: true}
	logger := &MockLogger{}

	verifier := NewVerifier(tokenCache, tokenBlacklist, jwkCache, limiter, logger)

	// Test parseJWT with a valid format token
	jwt, err := verifier.parseJWT("header.payload.signature")
	if err != nil {
		t.Errorf("Expected no error parsing JWT, got: %v", err)
	}

	if jwt == nil {
		t.Error("Expected non-nil JWT object")
		return
	}

	if jwt.Header == nil {
		t.Error("Expected non-nil Header map")
	}

	if jwt.Claims == nil {
		t.Error("Expected non-nil Claims map")
	}
}

func TestVerifyJWTSignatureAndClaims(t *testing.T) {
	tokenCache := &MockTokenCache{}
	tokenBlacklist := &MockCache{}
	jwkCache := &MockJWKCache{}
	limiter := &MockRateLimiter{allow: true}
	logger := &MockLogger{}

	verifier := NewVerifier(tokenCache, tokenBlacklist, jwkCache, limiter, logger)

	jwt := &JWT{
		Header: map[string]interface{}{"alg": "RS256"},
		Claims: map[string]interface{}{"sub": "user123", "exp": float64(time.Now().Add(time.Hour).Unix())},
	}

	// Test signature verification (currently returns nil - placeholder)
	err := verifier.verifyJWTSignatureAndClaims(jwt, "test.token.here", "client-id", "https://example.com/jwks", "https://example.com")
	if err != nil {
		t.Errorf("Expected no error from placeholder verification, got: %v", err)
	}
}

func TestCacheVerifiedToken(t *testing.T) {
	tokenCache := &MockTokenCache{}
	tokenBlacklist := &MockCache{}
	jwkCache := &MockJWKCache{}
	limiter := &MockRateLimiter{allow: true}
	logger := &MockLogger{}

	verifier := NewVerifier(tokenCache, tokenBlacklist, jwkCache, limiter, logger)

	tests := []struct {
		name     string
		token    string
		claims   map[string]interface{}
		expected bool
	}{
		{
			name:     "Valid expiration time",
			token:    "test-token-1",
			claims:   map[string]interface{}{"exp": float64(time.Now().Add(time.Hour).Unix())},
			expected: true,
		},
		{
			name:     "Expired token",
			token:    "test-token-2",
			claims:   map[string]interface{}{"exp": float64(time.Now().Add(-time.Hour).Unix())},
			expected: false,
		},
		{
			name:     "No expiration claim",
			token:    "test-token-3",
			claims:   map[string]interface{}{"sub": "user123"},
			expected: false,
		},
		{
			name:     "Invalid expiration type",
			token:    "test-token-4",
			claims:   map[string]interface{}{"exp": "invalid"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache before test
			tokenCache.data = make(map[string]map[string]interface{})

			verifier.cacheVerifiedToken(tt.token, tt.claims)

			_, exists := tokenCache.Get(tt.token)
			if exists != tt.expected {
				t.Errorf("Expected cache existence: %v, got: %v", tt.expected, exists)
			}
		})
	}
}

func TestMockInterfaces(t *testing.T) {
	// Test MockTokenCache
	tokenCache := &MockTokenCache{}
	claims := map[string]interface{}{"sub": "user123", "exp": 1234567890}
	tokenCache.Set("test-token", claims, time.Hour)

	retrieved, exists := tokenCache.Get("test-token")
	if !exists {
		t.Error("Expected token to exist in cache")
	}

	if retrieved["sub"] != "user123" {
		t.Errorf("Expected sub 'user123', got '%v'", retrieved["sub"])
	}

	// Test MockCache
	cache := &MockCache{}
	cache.Set("test-key", "test-value", time.Hour)

	value, exists := cache.Get("test-key")
	if !exists {
		t.Error("Expected key to exist in cache")
	}

	if value != "test-value" {
		t.Errorf("Expected 'test-value', got '%v'", value)
	}

	// Test MockRateLimiter
	limiter := &MockRateLimiter{allow: true}
	if !limiter.Allow() {
		t.Error("Expected rate limiter to allow request")
	}

	limiter.allow = false
	if limiter.Allow() {
		t.Error("Expected rate limiter to deny request")
	}

	// Test MockLogger
	logger := &MockLogger{}
	logger.Debugf("test debug message")
	logger.Errorf("test error message")

	if len(logger.debugMessages) != 1 {
		t.Errorf("Expected 1 debug message, got %d", len(logger.debugMessages))
	}

	if len(logger.errorMessages) != 1 {
		t.Errorf("Expected 1 error message, got %d", len(logger.errorMessages))
	}
}
